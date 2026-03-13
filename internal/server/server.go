package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/monkburger/taberna/internal/config"
)

// docRootSafe provides filesystem operations confined to a document root
// using os.Root (Go 1.24+).  On Linux this uses openat2 with
// RESOLVE_BENEATH for kernel-enforced containment.  On BSDs and macOS the
// Go runtime emulates containment with iterative openat/O_NOFOLLOW, which
// is best-effort but still prevents the TOCTOU races of stat-then-open.
type docRootSafe struct {
	root *os.Root
	dir  string // filepath.Clean'd document root, for path construction
}

func newDocRootSafe(docRoot string) (docRootSafe, error) {
	dir := filepath.Clean(docRoot)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return docRootSafe{}, fmt.Errorf("opening document root %q: %w", dir, err)
	}
	return docRootSafe{root: root, dir: dir}, nil
}

// rel converts absPath to an os.Root-relative path.  os.Root only accepts
// relative paths; this method also rejects ".." traversal as a defense-in-
// depth check before the kernel-level containment kicks in.
func (d docRootSafe) rel(absPath string) (string, error) {
	r, err := filepath.Rel(d.dir, absPath)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", os.ErrPermission
	}
	return filepath.ToSlash(r), nil
}

// Stat returns file info, rejecting symlinks that escape the document root.
func (d docRootSafe) Stat(absPath string) (os.FileInfo, error) {
	r, err := d.rel(absPath)
	if err != nil {
		return nil, err
	}
	return d.root.Stat(r)
}

// Open opens a file, rejecting symlinks that escape the document root.
// Caller must close the returned file.
func (d docRootSafe) Open(absPath string) (*os.File, error) {
	r, err := d.rel(absPath)
	if err != nil {
		return nil, err
	}
	return d.root.Open(r)
}

// ReadFile reads a contained file, capping reads at maxSize bytes to
// prevent a crafted sidecar from causing unbounded memory allocation.
func (d docRootSafe) ReadFile(absPath string, maxSize int64) ([]byte, error) {
	f, err := d.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxSize))
}

// safeFS implements http.FileSystem using os.Root for TOCTOU-safe symlink
// containment on all POSIX platforms.  When dirListing is false, directory
// requests are only permitted when an index file exists; directory listing
// is blocked via noListDir.
type safeFS struct {
	root       *os.Root
	dirListing bool
	indexFiles []string
}

func newSafeFS(root *os.Root, dirListing bool, indexFiles []string) safeFS {
	return safeFS{root: root, dirListing: dirListing, indexFiles: indexFiles}
}

func (s safeFS) Open(name string) (http.File, error) {
	rel := path.Clean("/" + name)[1:]
	if rel == "" {
		rel = "."
	}
	f, err := s.root.Open(rel)
	if err != nil {
		// os.Root returns platform-specific errors for symlinks that
		// escape the root (EXDEV on Linux, ELOOP or ENOENT on BSDs).
		// Map anything that isn't a genuine "not found" to 403 so
		// http.FileServer never leaks a 500 for an escape attempt.
		if !errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrPermission
		}
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if fi.IsDir() && !s.dirListing {
		for _, idxName := range s.indexFiles {
			idxRel := idxName
			if rel != "." {
				idxRel = rel + "/" + idxName
			}
			if _, err := s.root.Stat(idxRel); err == nil {
				return noListDir{f}, nil
			}
		}
		f.Close()
		return nil, os.ErrPermission
	}
	return f, nil
}

// noListDir wraps an http.File for a directory and overrides Readdir so that
// http.FileServer can never fall through to directory listing.
type noListDir struct{ http.File }

func (noListDir) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrPermission }

// loggingResponseWriter captures the status code and bytes written for access
// logging. Unwrap() exposes the underlying writer so that http.ResponseController
// can still reach optional interfaces (e.g. http.Flusher, http3.ResponseWriter).
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *loggingResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *loggingResponseWriter) WriteHeader(status int) {
	// Only record the first 2xx+ status.  1xx informational responses
	// (e.g. 103 Early Hints) must not lock in the logged status code.
	if w.status == 0 && status >= 200 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// limitListener wraps a net.Listener and enforces a cap on concurrent open
// connections. When max < 0 (unlimited) the original listener is returned
// unmodified.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(l net.Listener, max int) net.Listener {
	if max < 0 {
		return l
	}
	ll := &limitListener{Listener: l, sem: make(chan struct{}, max)}
	for i := 0; i < max; i++ {
		ll.sem <- struct{}{}
	}
	return ll
}

func (l *limitListener) Accept() (net.Conn, error) {
	<-l.sem
	c, err := l.Listener.Accept()
	if err != nil {
		l.sem <- struct{}{}
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { l.sem <- struct{}{} }}, nil
}

// limitConn returns its semaphore token on Close.  sync.Once guards
// against double-close (net/http can call Close more than once), which
// would over-credit the semaphore and break the connection cap.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// vhostRouter dispatches requests to per-virtual-host handlers based on the
// Host header. Exact names take priority over wildcard entries.
type vhostRouter struct {
	exact    map[string]http.Handler // "example.com"  -> handler
	wildcard map[string]http.Handler // ".example.com" -> handler (from *.example.com)
}

func (r *vhostRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := canonicalHost(req.Host)

	if h, ok := r.exact[host]; ok {
		h.ServeHTTP(w, req)
		return
	}

	if dot := strings.Index(host, "."); dot >= 0 {
		if h, ok := r.wildcard[host[dot:]]; ok {
			h.ServeHTTP(w, req)
			return
		}
	}

	http.Error(w, "421 Misdirected Request", http.StatusMisdirectedRequest)
}

// canonicalHost returns the lowercase hostname from a host[:port] string,
// correctly handling IPv6 addresses in either bracketed form ("[::1]:443")
// or bare form ("[::1]").
// TODO: There's a better way to do this in Go 1.20+ with net.SplitHostPort and net.ParseIP, but it doesn't handle the bare IPv6 case correctly.
// Revisit this when Go 1.24+ is the minimum supported version and net.SplitHostPort can be used without a fallback.
func canonicalHost(hostport string) string {
	lower := strings.ToLower(hostport)
	host, _, err := net.SplitHostPort(lower)
	if err != nil {
		// No port present.  Strip brackets around a bare IPv6 address,
		// e.g. "[::1]" → "::1".
		host = lower
		if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
			host = host[1 : len(host)-1]
		}
	}
	return host
}

func cleanURLPath(urlPath string) string {
	if urlPath == "" {
		return "/"
	}
	return path.Clean("/" + urlPath)
}

func docRootLookupPath(docRoot, urlPath string) string {
	cleaned := cleanURLPath(urlPath)
	rel := strings.TrimPrefix(cleaned, "/")
	if rel == "" {
		return docRoot
	}
	return filepath.Join(docRoot, filepath.FromSlash(rel))
}

func hasImplicitIndexHTMLRedirect(urlPath string) bool {
	return strings.HasSuffix(cleanURLPath(urlPath), "/index.html")
}

// acceptsEncoding reports whether the Accept-Encoding header value includes
// enc as an acceptable token.  It respects RFC 9110 §12.5.3 quality values:
// a token with q=0 is explicitly not acceptable; an explicit token always
// takes priority over the wildcard "*" token, so
// "Accept-Encoding: *, gzip;q=0" is correctly treated as rejecting gzip.
func acceptsEncoding(header, enc string) bool {
	// RFC 9110 §12.5.3: explicit tokens override the wildcard "*".
	// Scan all tokens, recording the quality of the first explicit match and
	// the first wildcard match.  If an explicit match is found it wins;
	// the wildcard is only consulted when no explicit match exists.
	explicitQ, hasExplicit := 0.0, false
	wildcardQ, hasWildcard := 0.0, false
	for _, token := range strings.Split(header, ",") {
		token = strings.TrimSpace(token)
		name := token
		q := 1.0
		if i := strings.IndexByte(token, ';'); i >= 0 {
			name = strings.TrimSpace(token[:i])
			for _, param := range strings.Split(strings.TrimSpace(token[i+1:]), ";") {
				param = strings.TrimSpace(param)
				if len(param) > 2 && strings.EqualFold(param[:2], "q=") {
					if v, err := strconv.ParseFloat(strings.TrimSpace(param[2:]), 64); err == nil {
						q = v
					}
				}
			}
		}
		if strings.EqualFold(name, enc) {
			if !hasExplicit { // first explicit match wins
				explicitQ = q
				hasExplicit = true
			}
		} else if name == "*" {
			if !hasWildcard { // first wildcard wins
				wildcardQ = q
				hasWildcard = true
			}
		}
	}
	if hasExplicit {
		return explicitQ > 0
	}
	return hasWildcard && wildcardQ > 0
}

// Server is the Taberna HTTP/3-first TLS-only server.
type Server struct {
	cfg            *config.Config
	certsMu        sync.RWMutex // guards certs and defaultCert for hot-reload via SIGHUP
	certs          map[string]*tls.Certificate
	defaultCert    *tls.Certificate
	router         *vhostRouter
	errorLog       *slog.Logger
	accessLog      *slog.Logger
	logFiles       []*os.File // closed on shutdown
	trustedProxies []*net.IPNet
}

// New builds a Server from cfg, loading and validating all TLS certificates
// and verifying that every document_root directory exists.
func New(cfg *config.Config) (*Server, error) {
	errorLog, accessLog, logFiles, err := openLoggers(cfg.Server.ErrorLog, cfg.Server.AccessLog)
	if err != nil {
		return nil, err
	}
	trustedProxies, err := parseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		for _, f := range logFiles {
			f.Close()
		}
		return nil, fmt.Errorf("server: %w", err)
	}
	s := &Server{
		cfg:   cfg,
		certs: make(map[string]*tls.Certificate),
		router: &vhostRouter{
			exact:    make(map[string]http.Handler),
			wildcard: make(map[string]http.Handler),
		},
		errorLog:       errorLog,
		accessLog:      accessLog,
		logFiles:       logFiles,
		trustedProxies: trustedProxies,
	}
	if err := s.loadCerts(); err != nil {
		s.closeLogFiles()
		return nil, err
	}
	if err := s.checkDocRoots(); err != nil {
		s.closeLogFiles()
		return nil, err
	}
	if err := s.buildRouter(); err != nil {
		s.closeLogFiles()
		return nil, err
	}
	return s, nil
}

// openLoggers opens the access and error log destinations and returns slog
// loggers backed by them.
//
// path == "" or "stderr" → os.Stderr
// path == "off"          → io.Discard
// otherwise             → the named file (created/appended, mode 0640)
//
// The error logger uses slog.NewTextHandler (human-readable key=value pairs).
// The access logger uses slog.NewJSONHandler (one JSON object per request,
// suitable for ingestion by log aggregators).
func openLoggers(errorPath, accessPath string) (errorLog, accessLog *slog.Logger, files []*os.File, err error) {
	open := func(p string) (io.Writer, *os.File, error) {
		switch p {
		case "", "stderr":
			return os.Stderr, nil, nil
		case "off":
			return io.Discard, nil, nil
		default:
			f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
			if err != nil {
				return nil, nil, fmt.Errorf("opening log file %q: %w", p, err)
			}
			return f, f, nil
		}
	}
	errW, errFile, e := open(errorPath)
	if e != nil {
		return nil, nil, nil, e
	}
	accW, accFile, e := open(accessPath)
	if e != nil {
		if errFile != nil {
			errFile.Close()
		}
		return nil, nil, nil, e
	}
	for _, f := range []*os.File{errFile, accFile} {
		if f != nil {
			files = append(files, f)
		}
	}
	errLogger := slog.New(slog.NewTextHandler(errW, &slog.HandlerOptions{Level: slog.LevelDebug}))
	accLogger := slog.New(slog.NewJSONHandler(accW, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return errLogger, accLogger, files, nil
}

func (s *Server) closeLogFiles() {
	for _, f := range s.logFiles {
		f.Close()
	}
}

func (s *Server) loadCerts() error {
	newCerts := make(map[string]*tls.Certificate)
	var defaultCert *tls.Certificate
	for _, vh := range s.cfg.VHosts {
		cert, err := tls.LoadX509KeyPair(vh.TLS.Cert, vh.TLS.Key)
		if err != nil {
			return fmt.Errorf("server: loading cert for %v: %w", vh.ServerNames, err)
		}
		// Append a separate intermediate chain file if configured.
		// If the cert file is already a full-chain bundle this is a no-op.
		if vh.TLS.Chain != "" {
			if err := appendChain(&cert, vh.TLS.Chain, vh.ServerNames, s.errorLog); err != nil {
				return err
			}
		}
		if err := checkCertExpiry(&cert, vh.ServerNames, s.errorLog); err != nil {
			return err
		}
		for _, name := range vh.ServerNames {
			key := strings.ToLower(name)
			if _, exists := newCerts[key]; exists {
				return fmt.Errorf("server: duplicate server_name %q", name)
			}
			c := cert
			newCerts[key] = &c
			if defaultCert == nil {
				defaultCert = &c
			}
		}
	}
	s.certsMu.Lock()
	s.certs = newCerts
	s.defaultCert = defaultCert
	s.certsMu.Unlock()
	return nil
}

// reloadCerts re-reads all TLS certificates from disk without dropping
// existing connections.  Intended to be triggered by SIGHUP so that cert
// renewals (e.g. Let's Encrypt) take effect without a full restart.
func (s *Server) reloadCerts() error {
	return s.loadCerts()
}

// appendChain reads a PEM file of intermediate certificates and appends their
// raw DER bytes to cert.Certificate (after the leaf).  The root CA should NOT
// be included in the chain file — clients already have it in their trust store
// and including it only wastes bytes on every TLS handshake.
func appendChain(cert *tls.Certificate, chainPath string, names []string, logger *slog.Logger) error {
	data, err := os.ReadFile(chainPath)
	if err != nil {
		return fmt.Errorf("server: reading chain for %v: %w", names, err)
	}
	var count int
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		// Validate it is a parseable X.509 certificate before trusting it.
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("server: invalid certificate in chain for %v: %w", names, err)
		}
		cert.Certificate = append(cert.Certificate, block.Bytes)
		count++
	}
	if count == 0 {
		return fmt.Errorf("server: chain file %q for %v contains no CERTIFICATE blocks", chainPath, names)
	}
	return nil
}

// checkCertExpiry returns an error if the leaf certificate has already expired,
// logs a warning if it expires within 30 days, and logs the full chain depth so
// the operator can confirm intermediates are present at startup.
func checkCertExpiry(cert *tls.Certificate, names []string, logger *slog.Logger) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("server: certificate for %v contains no data", names)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("server: parsing certificate for %v: %w", names, err)
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("server: certificate for %v expired on %s",
			names, leaf.NotAfter.Format(time.DateOnly))
	}
	if days := leaf.NotAfter.Sub(now).Hours() / 24; days < 30 {
		logger.Warn("certificate expiring soon",
			slog.Any("names", names),
			slog.Float64("days_remaining", days),
			slog.String("expires", leaf.NotAfter.Format(time.DateOnly)),
		)
	}
	// Log chain depth so the operator can confirm intermediates are present.
	// depth 1 = leaf only (no intermediates — may cause handshake failures on
	// clients that do not cache the intermediate from a prior connection).
	depth := len(cert.Certificate)
	if depth < 2 {
		logger.Warn("certificate chain has no intermediates (leaf only)",
			slog.Any("names", names),
			slog.Int("chain_depth", depth),
		)
	} else {
		logger.Info("certificate OK",
			slog.Any("names", names),
			slog.String("expires", leaf.NotAfter.Format(time.DateOnly)),
			slog.Int("chain_depth", depth),
		)
	}
	return nil
}

// checkDocRoots verifies that every vhost document_root exists and is a
// directory, failing fast at startup before any port is opened.
func (s *Server) checkDocRoots() error {
	for _, vh := range s.cfg.VHosts {
		fi, err := os.Stat(vh.DocumentRoot)
		if err != nil {
			return fmt.Errorf("server: vhost %v: document_root %q: %w",
				vh.ServerNames, vh.DocumentRoot, err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("server: vhost %v: document_root %q is not a directory",
				vh.ServerNames, vh.DocumentRoot)
		}
	}
	return nil
}

// getCertificate implements tls.Config.GetCertificate, selecting the right
// certificate by SNI name with single-level wildcard fallback.
// When no SNI is present (e.g. the client connected via IP address), the first
// loaded certificate is returned so the TLS handshake can still complete.
func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.certsMu.RLock()
	defer s.certsMu.RUnlock()
	name := strings.ToLower(hello.ServerName)
	if name == "" {
		// No SNI: return the first configured certificate deterministically.
		if s.defaultCert != nil {
			return s.defaultCert, nil
		}
		return nil, fmt.Errorf("server: no certificates loaded")
	}
	if cert, ok := s.certs[name]; ok {
		return cert, nil
	}
	if dot := strings.Index(name, "."); dot >= 0 {
		if cert, ok := s.certs["*"+name[dot:]]; ok {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("server: no certificate for %q", name)
}

// isKnownHost reports whether host (canonical form: lowercase, no port, no
// brackets) is served by a configured vhost.  Used to validate the redirect
// target and prevent open-redirect attacks via a crafted Host header.
func (s *Server) isKnownHost(host string) bool {
	if _, ok := s.router.exact[host]; ok {
		return true
	}
	if dot := strings.Index(host, "."); dot >= 0 {
		if _, ok := s.router.wildcard[host[dot:]]; ok {
			return true
		}
	}
	return false
}

func (s *Server) redirectHTTPSPort() string {
	if len(s.cfg.Server.Listen) == 0 {
		return "443"
	}
	addr, err := s.cfg.Server.Listen[0].Resolve()
	if err != nil {
		return "443"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "443"
	}
	return port
}

func httpsAuthority(host, port string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		if port == "" || port == "443" {
			return "[" + host + "]"
		}
		return net.JoinHostPort(host, port)
	}
	if port == "" || port == "443" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func (s *Server) buildRouter() error {
	for _, vh := range s.cfg.VHosts {
		drs, err := newDocRootSafe(vh.DocumentRoot)
		if err != nil {
			return err
		}
		fs := newSafeFS(drs.root, vh.DirListing, vh.IndexFiles)
		var handler http.Handler = http.FileServer(fs)
		handler = indexFilesMiddleware(drs, vh.IndexFiles, handler)
		handler = precompressedMiddleware(fs, handler)
		handler = compressionDictMiddleware(drs, handler)
		if vh.CacheMaxAge.Duration > 0 {
			handler = cacheControlMiddleware(vh.CacheMaxAge.Duration, handler)
		}
		if vh.CacheStatus {
			handler = cacheStatusMiddleware(handler)
		}
		handler = contentDigestMiddleware(handler)
		handler = earlyHintsMiddleware(drs, vh.IndexFiles, handler)
		for _, name := range vh.ServerNames {
			key := strings.ToLower(name)
			if strings.HasPrefix(key, "*.") {
				s.router.wildcard[key[1:]] = handler
			} else {
				s.router.exact[key] = handler
			}
		}
	}
	return nil
}

// indexFilesMiddleware enables serving custom index file names for directory
// requests.  http.FileServer only serves "index.html" natively; for any other
// configured name (e.g. "index.htm"), this middleware rewrites the URL path
// of directory requests to the first matching index file so FileServer serves
// it directly without a redirect or listing fallback.
//
// The middleware is a no-op when IndexFiles contains only the default
// "index.html", avoiding the extra stat on every request.
func indexFilesMiddleware(drs docRootSafe, indexFiles []string, next http.Handler) http.Handler {
	if len(indexFiles) == 0 || (len(indexFiles) == 1 && indexFiles[0] == "index.html") {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "" {
			p = "/"
		}
		if p[len(p)-1] == '/' {
			dir := docRootLookupPath(drs.dir, p)
			for _, idxName := range indexFiles {
				if _, err := drs.Stat(filepath.Join(dir, idxName)); err != nil {
					continue
				}
				if idxName != "index.html" {
					// Rewrite path; FileServer will serve the file directly.
					r2 := r.Clone(r.Context())
					r2.URL.Path = strings.TrimSuffix(p, "/") + "/" + idxName
					next.ServeHTTP(w, r2)
					return
				}
				// "index.html" found and first: FileServer handles it natively.
				break
			}
		}
		next.ServeHTTP(w, r)
	})
}

// precompressedMiddleware transparently serves pre-compressed sidecars
// (.br, .zst, .gz) in priority order: brotli → zstd → gzip.  If the client
// advertises support via Accept-Encoding and the sidecar exists, the
// compressed file is served with the correct Content-Encoding, Content-Type
// (of the original), and Vary headers.  Range requests are stripped because
// ranges on a content-encoded body are not meaningful to clients expecting
// the original.
func precompressedMiddleware(fs http.FileSystem, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if hasImplicitIndexHTMLRedirect(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		urlPath := r.URL.Path
		if urlPath == "" {
			urlPath = "/"
		}
		baseFile, err := fs.Open(urlPath)
		if err != nil {
			w.Header().Add("Vary", "Accept-Encoding")
			next.ServeHTTP(w, r)
			return
		}
		baseInfo, err := baseFile.Stat()
		baseFile.Close()
		if err != nil || baseInfo.IsDir() {
			w.Header().Add("Vary", "Accept-Encoding")
			next.ServeHTTP(w, r)
			return
		}
		ae := r.Header.Get("Accept-Encoding")
		for _, enc := range []struct{ name, ext string }{
			{"br", ".br"},
			{"zstd", ".zst"},
			{"gzip", ".gz"},
		} {
			if !acceptsEncoding(ae, enc.name) {
				continue
			}
			f, err := fs.Open(urlPath + enc.ext)
			if err != nil {
				continue
			}
			fi, err := f.Stat()
			if err != nil || fi.IsDir() || fi.ModTime().Before(baseInfo.ModTime()) {
				f.Close()
				continue
			}
			h := w.Header()
			h.Set("Content-Encoding", enc.name)
			h.Add("Vary", "Accept-Encoding")
			if ct := mime.TypeByExtension(path.Ext(urlPath)); ct != "" {
				h.Set("Content-Type", ct)
			}
			// Strip Range so ServeContent serves the full compressed body.
			r2 := r.Clone(r.Context())
			r2.Header.Del("Range")
			http.ServeContent(w, r2, urlPath+enc.ext, fi.ModTime(), f)
			f.Close()
			return
		}
		// No compressed sidecar found.  Still declare Vary so that caches do not
		// serve this response to clients that would have received a compressed
		// variant (RFC 9110 §12.5.3).
		w.Header().Add("Vary", "Accept-Encoding")
		next.ServeHTTP(w, r)
	})
}

// cacheWriter intercepts WriteHeader so that Cache-Control is only applied to
// successful (2xx) and revalidation (304) responses. Error responses such as
// 403 and 404 must never be cached as "public" for the configured max-age.
type cacheWriter struct {
	http.ResponseWriter
	cacheControl string
	wroteHeader  bool
}

func (cw *cacheWriter) WriteHeader(status int) {
	if !cw.wroteHeader {
		cw.wroteHeader = true
		if status/100 == 2 || status == http.StatusNotModified {
			cw.ResponseWriter.Header().Set("Cache-Control", cw.cacheControl)
		}
	}
	cw.ResponseWriter.WriteHeader(status)
}

func (cw *cacheWriter) Write(b []byte) (int, error) {
	if !cw.wroteHeader {
		// Implicit 200 OK — safe to cache.
		cw.wroteHeader = true
		cw.ResponseWriter.Header().Set("Cache-Control", cw.cacheControl)
	}
	return cw.ResponseWriter.Write(b)
}

func (cw *cacheWriter) Unwrap() http.ResponseWriter { return cw.ResponseWriter }

func cacheControlMiddleware(maxAge time.Duration, next http.Handler) http.Handler {
	v := fmt.Sprintf("public, max-age=%d", int64(maxAge.Seconds()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&cacheWriter{ResponseWriter: w, cacheControl: v}, r)
	})
}

// --- Cache-Status (RFC 9211) ---

// cacheStatusMiddleware adds a Cache-Status header to 2xx responses.
// taberna has no internal cache; every request is served directly from the
// filesystem, so the value is always "taberna; fwd=miss".  Intermediaries
// such as Fastly, Cloudflare, and Varnish parse this header for diagnostics.
func cacheStatusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&cacheStatusWriter{ResponseWriter: w}, r)
	})
}

type cacheStatusWriter struct {
	http.ResponseWriter
	headerWritten bool
}

func (cw *cacheStatusWriter) WriteHeader(status int) {
	if !cw.headerWritten && status/100 == 2 {
		cw.ResponseWriter.Header().Set("Cache-Status", `taberna; fwd=miss`)
	}
	cw.headerWritten = true
	cw.ResponseWriter.WriteHeader(status)
}

func (cw *cacheStatusWriter) Write(b []byte) (int, error) {
	if !cw.headerWritten {
		cw.ResponseWriter.Header().Set("Cache-Status", `taberna; fwd=miss`)
		cw.headerWritten = true
	}
	return cw.ResponseWriter.Write(b)
}

func (cw *cacheStatusWriter) Unwrap() http.ResponseWriter { return cw.ResponseWriter }

// --- Content-Digest (RFC 9530) ---

// digestResponseWriter wraps a ResponseWriter and computes a running SHA-256
// hash of all bytes written to the body.  After the handler chain returns,
// contentDigestMiddleware sends the digest as a trailer.
type digestResponseWriter struct {
	http.ResponseWriter
	h               hash.Hash
	status          int
	trailerDeclared bool
}

func (dw *digestResponseWriter) WriteHeader(status int) {
	if dw.status == 0 {
		dw.status = status
	}
	if !dw.trailerDeclared && status == http.StatusOK {
		// Pre-declare the trailer before the 200 header is flushed.
		dw.ResponseWriter.Header().Add("Trailer", "Content-Digest")
		dw.trailerDeclared = true
	}
	dw.ResponseWriter.WriteHeader(status)
}

func (dw *digestResponseWriter) Write(b []byte) (int, error) {
	if dw.status == 0 {
		dw.status = http.StatusOK
	}
	if !dw.trailerDeclared && dw.status == http.StatusOK {
		// Implicit 200 — declare the trailer before the first body write.
		dw.ResponseWriter.Header().Add("Trailer", "Content-Digest")
		dw.trailerDeclared = true
	}
	dw.h.Write(b)
	return dw.ResponseWriter.Write(b)
}

func (dw *digestResponseWriter) Unwrap() http.ResponseWriter { return dw.ResponseWriter }

// contentDigestMiddleware adds a sha-256 Content-Digest trailer (RFC 9530) to
// successful GET responses (200 OK only).  The digest is computed incrementally
// from the actual bytes sent, so it covers the encoded form (e.g. brotli/gzip/
// zstd/dcb/dcz) exactly as the client receives it.  Partial content (206),
// redirect, and error responses are left without a digest.  HEAD requests carry
// no body, so no digest is computed for them.
func contentDigestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		h := sha256.New()
		dw := &digestResponseWriter{ResponseWriter: w, h: h}
		next.ServeHTTP(dw, r)
		if dw.status == http.StatusOK && dw.trailerDeclared {
			digest := `sha-256=:` + base64.StdEncoding.EncodeToString(h.Sum(nil)) + `:`
			w.Header().Set("Content-Digest", digest)
		}
	})
}

// --- 103 Early Hints (RFC 8297) ---

// earlyHintsMiddleware sends a 103 Early Hints interim response before
// serving each file if a <urlpath>.hints sidecar exists in the document root.
// The sidecar is a plain text file: one Link header value per line, with '#'
// introducing comments and blank lines ignored.
//
// Example — /index.html.hints:
//
//	# preload critical resources
//	</css/app.css>; rel=preload; as=style
//	</js/app.js>; rel=preload; as=script
//
// The 103 response carries the Link headers only.  The same Link values are
// also present in the final 200 response, which is harmless and expected.
// Supported on HTTP/1.1, HTTP/2, and HTTP/3 — all three propagate 1xx interim
// responses correctly.
func earlyHintsMiddleware(drs docRootSafe, indexFiles []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if hasImplicitIndexHTMLRedirect(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			urlPath := cleanURLPath(r.URL.Path)
			filePath := docRootLookupPath(drs.dir, urlPath)
			var hintsPath string
			if fi, err := drs.Stat(filePath); err == nil && fi.IsDir() {
				// Directory request: look for <indexfile>.hints inside the dir.
				for _, idx := range indexFiles {
					candidate := filepath.Join(filePath, idx+".hints")
					if _, err := drs.Stat(candidate); err == nil {
						hintsPath = candidate
						break
					}
				}
			} else if err == nil {
				hintsPath = docRootLookupPath(drs.dir, urlPath+".hints")
			}
			if hintsPath != "" {
				// Limit hints file reads to 64KB to prevent unbounded allocation.
				if data, err := drs.ReadFile(hintsPath, 64*1024); err == nil {
					links := parseHintsFile(data)
					if len(links) > 0 {
						for _, link := range links {
							w.Header().Add("Link", link)
						}
						w.WriteHeader(http.StatusEarlyHints)
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// parseHintsFile splits raw .hints file content into individual Link values.
// Lines beginning with '#' and empty lines are ignored.
func parseHintsFile(data []byte) []string {
	var links []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		links = append(links, line)
	}
	return links
}

// --- Compression Dictionary Transport (RFC 9842) ---

// compressionDictMiddleware implements Compression Dictionary Transport
// (RFC 9842). It handles two duties per request:
//
//  1. Dictionary advertisement: if a <urlpath>.dict sidecar exists in the
//     document root, the response receives:
//     Use-As-Dictionary: match="<pattern>"
//     where <pattern> is the content of the sidecar (e.g. "/js/*.js").
//     The browser then stores the served file as a shared dictionary for
//     future requests matching the pattern.
//
//  2. Dictionary-compressed serving: if the client sends
//     Available-Dictionary: :SHA256HASH:
//     taberna looks for a <urlpath>.dcb (brotli) or <urlpath>.dcz (zstd)
//     dictionary-compressed sidecar. It reads <urlpath>.dh (the SF Bytes
//     hash of the dictionary that produced the sidecar) and compares it with
//     the client's hash. On match, the compressed sidecar is served with:
//     Content-Encoding: dcb  (or dcz)
//     Dictionary-ID: :HASH:
//     Vary: Accept-Encoding, Available-Dictionary
//
// Sidecar naming convention:
//
//	<file>.dict   — one-line match pattern; marks <file> as a dictionary
//	<file>.dcb    — dictionary-compressed brotli of <file>
//	<file>.dcz    — dictionary-compressed zstd of <file>
//	<file>.dh     — SF Bytes hash of the dictionary used (e.g. ":SHA256=:")
//
// Generate sidecars with any RFC 9842-compatible tool, for example:
//
//	echo "/js/*.js" > /var/www/js/app.v1.js.dict
//	zstd -D app.v1.js app.v2.js -o app.v2.js.dcz
//	printf ":%s:" "$(openssl dgst -sha256 -binary app.v1.js | base64 -w0)" \
//	  > app.v2.js.dh
func compressionDictMiddleware(drs docRootSafe, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if hasImplicitIndexHTMLRedirect(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		urlPath := cleanURLPath(r.URL.Path)
		filePath := docRootLookupPath(drs.dir, urlPath)
		baseInfo, err := drs.Stat(filePath)
		if err != nil || baseInfo.IsDir() {
			next.ServeHTTP(w, r)
			return
		}

		// ── 1. Dictionary-compressed response ───────────────────────────────
		// Serve a dictionary-compressed sidecar when the client advertises a
		// matching dictionary via Available-Dictionary (RFC 9842 §4).
		ae := r.Header.Get("Accept-Encoding")
		if availDict := r.Header.Get("Available-Dictionary"); availDict != "" {
			if clientHash := parseSFBytes(availDict); clientHash != "" {
				storedHash := readDictHash(drs, filePath+".dh")
				if storedHash != "" && storedHash == clientHash {
					for _, enc := range []struct{ name, ext string }{
						{"dcb", ".dcb"}, // dictionary-compressed brotli
						{"dcz", ".dcz"}, // dictionary-compressed zstd
					} {
						if !acceptsEncoding(ae, enc.name) {
							continue
						}
						f, err := drs.Open(filePath + enc.ext)
						if err != nil {
							continue
						}
						fi, err := f.Stat()
						if err != nil || fi.IsDir() || fi.ModTime().Before(baseInfo.ModTime()) {
							f.Close()
							continue
						}
						h := w.Header()
						h.Set("Content-Encoding", enc.name)
						h.Set("Vary", "Accept-Encoding, Available-Dictionary")
						h.Set("Dictionary-ID", ":"+clientHash+":")
						if ct := mime.TypeByExtension(filepath.Ext(urlPath)); ct != "" {
							h.Set("Content-Type", ct)
						}
						// Range requests on encoded bodies are not meaningful.
						r2 := r.Clone(r.Context())
						r2.Header.Del("Range")
						http.ServeContent(w, r2, filePath+enc.ext, fi.ModTime(), f)
						f.Close()
						return
					}
				}
			}
		}

		// ── 2. Dictionary advertisement ──────────────────────────────────────
		// If a .dict sidecar exists, wrap the response writer to inject
		// Use-As-Dictionary only on successful (2xx) responses.
		dictSidecar := filePath + ".dict"
		if data, err := drs.ReadFile(dictSidecar, 4096); err == nil {
			if pattern := strings.TrimSpace(string(data)); pattern != "" {
				next.ServeHTTP(&dictAdvWriter{
					ResponseWriter: w,
					pattern:        pattern,
					advertise:      r.Method == http.MethodGet,
				}, r)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// dictAdvWriter injects Use-As-Dictionary on the first full GET 200 response
// header write, leaving 1xx (e.g. 103 Early Hints), partial content, HEAD,
// redirects, and errors untouched.
type dictAdvWriter struct {
	http.ResponseWriter
	pattern       string
	advertise     bool
	headerWritten bool
}

func (dw *dictAdvWriter) WriteHeader(status int) {
	if !dw.headerWritten && dw.advertise && status == http.StatusOK {
		dw.ResponseWriter.Header().Set("Use-As-Dictionary", `match="`+dw.pattern+`"`)
	}
	dw.headerWritten = true
	dw.ResponseWriter.WriteHeader(status)
}

func (dw *dictAdvWriter) Write(b []byte) (int, error) {
	if !dw.headerWritten && dw.advertise {
		// Implicit 200 — set the header before the body flushes.
		dw.ResponseWriter.Header().Set("Use-As-Dictionary", `match="`+dw.pattern+`"`)
	}
	dw.headerWritten = true
	return dw.ResponseWriter.Write(b)
}

func (dw *dictAdvWriter) Unwrap() http.ResponseWriter { return dw.ResponseWriter }

// parseSFBytes parses a Structured Fields Bytes item (RFC 8941 §4.1.8).
// The value must be :BASE64: (colons wrapping standard base64).
// Returns the raw inner base64 string, or "" on any parse failure.
func parseSFBytes(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != ':' || value[len(value)-1] != ':' {
		return ""
	}
	inner := value[1 : len(value)-1]
	if _, err := base64.StdEncoding.DecodeString(inner); err != nil {
		return ""
	}
	return inner
}

// readDictHash reads a .dh file and returns its inner base64 hash string.
// The file must contain a single SF Bytes value, e.g. ":SHA256BASE64=:".
// Returns "" on any error or malformed content.
func readDictHash(drs docRootSafe, path string) string {
	data, err := drs.ReadFile(path, 4096)
	if err != nil {
		return ""
	}
	return parseSFBytes(strings.TrimSpace(string(data)))
}

// tcpTLSConfig returns TLS config for TCP listeners.  NextProtos advertises
// h2 and http/1.1 for ALPN so the client can negotiate HTTP/2 over TCP.
func (s *Server) tcpTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: s.getCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

// quicTLSConfig returns TLS config for QUIC listeners.  NextProtos is set
// by http3.ConfigureTLSConfig to ["h3"] — QUIC always speaks HTTP/3.
func (s *Server) quicTLSConfig() *tls.Config {
	return http3.ConfigureTLSConfig(&tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: s.getCertificate,
	})
}

// securityHeadersMiddleware injects the configured security response headers.
// Any header whose configured value is an empty string is not sent.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	sec := s.cfg.Server.Security
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if sec.HSTS != "" {
			h.Set("Strict-Transport-Security", sec.HSTS)
		}
		if sec.ContentTypeOptions != "" {
			h.Set("X-Content-Type-Options", sec.ContentTypeOptions)
		}
		if sec.FrameOptions != "" {
			h.Set("X-Frame-Options", sec.FrameOptions)
		}
		if sec.ContentSecurityPolicy != "" {
			h.Set("Content-Security-Policy", sec.ContentSecurityPolicy)
		}
		if sec.ReferrerPolicy != "" {
			h.Set("Referrer-Policy", sec.ReferrerPolicy)
		}
		if sec.PermissionsPolicy != "" {
			h.Set("Permissions-Policy", sec.PermissionsPolicy)
		}
		if sec.CrossOriginOpenerPolicy != "" {
			h.Set("Cross-Origin-Opener-Policy", sec.CrossOriginOpenerPolicy)
		}
		if sec.CrossOriginEmbedderPolicy != "" {
			h.Set("Cross-Origin-Embedder-Policy", sec.CrossOriginEmbedderPolicy)
		}
		if sec.CrossOriginResourcePolicy != "" {
			h.Set("Cross-Origin-Resource-Policy", sec.CrossOriginResourcePolicy)
		}
		next.ServeHTTP(w, r)
	})
}

// accessLogMiddleware logs one structured JSON record per completed request.
func (s *Server) accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lw, r)
		status := lw.status
		if status == 0 {
			status = http.StatusOK
		}
		s.accessLog.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("remote", s.realRemoteAddr(r)),
			slog.String("proto", r.Proto),
			slog.String("method", r.Method),
			slog.String("uri", r.URL.RequestURI()),
			slog.Int("status", status),
			slog.Int64("bytes", lw.bytes),
			slog.Duration("duration", time.Since(start).Round(time.Microsecond)),
			slog.String("ua", r.UserAgent()),
		)
	})
}

// realRemoteAddr returns the true client address for logging.  When the
// request arrives from a trusted proxy (or over a Unix socket), the
// RFC 7239 Forwarded header is checked first, then X-Forwarded-For.
func (s *Server) realRemoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// Unix socket connections have an empty or "@" remote addr — always trust.
	isTrusted := host == "" || host == "@"
	if !isTrusted && len(s.trustedProxies) > 0 {
		ip := net.ParseIP(host)
		for _, network := range s.trustedProxies {
			if ip != nil && network.Contains(ip) {
				isTrusted = true
				break
			}
		}
	}
	if !isTrusted {
		return r.RemoteAddr
	}
	// RFC 7239: Forwarded: for=<client> takes precedence over X-Forwarded-For.
	if fwd := r.Header.Get("Forwarded"); fwd != "" {
		for _, part := range strings.Split(fwd, ",") {
			for _, field := range strings.Split(strings.TrimSpace(part), ";") {
				field = strings.TrimSpace(field)
				if strings.HasPrefix(strings.ToLower(field), "for=") {
					if addr := parseForwardedForValue(field[4:]); addr != "" {
						return addr
					}
				}
			}
		}
	}
	// X-Forwarded-For: leftmost entry is the original client.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return r.RemoteAddr
}

func parseForwardedForValue(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	if value == "" {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		host := strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// parseTrustedProxies converts a slice of IP addresses or CIDR strings into
// a slice of *net.IPNet.  Plain IPs are converted to host CIDRs (/32 or /128).
func parseTrustedProxies(specs []string) ([]*net.IPNet, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(specs))
	for _, s := range specs {
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy address %q", s)
			}
			if ip.To4() != nil {
				s = s + "/32"
			} else {
				s = s + "/128"
			}
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", s, err)
		}
		nets = append(nets, ipnet)
	}
	return nets, nil
}

// Run starts a TCP+QUIC listener pair for each configured listen address and
// blocks until a listener error occurs or SIGINT/SIGTERM is received, at which
// point it performs a graceful shutdown.
func (s *Server) Run() error {
	cfg := s.cfg.Server

	// Middleware stack: access log -> security headers -> vhost router.
	handler := s.accessLogMiddleware(s.securityHeadersMiddleware(s.router))

	h3srv := &http3.Server{Handler: handler}

	// TCP handler adds Alt-Svc to advertise HTTP/3 to the client.
	tcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h3srv.SetQUICHeaders(w.Header()); err != nil {
			s.errorLog.Warn("Alt-Svc header error", slog.Any("err", err))
		}
		handler.ServeHTTP(w, r)
	})

	tcpSrv := &http.Server{
		Handler:           tcpHandler,
		TLSConfig:         s.tcpTLSConfig(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout.Duration,
		ReadTimeout:       cfg.ReadTimeout.Duration,
		WriteTimeout:      cfg.WriteTimeout.Duration,
		IdleTimeout:       cfg.IdleTimeout.Duration,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	// Unix domain socket server (plain HTTP — TLS is the caller's job).
	var unixSrv *http.Server
	if cfg.Unix.Enabled {
		unixSrv = &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout.Duration,
			ReadTimeout:       cfg.ReadTimeout.Duration,
			WriteTimeout:      cfg.WriteTimeout.Duration,
			IdleTimeout:       cfg.IdleTimeout.Duration,
			MaxHeaderBytes:    cfg.MaxHeaderBytes,
		}
	}

	n := len(cfg.Listen)
	listenerCount := n * 2 // TCP + QUIC per TLS address
	if cfg.Unix.Enabled {
		listenerCount++
	}
	if cfg.Redirect.Enabled {
		listenerCount += len(cfg.Redirect.Listen)
	}
	errCh := make(chan error, listenerCount)

	quicCfg := &quic.Config{
		MaxIncomingStreams: 250,
		KeepAlivePeriod:    30 * time.Second,
		EnableDatagrams:    false,
		// Allow0RTT enables QUIC 0-RTT session resumption for HTTP/3.  On
		// reconnection the client can send data with the first QUIC packet,
		// saving a full round-trip.  GET requests on a static file server are
		// idempotent, so replay risk is negligible.
		Allow0RTT: true,
	}

	for _, rawAddr := range cfg.Listen {
		addr, _ := rawAddr.Resolve()

		quicLn, err := quic.ListenAddrEarly(addr, s.quicTLSConfig(), quicCfg)
		if err != nil {
			return fmt.Errorf("server: quic listen %s: %w", addr, err)
		}

		// The connection limit MUST wrap the raw TCP listener, not the TLS
		// listener.  If limitConn wraps *tls.Conn, http.Server's type-assert
		// for *tls.Conn fails and HTTP/2 is silently disabled — all clients
		// fall back to HTTP/1.1.  Wrapping before TLS lets tls.NewListener
		// return an unwrapped *tls.Conn from Accept().
		rawLn, err := net.Listen("tcp", addr)
		if err != nil {
			_ = quicLn.Close()
			return fmt.Errorf("server: tcp listen %s: %w", addr, err)
		}
		tcpLn := tls.NewListener(newLimitListener(rawLn, cfg.MaxConnections), s.tcpTLSConfig())

		s.errorLog.Info("listening", slog.String("addr", addr), slog.String("protocols", "TLS 1.3 | HTTP/2 (TCP) | HTTP/3 (QUIC)"))

		go func(ql *quic.EarlyListener) { errCh <- h3srv.ServeListener(ql) }(quicLn)
		go func(l net.Listener) { errCh <- tcpSrv.Serve(l) }(tcpLn)
	}

	if cfg.Unix.Enabled {
		// Remove a stale socket file left from a previous run.
		if err := os.Remove(cfg.Unix.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("server: removing stale unix socket %q: %w", cfg.Unix.Path, err)
		}
		// Set umask 0177 before bind() so the kernel creates the socket
		// with mode 0600.  Without this, there's a TOCTOU window between
		// bind() (creates with default perms) and chmod() where another
		// process could connect to the socket with wider permissions.
		// The configured mode is applied by chmod() immediately after.
		oldMask := syscall.Umask(0o177)
		unixLn, err := net.Listen("unix", cfg.Unix.Path)
		syscall.Umask(oldMask)
		if err != nil {
			return fmt.Errorf("server: unix listen %q: %w", cfg.Unix.Path, err)
		}
		if err := os.Chmod(cfg.Unix.Path, os.FileMode(cfg.Unix.Mode)); err != nil {
			_ = unixLn.Close()
			return fmt.Errorf("server: chmod unix socket %q: %w", cfg.Unix.Path, err)
		}
		s.errorLog.Info("listening", slog.String("addr", "unix:"+cfg.Unix.Path), slog.String("protocols", "HTTP/1.1"))
		go func() { errCh <- unixSrv.Serve(unixLn) }()
	}

	// HTTP → HTTPS redirect listeners (plain HTTP, no TLS).
	var redirectSrvs []*http.Server
	if cfg.Redirect.Enabled {
		httpsPort := s.redirectHTTPSPort()
		// SECURITY: validate the Host header against configured vhosts before
		// building the Location URL.  An attacker-controlled Host header must
		// not produce a redirect to an arbitrary external domain.
		redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := canonicalHost(r.Host)
			if host == "" || !s.isKnownHost(host) {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			authority := httpsAuthority(host, httpsPort)
			http.Redirect(w, r, "https://"+authority+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
		for _, rawAddr := range cfg.Redirect.Listen {
			addr, _ := rawAddr.Resolve()
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("server: redirect listen %s: %w", addr, err)
			}
			rsrv := &http.Server{
				Handler:           redirectHandler,
				ReadHeaderTimeout: cfg.ReadHeaderTimeout.Duration,
				ReadTimeout:       cfg.ReadTimeout.Duration,
				WriteTimeout:      cfg.WriteTimeout.Duration,
				IdleTimeout:       cfg.IdleTimeout.Duration,
			}
			s.errorLog.Info("listening", slog.String("addr", addr), slog.String("protocols", "HTTP/1.1 → HTTPS redirect"))
			redirectSrvs = append(redirectSrvs, rsrv)
			go func(l net.Listener, srv *http.Server) { errCh <- srv.Serve(l) }(ln, rsrv)
		}
	}

	// signal.NotifyContext handles SIGTERM/SIGINT for graceful shutdown.
	// SIGHUP is kept on a separate channel so we can reload certs without
	// triggering the shutdown path.
	shutdownCtx, stopShutdown := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopShutdown()

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)

	for {
		select {
		case err := <-errCh:
			return err
		case <-sighupCh:
			// SIGHUP: reload TLS certificates without dropping connections.
			if err := s.reloadCerts(); err != nil {
				s.errorLog.Error("cert reload failed", slog.Any("err", err))
			} else {
				s.errorLog.Info("certificates reloaded")
			}
		case <-shutdownCtx.Done():
			// SIGTERM / SIGINT: graceful shutdown.
			stopShutdown() // stop further signals from re-entering the context
			s.errorLog.Info("graceful shutdown", slog.String("timeout", cfg.ShutdownTimeout.Duration.String()))
			ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout.Duration)
			if err := tcpSrv.Shutdown(ctx); err != nil {
				s.errorLog.Error("TCP shutdown error", slog.Any("err", err))
			}
			if err := h3srv.Shutdown(ctx); err != nil {
				s.errorLog.Error("QUIC shutdown error", slog.Any("err", err))
			}
			if unixSrv != nil {
				if err := unixSrv.Shutdown(ctx); err != nil {
					s.errorLog.Error("Unix shutdown error", slog.Any("err", err))
				}
				_ = os.Remove(cfg.Unix.Path)
			}
			for _, rsrv := range redirectSrvs {
				if err := rsrv.Shutdown(ctx); err != nil {
					s.errorLog.Error("redirect shutdown error", slog.Any("err", err))
				}
			}
			s.closeLogFiles()
			cancel()
			return nil
		}
	}
}
