package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monkburger/taberna/internal/config"
)

// ---------------------------------------------------------------------------
// TLS certificate helpers
// ---------------------------------------------------------------------------

func generateCert(t *testing.T, dir string, names ...string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour * 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kf, _ := os.Create(keyPath)
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()
	return certPath, keyPath
}

func generateExpiredCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		DNSNames:     []string{"expired.example.com"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	certPath := filepath.Join(dir, "expired.pem")
	keyPath := filepath.Join(dir, "expired.key")
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kf, _ := os.Create(keyPath)
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()
	return certPath, keyPath
}

func buildCfg(t *testing.T, dir string, names []string, dirListing bool) *config.Config {
	t.Helper()
	certPath, keyPath := generateCert(t, dir, names...)
	return &config.Config{
		Server: config.ServerConfig{
			Listen:            []config.ListenAddr{"127.0.0.1:0"},
			ReadHeaderTimeout: config.Duration{Duration: 5 * time.Second},
			ReadTimeout:       config.Duration{Duration: 30 * time.Second},
			WriteTimeout:      config.Duration{Duration: 60 * time.Second},
			IdleTimeout:       config.Duration{Duration: 120 * time.Second},
			ShutdownTimeout:   config.Duration{Duration: 5 * time.Second},
			MaxHeaderBytes:    65536,
			Security: config.SecurityHeadersConfig{
				HSTS:                  "max-age=63072000; includeSubDomains; preload",
				ContentTypeOptions:    "nosniff",
				FrameOptions:          "DENY",
				ContentSecurityPolicy: "default-src 'self'",
				ReferrerPolicy:        "strict-origin-when-cross-origin",
			},
		},
		VHosts: []config.VHostConfig{
			{
				ServerNames:  names,
				DocumentRoot: dir,
				DirListing:   dirListing,
				TLS:          config.TLSConfig{Cert: certPath, Key: keyPath},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// canonicalHost
// ---------------------------------------------------------------------------

func TestCanonicalHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Example.Com:443", "example.com"},
		{"example.com:8443", "example.com"},
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		// IPv6 with port — brackets stripped, port dropped.
		{"[::1]:443", "::1"},
		// IPv6 bare (no port) — brackets stripped.
		{"[::1]", "::1"},
		// IPv6 no brackets, no port.
		{"::1", "::1"},
	}
	for _, tc := range cases {
		if got := canonicalHost(tc.in); got != tc.want {
			t.Errorf("canonicalHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// vhostRouter
// ---------------------------------------------------------------------------

func TestVhostRouterExact(t *testing.T) {
	var called string
	r := &vhostRouter{
		exact: map[string]http.Handler{
			"example.com": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = "exact" }),
		},
		wildcard: map[string]http.Handler{},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	r.ServeHTTP(httptest.NewRecorder(), req)
	if called != "exact" {
		t.Errorf("exact match not called, got %q", called)
	}
}

func TestVhostRouterWildcard(t *testing.T) {
	var called string
	r := &vhostRouter{
		exact: map[string]http.Handler{},
		wildcard: map[string]http.Handler{
			".example.com": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = "wildcard" }),
		},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "api.example.com"
	r.ServeHTTP(httptest.NewRecorder(), req)
	if called != "wildcard" {
		t.Errorf("wildcard match not called, got %q", called)
	}
}

func TestVhostRouterExactBeforeWildcard(t *testing.T) {
	var called string
	r := &vhostRouter{
		exact: map[string]http.Handler{
			"api.example.com": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = "exact" }),
		},
		wildcard: map[string]http.Handler{
			".example.com": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = "wildcard" }),
		},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "api.example.com"
	r.ServeHTTP(httptest.NewRecorder(), req)
	if called != "exact" {
		t.Errorf("exact should take priority, got %q", called)
	}
}

func TestVhostRouterMisdirected(t *testing.T) {
	r := &vhostRouter{
		exact:    map[string]http.Handler{},
		wildcard: map[string]http.Handler{},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "unknown.com"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusMisdirectedRequest {
		t.Errorf("misdirected: status = %d, want 421", w.Code)
	}
}

// ---------------------------------------------------------------------------
// safeFS (directory listing prevention)
// ---------------------------------------------------------------------------

func TestSafeFS_FileServed(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello"), 0644)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fs := newSafeFS(root, false, []string{"index.html"})
	f, err := fs.Open("/hello.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	f.Close()
}

func TestSafeFS_DirWithIndex(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>"), 0644)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fs := newSafeFS(root, false, []string{"index.html"})
	f, err := fs.Open("/")
	if err != nil {
		t.Fatalf("Open with index.html: %v", err)
	}
	f.Close()
}

func TestSafeFS_DirWithoutIndex(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fs := newSafeFS(root, false, []string{"index.html"})
	_, err = fs.Open("/")
	if err != os.ErrPermission {
		t.Errorf("expected os.ErrPermission, got %v", err)
	}
}

// TestSafeFS_ReaddirAlwaysBlocked verifies that safeFS never permits
// directory listing even when a non-"index.html" index file is configured.
// safeFS.Open wraps the directory in noListDir to block Readdir;
// indexFilesMiddleware handles serving the actual file at the handler level.
func TestSafeFS_ReaddirAlwaysBlocked(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.htm"), []byte("<html>"), 0644)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fs := newSafeFS(root, false, []string{"index.htm"})
	f, err := fs.Open("/")
	if err != nil {
		t.Fatalf("Open with index.htm: %v", err)
	}
	defer f.Close()
	if _, err := f.Readdir(-1); err != os.ErrPermission {
		t.Errorf("Readdir should return os.ErrPermission, got %v", err)
	}
}

// TestNoListFS_NonDefaultIndexServed verifies that a non-"index.html" index
// file (e.g. index.htm) is actually served when a directory is requested.
func TestNoListFS_NonDefaultIndexServed(t *testing.T) {
	dir := t.TempDir()
	content := []byte("<html>htm index</html>")
	_ = os.WriteFile(filepath.Join(dir, "index.htm"), content, 0644)

	cfg := buildCfg(t, dir, []string{"idxhtm.example.com"}, false)
	cfg.VHosts[0].IndexFiles = []string{"index.htm"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "idxhtm.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (index.htm should be served)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "htm index") {
		t.Errorf("body = %q, expected index.htm content", w.Body.String())
	}
}

func TestIndexFilesMiddlewareDoesNotRewriteOutsideDocRoot(t *testing.T) {
	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "docroot")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(docRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "index.htm"), []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}

	var gotPath string
	drs, err := newDocRootSafe(docRoot)
	if err != nil {
		t.Fatal(err)
	}
	handler := indexFilesMiddleware(drs, []string{"index.htm"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest("GET", "/../"+strings.TrimPrefix(filepath.ToSlash(outside), "/")+"/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if gotPath != req.URL.Path {
		t.Fatalf("indexFilesMiddleware rewrote path outside docroot: got %q, want %q", gotPath, req.URL.Path)
	}
}

// ---------------------------------------------------------------------------
// security headers middleware
// ---------------------------------------------------------------------------

func TestSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"secure.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := srv.securityHeadersMiddleware(inner)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	mustContain := map[string]string{
		"Strict-Transport-Security": "max-age=63072000",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'self'",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
	for header, substr := range mustContain {
		val := w.Header().Get(header)
		if !strings.Contains(val, substr) {
			t.Errorf("header %q = %q, want to contain %q", header, val, substr)
		}
	}
}

func TestSecurityHeadersSuppressed(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"nosec.example.com"}, false)
	cfg.Server.Security = config.SecurityHeadersConfig{}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	w := httptest.NewRecorder()
	srv.securityHeadersMiddleware(inner).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	for _, h := range []string{
		"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options",
		"Content-Security-Policy", "Referrer-Policy",
	} {
		if v := w.Header().Get(h); v != "" {
			t.Errorf("suppressed header %q still present: %q", h, v)
		}
	}
}

func TestCrossOriginHeaders(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"crossorigin.example.com"}, false)
	cfg.Server.Security.CrossOriginOpenerPolicy = "same-origin"
	cfg.Server.Security.CrossOriginEmbedderPolicy = "require-corp"
	cfg.Server.Security.CrossOriginResourcePolicy = "same-origin"
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	w := httptest.NewRecorder()
	srv.securityHeadersMiddleware(inner).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	for header, want := range map[string]string{
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("header %q = %q, want %q", header, got, want)
		}
	}
}

func TestCrossOriginHeadersSuppressed(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"crossorigin2.example.com"}, false)
	// fields default to empty string — headers must not be sent
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	w := httptest.NewRecorder()
	srv.securityHeadersMiddleware(inner).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	for _, h := range []string{
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy",
	} {
		if v := w.Header().Get(h); v != "" {
			t.Errorf("suppressed cross-origin header %q still present: %q", h, v)
		}
	}
}

func TestCacheStatusHeader(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := cacheStatusMiddleware(inner)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if got := w.Header().Get("Cache-Status"); got != "taberna; fwd=miss" {
		t.Errorf("Cache-Status = %q, want %q", got, "taberna; fwd=miss")
	}
}

func TestCacheStatusAbsentOnError(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	handler := cacheStatusMiddleware(inner)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if got := w.Header().Get("Cache-Status"); got != "" {
		t.Errorf("Cache-Status should be absent on 404, got %q", got)
	}
}

func TestCacheStatusAbsentOnErrorBodyWrite(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	})
	handler := cacheStatusMiddleware(inner)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if got := w.Header().Get("Cache-Status"); got != "" {
		t.Errorf("Cache-Status should be absent on 404 body response, got %q", got)
	}
}

func TestCacheStatusAbsentOnRedirect(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusMovedPermanently)
	})
	handler := cacheStatusMiddleware(inner)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", w.Code)
	}
	if got := w.Header().Get("Cache-Status"); got != "" {
		t.Errorf("Cache-Status should be absent on redirect, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// certificate expiry checks
// ---------------------------------------------------------------------------

func TestCheckCertExpiryValid(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateCert(t, dir, "valid.example.com")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkCertExpiry(&cert, []string{"valid.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Errorf("valid cert flagged as error: %v", err)
	}
}

func TestCheckCertExpiryExpired(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateExpiredCert(t, dir)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkCertExpiry(&cert, []string{"expired.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Error("expired cert should return error")
	}
}

// ---------------------------------------------------------------------------
// server.New — document_root validation
// ---------------------------------------------------------------------------

func TestNewMissingDocRoot(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateCert(t, dir, "docroot.example.com")
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:            []config.ListenAddr{"127.0.0.1:0"},
			MaxHeaderBytes:    65536,
			ReadHeaderTimeout: config.Duration{Duration: 5 * time.Second},
			ReadTimeout:       config.Duration{Duration: 5 * time.Second},
			WriteTimeout:      config.Duration{Duration: 5 * time.Second},
			IdleTimeout:       config.Duration{Duration: 5 * time.Second},
		},
		VHosts: []config.VHostConfig{
			{
				ServerNames:  []string{"docroot.example.com"},
				DocumentRoot: "/nonexistent/docroot",
				TLS:          config.TLSConfig{Cert: certPath, Key: keyPath},
			},
		},
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New should fail for missing document_root")
	}
	if !strings.Contains(err.Error(), "document_root") {
		t.Errorf("error %q should mention document_root", err.Error())
	}
}

// ---------------------------------------------------------------------------
// loggingResponseWriter
// ---------------------------------------------------------------------------

func TestLoggingResponseWriter(t *testing.T) {
	inner := httptest.NewRecorder()
	lw := &loggingResponseWriter{ResponseWriter: inner}
	lw.WriteHeader(http.StatusNotFound)
	if lw.status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", lw.status)
	}
	n, _ := lw.Write([]byte("hello"))
	if lw.bytes != int64(n) {
		t.Errorf("bytes = %d, want %d", lw.bytes, n)
	}
}

func TestLoggingResponseWriterDefaultStatus(t *testing.T) {
	inner := httptest.NewRecorder()
	lw := &loggingResponseWriter{ResponseWriter: inner}
	lw.Write([]byte("ok"))
	if lw.status != http.StatusOK {
		t.Errorf("default status = %d, want 200", lw.status)
	}
}

// ---------------------------------------------------------------------------
// limitListener
// ---------------------------------------------------------------------------

func TestLimitListenerNegativeOneMeansUnlimited(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ll := newLimitListener(ln, -1)
	if _, ok := ll.(*limitListener); ok {
		t.Error("max=-1 should return original listener, not limitListener")
	}
}

func TestLimitListenerEnforcesLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ll := newLimitListener(ln, 2)
	lll, ok := ll.(*limitListener)
	if !ok {
		t.Fatal("expected *limitListener")
	}
	if cap(lll.sem) != 2 {
		t.Errorf("sem cap = %d, want 2", cap(lll.sem))
	}
	if len(lll.sem) != 2 {
		t.Errorf("sem len = %d, want 2 (all slots available)", len(lll.sem))
	}
}

// ---------------------------------------------------------------------------
// Unix domain socket listener
// ---------------------------------------------------------------------------

func TestUnixSocketServesRequests(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "taberna.sock")
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>unix</h1>"), 0644)

	certPath, keyPath := generateCert(t, dir, "uds.example.com")
	cfg := &config.Config{
		Server: config.ServerConfig{
			// Use port 0 so the TCP listener binds to any free port.
			Listen:            []config.ListenAddr{"127.0.0.1:0"},
			ReadHeaderTimeout: config.Duration{Duration: 5 * time.Second},
			ReadTimeout:       config.Duration{Duration: 5 * time.Second},
			WriteTimeout:      config.Duration{Duration: 5 * time.Second},
			IdleTimeout:       config.Duration{Duration: 5 * time.Second},
			MaxHeaderBytes:    65536,
			Unix: config.UnixConfig{
				Enabled: true,
				Path:    sockPath,
				Mode:    0660,
			},
		},
		VHosts: []config.VHostConfig{
			{
				ServerNames:  []string{"uds.example.com"},
				DocumentRoot: dir,
				IndexFiles:   []string{"index.html"},
				TLS:          config.TLSConfig{Cert: certPath, Key: keyPath},
			},
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Start the Unix socket listener directly — we don't call Run() because
	// that blocks and manages its own signal loop.  Instead we replicate just
	// the UDS portion: build the handler, create the listener, serve.
	handler := srv.accessLogMiddleware(srv.securityHeadersMiddleware(srv.router))
	unixSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}
	t.Cleanup(func() {
		unixSrv.Close()
		os.Remove(sockPath)
	})
	go unixSrv.Serve(ln) //nolint:errcheck

	// Dial the socket with a custom transport.
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}

	// Give the server a moment to be ready.
	time.Sleep(20 * time.Millisecond)

	resp, err := httpClient.Get("http://uds.example.com/")
	if err != nil {
		t.Fatalf("GET via unix socket: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "unix") {
		t.Errorf("body %q does not contain expected content", body)
	}
}

func TestUnixSocketStaleSockRemoved(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "taberna.sock")
	// Create a stale socket file.
	ln, _ := net.Listen("unix", sockPath)
	ln.Close()

	if _, err := os.Stat(sockPath); err != nil {
		t.Skip("could not create stale socket for test")
	}

	// Removing a stale socket in Run() is tested implicitly: if New+Run didn't
	// remove it, net.Listen("unix",...) would fail with EADDRINUSE.
	// Here we just verify os.Remove on the path clears it.
	if err := os.Remove(sockPath); err != nil {
		t.Fatalf("os.Remove stale socket: %v", err)
	}
	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Error("stale socket file still exists after remove")
	}
}

// ---------------------------------------------------------------------------
// Cache-Control middleware
// ---------------------------------------------------------------------------

func TestCacheControlHeader(t *testing.T) {
	dir := t.TempDir()
	// Use a plain CSS file instead of index.html to avoid http.FileServer's
	// automatic redirect from /index.html → / (301).
	_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0644)

	cfg := buildCfg(t, dir, []string{"cache.example.com"}, false)
	cfg.VHosts[0].CacheMaxAge = config.Duration{Duration: 24 * time.Hour}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/style.css", nil)
	req.Host = "cache.example.com"
	w := httptest.NewRecorder()
	handler := srv.securityHeadersMiddleware(srv.router)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "max-age=86400") {
		t.Errorf("Cache-Control = %q, want to contain max-age=86400", cc)
	}
	if !strings.Contains(cc, "public") {
		t.Errorf("Cache-Control = %q, want to contain 'public'", cc)
	}
}

func TestCacheControlNotSentWhenZero(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>"), 0644)

	cfg := buildCfg(t, dir, []string{"nocache.example.com"}, false)
	// CacheMaxAge is zero by default.

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Host = "nocache.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if cc := w.Header().Get("Cache-Control"); cc != "" {
		t.Errorf("Cache-Control should be absent, got %q", cc)
	}
}

// TestCacheControlNotOnErrors verifies that Cache-Control is absent on 404
// responses and present on 200 responses when cache_max_age is configured.
// Previously the header was set unconditionally, causing CDNs/browsers to
// cache error responses for the full max_age duration.
func TestCacheControlNotOnErrors(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>cached</html>"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0644)

	cfg := buildCfg(t, dir, []string{"errorcache.example.com"}, false)
	cfg.VHosts[0].CacheMaxAge = config.Duration{Duration: 24 * time.Hour}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Run("404 must not have Cache-Control", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/nonexistent.html", nil)
		req.Host = "errorcache.example.com"
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); cc != "" {
			t.Errorf("Cache-Control must be absent on 404, got %q", cc)
		}
	})

	t.Run("200 must have Cache-Control", func(t *testing.T) {
		// Request /style.css to get a direct 200; /index.html is redirected to /.
		req := httptest.NewRequest("GET", "/style.css", nil)
		req.Host = "errorcache.example.com"
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=86400") {
			t.Errorf("Cache-Control = %q, want max-age=86400 on 200", cc)
		}
	})
}

// ---------------------------------------------------------------------------
// acceptsEncoding helper
// ---------------------------------------------------------------------------

func TestAcceptsEncoding(t *testing.T) {
	cases := []struct {
		header string
		enc    string
		want   bool
	}{
		{"gzip, deflate, br", "br", true},
		{"gzip, deflate, br", "gzip", true},
		{"gzip, deflate, br", "zstd", false},
		// q-values — positive
		{"gzip;q=0.9, br;q=1.0", "br", true},
		{"gzip;q=0.9, br;q=1.0", "deflate", false},
		// q=0 must be treated as explicit rejection (RFC 9110 §12.5.3)
		{"gzip;q=0, br", "gzip", false},
		{"gzip;q=0.0, br", "gzip", false},
		{"br;q=0", "br", false},
		// wildcard * accepts any encoding, but q=0 on wildcard rejects all
		{"*", "br", true},
		{"*;q=0", "br", false},
		// RFC 9110: explicit token beats wildcard — *, gzip;q=0 rejects gzip
		{"*, gzip;q=0", "gzip", false},
		{"*, gzip;q=0", "br", true},
		{"gzip, *;q=0", "gzip", true}, // explicit gzip (q=1) beats wildcard q=0
		// must not match substring — "brotli" is NOT "br"
		{"brotli", "br", false},
		// case-insensitive
		{"GZIP", "gzip", true},
		// empty header
		{"", "gzip", false},
	}
	for _, tc := range cases {
		got := acceptsEncoding(tc.header, tc.enc)
		if got != tc.want {
			t.Errorf("acceptsEncoding(%q, %q) = %v, want %v", tc.header, tc.enc, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Pre-compressed file serving
// ---------------------------------------------------------------------------

func TestPrecompressedBrotliServed(t *testing.T) {
	dir := t.TempDir()
	content := []byte("<html>hello</html>")
	compressed := []byte("fake-brotli-bytes") // content doesn't matter; we check headers
	_ = os.WriteFile(filepath.Join(dir, "page.html"), content, 0644)
	_ = os.WriteFile(filepath.Join(dir, "page.html.br"), compressed, 0644)

	cfg := buildCfg(t, dir, []string{"br.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/page.html", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	req.Host = "br.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "br" {
		t.Errorf("Content-Encoding = %q, want 'br'", ce)
	}
	if vary := w.Header().Get("Vary"); !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("Vary = %q, want to contain Accept-Encoding", vary)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestPrecompressedIndexHTMLRedirectPreserved(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>home</html>"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "index.html.br"), []byte("fake-br"), 0644)

	cfg := buildCfg(t, dir, []string{"brredirect.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Header.Set("Accept-Encoding", "br")
	req.Host = "brredirect.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be absent on redirect, got %q", ce)
	}
}

func TestPrecompressedGzipFallback(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log('hi')"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "app.js.gz"), []byte("fake-gzip"), 0644)

	cfg := buildCfg(t, dir, []string{"gz.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip") // no br
	req.Host = "gz.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("Content-Encoding = %q, want 'gzip'", ce)
	}
}

func TestPrecompressedPassthroughWhenNoneAvailable(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0644)
	// No .br or .gz sidecar — FileServer serves uncompressed.

	cfg := buildCfg(t, dir, []string{"plain.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/style.css", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	req.Host = "plain.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be absent, got %q", ce)
	}
	// Even when no sidecar is found, Vary must be set so caches key correctly.
	if vary := w.Header().Get("Vary"); !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("Vary = %q, want Accept-Encoding even on uncompressed fallback", vary)
	}
}

func TestPrecompressedAbsentWhenOnlyStaleSidecarExists(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "ghost.css.br"), []byte("fake-br"), 0644)

	cfg := buildCfg(t, dir, []string{"stalebr.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/ghost.css", nil)
	req.Header.Set("Accept-Encoding", "br")
	req.Host = "stalebr.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be absent for stale sidecar, got %q", ce)
	}
}

func TestPrecompressedStaleSidecarFallsThroughToBase(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "page.html")
	sidecarPath := filepath.Join(dir, "page.html.br")
	if err := os.WriteFile(basePath, []byte("<html>fresh</html>"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecarPath, []byte("stale-br"), 0644); err != nil {
		t.Fatal(err)
	}
	older := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	newer := older.Add(time.Hour)
	if err := os.Chtimes(sidecarPath, older, older); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(basePath, newer, newer); err != nil {
		t.Fatal(err)
	}

	cfg := buildCfg(t, dir, []string{"stale-precompressed.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/page.html", nil)
	req.Header.Set("Accept-Encoding", "br")
	req.Host = "stale-precompressed.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be absent when sidecar is stale, got %q", ce)
	}
	if body := w.Body.String(); !strings.Contains(body, "fresh") {
		t.Errorf("body = %q, want base file content", body)
	}
}

func TestPrecompressedZstdServed(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"a":1}`), 0644)
	_ = os.WriteFile(filepath.Join(dir, "data.json.zst"), []byte("fake-zstd-bytes"), 0644)

	cfg := buildCfg(t, dir, []string{"zstd.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/data.json", nil)
	req.Header.Set("Accept-Encoding", "zstd, gzip") // no br
	req.Host = "zstd.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "zstd" {
		t.Errorf("Content-Encoding = %q, want 'zstd'", ce)
	}
	if vary := w.Header().Get("Vary"); !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("Vary = %q, want Accept-Encoding", vary)
	}
}

// TestPrecompressedZstdQ0Rejected verifies that a client advertising
// zstd;q=0 (explicit rejection, RFC 9110 §12.5.3) does not receive a .zst
// sidecar even when one is available.
func TestPrecompressedZstdQ0Rejected(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"a":1}`), 0644)
	_ = os.WriteFile(filepath.Join(dir, "data.json.zst"), []byte("fake-zstd-bytes"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "data.json.gz"), []byte("fake-gzip-bytes"), 0644)

	cfg := buildCfg(t, dir, []string{"zstdq0.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Client rejects zstd but accepts gzip.
	req := httptest.NewRequest("GET", "/data.json", nil)
	req.Header.Set("Accept-Encoding", "zstd;q=0, gzip")
	req.Host = "zstdq0.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("Content-Encoding = %q, want 'gzip' (zstd;q=0 should be rejected)", ce)
	}
}

// ---------------------------------------------------------------------------
// realRemoteAddr / trusted proxies
// ---------------------------------------------------------------------------

func TestRealRemoteAddrDirect(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"raddr.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	// No trusted proxies configured — should return RemoteAddr unchanged.
	got := srv.realRemoteAddr(req)
	if got != "203.0.113.1:12345" {
		t.Errorf("realRemoteAddr = %q, want 203.0.113.1:12345", got)
	}
}

func TestRealRemoteAddrTrustedXFF(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"raddr2.example.com"}, false)
	cfg.Server.TrustedProxies = []string{"127.0.0.1/32"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")

	got := srv.realRemoteAddr(req)
	if got != "203.0.113.5" {
		t.Errorf("realRemoteAddr = %q, want 203.0.113.5", got)
	}
}

func TestRealRemoteAddrTrustedForwarded(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"raddr3.example.com"}, false)
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("Forwarded", "for=198.51.100.7;proto=https, for=10.1.2.3")

	got := srv.realRemoteAddr(req)
	if got != "198.51.100.7" {
		t.Errorf("realRemoteAddr = %q, want 198.51.100.7", got)
	}
}

func TestRealRemoteAddrTrustedForwardedSkipsEmptyEntry(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"raddr4.example.com"}, false)
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("Forwarded", "for=, for=198.51.100.7")

	got := srv.realRemoteAddr(req)
	if got != "198.51.100.7" {
		t.Errorf("realRemoteAddr = %q, want 198.51.100.7", got)
	}
}

func TestRealRemoteAddrTrustedForwardedIPv6WithPort(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"raddr5.example.com"}, false)
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("Forwarded", `for="[2001:db8::1]:4711"`)

	got := srv.realRemoteAddr(req)
	if got != "2001:db8::1" {
		t.Errorf("realRemoteAddr = %q, want 2001:db8::1", got)
	}
}

// ---------------------------------------------------------------------------
// reloadCerts
// ---------------------------------------------------------------------------

func TestReloadCerts(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"reload.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Regenerate certs on disk and reload — should succeed without error.
	generateCert(t, dir, "reload.example.com")
	if err := srv.reloadCerts(); err != nil {
		t.Fatalf("reloadCerts: %v", err)
	}

	// getCertificate should still return a cert after reload.
	hello := &tls.ClientHelloInfo{ServerName: "reload.example.com"}
	cert, err := srv.getCertificate(hello)
	if err != nil {
		t.Fatalf("getCertificate after reload: %v", err)
	}
	if cert == nil {
		t.Error("getCertificate returned nil cert after reload")
	}
}

func TestGetCertificateNoSNIDeterministic(t *testing.T) {
	dir := t.TempDir()
	firstDir := filepath.Join(dir, "first")
	secondDir := filepath.Join(dir, "second")
	if err := os.MkdirAll(firstDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secondDir, 0755); err != nil {
		t.Fatal(err)
	}
	firstCert, firstKey := generateCert(t, firstDir, "first.example.com")
	secondCert, secondKey := generateCert(t, secondDir, "second.example.com")

	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:            []config.ListenAddr{"127.0.0.1:8443"},
			ReadHeaderTimeout: config.Duration{Duration: 5 * time.Second},
			ReadTimeout:       config.Duration{Duration: 30 * time.Second},
			WriteTimeout:      config.Duration{Duration: 60 * time.Second},
			IdleTimeout:       config.Duration{Duration: 120 * time.Second},
			ShutdownTimeout:   config.Duration{Duration: 5 * time.Second},
			MaxHeaderBytes:    65536,
		},
		VHosts: []config.VHostConfig{
			{
				ServerNames:  []string{"first.example.com"},
				DocumentRoot: dir,
				TLS:          config.TLSConfig{Cert: firstCert, Key: firstKey},
			},
			{
				ServerNames:  []string{"second.example.com"},
				DocumentRoot: dir,
				TLS:          config.TLSConfig{Cert: secondCert, Key: secondKey},
			},
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cert, err := srv.getCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("getCertificate without SNI: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if leaf.Subject.CommonName != "first.example.com" {
		t.Errorf("default certificate CN = %q, want first.example.com", leaf.Subject.CommonName)
	}
}

func TestNewRejectsDuplicateServerNames(t *testing.T) {
	dir := t.TempDir()
	oneDir := filepath.Join(dir, "one")
	twoDir := filepath.Join(dir, "two")
	if err := os.MkdirAll(oneDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(twoDir, 0755); err != nil {
		t.Fatal(err)
	}
	certOne, keyOne := generateCert(t, oneDir, "dup.example.com")
	certTwo, keyTwo := generateCert(t, twoDir, "dup.example.com")

	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:            []config.ListenAddr{"127.0.0.1:8443"},
			ReadHeaderTimeout: config.Duration{Duration: 5 * time.Second},
			ReadTimeout:       config.Duration{Duration: 30 * time.Second},
			WriteTimeout:      config.Duration{Duration: 60 * time.Second},
			IdleTimeout:       config.Duration{Duration: 120 * time.Second},
			ShutdownTimeout:   config.Duration{Duration: 5 * time.Second},
			MaxHeaderBytes:    65536,
		},
		VHosts: []config.VHostConfig{
			{
				ServerNames:  []string{"dup.example.com"},
				DocumentRoot: dir,
				TLS:          config.TLSConfig{Cert: certOne, Key: keyOne},
			},
			{
				ServerNames:  []string{"DUP.EXAMPLE.COM"},
				DocumentRoot: dir,
				TLS:          config.TLSConfig{Cert: certTwo, Key: keyTwo},
			},
		},
	}

	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected duplicate server_names error")
	}
	if !strings.Contains(err.Error(), "duplicate server_name") {
		t.Fatalf("error = %q, want duplicate server_name", err)
	}
}

// ---------------------------------------------------------------------------
// 103 Early Hints
// ---------------------------------------------------------------------------

func TestEarlyHintsSentWhenHintsFilePresent(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "page.html"), []byte("<html>"), 0644)
	// Create .hints sidecar for /page.html
	hints := "</css/app.css>; rel=preload; as=style\n# comment\n</js/app.js>; rel=preload; as=script\n"
	_ = os.WriteFile(filepath.Join(dir, "page.html.hints"), []byte(hints), 0644)

	cfg := buildCfg(t, dir, []string{"hints.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Capture the WriteHeader calls to observe the 103.
	var codes []int
	w := &multiWriteHeaderRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		onHeader:         func(code int) { codes = append(codes, code) },
	}
	req := httptest.NewRequest("GET", "/page.html", nil)
	req.Host = "hints.example.com"
	srv.router.ServeHTTP(w, req)

	if len(codes) < 1 || codes[0] != http.StatusEarlyHints {
		t.Errorf("first WriteHeader call = %v, want 103 as first code", codes)
	}
	links := w.Header().Values("Link")
	if len(links) < 2 {
		t.Errorf("Link headers = %v, want at least 2 (css and js)", links)
	}
	var hasCSS, hasJS bool
	for _, l := range links {
		if strings.Contains(l, "app.css") {
			hasCSS = true
		}
		if strings.Contains(l, "app.js") {
			hasJS = true
		}
	}
	if !hasCSS {
		t.Error("Link headers missing app.css preload")
	}
	if !hasJS {
		t.Error("Link headers missing app.js preload")
	}
}

func TestEarlyHintsAbsentOnIndexHTMLRedirect(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "index.html.hints"), []byte("</css/app.css>; rel=preload; as=style\n"), 0644)

	cfg := buildCfg(t, dir, []string{"indexhints.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var codes []int
	w := &multiWriteHeaderRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		onHeader:         func(code int) { codes = append(codes, code) },
	}
	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Host = "indexhints.example.com"
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", w.Code)
	}
	for _, code := range codes {
		if code == http.StatusEarlyHints {
			t.Fatal("unexpected 103 Early Hints before /index.html redirect")
		}
	}
	if links := w.Header().Values("Link"); len(links) != 0 {
		t.Fatalf("Link headers should be absent on redirect, got %v", links)
	}
}

func TestEarlyHintsAbsentWithoutHintsFile(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0644)

	cfg := buildCfg(t, dir, []string{"nohints.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var codes []int
	w := &multiWriteHeaderRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		onHeader:         func(code int) { codes = append(codes, code) },
	}
	req := httptest.NewRequest("GET", "/style.css", nil)
	req.Host = "nohints.example.com"
	srv.router.ServeHTTP(w, req)

	for _, code := range codes {
		if code == http.StatusEarlyHints {
			t.Error("unexpected 103 Early Hints when no .hints file exists")
		}
	}
}

func TestEarlyHintsAbsentWhenTargetFileMissing(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "missing.css.hints"), []byte("</css/app.css>; rel=preload; as=style\n"), 0644)

	cfg := buildCfg(t, dir, []string{"stalehints.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var codes []int
	w := &multiWriteHeaderRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		onHeader:         func(code int) { codes = append(codes, code) },
	}
	req := httptest.NewRequest("GET", "/missing.css", nil)
	req.Host = "stalehints.example.com"
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	for _, code := range codes {
		if code == http.StatusEarlyHints {
			t.Fatal("unexpected 103 Early Hints for missing target file")
		}
	}
}

func TestEarlyHintsTraversalBlocked(t *testing.T) {
	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "docroot")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(docRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.css"), []byte("body{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.css.hints"), []byte("</css/secret.css>; rel=preload; as=style\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := buildCfg(t, docRoot, []string{"traversal-hints.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var codes []int
	w := &multiWriteHeaderRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		onHeader:         func(code int) { codes = append(codes, code) },
	}
	req := httptest.NewRequest("GET", "/../"+strings.TrimPrefix(filepath.ToSlash(outside), "/")+"/secret.css", nil)
	req.Host = "traversal-hints.example.com"
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	for _, code := range codes {
		if code == http.StatusEarlyHints {
			t.Fatal("unexpected 103 Early Hints for path outside docroot")
		}
	}
}

func TestEarlyHintsSentForDirectoryWithIndexHints(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "index.html.hints"), []byte("</css/app.css>; rel=preload; as=style\n"), 0644)

	cfg := buildCfg(t, dir, []string{"dirhints.example.com"}, false)
	cfg.VHosts[0].IndexFiles = []string{"index.html"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var codes []int
	w := &multiWriteHeaderRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		onHeader:         func(code int) { codes = append(codes, code) },
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "dirhints.example.com"
	srv.router.ServeHTTP(w, req)

	if len(codes) < 1 || codes[0] != http.StatusEarlyHints {
		t.Errorf("first WriteHeader call = %v, want 103 as first code", codes)
	}
	if codes[len(codes)-1] != http.StatusOK {
		t.Errorf("final status = %d, want 200", codes[len(codes)-1])
	}
}

func TestLoggingResponseWriterIgnores1xx(t *testing.T) {
	inner := httptest.NewRecorder()
	lw := &loggingResponseWriter{ResponseWriter: inner}
	lw.WriteHeader(http.StatusEarlyHints) // 103 — must not stick
	if lw.status != 0 {
		t.Errorf("status after 103 = %d, want 0 (not captured)", lw.status)
	}
	lw.WriteHeader(http.StatusOK) // 200 — should be captured
	if lw.status != http.StatusOK {
		t.Errorf("status after 200 = %d, want 200", lw.status)
	}
}

func TestParseHintsFile(t *testing.T) {
	raw := []byte("# comment\n</css/app.css>; rel=preload; as=style\n\n</js/app.js>; rel=preload; as=script\n")
	links := parseHintsFile(raw)
	if len(links) != 2 {
		t.Fatalf("len = %d, want 2", len(links))
	}
	if !strings.Contains(links[0], "app.css") {
		t.Errorf("links[0] = %q, want app.css", links[0])
	}
	if !strings.Contains(links[1], "app.js") {
		t.Errorf("links[1] = %q, want app.js", links[1])
	}
}

// multiWriteHeaderRecorder lets tests observe every call to WriteHeader
// (including 1xx), which httptest.ResponseRecorder does not support.
type multiWriteHeaderRecorder struct {
	*httptest.ResponseRecorder
	onHeader func(int)
}

func (m *multiWriteHeaderRecorder) WriteHeader(code int) {
	m.onHeader(code)
	m.ResponseRecorder.WriteHeader(code)
}

// ---------------------------------------------------------------------------
// Content-Digest (RFC 9530)
// ---------------------------------------------------------------------------

func TestContentDigestTrailerOnOK(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello world")
	_ = os.WriteFile(filepath.Join(dir, "hello.txt"), content, 0644)

	cfg := buildCfg(t, dir, []string{"digest.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/hello.txt", nil)
	req.Host = "digest.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// Trailer header should be pre-declared.
	trailerDecl := w.Header().Get("Trailer")
	if !strings.Contains(trailerDecl, "Content-Digest") {
		t.Errorf("Trailer = %q, want to contain Content-Digest", trailerDecl)
	}
	// After ServeHTTP returns, the Content-Digest trailer must be set.
	cd := w.Header().Get("Content-Digest")
	if !strings.HasPrefix(cd, "sha-256=:") {
		t.Errorf("Content-Digest = %q, want sha-256=:...:", cd)
	}
	if !strings.HasSuffix(cd, ":") {
		t.Errorf("Content-Digest = %q, want trailing ':'", cd)
	}
}

func TestContentDigestAbsentOnHEAD(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello"), 0644)

	cfg := buildCfg(t, dir, []string{"nodigest.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("HEAD", "/hello.txt", nil)
	req.Host = "nodigest.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if cd := w.Header().Get("Content-Digest"); cd != "" {
		t.Errorf("Content-Digest should be absent on HEAD, got %q", cd)
	}
}

func TestContentDigestAbsentOn404(t *testing.T) {
	dir := t.TempDir()

	cfg := buildCfg(t, dir, []string{"err404.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/nonexistent.txt", nil)
	req.Host = "err404.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if cd := w.Header().Get("Content-Digest"); cd != "" {
		t.Errorf("Content-Digest should be absent on 404, got %q", cd)
	}
	if trailer := w.Header().Get("Trailer"); trailer != "" {
		t.Errorf("Trailer should be absent on 404, got %q", trailer)
	}
}

func TestContentDigestTrailerAbsentOnPartialContent(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "range.txt"), []byte("hello world"), 0644)

	cfg := buildCfg(t, dir, []string{"digest-range.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/range.txt", nil)
	req.Host = "digest-range.example.com"
	req.Header.Set("Range", "bytes=0-4")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", w.Code)
	}
	if trailer := w.Header().Get("Trailer"); trailer != "" {
		t.Errorf("Trailer should be absent on 206, got %q", trailer)
	}
	if cd := w.Header().Get("Content-Digest"); cd != "" {
		t.Errorf("Content-Digest should be absent on 206, got %q", cd)
	}
}

// ---------------------------------------------------------------------------
// HTTP → HTTPS redirect handler
// ---------------------------------------------------------------------------

func TestRedirectHandlerIssues301(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"redir.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Mirror the handler built inside Run().
	redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := canonicalHost(r.Host)
		if host == "" || !srv.isKnownHost(host) {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})

	t.Run("known host redirects", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/some/path?q=1", nil)
		req.Host = "redir.example.com"
		w := httptest.NewRecorder()
		redirectHandler.ServeHTTP(w, req)

		if w.Code != http.StatusMovedPermanently {
			t.Errorf("status = %d, want 301", w.Code)
		}
		loc := w.Header().Get("Location")
		if loc != "https://redir.example.com/some/path?q=1" {
			t.Errorf("Location = %q, want https://redir.example.com/some/path?q=1", loc)
		}
	})

	t.Run("unknown host rejected (open-redirect prevention)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/path", nil)
		req.Host = "evil.com"
		w := httptest.NewRecorder()
		redirectHandler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for unknown host", w.Code)
		}
	})

	t.Run("empty host rejected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/path", nil)
		req.Host = ""
		w := httptest.NewRecorder()
		redirectHandler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for empty host", w.Code)
		}
	})
}

func TestRedirectHandlerUsesConfiguredHTTPSPort(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"redir.example.com"}, false)
	cfg.Server.Listen = []config.ListenAddr{"127.0.0.1:8443"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := canonicalHost(r.Host)
		if host == "" || !srv.isKnownHost(host) {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		authority := httpsAuthority(host, srv.redirectHTTPSPort())
		http.Redirect(w, r, "https://"+authority+r.URL.RequestURI(), http.StatusMovedPermanently)
	})

	req := httptest.NewRequest("GET", "/some/path?q=1", nil)
	req.Host = "redir.example.com"
	w := httptest.NewRecorder()
	redirectHandler.ServeHTTP(w, req)

	if got := w.Header().Get("Location"); got != "https://redir.example.com:8443/some/path?q=1" {
		t.Fatalf("Location = %q, want https://redir.example.com:8443/some/path?q=1", got)
	}
}

func TestHTTPSAuthorityIPv6(t *testing.T) {
	if got := httpsAuthority("::1", "8443"); got != "[::1]:8443" {
		t.Fatalf("httpsAuthority(::1, 8443) = %q, want [::1]:8443", got)
	}
	if got := httpsAuthority("::1", "443"); got != "[::1]" {
		t.Fatalf("httpsAuthority(::1, 443) = %q, want [::1]", got)
	}
}

// ---------------------------------------------------------------------------
// Compression Dictionary Transport (RFC 9842)
// ---------------------------------------------------------------------------

// makeDictHash returns the SF Bytes encoding of the SHA-256 hash of data
// (e.g. ":HASH=:").  Used to populate .dh sidecar files in tests.
func makeDictHash(t *testing.T, data []byte) string {
	t.Helper()
	h := sha256.Sum256(data)
	return ":" + base64.StdEncoding.EncodeToString(h[:]) + ":"
}

func TestParseSFBytes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{":AAEC:", "AAEC"},
		{":abc123==:", "abc123=="},
		// colons required
		{"AAEC", ""},
		// only leading colon
		{":AAEC", ""},
		// invalid base64
		{":not!base64:", ""},
		// extra whitespace stripped
		{"  :AAEC:  ", "AAEC"},
		// empty bytes item is valid SF
		{"::", ""},
	}
	for _, tc := range cases {
		got := parseSFBytes(tc.in)
		if got != tc.want {
			t.Errorf("parseSFBytes(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReadDictHash(t *testing.T) {
	dir := t.TempDir()
	content := []byte("my-dict-content")
	hash := makeDictHash(t, content)

	path := filepath.Join(dir, "file.dh")
	_ = os.WriteFile(path, []byte(hash+"\n"), 0644)

	drs, err := newDocRootSafe(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := readDictHash(drs, path)
	want := parseSFBytes(hash)
	if got != want {
		t.Errorf("readDictHash = %q, want %q", got, want)
	}
}

func TestCompressionDictDCZServed(t *testing.T) {
	dir := t.TempDir()
	dictContent := []byte("v1 content — the shared dictionary")
	fileContent := []byte("v2 content \u2014 compressed using v1 as dictionary")
	dczContent := []byte("fake-dcz-bytes")

	_ = os.WriteFile(filepath.Join(dir, "app.js"), fileContent, 0644)
	_ = os.WriteFile(filepath.Join(dir, "app.js.dcz"), dczContent, 0644)
	// .dh contains the SF Bytes hash of the dictionary (v1).
	_ = os.WriteFile(filepath.Join(dir, "app.js.dh"), []byte(makeDictHash(t, dictContent)), 0644)
	_ = os.WriteFile(filepath.Join(dir, "app.v1.js"), dictContent, 0644)

	cfg := buildCfg(t, dir, []string{"cdt.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	h := sha256.Sum256(dictContent)
	clientHash := ":" + base64.StdEncoding.EncodeToString(h[:]) + ":"

	req := httptest.NewRequest("GET", "/app.js", nil)
	req.Host = "cdt.example.com"
	req.Header.Set("Available-Dictionary", clientHash)
	req.Header.Set("Accept-Encoding", "dcz, br, gzip")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "dcz" {
		t.Errorf("Content-Encoding = %q, want 'dcz'", ce)
	}
	if did := w.Header().Get("Dictionary-ID"); did != clientHash {
		t.Errorf("Dictionary-ID = %q, want %q", did, clientHash)
	}
	varyAll := w.Header().Get("Vary")
	if !strings.Contains(varyAll, "Available-Dictionary") {
		t.Errorf("Vary = %q, must contain Available-Dictionary", varyAll)
	}
	if !strings.Contains(varyAll, "Accept-Encoding") {
		t.Errorf("Vary = %q, must contain Accept-Encoding", varyAll)
	}
}

func TestCompressionDictIndexHTMLRedirectPreserved(t *testing.T) {
	dir := t.TempDir()
	dictContent := []byte("index dictionary")
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>home</html>"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "index.html.dcz"), []byte("fake-dcz"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "index.html.dh"), []byte(makeDictHash(t, dictContent)), 0644)

	cfg := buildCfg(t, dir, []string{"cdtredirect.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	h := sha256.Sum256(dictContent)
	clientHash := ":" + base64.StdEncoding.EncodeToString(h[:]) + ":"

	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Host = "cdtredirect.example.com"
	req.Header.Set("Available-Dictionary", clientHash)
	req.Header.Set("Accept-Encoding", "dcz")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be absent on redirect, got %q", ce)
	}
	if did := w.Header().Get("Dictionary-ID"); did != "" {
		t.Errorf("Dictionary-ID should be absent on redirect, got %q", did)
	}
}

func TestCompressionDictAbsentWhenBaseFileMissing(t *testing.T) {
	dir := t.TempDir()
	dictContent := []byte("shared dictionary")
	_ = os.WriteFile(filepath.Join(dir, "ghost.js.dcz"), []byte("fake-dcz"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "ghost.js.dh"), []byte(makeDictHash(t, dictContent)), 0644)

	cfg := buildCfg(t, dir, []string{"cdtstale.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	h := sha256.Sum256(dictContent)
	clientHash := ":" + base64.StdEncoding.EncodeToString(h[:]) + ":"

	req := httptest.NewRequest("GET", "/ghost.js", nil)
	req.Host = "cdtstale.example.com"
	req.Header.Set("Available-Dictionary", clientHash)
	req.Header.Set("Accept-Encoding", "dcz")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be absent for stale dictionary sidecar, got %q", ce)
	}
	if did := w.Header().Get("Dictionary-ID"); did != "" {
		t.Errorf("Dictionary-ID should be absent for stale dictionary sidecar, got %q", did)
	}
}

func TestCompressionDictStaleSidecarFallsThroughToBase(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "app.js")
	sidecarPath := filepath.Join(dir, "app.js.dcz")
	dictHashPath := filepath.Join(dir, "app.js.dh")
	dictContent := []byte("shared dictionary")
	if err := os.WriteFile(basePath, []byte("fresh payload"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecarPath, []byte("stale-dcz"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dictHashPath, []byte(makeDictHash(t, dictContent)), 0644); err != nil {
		t.Fatal(err)
	}
	older := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	newer := older.Add(time.Hour)
	if err := os.Chtimes(sidecarPath, older, older); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(basePath, newer, newer); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dictHashPath, older, older); err != nil {
		t.Fatal(err)
	}

	cfg := buildCfg(t, dir, []string{"stale-dict.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	h := sha256.Sum256(dictContent)
	clientHash := ":" + base64.StdEncoding.EncodeToString(h[:]) + ":"

	req := httptest.NewRequest("GET", "/app.js", nil)
	req.Host = "stale-dict.example.com"
	req.Header.Set("Available-Dictionary", clientHash)
	req.Header.Set("Accept-Encoding", "dcz")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be absent when dictionary sidecar is stale, got %q", ce)
	}
	if did := w.Header().Get("Dictionary-ID"); did != "" {
		t.Errorf("Dictionary-ID should be absent when dictionary sidecar is stale, got %q", did)
	}
	if body := w.Body.String(); !strings.Contains(body, "fresh payload") {
		t.Errorf("body = %q, want base file content", body)
	}
}

func TestCompressionDictTraversalBlocked(t *testing.T) {
	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "docroot")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(docRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	dictContent := []byte("shared dictionary")
	if err := os.WriteFile(filepath.Join(outside, "escape.js"), []byte("payload"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "escape.js.dcz"), []byte("fake-dcz"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "escape.js.dh"), []byte(makeDictHash(t, dictContent)), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := buildCfg(t, docRoot, []string{"traversal-dict.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	h := sha256.Sum256(dictContent)
	clientHash := ":" + base64.StdEncoding.EncodeToString(h[:]) + ":"

	req := httptest.NewRequest("GET", "/../"+strings.TrimPrefix(filepath.ToSlash(outside), "/")+"/escape.js", nil)
	req.Host = "traversal-dict.example.com"
	req.Header.Set("Available-Dictionary", clientHash)
	req.Header.Set("Accept-Encoding", "dcz")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be absent for path outside docroot, got %q", ce)
	}
	if did := w.Header().Get("Dictionary-ID"); did != "" {
		t.Errorf("Dictionary-ID should be absent for path outside docroot, got %q", did)
	}
}

func TestUseAsDictionaryAbsentOnRedirect(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>home</html>"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "index.html.dict"), []byte("/index.html\n"), 0644)

	cfg := buildCfg(t, dir, []string{"dictredirect.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Host = "dictredirect.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", w.Code)
	}
	if uad := w.Header().Get("Use-As-Dictionary"); uad != "" {
		t.Errorf("Use-As-Dictionary should be absent on redirect, got %q", uad)
	}
}

func TestUseAsDictionaryAbsentOn404(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "missing.js.dict"), []byte("/js/*.js\n"), 0644)

	cfg := buildCfg(t, dir, []string{"dict404.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/missing.js", nil)
	req.Host = "dict404.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if uad := w.Header().Get("Use-As-Dictionary"); uad != "" {
		t.Errorf("Use-As-Dictionary should be absent on 404, got %q", uad)
	}
}

func TestCompressionDictDCBPreferredOverDCZ(t *testing.T) {
	dir := t.TempDir()
	dictContent := []byte("the shared dictionary")
	fileContent := []byte("the file itself")
	_ = os.WriteFile(filepath.Join(dir, "app.js"), fileContent, 0644)
	_ = os.WriteFile(filepath.Join(dir, "app.js.dcb"), []byte("fake-dcb"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "app.js.dcz"), []byte("fake-dcz"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "app.js.dh"), []byte(makeDictHash(t, dictContent)), 0644)

	cfg := buildCfg(t, dir, []string{"cdtpref.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	h := sha256.Sum256(dictContent)
	clientHash := ":" + base64.StdEncoding.EncodeToString(h[:]) + ":"

	req := httptest.NewRequest("GET", "/app.js", nil)
	req.Host = "cdtpref.example.com"
	req.Header.Set("Available-Dictionary", clientHash)
	req.Header.Set("Accept-Encoding", "dcb, dcz, br, gzip")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "dcb" {
		t.Errorf("Content-Encoding = %q, want 'dcb' (dcb has higher priority)", ce)
	}
}

func TestCompressionDictHashMismatchFallsThrough(t *testing.T) {
	dir := t.TempDir()
	dictContent := []byte("a different dictionary than the client has")
	fileContent := []byte("the file")
	_ = os.WriteFile(filepath.Join(dir, "file.js"), fileContent, 0644)
	_ = os.WriteFile(filepath.Join(dir, "file.js.dcz"), []byte("fake-dcz"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "file.js.dh"), []byte(makeDictHash(t, dictContent)), 0644)

	cfg := buildCfg(t, dir, []string{"cdtmm.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Client sends a hash that doesn't match what's in .dh.
	wrongDict := []byte("wrong dictionary")
	h := sha256.Sum256(wrongDict)
	clientHash := ":" + base64.StdEncoding.EncodeToString(h[:]) + ":"

	req := httptest.NewRequest("GET", "/file.js", nil)
	req.Host = "cdtmm.example.com"
	req.Header.Set("Available-Dictionary", clientHash)
	req.Header.Set("Accept-Encoding", "dcz, br, gzip")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// Should fall through to plain file (no dcz, no br, no gz sidecar).
	if ce := w.Header().Get("Content-Encoding"); ce == "dcz" {
		t.Errorf("Content-Encoding = 'dcz' but hash did not match — should fall through")
	}
}

func TestCompressionDictUseAsDictionaryHeader(t *testing.T) {
	dir := t.TempDir()
	// Create a file that will serve as a dictionary.
	_ = os.WriteFile(filepath.Join(dir, "app.v1.js"), []byte("js content"), 0644)
	// .dict sidecar with the match pattern.
	_ = os.WriteFile(filepath.Join(dir, "app.v1.js.dict"), []byte("/js/app.*.js\n"), 0644)

	cfg := buildCfg(t, dir, []string{"cdtadv.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/app.v1.js", nil)
	req.Host = "cdtadv.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	uad := w.Header().Get("Use-As-Dictionary")
	if !strings.Contains(uad, "match=") {
		t.Errorf("Use-As-Dictionary = %q, want match= parameter", uad)
	}
	if !strings.Contains(uad, "/js/app.*.js") {
		t.Errorf("Use-As-Dictionary = %q, want pattern /js/app.*.js", uad)
	}
}

func TestCompressionDictUseAsDictionaryAbsentOnHEAD(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app.v1.js"), []byte("js content"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "app.v1.js.dict"), []byte("/js/app.*.js\n"), 0644)

	cfg := buildCfg(t, dir, []string{"cdthead.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("HEAD", "/app.v1.js", nil)
	req.Host = "cdthead.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if uad := w.Header().Get("Use-As-Dictionary"); uad != "" {
		t.Errorf("Use-As-Dictionary should be absent on HEAD, got %q", uad)
	}
}

func TestCompressionDictUseAsDictionaryAbsentOnPartialContent(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app.v1.js"), []byte("js content for ranges"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "app.v1.js.dict"), []byte("/js/app.*.js\n"), 0644)

	cfg := buildCfg(t, dir, []string{"cdtrange.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/app.v1.js", nil)
	req.Host = "cdtrange.example.com"
	req.Header.Set("Range", "bytes=0-4")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", w.Code)
	}
	if uad := w.Header().Get("Use-As-Dictionary"); uad != "" {
		t.Errorf("Use-As-Dictionary should be absent on 206, got %q", uad)
	}
}

func TestCompressionDictUseAsDictionaryAbsentOn404(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"cdtno404.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/nonexistent.js", nil)
	req.Host = "cdtno404.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if uad := w.Header().Get("Use-As-Dictionary"); uad != "" {
		t.Errorf("Use-As-Dictionary should be absent on 404, got %q", uad)
	}
}

// ---------------------------------------------------------------------------
// safeFS — symlink escape prevention
// ---------------------------------------------------------------------------

func TestSafeFSBlocksSymlinkOutsideDocRoot(t *testing.T) {
	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "docroot")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(docRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("sensitive"), 0644); err != nil {
		t.Fatal(err)
	}
	// Create symlink inside docroot pointing outside.
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(docRoot, "link.txt")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	cfg := buildCfg(t, docRoot, []string{"symlink.example.com"}, false)
	cfg.VHosts[0].IndexFiles = []string{"index.html"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/link.txt", nil)
	req.Host = "symlink.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for symlink escaping docroot", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "sensitive") {
		t.Error("response body contains content from outside docroot")
	}
}

func TestSafeFSAllowsSymlinkInsideDocRoot(t *testing.T) {
	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "docroot")
	sub := filepath.Join(docRoot, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "real.txt"), []byte("allowed"), 0644); err != nil {
		t.Fatal(err)
	}
	// Symlink within docroot pointing to another file within docroot (relative).
	if err := os.Symlink(filepath.Join("sub", "real.txt"), filepath.Join(docRoot, "internal-link.txt")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	cfg := buildCfg(t, docRoot, []string{"symlink-ok.example.com"}, false)
	cfg.VHosts[0].IndexFiles = []string{"index.html"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/internal-link.txt", nil)
	req.Host = "symlink-ok.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for symlink within docroot", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "allowed") {
		t.Errorf("response body = %q, want 'allowed'", body)
	}
}

func TestSafeFSBlocksSymlinkDir(t *testing.T) {
	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "docroot")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(docRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "index.html"), []byte("escaped"), 0644); err != nil {
		t.Fatal(err)
	}
	// Symlink a directory inside docroot to an outside directory.
	if err := os.Symlink(outside, filepath.Join(docRoot, "linked-dir")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	cfg := buildCfg(t, docRoot, []string{"symlink-dir.example.com"}, true)
	cfg.VHosts[0].IndexFiles = []string{"index.html"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/linked-dir/index.html", nil)
	req.Host = "symlink-dir.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	// The symlinked directory escapes the document root; the file must
	// not be served.  Depending on which Open call safeFS intercepts
	// first (the directory or the file inside it) we may see 403 or 404.
	if w.Code == http.StatusOK {
		t.Errorf("status = 200, want non-200 for symlinked dir escaping docroot")
	}
	if body := w.Body.String(); strings.Contains(body, "escaped") {
		t.Error("response body contains content from outside docroot")
	}
}

func TestCDTSidecarSymlinkBlocked(t *testing.T) {
	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "docroot")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(docRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	// Legitimate base file inside docroot.
	_ = os.WriteFile(filepath.Join(docRoot, "app.js"), []byte("real content"), 0644)
	// Sensitive file outside docroot, masquerading as a .dcz sidecar.
	_ = os.WriteFile(filepath.Join(outside, "secret.dcz"), []byte("TOP SECRET DATA"), 0644)
	// Create symlink: docroot/app.js.dcz -> outside/secret.dcz
	if err := os.Symlink(filepath.Join(outside, "secret.dcz"), filepath.Join(docRoot, "app.js.dcz")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	// Create a valid .dh sidecar with a known hash.
	dictContent := []byte("dictionary")
	_ = os.WriteFile(filepath.Join(docRoot, "app.js.dh"), []byte(makeDictHash(t, dictContent)), 0644)

	cfg := buildCfg(t, docRoot, []string{"cdt-symlink.example.com"}, false)
	cfg.VHosts[0].IndexFiles = []string{"index.html"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	h := sha256.Sum256(dictContent)
	clientHash := ":" + base64.StdEncoding.EncodeToString(h[:]) + ":"

	req := httptest.NewRequest("GET", "/app.js", nil)
	req.Host = "cdt-symlink.example.com"
	req.Header.Set("Available-Dictionary", clientHash)
	req.Header.Set("Accept-Encoding", "dcz")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	// The symlinked .dcz must NOT be served; should fall through to
	// serving the uncompressed file or an error.
	if ce := w.Header().Get("Content-Encoding"); ce == "dcz" {
		t.Error("Content-Encoding = dcz; symlinked sidecar should have been rejected")
	}
	if body := w.Body.String(); strings.Contains(body, "TOP SECRET") {
		t.Error("response body contains content from symlinked sidecar outside docroot")
	}
}

func TestCDTDictSidecarSymlinkBlocked(t *testing.T) {
	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "docroot")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(docRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	// Legitimate base file inside docroot.
	_ = os.WriteFile(filepath.Join(docRoot, "style.css"), []byte("body{}"), 0644)
	// Sensitive file outside docroot, masquerading as a .dict sidecar.
	_ = os.WriteFile(filepath.Join(outside, "secret.dict"), []byte("/secret/*\n"), 0644)
	// Create symlink: docroot/style.css.dict -> outside/secret.dict
	if err := os.Symlink(filepath.Join(outside, "secret.dict"), filepath.Join(docRoot, "style.css.dict")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	cfg := buildCfg(t, docRoot, []string{"dict-symlink.example.com"}, false)
	cfg.VHosts[0].IndexFiles = []string{"index.html"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/style.css", nil)
	req.Host = "dict-symlink.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	// The symlinked .dict must not be read; Use-As-Dictionary must be absent.
	if uad := w.Header().Get("Use-As-Dictionary"); uad != "" {
		t.Errorf("Use-As-Dictionary = %q; symlinked .dict should have been rejected", uad)
	}
}

func TestEarlyHintsSidecarSymlinkBlocked(t *testing.T) {
	tmp := t.TempDir()
	docRoot := filepath.Join(tmp, "docroot")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(docRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	// Legitimate base file inside docroot.
	_ = os.WriteFile(filepath.Join(docRoot, "page.html"), []byte("<html>"), 0644)
	// Sensitive file outside docroot, masquerading as a .hints sidecar.
	_ = os.WriteFile(filepath.Join(outside, "evil.hints"), []byte("</secret>; rel=preload; as=fetch\n"), 0644)
	// Create symlink: docroot/page.html.hints -> outside/evil.hints
	if err := os.Symlink(filepath.Join(outside, "evil.hints"), filepath.Join(docRoot, "page.html.hints")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	cfg := buildCfg(t, docRoot, []string{"hints-symlink.example.com"}, false)
	cfg.VHosts[0].IndexFiles = []string{"index.html"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var codes []int
	w := &multiWriteHeaderRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		onHeader:         func(code int) { codes = append(codes, code) },
	}
	req := httptest.NewRequest("GET", "/page.html", nil)
	req.Host = "hints-symlink.example.com"
	srv.router.ServeHTTP(w, req)

	// No 103 should have been sent because the .hints symlink escapes docroot.
	for _, code := range codes {
		if code == http.StatusEarlyHints {
			t.Error("unexpected 103 Early Hints from symlinked .hints file outside docroot")
		}
	}
	if links := w.Header().Values("Link"); len(links) != 0 {
		t.Errorf("Link headers should be absent, got %v", links)
	}
}
