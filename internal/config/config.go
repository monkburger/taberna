package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// ListenAddr is a listen address from the config file.
// See Resolve for accepted formats (bare port, host:port, bracketed IPv6).
type ListenAddr string

// Resolve returns the normalised "host:port" string ready to pass to net.Listen
// or quic.ListenAddrEarly. Bare port numbers are expanded to "0.0.0.0:<port>".
// The alias "*" is expanded to "0.0.0.0".
func (l ListenAddr) Resolve() (string, error) {
	s := strings.TrimSpace(string(l))
	if s == "" {
		return "", fmt.Errorf("empty listen address")
	}

	// Bare port number: "443", "8443"
	if _, err := strconv.Atoi(s); err == nil {
		if s == "0" {
			return "", fmt.Errorf("listen address %q: port 0 is not allowed", l)
		}
		return "0.0.0.0:" + s, nil
	}

	// Expand "*" shorthand to all-IPv4.
	if strings.HasPrefix(s, "*:") {
		s = "0.0.0.0:" + s[2:]
	}

	// Validate the resulting host:port pair.
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("invalid listen address %q: %w", l, err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("invalid port in listen address %q", l)
	}
	if port == "0" {
		return "", fmt.Errorf("listen address %q: port 0 is not allowed", l)
	}
	// Re-format so IPv6 bare addresses are always bracketed.
	return net.JoinHostPort(host, port), nil
}

// Duration wraps time.Duration for TOML unmarshalling.  Accepts standard Go
// duration syntax ("5s", "1m30s") plus a "d" (day) unit that Go's stdlib
// does not support — "7d" is rewritten to "168h" before parsing.
type Duration struct{ time.Duration }

// dayDurationRE matches the "Nd" or "N.Nd" day-unit tokens that we rewrite
// to hours before handing the string to time.ParseDuration.
var dayDurationRE = regexp.MustCompile(`(\d+(?:\.\d+)?)d`)

func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := parseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", text, err)
	}
	d.Duration = parsed
	return nil
}

func parseDuration(text string) (time.Duration, error) {
	if strings.Contains(text, "d") {
		text = dayDurationRE.ReplaceAllStringFunc(text, func(match string) string {
			days, err := strconv.ParseFloat(strings.TrimSuffix(match, "d"), 64)
			if err != nil {
				return match
			}
			hours := days * 24
			return strconv.FormatFloat(hours, 'f', -1, 64) + "h"
		})
	}
	return time.ParseDuration(text)
}

// SecurityHeadersConfig controls the security-related HTTP response headers
// injected on every response.  An empty string disables that specific header
// (not recommended for HSTS or X-Content-Type-Options on a TLS-only server).
type SecurityHeadersConfig struct {
	HSTS                  string `toml:"hsts"`
	ContentTypeOptions    string `toml:"content_type_options"`
	FrameOptions          string `toml:"frame_options"`
	ContentSecurityPolicy string `toml:"content_security_policy"`
	ReferrerPolicy        string `toml:"referrer_policy"`
	PermissionsPolicy     string `toml:"permissions_policy"`
	// Cross-origin isolation headers (required for SharedArrayBuffer,
	// high-resolution timers, etc.).
	CrossOriginOpenerPolicy   string `toml:"cross_origin_opener_policy"`
	CrossOriginEmbedderPolicy string `toml:"cross_origin_embedder_policy"`
	CrossOriginResourcePolicy string `toml:"cross_origin_resource_policy"`
}

// UnixConfig controls the optional Unix domain socket listener.
// When enabled, taberna starts a plain-HTTP (no TLS) server on the socket in
// addition to the normal TLS listeners.  This is intended for a local reverse
// proxy (nginx, haproxy, caddy) that terminates TLS and forwards requests to
// taberna over the socket.
type UnixConfig struct {
	Enabled bool   `toml:"enabled"`
	Path    string `toml:"path"` // e.g. "/run/taberna/taberna.sock"
	Mode    uint32 `toml:"mode"` // file permission bits; default 0660
}

// RedirectConfig controls the optional HTTP-to-HTTPS redirect listener.
// When enabled, Taberna binds one or more plain-HTTP ports and responds to every
// incoming request with a permanent (301) redirect to the https:// equivalent.
// Defaults to port 80 when no listen addresses are given.
type RedirectConfig struct {
	Enabled bool         `toml:"enabled"`
	Listen  []ListenAddr `toml:"listen"` // defaults to ["80"]
}

// ServerConfig holds the global listener and operational settings.
type ServerConfig struct {
	Listen            []ListenAddr          `toml:"listen"`
	MimeTypesFile     string                `toml:"mime_types"`
	AccessLog         string                `toml:"access_log"` // path, "off", or "" (stderr)
	ErrorLog          string                `toml:"error_log"`  // path, "off", or "" (stderr)
	Unix              UnixConfig            `toml:"unix"`
	Redirect          RedirectConfig        `toml:"redirect"`
	TrustedProxies    []string              `toml:"trusted_proxies"` // CIDRs or IPs whose X-Forwarded-For/Forwarded headers are trusted
	ReadHeaderTimeout Duration              `toml:"read_header_timeout"`
	ReadTimeout       Duration              `toml:"read_timeout"`
	WriteTimeout      Duration              `toml:"write_timeout"`
	IdleTimeout       Duration              `toml:"idle_timeout"`
	ShutdownTimeout   Duration              `toml:"shutdown_timeout"`
	MaxHeaderBytes    int                   `toml:"max_header_bytes"`
	MaxConnections    int                   `toml:"max_connections"`
	Security          SecurityHeadersConfig `toml:"security"`
}

// TLSConfig points to the certificate, private key, and optional intermediate
// chain for a virtual host.
//
// cert may be a full-chain PEM bundle (leaf + intermediates concatenated, e.g.
// Let's Encrypt's fullchain.pem), in which case chain should be left empty.
// Alternatively, cert can be just the leaf certificate and chain can point to
// a separate PEM file containing one or more intermediate certificates in order
// (issuing intermediate first, root last).  The root CA itself should NOT be
// included — clients already have it in their trust store.
type TLSConfig struct {
	Cert  string `toml:"cert"`
	Key   string `toml:"key"`
	Chain string `toml:"chain"` // optional separate intermediate chain PEM
}

// VHostConfig defines a single virtual host: one or more names, a document
// root served as static files, and the TLS material.
//
// server_names supports both exact names ("example.com") and a single-level
// wildcard ("*.example.com").  Deeper wildcards are not supported.
type VHostConfig struct {
	ServerNames  []string  `toml:"server_names"`
	DocumentRoot string    `toml:"document_root"`
	DirListing   bool      `toml:"dir_listing"`
	IndexFiles   []string  `toml:"index_files"`   // tried in order; default ["index.html"]
	CacheMaxAge  Duration  `toml:"cache_max_age"` // 0 = no Cache-Control header sent
	CacheStatus  bool      `toml:"cache_status"`  // send Cache-Status (RFC 9211)
	TLS          TLSConfig `toml:"tls"`
}

// Config is the top-level structure parsed from taberna.toml.
type Config struct {
	Server ServerConfig  `toml:"server"`
	VHosts []VHostConfig `toml:"vhost"`
}

// Load reads and validates the TOML config at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	meta, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("config %q: unknown keys: %v", path, undecoded)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefault(s *string, val string) {
	if *s == "" {
		*s = val
	}
}

func validate(cfg *Config) error {
	// Listen defaults.
	if len(cfg.Server.Listen) == 0 {
		cfg.Server.Listen = []ListenAddr{"0.0.0.0:443"}
	}
	for _, l := range cfg.Server.Listen {
		if _, err := l.Resolve(); err != nil {
			return fmt.Errorf("config: server.listen: %w", err)
		}
	}

	// Timeout defaults.
	if cfg.Server.ReadHeaderTimeout.Duration == 0 {
		cfg.Server.ReadHeaderTimeout.Duration = 5 * time.Second
	}
	if cfg.Server.ReadTimeout.Duration == 0 {
		cfg.Server.ReadTimeout.Duration = 30 * time.Second
	}
	if cfg.Server.WriteTimeout.Duration == 0 {
		cfg.Server.WriteTimeout.Duration = 60 * time.Second
	}
	if cfg.Server.IdleTimeout.Duration == 0 {
		cfg.Server.IdleTimeout.Duration = 120 * time.Second
	}
	if cfg.Server.ShutdownTimeout.Duration == 0 {
		cfg.Server.ShutdownTimeout.Duration = 10 * time.Second
	}

	// Connection / header size limits.
	if cfg.Server.MaxHeaderBytes == 0 {
		cfg.Server.MaxHeaderBytes = 65536 // 64 KB
	}
	// MaxConnections: -1 = unlimited, 0 = use default (512), >0 = explicit cap.
	switch {
	case cfg.Server.MaxConnections == 0:
		cfg.Server.MaxConnections = 512
	case cfg.Server.MaxConnections < -1:
		return fmt.Errorf("config: server.max_connections must be -1 (unlimited) or a positive integer, got %d", cfg.Server.MaxConnections)
	}

	// Security header defaults (non-empty = send, "" = suppress).
	sec := &cfg.Server.Security
	setDefault(&sec.HSTS, "max-age=63072000; includeSubDomains; preload")
	setDefault(&sec.ContentTypeOptions, "nosniff")
	setDefault(&sec.FrameOptions, "DENY")
	setDefault(&sec.ContentSecurityPolicy, "default-src 'self'")
	setDefault(&sec.ReferrerPolicy, "strict-origin-when-cross-origin")
	// PermissionsPolicy: empty default — header not sent unless configured.

	// Unix domain socket defaults.
	if cfg.Server.Unix.Enabled {
		if cfg.Server.Unix.Path == "" {
			return fmt.Errorf("config: server.unix.enabled is true but server.unix.path is empty")
		}
		if cfg.Server.Unix.Mode == 0 {
			cfg.Server.Unix.Mode = 0660
		}
		if cfg.Server.Unix.Mode > 0o777 {
			return fmt.Errorf("config: server.unix.mode %04o exceeds maximum 0777 — did you write a decimal value instead of octal?", cfg.Server.Unix.Mode)
		}
	}

	// Trusted proxy validation — accepts plain IPs or CIDR notation.
	for _, proxy := range cfg.Server.TrustedProxies {
		if strings.Contains(proxy, "/") {
			if _, _, err := net.ParseCIDR(proxy); err != nil {
				return fmt.Errorf("config: invalid server.trusted_proxy CIDR %q: %w", proxy, err)
			}
		} else {
			if net.ParseIP(proxy) == nil {
				return fmt.Errorf("config: invalid server.trusted_proxy address %q", proxy)
			}
		}
	}

	// HTTP→HTTPS redirect defaults.
	if cfg.Server.Redirect.Enabled {
		if len(cfg.Server.Redirect.Listen) == 0 {
			cfg.Server.Redirect.Listen = []ListenAddr{"80"}
		}
		for _, l := range cfg.Server.Redirect.Listen {
			if _, err := l.Resolve(); err != nil {
				return fmt.Errorf("config: server.redirect.listen: %w", err)
			}
		}
	}

	if len(cfg.VHosts) == 0 {
		return fmt.Errorf("config: at least one [[vhost]] block is required")
	}

	for i, vh := range cfg.VHosts {
		if len(vh.IndexFiles) == 0 {
			cfg.VHosts[i].IndexFiles = []string{"index.html"}
		}
		if len(vh.ServerNames) == 0 {
			return fmt.Errorf("config: vhost[%d]: server_names must not be empty", i)
		}
		if vh.DocumentRoot == "" {
			return fmt.Errorf("config: vhost[%d]: document_root must not be empty", i)
		}
		if vh.TLS.Cert == "" {
			return fmt.Errorf("config: vhost[%d]: tls.cert is required", i)
		}
		if vh.TLS.Key == "" {
			return fmt.Errorf("config: vhost[%d]: tls.key is required", i)
		}
		if vh.TLS.Chain != "" {
			if _, err := os.Stat(vh.TLS.Chain); err != nil {
				return fmt.Errorf("config: vhost[%d]: tls.chain %q: %w", i, vh.TLS.Chain, err)
			}
		}
	}

	seenServerNames := make(map[string]int)
	for i, vh := range cfg.VHosts {
		for _, name := range vh.ServerNames {
			key := strings.ToLower(name)
			if prev, ok := seenServerNames[key]; ok {
				return fmt.Errorf("config: duplicate server_name %q in vhost[%d] and vhost[%d]", name, prev, i)
			}
			seenServerNames[key] = i
		}
	}
	return nil
}
