package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTOML writes content to a temp file and returns its path.
func writeTOML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "taberna-*.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

// minimalTOML returns a valid minimal config referencing real paths under dir.
func minimalTOML(t *testing.T, dir string) string {
	t.Helper()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	// Write placeholder files so os.Stat in validate() doesn't fire for chain,
	// but cert/key validation only checks the field is non-empty (load happens
	// in server.New, not config.Load).
	_ = os.WriteFile(certFile, []byte("placeholder"), 0600)
	_ = os.WriteFile(keyFile, []byte("placeholder"), 0600)
	return `
[[vhost]]
server_names  = ["example.com"]
document_root = "` + dir + `"

  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"
`
}

// ---------------------------------------------------------------------------
// ListenAddr.Resolve
// ---------------------------------------------------------------------------

func TestListenAddrResolve(t *testing.T) {
	cases := []struct {
		input   string
		want    string
		wantErr bool
	}{
		// bare port
		{"443", "0.0.0.0:443", false},
		{"8443", "0.0.0.0:8443", false},
		// wildcard shorthand
		{"*:443", "0.0.0.0:443", false},
		// explicit IPv4
		{"127.0.0.1:443", "127.0.0.1:443", false},
		// IPv6 bracketed
		{"[::1]:443", "[::1]:443", false},
		{"[::]:443", "[::]:443", false},
		// hostname
		{"localhost:8443", "localhost:8443", false},
		// errors
		{"", "", true},
		{"0", "", true},
		{"abc", "", true},                   // no port
		{"999999", "0.0.0.0:999999", false}, // bare >65535: Resolve succeeds; OS rejects at bind
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ListenAddr(tc.input).Resolve()
			if tc.wantErr {
				if err == nil {
					t.Errorf("Resolve(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("Resolve(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Duration.UnmarshalText
// ---------------------------------------------------------------------------

func TestDurationUnmarshal(t *testing.T) {
	cases := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"5s", 5 * time.Second, false},
		{"1m30s", 90 * time.Second, false},
		{"100ms", 100 * time.Millisecond, false},
		{"7d", 168 * time.Hour, false},
		{"1.5d30m", 36*time.Hour + 30*time.Minute, false},
		{"bad", 0, true},
		{"", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalText([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Errorf("UnmarshalText(%q) want error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalText(%q) unexpected error: %v", tc.input, err)
			}
			if d.Duration != tc.want {
				t.Errorf("UnmarshalText(%q) = %v, want %v", tc.input, d.Duration, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// config.Load — defaults applied
// ---------------------------------------------------------------------------

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	path := writeTOML(t, minimalTOML(t, dir))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Listen default
	if len(cfg.Server.Listen) != 1 || string(cfg.Server.Listen[0]) != "0.0.0.0:443" {
		t.Errorf("default listen = %v, want [0.0.0.0:443]", cfg.Server.Listen)
	}
	// Timeout defaults
	if cfg.Server.ReadHeaderTimeout.Duration != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 5s", cfg.Server.ReadHeaderTimeout.Duration)
	}
	if cfg.Server.ReadTimeout.Duration != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", cfg.Server.ReadTimeout.Duration)
	}
	if cfg.Server.WriteTimeout.Duration != 60*time.Second {
		t.Errorf("WriteTimeout = %v, want 60s", cfg.Server.WriteTimeout.Duration)
	}
	if cfg.Server.IdleTimeout.Duration != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want 120s", cfg.Server.IdleTimeout.Duration)
	}
	if cfg.Server.ShutdownTimeout.Duration != 10*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 10s", cfg.Server.ShutdownTimeout.Duration)
	}
	// MaxHeaderBytes default
	if cfg.Server.MaxHeaderBytes != 65536 {
		t.Errorf("MaxHeaderBytes = %d, want 65536", cfg.Server.MaxHeaderBytes)
	}
	// MaxConnections default (0 → 512)
	if cfg.Server.MaxConnections != 512 {
		t.Errorf("MaxConnections = %d, want 512", cfg.Server.MaxConnections)
	}
	// Security header defaults
	sec := cfg.Server.Security
	if sec.HSTS == "" {
		t.Error("HSTS default should not be empty")
	}
	if sec.ContentTypeOptions != "nosniff" {
		t.Errorf("ContentTypeOptions = %q, want nosniff", sec.ContentTypeOptions)
	}
	if sec.FrameOptions != "DENY" {
		t.Errorf("FrameOptions = %q, want DENY", sec.FrameOptions)
	}
	if sec.ContentSecurityPolicy == "" {
		t.Error("ContentSecurityPolicy default should not be empty")
	}
	if sec.ReferrerPolicy == "" {
		t.Error("ReferrerPolicy default should not be empty")
	}
	// PermissionsPolicy default is empty (not sent)
	if sec.PermissionsPolicy != "" {
		t.Errorf("PermissionsPolicy default should be empty, got %q", sec.PermissionsPolicy)
	}
}

// ---------------------------------------------------------------------------
// config.Load — custom values override defaults
// ---------------------------------------------------------------------------

func TestLoadCustomValues(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, []byte("x"), 0600)
	_ = os.WriteFile(keyFile, []byte("x"), 0600)

	toml := `
[server]
listen               = ["127.0.0.1:9443"]
read_header_timeout  = "2s"
write_timeout        = "10s"
max_connections      = 100

[server.security]
hsts             = "max-age=3600"
frame_options    = "SAMEORIGIN"
permissions_policy = "camera=()"

[[vhost]]
server_names  = ["test.local"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"
`
	path := writeTOML(t, toml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Server.Listen) != 1 || string(cfg.Server.Listen[0]) != "127.0.0.1:9443" {
		t.Errorf("listen = %v", cfg.Server.Listen)
	}
	if cfg.Server.ReadHeaderTimeout.Duration != 2*time.Second {
		t.Errorf("ReadHeaderTimeout = %v", cfg.Server.ReadHeaderTimeout.Duration)
	}
	if cfg.Server.WriteTimeout.Duration != 10*time.Second {
		t.Errorf("WriteTimeout = %v", cfg.Server.WriteTimeout.Duration)
	}
	if cfg.Server.MaxConnections != 100 {
		t.Errorf("MaxConnections = %d", cfg.Server.MaxConnections)
	}
	if cfg.Server.Security.HSTS != "max-age=3600" {
		t.Errorf("HSTS = %q", cfg.Server.Security.HSTS)
	}
	if cfg.Server.Security.FrameOptions != "SAMEORIGIN" {
		t.Errorf("FrameOptions = %q", cfg.Server.Security.FrameOptions)
	}
	if cfg.Server.Security.PermissionsPolicy != "camera=()" {
		t.Errorf("PermissionsPolicy = %q", cfg.Server.Security.PermissionsPolicy)
	}
}

// ---------------------------------------------------------------------------
// config.Load — validation errors
// ---------------------------------------------------------------------------

func TestLoadValidationErrors(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, []byte("x"), 0600)
	_ = os.WriteFile(keyFile, []byte("x"), 0600)

	cases := []struct {
		name    string
		toml    string
		wantMsg string
	}{
		{
			name:    "no vhosts",
			toml:    ``,
			wantMsg: "at least one [[vhost]]",
		},
		{
			name: "missing server_names",
			toml: `[[vhost]]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"`,
			wantMsg: "server_names must not be empty",
		},
		{
			name: "missing document_root",
			toml: `[[vhost]]
server_names = ["x.com"]
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"`,
			wantMsg: "document_root must not be empty",
		},
		{
			name: "missing cert",
			toml: `[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  key = "` + keyFile + `"`,
			wantMsg: "tls.cert is required",
		},
		{
			name: "missing key",
			toml: `[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"`,
			wantMsg: "tls.key is required",
		},
		{
			name: "chain file does not exist",
			toml: `[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  cert  = "` + certFile + `"
  key   = "` + keyFile + `"
  chain = "/nonexistent/chain.pem"`,
			wantMsg: "tls.chain",
		},
		{
			name: "invalid listen address",
			toml: `[server]
listen = ["noport"]
[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"`,
			wantMsg: "server.listen",
		},
		{
			name: "bare port zero",
			toml: `[server]
listen = ["0"]
[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"`,
			wantMsg: "port 0 is not allowed",
		},
		{
			name: "port zero",
			toml: `[server]
listen = ["0.0.0.0:0"]
[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"`,
			wantMsg: "port 0 is not allowed",
		},
		{
			name: "duplicate server names across vhosts",
			toml: `[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"

[[vhost]]
server_names  = ["X.COM"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"`,
			wantMsg: "duplicate server_name",
		},
		{
			name: "unix enabled without path",
			toml: `[server.unix]
enabled = true
[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"`,
			wantMsg: "server.unix.path is empty",
		},
		{
			name: "unix mode exceeds 0777",
			toml: `[server.unix]
enabled = true
path    = "/tmp/test.sock"
mode    = 999
[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"`,
			wantMsg: "exceeds maximum 0777",
		},
		{
			name: "max_connections below -1",
			toml: `[server]
max_connections = -2
[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"`,
			wantMsg: "max_connections must be -1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTOML(t, tc.toml)
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/taberna.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// config.Load — unix domain socket settings
// ---------------------------------------------------------------------------

func TestLoadUnixDefaults(t *testing.T) {
	dir := t.TempDir()
	path := writeTOML(t, minimalTOML(t, dir))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Unix.Enabled {
		t.Error("Unix.Enabled should default to false")
	}
}

func TestLoadUnixCustomPath(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, []byte("x"), 0600)
	_ = os.WriteFile(keyFile, []byte("x"), 0600)

	tomlStr := `
[server.unix]
enabled = true
path    = "/tmp/test.sock"

[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"
`
	path := writeTOML(t, tomlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Server.Unix.Enabled {
		t.Error("Unix.Enabled should be true")
	}
	if cfg.Server.Unix.Path != "/tmp/test.sock" {
		t.Errorf("Unix.Path = %q, want /tmp/test.sock", cfg.Server.Unix.Path)
	}
	if cfg.Server.Unix.Mode != 0660 {
		t.Errorf("Unix.Mode = %04o, want 0660", cfg.Server.Unix.Mode)
	}
}

// ---------------------------------------------------------------------------
// config.Load — trusted_proxies validation
// ---------------------------------------------------------------------------

func TestLoadTrustedProxiesValid(t *testing.T) {
	dir := t.TempDir()
	tomlStr := `
[server]
trusted_proxies = ["127.0.0.1", "10.0.0.0/8", "::1"]
` + minimalTOML(t, dir)
	cfg, err := Load(writeTOML(t, tomlStr))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Server.TrustedProxies) != 3 {
		t.Errorf("TrustedProxies len = %d, want 3", len(cfg.Server.TrustedProxies))
	}
}

func TestLoadTrustedProxiesBadCIDR(t *testing.T) {
	dir := t.TempDir()
	tomlStr := `
[server]
trusted_proxies = ["not-an-ip"]
` + minimalTOML(t, dir)
	_, err := Load(writeTOML(t, tomlStr))
	if err == nil {
		t.Fatal("expected error for invalid trusted proxy")
	}
	if !strings.Contains(err.Error(), "trusted_proxy") {
		t.Errorf("error %q should mention trusted_proxy", err.Error())
	}
}

// ---------------------------------------------------------------------------
// config.Load — cache_max_age
// ---------------------------------------------------------------------------

func TestLoadCacheMaxAge(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, []byte("x"), 0600)
	_ = os.WriteFile(keyFile, []byte("x"), 0600)

	tomlStr := `
[[vhost]]
server_names  = ["x.com"]
document_root = "` + dir + `"
cache_max_age = "7d"
  [vhost.tls]
  cert = "` + certFile + `"
  key  = "` + keyFile + `"
`
	cfg, err := Load(writeTOML(t, tomlStr))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := 168 * time.Hour
	if cfg.VHosts[0].CacheMaxAge.Duration != want {
		t.Errorf("CacheMaxAge = %v, want %v", cfg.VHosts[0].CacheMaxAge.Duration, want)
	}
}

func TestLoadCacheMaxAgeDefault(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(writeTOML(t, minimalTOML(t, dir)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.VHosts[0].CacheMaxAge.Duration != 0 {
		t.Errorf("CacheMaxAge default = %v, want 0", cfg.VHosts[0].CacheMaxAge.Duration)
	}
}

// ---------------------------------------------------------------------------
// config.Load — redirect config
// ---------------------------------------------------------------------------

func TestLoadRedirectDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(writeTOML(t, minimalTOML(t, dir)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Redirect.Enabled {
		t.Error("Redirect.Enabled should default to false")
	}
	if len(cfg.Server.Redirect.Listen) != 0 {
		t.Errorf("Redirect.Listen should default to empty, got %v", cfg.Server.Redirect.Listen)
	}
}

func TestLoadRedirectDefaultListen(t *testing.T) {
	dir := t.TempDir()
	tomlStr := `
[server.redirect]
enabled = true
` + minimalTOML(t, dir)
	cfg, err := Load(writeTOML(t, tomlStr))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Server.Redirect.Enabled {
		t.Error("Redirect.Enabled should be true")
	}
	// Default listen should be filled in as ["80"].
	if len(cfg.Server.Redirect.Listen) != 1 || string(cfg.Server.Redirect.Listen[0]) != "80" {
		t.Errorf("Redirect.Listen = %v, want [80]", cfg.Server.Redirect.Listen)
	}
}

func TestLoadRedirectCustomListen(t *testing.T) {
	dir := t.TempDir()
	tomlStr := `
[server.redirect]
enabled = true
listen  = ["0.0.0.0:8080", "[::]:8080"]
` + minimalTOML(t, dir)
	cfg, err := Load(writeTOML(t, tomlStr))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Server.Redirect.Listen) != 2 {
		t.Errorf("Redirect.Listen len = %d, want 2", len(cfg.Server.Redirect.Listen))
	}
}

func TestLoadRedirectValidationErrors(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		frag    string
		wantMsg string
	}{
		{
			name: "bad trusted proxy CIDR",
			frag: `[server]
trusted_proxies = ["999.999.0.0/24"]
`,
			wantMsg: "trusted_proxy",
		},
		{
			name: "bad redirect listen",
			frag: `[server.redirect]
enabled = true
listen  = ["noport"]
`,
			wantMsg: "server.redirect.listen",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTOML(t, tc.frag+minimalTOML(t, dir))
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}
