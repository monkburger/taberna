package mime

import (
	"mime"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// loadFile
// ---------------------------------------------------------------------------

func TestLoadFileStandardFormat(t *testing.T) {
	// Standard Apache/IANA format: type ext [ext ...]
	data := "# comment\ntext/x-taberna-test   fmto fmtx\napplication/x-taberna app\n"
	path := writeMimeFile(t, data)
	if err := loadFile(path); err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	assertMIME(t, ".fmto", "text/x-taberna-test")
	assertMIME(t, ".fmtx", "text/x-taberna-test")
	assertMIME(t, ".app", "application/x-taberna")
}

func TestLoadFileBSDFormat(t *testing.T) {
	// BSD-reversed format: ext [ext ...] type
	data := "fmtbsd1 fmtbsd2   text/x-taberna-bsd\n"
	path := writeMimeFile(t, data)
	if err := loadFile(path); err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	assertMIME(t, ".fmtbsd1", "text/x-taberna-bsd")
	assertMIME(t, ".fmtbsd2", "text/x-taberna-bsd")
}

func TestLoadFileSkipsInvalidLines(t *testing.T) {
	data := "# header\n\nnotavalidline\ntext/x-ok okext\n"
	path := writeMimeFile(t, data)
	if err := loadFile(path); err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	assertMIME(t, ".okext", "text/x-ok")
}

func TestLoadFileUppercaseNormalised(t *testing.T) {
	data := "TEXT/X-UPPER-TABERNA  UPEXT\n"
	path := writeMimeFile(t, data)
	if err := loadFile(path); err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	// Both lookup and registration are lowercased.
	assertMIME(t, ".upext", "text/x-upper-taberna")
}

func TestLoadFileLeadingDotInExt(t *testing.T) {
	// Extensions that already have a leading dot should still work.
	data := "text/x-dotted-taberna .dotted\n"
	path := writeMimeFile(t, data)
	if err := loadFile(path); err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	assertMIME(t, ".dotted", "text/x-dotted-taberna")
}

func TestLoadFileMissing(t *testing.T) {
	err := loadFile("/nonexistent/path/mime.types")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// registerBuiltins / Init
// ---------------------------------------------------------------------------

func TestBuiltinTypes(t *testing.T) {
	// Call registerBuiltins directly to ensure common extensions are covered.
	registerBuiltins()
	must := []struct{ ext, want string }{
		{".html", "text/html"},
		{".css", "text/css"},
		{".js", "text/javascript"},
		{".json", "application/json"},
		{".png", "image/png"},
		{".jpg", "image/jpeg"},
		{".svg", "image/svg+xml"},
		{".woff2", "font/woff2"},
		{".mp4", "video/mp4"},
		{".mp3", "audio/mpeg"},
		{".wasm", "application/wasm"},
		{".pdf", "application/pdf"},
	}
	for _, tc := range must {
		t.Run(tc.ext, func(t *testing.T) {
			assertMIME(t, tc.ext, tc.want)
		})
	}
}

func TestInitCustomFileOverrides(t *testing.T) {
	// Custom file should take precedence — register a unique extension.
	data := "text/x-custom-override  customoverride\n"
	path := writeMimeFile(t, data)
	if err := Init(path); err != nil {
		t.Fatalf("Init: %v", err)
	}
	assertMIME(t, ".customoverride", "text/x-custom-override")
}

func TestInitMissingCustomFile(t *testing.T) {
	err := Init("/nonexistent/custom.types")
	if err == nil {
		t.Fatal("Init with missing custom file should return error")
	}
}

func TestInitEmptyCustomPath(t *testing.T) {
	// Empty string means "no custom file" — should succeed.
	if err := Init(""); err != nil {
		t.Fatalf("Init with empty path: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeMimeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mime.types")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertMIME(t *testing.T, ext, want string) {
	t.Helper()
	got := mime.TypeByExtension(ext)
	// TypeByExtension may append "; charset=…" — strip parameters.
	if idx := len(got); idx > 0 {
		for i, c := range got {
			if c == ';' {
				got = got[:i]
				break
			}
		}
	}
	if got != want {
		t.Errorf("TypeByExtension(%q) = %q, want %q", ext, got, want)
	}
}
