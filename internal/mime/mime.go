// Package mime initialises Go's mime type registry with a useful set of types
// for a web server, even on minimal/embedded systems that have no system
// mime.types file.
//
// Loading priority (last writer wins):
//  1. Built-in table  - a curated set of common web types, always present.
//  2. System mime.types - discovered from standard OS paths if they exist.
//  3. Custom file - the path configured in taberna.toml [server] mime_types.
package mime

import (
	"bufio"
	"fmt"
	"mime"
	"os"
	"strings"
)

// systemPaths are the standard locations for mime.types on Unix-like systems.
var systemPaths = []string{
	"/etc/mime.types",
	"/usr/local/etc/mime.types",
	"/etc/apache2/mime.types",
	"/etc/httpd/mime.types",
	"/etc/httpd/conf/mime.types",
	"/usr/share/misc/mime.types",
}

// builtins is a curated table of MIME types that a web server always needs,
// regardless of what (if anything) is installed on the host system.
var builtins = map[string][]string{
	// Text
	"text/html":       {"html", "htm"},
	"text/css":        {"css"},
	"text/javascript": {"js", "mjs"},
	"text/plain":      {"txt", "text", "conf", "def", "log"},
	"text/xml":        {"xml"},
	"text/csv":        {"csv"},
	"text/markdown":   {"md", "markdown"},
	"text/calendar":   {"ics"},
	// Application
	"application/json":          {"json"},
	"application/ld+json":       {"jsonld"},
	"application/xhtml+xml":     {"xhtml"},
	"application/pdf":           {"pdf"},
	"application/zip":           {"zip"},
	"application/gzip":          {"gz"},
	"application/x-tar":         {"tar"},
	"application/wasm":          {"wasm"},
	"application/octet-stream":  {"bin", "exe", "dll", "so", "dmg", "img"},
	"application/manifest+json": {"webmanifest"},
	// Fonts
	"font/woff":  {"woff"},
	"font/woff2": {"woff2"},
	"font/ttf":   {"ttf"},
	"font/otf":   {"otf"},
	// Images
	"image/jpeg":    {"jpg", "jpeg"},
	"image/png":     {"png"},
	"image/gif":     {"gif"},
	"image/webp":    {"webp"},
	"image/svg+xml": {"svg", "svgz"},
	"image/x-icon":  {"ico"},
	"image/avif":    {"avif"},
	"image/apng":    {"apng"},
	// Video
	"video/mp4":       {"mp4", "m4v"},
	"video/webm":      {"webm"},
	"video/ogg":       {"ogv"},
	"video/quicktime": {"mov"},
	// Audio
	"audio/mpeg":  {"mp3"},
	"audio/ogg":   {"ogg", "oga"},
	"audio/wav":   {"wav"},
	"audio/webm":  {"weba"},
	"audio/flac":  {"flac"},
	"audio/aac":   {"aac"},
	"audio/x-m4a": {"m4a"},
}

// Init registers MIME types in priority order (last writer wins):
//  1. Built-in table.
//  2. Any system mime.types files that are readable on this host.
//  3. The custom file at customPath (if non-empty).
func Init(customPath string) error {
	registerBuiltins()
	loadSystemFiles()
	if customPath != "" {
		if err := loadFile(customPath); err != nil {
			return fmt.Errorf("mime: custom file %q: %w", customPath, err)
		}
	}
	return nil
}

func registerBuiltins() {
	for mtype, exts := range builtins {
		for _, ext := range exts {
			_ = mime.AddExtensionType("."+ext, mtype)
		}
	}
}

func loadSystemFiles() {
	for _, p := range systemPaths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		_ = loadFile(p)
	}
}

// loadFile parses a mime.types file and registers each entry.
// Handles both the standard format (MIME type first) used by most Linux
// distros and the reversed format (extensions first, MIME type last) found
// on some BSDs (e.g. OpenBSD /usr/share/misc/mime.types).
func loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// If the first field contains '/' it is the MIME type (standard format).
		// Otherwise assume BSD-reversed format: extensions first, MIME type last.
		mtype, exts := fields[0], fields[1:]
		if !strings.Contains(fields[0], "/") {
			mtype = fields[len(fields)-1]
			exts = fields[:len(fields)-1]
		}
		mtype = strings.ToLower(strings.TrimSpace(mtype))
		if !strings.Contains(mtype, "/") {
			continue
		}
		for _, ext := range exts {
			ext = strings.ToLower(strings.TrimSpace(ext))
			if ext == "" {
				continue
			}
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			_ = mime.AddExtensionType(ext, mtype)
		}
	}
	return scanner.Err()
}
