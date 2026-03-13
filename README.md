# taberna

Static file server that implements HTTP correctly. TLS 1.3-only, HTTP/3-first,
single binary, no external dependencies.

It exists for cases where correct protocol behavior matters and pulling in
nginx is more than the job requires. No reverse proxying, no scripts, no
plugins. Deliberately scoped; deliberately correct.

Status: WIP. We are still tightening behavior and docs, so expect changes while
the project settles. You could say we are in the Ludicrous Speed phase.

---

## Contents

- [When to use it](#when-to-use-it)
- [Features](#features)
- [Install](#install)
- [Run](#run)
- [Configuration](#configuration)
  - [server](#server)
  - [server.security](#serversecurity)
  - [server.redirect](#serverredirect)
  - [server.unix](#serverunix)
  - [trusted\_proxies](#trusted_proxies)
  - [vhost](#vhost)
  - [Pre-compressed files](#pre-compressed-files)
- [103 Early Hints](#103-early-hints)
- [Content-Digest](#content-digest)
- [Compression Dictionary Transport](#compression-dictionary-transport)
- [TLS certificates](#tls-certificates)
- [Deployment](#deployment)
  - [Systemd](#systemd)
  - [Let's Encrypt](#lets-encrypt)
  - [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Build targets](#build-targets)
- [Roadmap](#roadmap)
- [Design philosophy](#design-philosophy)
- [Standards](#standards)
- [License](#license)

---

## When to use it

taberna is the right fit when:

- You're serving static files: HTML, CSS, JS, images, fonts, downloads
- You want correct protocol behavior (HTTP, TLS, caching, content negotiation)
  without configuring a full web server
- You're on constrained hardware: a Raspberry Pi, a cheap VPS, an embedded
  device where every megabyte of RAM counts
- You want a single binary you can drop anywhere and run, with one config file
  you can read in a few minutes
- You need virtual hosting across multiple domains from one process

taberna is **not** the right fit when you need:

- Dynamic content, CGI, FastCGI, or server-side scripting
- URL rewriting or complex routing rules
- Reverse proxying to upstream services
- Load balancing
- Any plugin or module system

If you need those things, reach for nginx, Caddy, or a purpose-built
application server. taberna does not plan to grow in that direction.

---

## Features

These features are implemented in the current codebase and covered by tests.

**Protocol**
- TLS 1.3 minimum. Older versions are not negotiated.
- HTTP/3 (QUIC) + HTTP/2 + HTTP/1.1 served from the same port; clients
  negotiate the best protocol they support automatically
- `Alt-Svc` header sent on every TCP response to advertise HTTP/3
- QUIC tuned: 250 max concurrent streams, 30 s keep-alive ping, datagrams
  disabled
- **QUIC 0-RTT**: on reconnection, clients send data with the first QUIC
  packet (no round-trip). Safe for GET requests on a static file server

**Hosting**
- Virtual hosting with per-vhost document roots, TLS certificates, and
  cache settings
- Exact domain names and single-level wildcards (`*.example.com`)
- Directory listing on/off per vhost
- Configurable index file list, tried in order

**Performance**
- Pre-compressed file serving: drop `.br`, `.zst`, or `.gz` sidecars next to
  your files and taberna serves them automatically to clients that support
  them. No runtime compression and no request-time CPU cost. Priority:
  brotli → zstd → gzip
- `Accept-Encoding` quality values are parsed per RFC 9110 §12.5.3:
  a token with `q=0` (explicit rejection) is never served, even if a sidecar
  exists. Most servers get this wrong.
- `Vary: Accept-Encoding` is sent on every file response, even the uncompressed
  fallback, so shared caches key correctly regardless of sidecar availability
- Per-vhost `Cache-Control`: sends `public, max-age=N` on 2xx and 304
  responses; error responses are never cached
- **103 Early Hints** (RFC 8297): drop a `.hints` sidecar alongside any file
  and taberna sends a 103 interim response advertising those resources before
  the main response. Browsers start fetching subresources immediately. Supported
  on HTTP/1.1, HTTP/2, and HTTP/3.
- **Compression Dictionary Transport** (RFC 9842): drop `.dict`, `.dcb`/`.dcz`,
  and `.dh` sidecars next to any file to enable dictionary-compressed delta
  serving. Browsers that already hold the dictionary download only the
  diff. A new build of a JS bundle is often 95 %+ smaller. No configuration;
  sidecar presence activates the feature. Browsers without dictionary support
  fall back transparently to pre-compressed or uncompressed sidecars.

**Operations**
- Zero-downtime TLS certificate reload on `SIGHUP`: no dropped connections,
  works with Let's Encrypt renewal hooks
- Graceful shutdown on `SIGTERM` / `SIGINT`: in-flight requests complete
  before the process exits
- HTTP → HTTPS redirect listener: bind a plain HTTP port and taberna issues
  301 redirects; Host header is validated to prevent open redirects
- Unix domain socket listener for local reverse proxy setups
- Structured access log (`slog` JSONHandler): one JSON record per request.
  Fields: `time`, `level`, `msg` (`"request"`), `remote`, `proto`, `method`,
  `uri`, `status` (int), `bytes` (int), `duration` (nanoseconds), `ua`.
  Directly ingestible by Loki, Datadog, Elastic, Vector, Splunk, and others
  without custom parsing
- Error log (`slog` TextHandler): `key=value` text lines, readable on
  terminals and parseable by aggregators that accept that format
- **Content-Digest trailer** (RFC 9530): taberna computes a SHA-256 hash of
  every GET response body and sends it as a `Content-Digest: sha-256=:...:` HTTP
  trailer. Clients and intermediaries can verify integrity without a separate
  checksum file. The hash covers the actual bytes sent (brotli/zstd/gzip/dcb/dcz
  if a compressed sidecar was served). Supported in HTTP/1.1 chunked, HTTP/2,
  HTTP/3.

**Security**
- Security headers on every response: HSTS, `X-Content-Type-Options`,
  `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`,
  `Permissions-Policy`, configurable per header with sensible defaults
- **Cross-origin isolation headers**: `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`, required
  for `SharedArrayBuffer`, high-resolution timers, and strict cross-origin
  fetch control. Each is individually configurable; empty string suppresses it
- Trusted proxy support: reads real client IPs from `Forwarded` (RFC 7239)
  or `X-Forwarded-For` only from configured CIDRs

**Observability**
- **Cache-Status header** (RFC 9211), opt-in per vhost: `Cache-Status:
  taberna; fwd=miss`. CDN and reverse proxy layers (Fastly, Cloudflare,
  Varnish) parse this header for cache diagnostics and hit-rate attribution

**Miscellaneous**
- Hard connection cap (`max_connections`) and five independent timeouts
- Custom MIME types via an optional `mime.types` file layered on top of
  built-in defaults
- Single static binary, ~10 MB stripped: no shared libraries, no runtime,
  no install step

---

## Install

Requires Go 1.24 or later.

```
git clone https://github.com/monkburger/taberna
cd taberna
make static
```

`make static` produces a fully stripped, statically linked binary with no
CGO. Copy it to any Linux/macOS/\*BSD machine and run it.

On Linux, to bind ports 80 and 443 without running as root:

```
make setcap
```

This calls `setcap cap_net_bind_service=+ep` on the binary. You only need to
redo this after recompiling.

---

## Run

```
./taberna -config /etc/taberna/taberna.toml
```

`-config` defaults to `taberna.toml` in the current directory. That is the only
flag.

Signals:

| Signal | Effect |
|--------|--------|
| `SIGTERM` | Graceful shutdown; waits for in-flight requests to finish |
| `SIGINT` | Same as SIGTERM |
| `SIGHUP` | Reload TLS certificates from disk; no connections dropped |

To test locally, generate a self-signed certificate and write a minimal config:

```sh
# Generate a self-signed cert for localhost (requires openssl)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout localhost.key -out localhost.crt -days 365 -nodes \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Minimal config, save as local.toml
cat > local.toml <<'EOF'
[server]
listen = ["127.0.0.1:8443"]

[[vhost]]
server_names  = ["localhost"]
document_root = "/var/www/html"   # or any directory
  [vhost.tls]
  cert = "localhost.crt"
  key  = "localhost.key"
EOF

./taberna -config local.toml
curl --insecure https://localhost:8443/
```

---

## Configuration

taberna uses [TOML](https://toml.io) today. It is easy to read, easy to diff,
and easy to edit by hand when production is on fire.

If you have not used TOML before, think INI with real types. The full spec is
at [toml.io](https://toml.io) and is short enough to read in one coffee.

JSON support may be added later, and we may support other config formats in the
future if there is a real operational benefit. For now, TOML is the supported
format.

---

### `[server]`

```toml
[server]

# Addresses to listen on for TLS (TCP + QUIC/UDP). One listener pair per entry.
# Formats: bare port "443", "host:port", or "[::]:443" for all IPv6 interfaces.
# Default: ["0.0.0.0:443"]
listen = ["443"]

# Path to an additional mime.types file. Empty = built-in types only.
# mime_types = "/etc/taberna/mime.types"

# Log destinations.
# Values: "" or "stderr" → stderr (default)  |  "off" → discard  |  "/path" → file
#         File is created with mode 0640 if it doesn't exist; appended to if it does.
#
# access_log: one JSON record per request (slog JSONHandler).
#   Fields: time, level, msg ("request"), remote (IP:port), proto, method, uri,
#           status (int), bytes (int), duration (nanoseconds), ua (User-Agent).
#   Example:
#   {"time":"2026-01-01T00:00:00Z","level":"INFO","msg":"request",
#    "remote":"203.0.113.5:52341","proto":"HTTP/3.0","method":"GET",
#    "uri":"/","status":200,"bytes":2048,"duration":312000,"ua":"curl/8.7.1"}
#
# error_log: key=value text lines (slog TextHandler).
#   Example:
#   time=2026-01-01T00:00:00.000Z level=INFO msg=listening addr=0.0.0.0:443
access_log = "/var/log/taberna/access.log"
error_log  = "/var/log/taberna/error.log"

# How long to wait for the client to send request headers. Tighten this on
# exposed servers to blunt slow-loris style attacks.
read_header_timeout = "5s"

# Time to read the full request (headers + body).
read_timeout = "30s"

# Time allowed to send the full response.
write_timeout = "60s"

# How long an idle keep-alive connection is kept open.
idle_timeout = "120s"

# Grace period on SIGTERM/SIGINT before connections are forcibly closed.
shutdown_timeout = "10s"

# Maximum request header size in bytes. Requests larger than this get a 431.
max_header_bytes = 65536  # 64 KB

# Hard cap on concurrent TCP connections per listen address.
# -1 = unlimited. 0 = use default (512). Positive integer = explicit cap.
max_connections = 0
```

---

### `[server.security]`

These headers go out on every response regardless of vhost. Setting any field
to `""` suppresses that header entirely.

```toml
[server.security]

# HTTP Strict Transport Security. The two-year value below is the minimum for
# HSTS preloading (hstspreload.org).
hsts = "max-age=63072000; includeSubDomains; preload"

# Prevents MIME-type sniffing in browsers.
content_type_options = "nosniff"

# Clickjacking protection. SAMEORIGIN allows framing from the same origin.
frame_options = "DENY"

# Content Security Policy. Tighten this per your application's needs.
content_security_policy = "default-src 'self'"

# Controls how much referrer information is sent with outbound requests.
referrer_policy = "strict-origin-when-cross-origin"

# Feature/permissions policy. Empty = header not sent.
permissions_policy = ""

# Cross-origin isolation. Together these three headers enable the
# cross-origin isolated browsing context that unlocks SharedArrayBuffer
# and high-resolution performance timers. Empty string = header not sent.
#
# COOP: isolates the browsing context group from popups / openers.
#   Values: same-origin | same-origin-allow-popups | unsafe-none
cross_origin_opener_policy = ""

# COEP: requires all sub-resources to opt in to cross-origin loading.
#   Values: require-corp | credentialless | unsafe-none
cross_origin_embedder_policy = ""

# CORP: controls which origins may load this resource via fetch/XHR/img.
#   Values: same-origin | same-site | cross-origin
cross_origin_resource_policy = ""
```

---

### `[server.redirect]`

When enabled, taberna binds plain HTTP listeners that issue 301 redirects to the
HTTPS equivalent. The Host header is validated against configured vhosts, so a
crafted Host cannot redirect to an external domain.

```toml
[server.redirect]
enabled = true
listen  = ["80"]   # defaults to ["80"] when omitted
```

---

### `[server.unix]`

Starts a plain HTTP/1.1 listener on a Unix domain socket in addition to the
TLS/QUIC listeners. Useful when a local reverse proxy (nginx, haproxy, Caddy)
terminates TLS and forwards to taberna over the socket, avoiding TLS overhead and
an open network port.

```toml
[server.unix]
enabled = true
path    = "/run/taberna/taberna.sock"

# Permission bits applied to the socket file after creation.
# 0660 = owner + group can connect. 0600 = owner only.
mode = 0660
```

---

### `trusted_proxies`

Tells taberna which upstream addresses are allowed to set `Forwarded` or
`X-Forwarded-For` headers that it will trust for real IP extraction. Everything
else uses `RemoteAddr` directly.

```toml
[server]
trusted_proxies = [
    "127.0.0.1/32",    # local loopback
    "::1/128",         # IPv6 loopback
    "10.0.0.0/8",      # private range
]
```

`Forwarded` (RFC 7239) takes precedence over `X-Forwarded-For` when both
are present.

---

### `[[vhost]]`

At least one `[[vhost]]` block is required. Each one defines a set of domain
names, a document root, and a TLS certificate to use for those names.

```toml
[[vhost]]

# One or more hostnames this vhost answers to. Required.
# Supports exact names and single-level wildcards (*.example.com).
server_names = ["example.com", "www.example.com"]

# Directory to serve. Must exist and be a directory at startup. Required.
document_root = "/var/www/example"

# Whether to serve directory listings. Default: false.
# When false and no index file is found, returns 403.
dir_listing = false

# Files to look for when a directory is requested, tried in order.
# Default: ["index.html"]
index_files = ["index.html", "index.htm"]

# Cache-Control max-age for 2xx and 304 responses from this vhost.
# Uses Go duration syntax: "24h", "7d", "30m", etc.
# 0 or omitted = no Cache-Control header sent.
# Error responses (4xx, 5xx) are never cached regardless of this setting.
cache_max_age = "24h"

# Emit a Cache-Status: taberna; fwd=miss header on 2xx responses (RFC 9211).
# Useful when taberna sits behind a CDN layer that parses Cache-Status for
# diagnostics or hit-rate attribution. Default: false.
# cache_status = false

  [vhost.tls]
  # PEM certificate file. Can be a full-chain bundle (leaf + intermediates
  # concatenated), such as Let's Encrypt's fullchain.pem.
  cert = "/etc/ssl/example.com/fullchain.pem"

  # PEM private key file.
  key = "/etc/ssl/example.com/privkey.pem"

  # Optional: path to a separate PEM file of intermediate CA certificates,
  # in order from issuing intermediate to root. Leave empty when cert is
  # already a full-chain bundle. Do not include the root CA; browsers
  # already have it and including it wastes handshake bytes.
  chain = ""
```

Multiple vhosts in one file:

```toml
[[vhost]]
server_names  = ["example.com", "www.example.com"]
document_root = "/var/www/example"
  [vhost.tls]
  cert = "/etc/ssl/example.com/fullchain.pem"
  key  = "/etc/ssl/example.com/privkey.pem"

[[vhost]]
server_names  = ["*.apps.internal"]
document_root = "/var/www/apps"
  [vhost.tls]
  cert = "/etc/ssl/apps.internal/fullchain.pem"
  key  = "/etc/ssl/apps.internal/privkey.pem"
```

---

### Pre-compressed files

taberna can serve pre-compressed versions of static files without any runtime
compression. For any requested path, say `/app.js`, it checks for sidecars in
the same directory in this order:

1. `app.js.br`: served as `Content-Encoding: br` if the client sends
   `Accept-Encoding: br`
2. `app.js.zst`: served as `Content-Encoding: zstd` if the client sends
   `Accept-Encoding: zstd` (Chrome 118+, Firefox 126+)
3. `app.js.gz`: served as `Content-Encoding: gzip` if the client sends
   `Accept-Encoding: gzip`
4. `app.js`: served uncompressed as a fallback

`Vary: Accept-Encoding` is sent on every file response (including the
uncompressed fallback) so caches key correctly.

A client advertising e.g. `Accept-Encoding: gzip;q=0` explicitly rejects gzip
per RFC 9110 §12.5.3; taberna won't serve a `.gz` sidecar to that client even
if one exists. Most servers get this wrong.

Generate sidecars at deploy time (keep originals with `-k`):

```
brotli  -k /var/www/example/app.js
zstd    -k /var/www/example/app.js
gzip    -k /var/www/example/app.js
```

---

## 103 Early Hints

taberna sends a [103 Early Hints](https://www.rfc-editor.org/rfc/rfc8297)
interim response for any file that has a `.hints` sidecar in the document root.

**What it does:** the browser receives the 103 with `Link` preload headers
*before* the 200. It starts fetching declared subresources immediately, shaving
off one full server round-trip of latency for critical assets.

**How to use it:** create a plain-text file next to any file you want to hint.
The filename is `<url-path>.hints`, relative to the document root. Each
non-empty, non-comment line is a `Link` header value.

Example: `/var/www/example/index.html.hints`:

```
# preload critical assets for /index.html
</css/app.css>; rel=preload; as=style
</js/app.js>; rel=preload; as=script; crossorigin
</fonts/inter.woff2>; rel=preload; as=font; type="font/woff2"; crossorigin
```

The same `Link` values also appear in the 200 response, which is the standard
pattern described in RFC 8297. No configuration required; the feature is active
when a `.hints` file is present and inactive when it is not.

Supported on HTTP/1.1, HTTP/2, and HTTP/3.

---

## Content-Digest

taberna adds a `Content-Digest: sha-256=:...:` HTTP trailer to every successful
GET response per [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530).

The digest is computed incrementally from the actual bytes sent. If a
compressed sidecar (`.br`, `.zst`, `.gz`, `.dcb`, `.dcz`) was served, the
digest covers the compressed bytes, which is exactly what the client received.
Only 200 OK responses carry the digest; partial content (206), redirects, and
error responses are left without one.

Clients and intermediaries can verify integrity without a separate checksum
file. To check manually:

```sh
curl -s -D - --tr-encoding https://example.com/app.js | grep Content-Digest
```

The `Trailer: Content-Digest` header is pre-declared in the response so that
HTTP/1.1 chunked encoding, HTTP/2, and HTTP/3 can all deliver the trailer
correctly after the body. No configuration required.

---

## Compression Dictionary Transport

taberna implements [Compression Dictionary Transport (RFC 9842)](https://www.rfc-editor.org/rfc/rfc9842), which lets browsers reuse a previously cached resource as a shared dictionary when fetching an update. The delta between two versions of a large JavaScript bundle can be under 5% of its original size.

The feature is entirely sidecar-based and requires no configuration.

### How it works

**Dictionary advertisement.** taberna adds `Use-As-Dictionary` to a response when a `<path>.dict` sidecar exists alongside the served file. The sidecar contains a single line with the URL match pattern, so the browser knows which future URLs can use this file as a dictionary:

```
# /var/www/js/app.v1.js.dict
/js/app.*.js
```

The browser stores `app.v1.js` and advertises it on matching future requests with `Available-Dictionary: :HASH:`.

**Dictionary-compressed serving.** When a request arrives with `Available-Dictionary: :HASH:`, taberna checks for:

| Sidecar | Meaning |
|---------|----------|
| `<path>.dcb` | Dictionary-compressed Brotli |
| `<path>.dcz` | Dictionary-compressed Zstandard |
| `<path>.dh`  | SF Bytes hash of the dictionary (`:<base64-sha256>:`) |

If the hash in the request matches `.dh`, taberna serves the matching sidecar with:

```
Content-Encoding: dcb          (or dcz; dcb is tried first)
Dictionary-ID: :HASH:
Vary: Accept-Encoding, Available-Dictionary
```

Clients without the dictionary, or clients not advertising dictionary support, receive the normal pre-compressed or uncompressed file.

### Generating sidecars

```sh
# 1. Mark app.v1.js as a dictionary for future /js/app.*.js requests.
echo "/js/app.*.js" > /var/www/js/app.v1.js.dict

# 2. Compress app.v2.js using app.v1.js as the shared dictionary.
#    Requires zstd 1.5+ (or a CDT-aware brotli build for .dcb).
zstd -D app.v1.js app.v2.js -o /var/www/js/app.v2.js.dcz

# 3. Store the SHA-256 of the dictionary as a Structured Fields Bytes value.
printf ":%s:" "$(openssl dgst -sha256 -binary app.v1.js | base64 -w0)" \
  > /var/www/js/app.v2.js.dh
```

Keep the original `app.v2.js` in place; clients without dictionary support fetch it directly.

**Browser support:** Chrome 118+, Edge 118+. Safari and Firefox support is tracked upstream. Older clients receive the unmodified file.

---

## TLS certificates

taberna expects a PEM certificate and a PEM private key per vhost. Any CA works.
For production, [Let's Encrypt](https://letsencrypt.org) via
[certbot](https://certbot.eff.org) or [acme.sh](https://acme.sh) is the
standard low-cost option.

Quick certbot example (standalone, run before starting taberna):

```
certbot certonly --standalone -d example.com -d www.example.com
```

This writes `fullchain.pem` and `privkey.pem` to
`/etc/letsencrypt/live/example.com/`. Point `cert` and `key` there.

Renewal hook to reload without restarting:

```
/etc/letsencrypt/renewal-hooks/deploy/taberna-reload.sh
---
#!/bin/sh
systemctl kill --signal=HUP taberna
```

taberna picks up the new certificates on `SIGHUP` with no downtime.

---

## Deployment

### Systemd

```ini
[Unit]
Description=taberna static file server
After=network.target

[Service]
ExecStart=/usr/local/bin/taberna -config /etc/taberna/taberna.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
User=www-data
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Reload config (certificates) without restarting:

```
systemctl reload taberna
```

### Let's Encrypt

See the [TLS certificates](#tls-certificates) section above.

### Behind a reverse proxy

If nginx, Caddy, or haproxy sits in front of taberna, the recommended setup is
to have taberna listen on a Unix domain socket:

```toml
[server.unix]
enabled = true
path    = "/run/taberna/taberna.sock"
mode    = 0660

[server]
trusted_proxies = ["127.0.0.1/32"]
```

Then configure the proxy to forward to `unix:/run/taberna/taberna.sock` and pass
`X-Forwarded-For` or `Forwarded`. taberna will log the real client IP.

Direct TLS and the Unix socket can both be active at the same time, which is useful
during a migration.

---

## Build targets

```
make build    # development build (dynamically linked, fast)
make static   # production build (static, stripped, version-stamped)
make release  # like static but names the output with version + arch
make setcap   # grant the binary cap_net_bind_service (run after each build)
make check    # vet + full test suite (CI gate)
make test     # test suite only
make cover    # test suite + HTML coverage report
make fmt      # gofmt all source files
make tidy     # go mod tidy + verify
make clean    # remove build artifacts
```

---

## Roadmap

taberna is deliberately small and the core feature set is considered stable.
There are a few things worth doing in future that stay within the original
scope:

- **Access control lists.** Simple IP allowlists per vhost, without touching
  the proxy/routing space.
- **ETag hardening.** The current ETag comes from `http.FileServer`'s
  default (inode + mtime + size). A content-hash ETag would be stronger and
  portable across instances.
- **Plugin or hook interface (tentative).** There's been thought about a
  narrow request/response hook interface, something that would let small
  Go binaries or scripts participate in request handling without taberna
  growing a full scripting engine. Nothing is designed or committed yet.
  If that ever ships, it would stay optional and the no-plugin path would
  remain zero-overhead.

What is not on the roadmap: reverse proxying, CGI, server-side scripting,
template rendering, or a control API. Those belong in a different tool.

---

## A note on the docs

These docs are written by someone who has had to debug production systems at
unfriendly hours. Short sentences, direct wording, copy-paste examples.

The goal is simple: get you from question to answer fast, without making you
read a novel.

---

## Design philosophy

The configuration schema and internal API are designed around cognitive
ergonomics: Grice's conversational maxims for naming, Miller's Law for
parameter grouping, affordance theory for key design, and POLA for defaults.

Full rationale and references: [DESIGN-PHILOSOPHY.md](DESIGN-PHILOSOPHY.md).

---

## Standards

RFCs and specifications that taberna implements or depends on.

| Standard | What it covers |
|----------|----------------|
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3 | The only TLS version accepted. No 1.2 fallback. |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) — HTTP/3 | Primary transport via QUIC; advertised with `Alt-Svc`. |
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) — HTTP/2 | Negotiated over TCP via ALPN for clients without QUIC. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) — HTTP Semantics | Content negotiation, `Accept-Encoding` quality values (§12.5.3). |
| [RFC 8297](https://www.rfc-editor.org/rfc/rfc8297) — 103 Early Hints | Sent from `.hints` sidecars to push `Link` headers before the final response. |
| [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) — Content-Digest | SHA-256 digest sent as a trailer on every GET response. |
| [RFC 9842](https://www.rfc-editor.org/rfc/rfc9842) — Compression Dictionary Transport | Shared-dictionary content encoding via `.dict` / `.dcb` / `.dcz` sidecars. |
| [RFC 9211](https://www.rfc-editor.org/rfc/rfc9211) — Cache-Status | Optional per-vhost header indicating cache hit/miss provenance. |
| [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239) — Forwarded | Trusted-proxy client-IP extraction; takes precedence over `X-Forwarded-For`. |
| [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941) — Structured Field Values | Used to parse `Available-Dictionary` for dictionary transport. |

---

## License

BSD 2-Clause. See [LICENSE](LICENSE).
