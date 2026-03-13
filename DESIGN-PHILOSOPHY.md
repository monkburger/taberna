# Design Philosophy: Cognitive Ergonomics

A config file you have to puzzle over at 3 AM is a config file that will bite
you. The choices below try to make taberna's configuration obvious on first
read and hard to misconfigure.

---

## Naming

Every key says what it does in plain English. Timeouts are durations
(`read_timeout = "30s"`), not bare integers that force you to guess the unit.
Booleans read as yes/no questions (`enabled`, `dir_listing`, `cache_status`).
Naming is consistent across sections — `enabled` means the same thing in
`[server.unix]` and `[server.redirect]`, never `active` in one and `on` in
another.

This follows Grice's Maxim of Manner: say it clearly, say it once.

## Grouping

Related settings live together in TOML tables that stay small:

- `[server]` — listen addresses, timeouts, connection limits, logging
- `[server.security]` — response headers (HSTS, CSP, frame options, …)
- `[server.redirect]` — HTTP→HTTPS redirect listener
- `[server.unix]` — Unix domain socket listener
- `[vhost.*]` — per-domain document root, TLS material, caching

Each group has roughly 5–9 keys. You can scan any section without scrolling.
Miller's "7 ± 2" is the rough target — not because it's a hard rule, but
because config blocks that grow past a dozen fields tend to hide the important
knobs.

## Defaults that do the right thing

Zero-values and omitted fields should leave the server in a safe, production-
ready state, not a "technically works but will OOM under load" state.

- `max_connections` defaults to 512 when omitted or set to 0. Setting it to
  -1 opts into unlimited explicitly, so you can't get there by accident.
- `unix.mode` is validated as an octal value. Writing `660` (decimal) instead
  of `0o660` is caught at startup with a diagnostic that tells you what
  happened.
- Unknown TOML keys are rejected, not silently ignored. A typo like
  `idle_timout` won't leave you wondering why connections never close.

This is the Principle of Least Astonishment: the server should behave the way
a Unix sysadmin expects before they've read the docs.

## Error messages

When validation fails, the message says what went wrong *and* what to do about
it. "mode 999 exceeds maximum 0777 — did you write a decimal value instead of
octal?" is more useful than "invalid mode."

---

## Further reading

The ideas above didn't come from nowhere. A few of the sources that shaped
these decisions:

- Miller, G.A. (1956). "The Magical Number Seven, Plus or Minus Two."
  *Psychological Review* 63(2). The basis for keeping config groups small.
- Norman, D. (1988). *The Design of Everyday Things.* Affordance theory — keys
  should suggest their own constraints through naming.
- Grice, H.P. (1975). "Logic and Conversation." The cooperative maxims,
  especially Manner (be clear, be brief, be orderly).
- Sweller, J. (1988). "Cognitive Load Theory." Reducing extraneous load so
  the person debugging at 3 AM can focus on the actual problem.
- Saltzer, J.H. & Schroeder, M.D. (1975). "The Protection of Information in
  Computer Systems." Least privilege, economy of mechanism, fail-safe defaults.
- IEEE Std 1003.1-2017 (POSIX). Deterministic behavior across Linux, BSD, and
  macOS — particularly for file permissions, signals, and socket semantics.
