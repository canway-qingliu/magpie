# Codex upstream request identity

This page describes the outbound TLS and header behavior for requests to
OpenAI's ChatGPT backend. It does not claim to reproduce Codex's complete
network fingerprint.

## Transport scope

The gateway's ordinary vendor transport uses Go's default TLS configuration.
`netproxy.Dispatch` routes the ChatGPT backend over HTTP/1.1, as Codex does.
Only that route receives `codexTLSConfig`; it sets the supported TLS versions,
cipher suites, curves and ALPN before the HTTP/1.1 route clears ALPN. Go's
`crypto/tls` still has its own ClientHello ordering and details, so this is a
similar profile, not a byte-for-byte rustls fingerprint. The Codex route also
disables automatic compression so Go does not add `Accept-Encoding: gzip`.

An HTTP/1.1 route from another source — a provider the user asked to be
spoken HTTP/1.1 to (`netproxy.WithHTTP1`), or a host whose HTTP/2 connection
failed a TLS record and is spoken HTTP/1.1 to for six hours
(`netproxy.h2BrokenFor`) — is not the ChatGPT backend's route. It keeps the
base transport's TLS configuration and its automatic compression: Codex's
profile is Codex's, and is not put on another vendor's connections.

## Request identity

The Codex backend preserves the caller's identity headers when
`fromCodex` recognizes a Codex CLI, desktop client, ACP adapter or hosted
Codex request. Those requests can include the client's OS, terminal, session
and turn metadata; OpenAI receives them as part of the Codex request.

For other callers, `sanitizeNonCodexHeaders` sets `User-Agent` to
`magpie/<version>`, removes `Originator`, magpie headers, Codex session and
turn headers, and removes `Accept-Encoding`. It does not read or transmit
`TERM_PROGRAM`, `TERM_PROGRAM_VERSION` or `TERM`. Generic request headers such
as `Accept`, `Accept-Language`, `Cache-Control` and `Pragma` are preserved or
filled with defaults.

The Codex relay used when magpie is not running is a separate path for Codex's
own ChatGPT sign-in. It forwards Codex's request identity and removes
`Accept-Encoding`; the HTTP/1.1 transport prevents Go from adding it again.

## Sources

- TLS profile and non-Codex header sanitation:
  [`codex_fingerprint.go`](../internal/gateway/codex_fingerprint.go)
- HTTP/1.1 and per-route transport selection:
  [`upstream_transport.go`](../internal/gateway/upstream_transport.go),
  [`netproxy.go`](../internal/netproxy/netproxy.go),
  [`codex_http1.go`](../internal/provider/codex_http1.go)
- Codex backend and relay callers:
  [`codex_backend.go`](../internal/gateway/codex_backend.go),
  [`codex_relay.go`](../internal/gateway/codex_relay.go)
- Tests for header sanitation and route-specific TLS/compression:
  [`codex_fingerprint_test.go`](../internal/gateway/codex_fingerprint_test.go),
  [`netproxy_test.go`](../internal/netproxy/netproxy_test.go)
