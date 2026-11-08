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

Two routes reach the ChatGPT backend, and they differ in who signs the
request.

An account of magpie's signs it: the pool route (`/v1/responses` with a
Codex account) and the native compaction on an account. The account's
sign-in goes in place of the caller's, so the caller's own name never
reaches OpenAI, and the request is a Codex turn. The headers the backend
reads a turn by go with it — `codexHeader`: the call kind
(`x-openai-subagent`), the turn's metadata, the session the conversation
is cached under. They are relayed as they came, as upstream does: a
caller that speaks Codex's dialect (an agent that names its call kind)
keeps naming it.

A caller that is Codex keeps its own User-Agent on that route too: the
account signs the request as Codex, but the client that sent it is the one
that says which client, system and terminal it is, and nothing else of
that string is changed. Its own `originator` goes with it, which says the
same of it. Only the version is: never older than the version the request
is signed as, because the backend serves a model only to a client new
enough for it (a request that says it is an older Codex is refused the
newest models, "The 'gpt-6.1-sol' model is not supported when using Codex
with a ChatGPT account").

The caller signs for itself: its own ChatGPT token goes with the request,
as it came. Then the caller's own client, terminal and Codex session are
taken away and Codex's own name is sent instead, so the backend reads
every request for a Codex model as the Codex request it is.

The two lists are one file's business, and say where they differ:

- `codexHeader` — what the backend reads a turn by. It goes on a Codex
  turn, and on a turn an account signs.
- `codexSignInHeader` — the sign-in's own: the credential, Codex's device
  attestation, what holds for Codex's own plan alone
  (`x-openai-codex-luna-reserve`) and the backend's routing of the turn
  for that account (`x-codex-turn-state`). These go with the sign-in that
  is used, so they are never the caller's identity to be taken away.
- `codexRequestHeader` — what the request itself is: the Lite flag
  (`X-OpenAI-Internal-Codex-Responses-Lite`), which goes with the request
  whoever sent it.
- `codexCallerHeader` — the caller's own identity: what the backend reads
  a turn by, less what the request itself is, plus the caller's own name
  (its `User-Agent` and `originator`). A caller that is not Codex has
  none of it sent: Codex's own name is sent instead.

The last one is derived from the first, so a header the backend starts to
read is taken away from a caller that is not Codex until somebody says it
is about the request and not the caller. `sanitizeNonCodexHeaders` puts
Codex's own identity on the request — its `User-Agent`, its `originator`
and its `version` — takes away what `codexCallerHeader` names and what
is magpie's own (`x-magpie-`), and removes `Accept-Encoding`. It does not
read or transmit `TERM_PROGRAM`, `TERM_PROGRAM_VERSION` or `TERM`.
Generic request headers such as `Accept`, `Accept-Language`,
`Cache-Control` and `Pragma` are preserved or filled with defaults.

A Codex request keeps its own identity: `fromCodex` recognizes a Codex
CLI, desktop client, ACP adapter or hosted Codex request, and its headers
reach OpenAI as part of the Codex request they are.

The Codex relay used when magpie is not running is a separate path for Codex's
own ChatGPT sign-in. It forwards Codex's request identity and removes
`Accept-Encoding`; the HTTP/1.1 transport prevents Go from adding it again.

Every request to the backend carries Codex's User-Agent: the caller's own,
when the caller is Codex and it sent one, and Codex's own where the caller
sent none (`codexIdentityFor`) or where the caller is not Codex at all
(`sanitizeNonCodexHeaders`). A request that goes out with no User-Agent
goes with Go's own default (`Go-http-client/1.1`), which says what magpie
is written in — nothing the backend needs to know, and a thing worth not
telling a vendor whose terms magpie is careful with. A caller that names
itself Codex by its `originator` alone keeps that name and is given
Codex's User-Agent.

The version is what the backend gates its newest models on, so the one in
a User-Agent is never older than the version the request is signed as
(`codexUserAgentFor`). A client's own User-Agent keeps its system and
terminal; only that version is raised, where it is older.

## Sources

- TLS profile and non-Codex header sanitation:
  [`codex_fingerprint.go`](../internal/gateway/codex_fingerprint.go)
- Codex's own identity, the User-Agent a request goes with and the version
  in it:
  [`codex_request.go`](../internal/provider/codex_request.go)
- The header lists and the backend they answer for:
  [`codex_backend.go`](../internal/gateway/codex_backend.go),
  [`additional_tools.go`](../internal/gateway/additional_tools.go)
- HTTP/1.1 and per-route transport selection:
  [`upstream_transport.go`](../internal/gateway/upstream_transport.go),
  [`netproxy.go`](../internal/netproxy/netproxy.go),
  [`codex_http1.go`](../internal/provider/codex_http1.go)
- Codex backend and relay callers:
  [`codex_backend.go`](../internal/gateway/codex_backend.go),
  [`codex_relay.go`](../internal/gateway/codex_relay.go)
- Tests for header sanitation and route-specific TLS/compression:
  [`codex_fingerprint_test.go`](../internal/gateway/codex_fingerprint_test.go),
  [`codex_header_policy_test.go`](../internal/gateway/codex_header_policy_test.go),
  [`netproxy_test.go`](../internal/netproxy/netproxy_test.go)
