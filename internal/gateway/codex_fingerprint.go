package gateway

import (
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/yetone/magpie/internal/provider"
)

// codexTLSConfig is used only for requests to the ChatGPT backend. It follows
// rustls's protocol, cipher and curve choices, but Go's TLS stack does not
// reproduce rustls's complete ClientHello byte for byte.
func codexTLSConfig() *tls.Config {
	config := &tls.Config{}
	if upstreamTLS != nil {
		config = upstreamTLS.Clone()
	}
	config.MinVersion = tls.VersionTLS12
	config.MaxVersion = tls.VersionTLS13
	config.CipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	config.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	config.NextProtos = []string{"h2", "http/1.1"}
	return config
}

// codexRequestHeader says a header says what the request itself is, and
// not who the caller is: the Lite flag, which says the request is a
// Responses-Lite one and goes with it (the backend reads it, and the
// socket path moves it into the message's client_metadata).
//
// It is the one of the backend's headers about a request that is not the
// caller's own (codexHeader): every other one says which call it is,
// which turn of the conversation, or which conversation.
func codexRequestHeader(k string) bool {
	return strings.EqualFold(k, liteHeader)
}

// codexCallerHeader says a header of the caller's is the caller's own
// identity and not the backend's: what the backend reads a turn by
// (codexHeader — the call kind, the turn's metadata, the session the
// conversation is cached under) and the caller's own name (its User-Agent
// and originator).
//
// A caller that is Codex sends them and they go: they are how the backend
// reads a Codex turn, and how it finds a conversation's cached prompt. A
// caller that is not Codex sends none of them: the backend would read the
// request as a Codex turn, and it is not one. What the request itself is
// goes with it (codexRequestHeader).
//
// The sign-in's own headers are not among them (codexSignInHeader): the
// credential and the device attestation are what the request is sent with,
// and what holds for an account's plan alone is that account's.
func codexCallerHeader(k string) bool {
	switch strings.ToLower(k) {
	case "user-agent", "originator":
		return true
	}
	return codexHeader(k) && !codexRequestHeader(k)
}

// sanitizeNonCodexHeaders gives a caller that is not Codex the identity of
// a Codex client and takes away what says which client, terminal or Codex
// session the request came from (codexCallerHeader), so the ChatGPT
// backend reads every request for a Codex model as the Codex request it is.
//
// The sign-in's own headers stay (codexSignInHeader): the credential and
// the device attestation are what the request is sent with, the turn
// state's routing is the backend's, and what holds for the account's plan
// alone is that account's. So does magpie's own header (x-magpie-): it
// is the window's, not the backend's.
func sanitizeNonCodexHeaders(h http.Header) {
	for name := range h {
		key := strings.ToLower(name)
		if codexCallerHeader(key) || strings.HasPrefix(key, "x-magpie-") {
			delete(h, name)
		}
	}
	// the request is a request for a Codex model, so it goes as a Codex
	// client: Codex's own name, not the caller's and not magpie's
	provider.CodexClientIdentity(h)
	if h.Get("Accept") == "" {
		h.Set("Accept", "application/json")
	}
	if h.Get("Accept-Language") == "" {
		h.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", "no-cache")
	}
	if h.Get("Pragma") == "" {
		h.Set("Pragma", "no-cache")
	}
	h.Del("Accept-Encoding")
}

func isCodexClient(r *http.Request) bool { return fromCodex(r.Header) }

// codexAccountTurn says a turn to a ChatGPT account came from a Codex
// client: the account is one of the ChatGPT backend's, and the client
// names itself Codex (fromCodex).
func codexAccountTurn(p provider.Provider, in http.Header) bool {
	return p.Account != nil && p.Account.Agent == "codex" && fromCodex(in)
}

// codexIdentityFor gives a request to the ChatGPT backend the identity of a
// Codex client, where it names no client of its own: its User-Agent, its
// originator and the version that go with them.
//
// A request that goes out with no User-Agent goes with Go's own default
// ("Go-http-client/1.1"), which says what magpie is written in — nothing
// the backend needs to know, and a thing worth not telling a vendor whose
// terms magpie is careful with.
func codexIdentityFor(req *http.Request) {
	provider.CodexClientIdentity(req.Header)
}
