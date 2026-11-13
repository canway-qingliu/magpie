package gateway

import (
	"crypto/tls"
	"net/http"
	"slices"
	"strings"

	"github.com/yetone/magpie/internal/provider"
)

// codexTLSConfig is used only for requests to the ChatGPT backend. It follows
// rustls's protocol, cipher and curve choices, but Go's TLS stack does not
// reproduce rustls's complete ClientHello byte for byte.
//
// It is the profile a request takes when no account names its own
// (codexTLSConfigFor).
func codexTLSConfig() *tls.Config {
	config := &tls.Config{}
	if upstreamTLS != nil {
		config = upstreamTLS.Clone()
	}
	config.MinVersion = tls.VersionTLS12
	config.MaxVersion = tls.VersionTLS13
	config.CipherSuites = codexAllCipherSuites
	config.CurvePreferences = codexAllCurves
	config.NextProtos = []string{"h2", "http/1.1"}
	return config
}

// codexAllCipherSuites is every suite a Codex route may offer, and
// codexAllCurves every curve it may name. A profile of an account is a
// part of each, so no account offers one magpie has no name for.
var (
	codexAllCipherSuites = []uint16{
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
	codexAllCurves = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
)

// codexTLSConfigFor is the TLS identity of the account named. Two accounts
// of one subscription reach the backend as two clients, distinct in what
// their hellos offer: their curves, and with them the key share each
// sends, and their cipher suites.
//
// What tells them apart is which suites and curves are in a profile, never
// the order they are written in: Go's crypto/tls takes a list as a set and
// offers its own preference order over it (Config.cipherSuites,
// Config.curvePreferences). So each account's profile is a part of
// codexAllCipherSuites and codexAllCurves, chosen by the account's name —
// the same account, the same profile, whatever machine it runs from.
//
// X25519 is in every profile, as it is in every recent client's: a hello
// that offers it none is a client no backend has seen, which is a mark of
// its own. What varies is P-256 and P-384 beside it, and the TLS 1.2
// suites — a TLS 1.3 suite's place in a hello is Go's own, whatever the
// config names (Config.cipherSuites filters TLS 1.0-1.2 alone).
func codexTLSConfigFor(account string) *tls.Config {
	// FNV-1a, then fmix64: a stable hash, unlike hash/maphash's per-run
	// seed, mixed so each bit of it is the account's alone
	var h uint64 = 14695981039346656037
	for i := 0; i < len(account); i++ {
		h ^= uint64(account[i])
		h *= 1099511628211
	}
	h = fmix64(h)
	// X25519 always, as every recent client offers it; P-256 and P-384 by a
	// bit each, and P-256 when neither, since a hello naming one curve is a
	// client no backend has seen
	curves := []tls.CurveID{tls.X25519}
	for i, c := range []tls.CurveID{tls.CurveP256, tls.CurveP384} {
		if h>>uint(i+2)&1 == 0 {
			curves = append(curves, c)
		}
	}
	if len(curves) == 1 {
		curves = append(curves, tls.CurveP256)
	}
	// the TLS 1.2 suites by a bit each, TLS 1.3's always: Go offers those
	// after the set the config names (Config.cipherSuites filters TLS
	// 1.0-1.2 alone), so leaving one out would say nothing of the account
	suites := make([]uint16, 0, len(codexAllCipherSuites))
	var chosen []uint16
	for i, s := range codexAllCipherSuites {
		switch {
		case !tls12Suite(s):
			suites = append(suites, s)
		case h>>uint(i+16)&1 == 0:
			chosen = append(chosen, s)
		}
	}
	for i := 0; len(chosen) < 2 && i < len(codexAllCipherSuites); i++ {
		// every account offers two TLS 1.2 suites, so a hello offering one
		// is no account of magpie's
		if s := codexAllCipherSuites[len(codexAllCipherSuites)-1-i]; tls12Suite(s) && !slices.Contains(chosen, s) {
			chosen = append(chosen, s)
		}
	}
	suites = append(suites, chosen...)
	config := codexTLSConfig()
	config.CurvePreferences = curves
	config.CipherSuites = suites
	return config
}

// fmix64 is murmur3's finalizer: it spreads a value's every bit, so a
// change anywhere in an account's name moves the bits a profile reads.
func fmix64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// tls12Suite says s is a TLS 1.0-1.2 suite: the ones Config.CipherSuites
// has a say in. TLS 1.3's are 0x1301 to 0x1303.
func tls12Suite(s uint16) bool { return s < tls.TLS_AES_128_GCM_SHA256 || s > 0x1303 }

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
