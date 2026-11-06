package gateway

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
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

// codexHTTP2Config is kept on the shared transport for its existing HTTP/2
// limits. The ChatGPT backend itself is routed over HTTP/1.1.
func codexHTTP2Config() *http.HTTP2Config {
	return &http.HTTP2Config{MaxConcurrentStreams: 100, MaxReadFrameSize: 16384}
}

// sanitizeNonCodexHeaders gives non-Codex callers an honest, stable
// User-Agent and strips headers that identify their client, terminal or
// Codex session before the request reaches the ChatGPT backend.
func sanitizeNonCodexHeaders(h http.Header) {
	h.Set("User-Agent", fmt.Sprintf("magpie/%s", Version))
	h.Del("Originator")
	for name := range h {
		key := strings.ToLower(name)
		if strings.HasPrefix(key, "x-magpie-") || strings.HasPrefix(key, "x-codex-") ||
			key == "x-openai-subagent" || key == "x-openai-memgen-request" ||
			key == "session-id" || key == "thread-id" || key == "session_id" ||
			key == "conversation_id" || key == "x-client-request-id" {
			h.Del(name)
		}
	}
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
