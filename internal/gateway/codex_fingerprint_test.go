package gateway

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestCodexTLSConfig(t *testing.T) {
	config := codexTLSConfig()

	// Verify TLS version
	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion TLS 1.2, got %v", config.MinVersion)
	}
	if config.MaxVersion != tls.VersionTLS13 {
		t.Errorf("Expected MaxVersion TLS 1.3, got %v", config.MaxVersion)
	}

	// Verify cipher suites (Chrome's)
	expectedCiphers := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
	for _, cipher := range expectedCiphers {
		found := false
		for _, c := range config.CipherSuites {
			if c == cipher {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected cipher suite %v not found", cipher)
		}
	}

	// Verify curves
	expectedCurves := []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
	for _, curve := range expectedCurves {
		found := false
		for _, c := range config.CurvePreferences {
			if c == curve {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected curve %v not found", curve)
		}
	}
}

func TestCodexHTTP2Config(t *testing.T) {
	config := codexHTTP2Config()

	if config.MaxConcurrentStreams != 100 {
		t.Errorf("Expected MaxConcurrentStreams 100, got %v", config.MaxConcurrentStreams)
	}
	if config.MaxReadFrameSize != 16384 {
		t.Errorf("Expected MaxReadFrameSize 16384, got %v", config.MaxReadFrameSize)
	}
}

func TestMimicCodexHeaders(t *testing.T) {
	h := http.Header{}

	mimicCodexHeaders(h)

	// Verify User-Agent
	ua := h.Get("User-Agent")
	if ua == "" {
		t.Error("Expected User-Agent to be set")
	}
	// Verify User-Agent format: codex_cli_rs/0.163.0 (Mac OS 15.8.1; arm64) iTerm.app/3.5.0
	if !strings.Contains(ua, "codex_cli_rs/") {
		t.Errorf("Expected User-Agent to contain 'codex_cli_rs/', got %v", ua)
	}
	if !strings.Contains(ua, "(") || !strings.Contains(ua, ")") {
		t.Errorf("Expected User-Agent to contain OS info in parentheses, got %v", ua)
	}
	// Verify Go's default User-Agent is removed
	if strings.HasPrefix(ua, "Go-http-client/") {
		t.Errorf("Expected Go's default User-Agent to be removed, got %v", ua)
	}

	// Verify Accept
	if h.Get("Accept") != "application/json" {
		t.Errorf("Expected Accept application/json, got %v", h.Get("Accept"))
	}

	// Verify Accept-Language
	if h.Get("Accept-Language") == "" {
		t.Error("Expected Accept-Language to be set")
	}

	// Verify Cache-Control
	if h.Get("Cache-Control") != "no-cache" {
		t.Errorf("Expected Cache-Control no-cache, got %v", h.Get("Cache-Control"))
	}

	// Verify Pragma
	if h.Get("Pragma") != "no-cache" {
		t.Errorf("Expected Pragma no-cache, got %v", h.Get("Pragma"))
	}

	// Verify originator
	if h.Get("originator") != "codex_cli_rs" {
		t.Errorf("Expected originator codex_cli_rs, got %v", h.Get("originator"))
	}

	// Verify Accept-Encoding is removed
	if h.Get("Accept-Encoding") != "" {
		t.Error("Expected Accept-Encoding to be removed")
	}
}

func TestMimicCodexHeadersRemovesGoFingerprint(t *testing.T) {
	h := http.Header{}
	// Set Go's default headers
	h.Set("User-Agent", "Go-http-client/1.1")
	h.Set("Accept-Encoding", "gzip")

	mimicCodexHeaders(h)

	// Verify Go's User-Agent is replaced
	ua := h.Get("User-Agent")
	if strings.HasPrefix(ua, "Go-http-client/") {
		t.Errorf("Expected Go's User-Agent to be replaced, got %v", ua)
	}
	if !strings.Contains(ua, "codex_cli_rs/") {
		t.Errorf("Expected User-Agent to contain 'codex_cli_rs/', got %v", ua)
	}

	// Verify Go's Accept-Encoding is removed
	if h.Get("Accept-Encoding") != "" {
		t.Errorf("Expected Accept-Encoding to be removed, got %v", h.Get("Accept-Encoding"))
	}
}

func TestCodexTransport(t *testing.T) {
	transport := codexTransport(10 * time.Second)

	if transport.MaxIdleConnsPerHost != 16 {
		t.Errorf("Expected MaxIdleConnsPerHost 16, got %v", transport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout != 120*time.Second {
		t.Errorf("Expected IdleConnTimeout 120s, got %v", transport.IdleConnTimeout)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Error("Expected ForceAttemptHTTP2 to be true")
	}
	if transport.TLSClientConfig == nil {
		t.Error("Expected TLSClientConfig to be set")
	}
	if transport.HTTP2 == nil {
		t.Error("Expected HTTP2 to be set")
	}
}

func TestCodexUTLSConfig(t *testing.T) {
	config := codexUTLSConfig()

	// Verify TLS version
	if config.MinVersion != utls.VersionTLS12 {
		t.Errorf("Expected MinVersion TLS 1.2, got %v", config.MinVersion)
	}
	if config.MaxVersion != utls.VersionTLS13 {
		t.Errorf("Expected MaxVersion TLS 1.3, got %v", config.MaxVersion)
	}

	// Verify cipher suites (rustls's default)
	expectedCiphers := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
	for _, cipher := range expectedCiphers {
		found := false
		for _, c := range config.CipherSuites {
			if c == cipher {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected cipher suite %v not found", cipher)
		}
	}

	// Verify curves
	expectedCurves := []utls.CurveID{
		utls.X25519,
		utls.CurveP256,
		utls.CurveP384,
	}
	for _, curve := range expectedCurves {
		found := false
		for _, c := range config.CurvePreferences {
			if c == curve {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected curve %v not found", curve)
		}
	}

	// Verify ALPN protocols
	expectedProtos := []string{"h2", "http/1.1"}
	if len(config.NextProtos) != len(expectedProtos) {
		t.Errorf("Expected %d ALPN protocols, got %d", len(expectedProtos), len(config.NextProtos))
	}
	for i, proto := range expectedProtos {
		if i >= len(config.NextProtos) || config.NextProtos[i] != proto {
			t.Errorf("Expected ALPN protocol %s at index %d, got %v", proto, i, config.NextProtos)
		}
	}
}

func TestCodexUTLSClientHelloID(t *testing.T) {
	id := codexUTLSClientHelloID()

	// Verify we're using Chrome's fingerprint (closest to rustls)
	if id != utls.HelloChrome_Auto {
		t.Errorf("Expected HelloChrome_Auto, got %v", id)
	}
}

func TestCodexUTLSDialer(t *testing.T) {
	dialer := codexUTLSDialer()
	if dialer == nil {
		t.Error("Expected dialer to be non-nil")
	}
}

func TestCodexTransportWithUTLS(t *testing.T) {
	transport := codexTransportWithUTLS(10 * time.Second)

	if transport.MaxIdleConnsPerHost != 16 {
		t.Errorf("Expected MaxIdleConnsPerHost 16, got %v", transport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout != 120*time.Second {
		t.Errorf("Expected IdleConnTimeout 120s, got %v", transport.IdleConnTimeout)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Error("Expected ForceAttemptHTTP2 to be true")
	}
	if transport.DialContext == nil {
		t.Error("Expected DialContext to be set")
	}
	if transport.HTTP2 == nil {
		t.Error("Expected HTTP2 to be set")
	}
}

func TestIsCodexClient(t *testing.T) {
	tests := []struct {
		name     string
		ua       string
		expected bool
	}{
		{
			name:     "Codex CLI User-Agent",
			ua:       "codex_cli_rs/0.163.0 (Mac OS 15.8.1; arm64) iTerm.app/3.5.0",
			expected: true,
		},
		{
			name:     "Codex in User-Agent",
			ua:       "Some App with codex/1.0",
			expected: true,
		},
		{
			name:     "Codex CLI lowercase",
			ua:       "codex_cli_rs/0.163.0",
			expected: true,
		},
		{
			name:     "Non-Codex User-Agent",
			ua:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			expected: false,
		},
		{
			name:     "Empty User-Agent",
			ua:       "",
			expected: false,
		},
		{
			name:     "Claude Code User-Agent",
			ua:       "claude-cli/1.0.0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("User-Agent", tt.ua)

			got := isCodexClient(req)
			if got != tt.expected {
				t.Errorf("isCodexClient(%q) = %v, expected %v", tt.ua, got, tt.expected)
			}
		})
	}
}
