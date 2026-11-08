package gateway

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestCodexTLSConfig(t *testing.T) {
	config := codexTLSConfig()
	if config.MinVersion != tls.VersionTLS12 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions = %d..%d, want TLS 1.2..1.3", config.MinVersion, config.MaxVersion)
	}
	for _, want := range []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256} {
		if !slices.Contains(config.CipherSuites, want) {
			t.Errorf("cipher suite %d missing from %v", want, config.CipherSuites)
		}
	}
	if config.NextProtos[0] != "h2" || config.NextProtos[1] != "http/1.1" {
		t.Errorf("ALPN = %v", config.NextProtos)
	}
}

func TestSanitizeNonCodexHeaders(t *testing.T) {
	t.Setenv("TERM_PROGRAM", "Private Terminal")
	t.Setenv("TERM_PROGRAM_VERSION", "99.1")
	t.Setenv("TERM", "private-term")
	h := http.Header{
		"User-Agent":            {"PrivateEditor/8.2"},
		"Originator":            {"private-editor"},
		"X-Codex-Turn-Metadata": {`{"session_id":"private-session"}`},
		"Session-Id":            {"private-session"},
		"X-Openai-Subagent":     {"review"},
		"X-Magpie-Session":      {"private-session"},
		"Accept-Encoding":       {"gzip"},
	}
	sanitizeNonCodexHeaders(h)
	// the request is for a Codex model, so it goes as a Codex client
	if got := h.Get("User-Agent"); !strings.HasPrefix(got, "codex_cli_rs/") {
		t.Errorf("User-Agent = %q, want Codex's own", got)
	}
	if got := h.Get("Originator"); got != "codex_cli_rs" {
		t.Errorf("Originator = %q, want Codex's own", got)
	}
	for _, name := range []string{"X-Codex-Turn-Metadata", "Session-Id", "X-Openai-Subagent", "X-Magpie-Session", "Accept-Encoding"} {
		if got := h.Get(name); got != "" {
			t.Errorf("%s leaked as %q", name, got)
		}
	}
	ua := h.Get("User-Agent")
	if strings.Contains(ua, "Private") || strings.Contains(ua, "99.1") || strings.Contains(ua, "private-term") {
		t.Errorf("terminal identity leaked in User-Agent: %q", ua)
	}
}

func TestIsCodexClient(t *testing.T) {
	for _, tt := range []struct {
		name string
		head http.Header
		want bool
	}{
		{"Codex CLI", http.Header{"User-Agent": {"codex_cli_rs/0.163.0"}}, true},
		{"Codex Desktop originator", http.Header{"Originator": {"Codex Desktop"}}, true},
		{"ACP adapter", http.Header{"User-Agent": {"acp-extension-codex/0.9.0"}}, true},
		{"hosted Codex", http.Header{"User-Agent": {"vscode_agent_host/1.0"}}, true},
		{"incidental codex substring", http.Header{"User-Agent": {"Some App with codex/1.0"}}, false},
		{"other app", http.Header{"User-Agent": {"PrivateEditor/8.2"}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
			req.Header = tt.head
			if got := isCodexClient(req); got != tt.want {
				t.Errorf("isCodexClient(%v) = %v, want %v", tt.head, got, tt.want)
			}
		})
	}
}
