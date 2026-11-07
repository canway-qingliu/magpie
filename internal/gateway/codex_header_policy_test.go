package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/provider"
)

// The two lists that say which of the caller's headers go to the ChatGPT
// backend answer about a header the same way: the backend's vocabulary
// about a turn (codexHeader) and the sign-in's own headers
// (codexSignInHeader). A header in both would be taken away on the route
// where the caller signs for itself and kept on the route where an
// account signs, and the two routes would differ about it without
// anyone saying so.
func TestCodexHeaderListsApart(t *testing.T) {
	for _, h := range []string{
		"authorization", "x-oai-attestation", "x-openai-codex-luna-reserve",
		"x-codex-turn-state", "x-openai-subagent", "x-openai-memgen-request",
		"x-codex-turn-metadata", "x-codex-installation-id", "version",
		"session-id", "thread-id", "session_id", "conversation_id",
		"x-client-request-id", "originator", "user-agent", "accept",
		"content-type", "chatgpt-account-id", "x-magpie-session",
	} {
		if codexHeader(h) && codexSignInHeader(h) {
			t.Errorf("%s is a turn header and a sign-in header at once", h)
		}
	}
}

// What of a caller's request reaches the ChatGPT backend, header by
// header: the backend's vocabulary about a turn and the caller's own name
// are taken away for a caller that is not Codex, the sign-in's own
// headers and everything else stay.
func TestSanitizeNonCodexHeadersTable(t *testing.T) {
	for _, tt := range []struct {
		name string
		kept bool
	}{
		{"x-openai-subagent", false},
		{"x-openai-memgen-request", false},
		{"x-openai-internal-codex-responses-lite", true},
		{"x-openai-codex-luna-reserve", true},
		{"x-codex-turn-metadata", false},
		{"x-codex-installation-id", false},
		{"x-codex-turn-state", true},
		{"x-oai-attestation", true},
		{"version", false},
		{"session-id", false},
		{"thread-id", false},
		{"session_id", false},
		{"conversation_id", false},
		{"x-client-request-id", false},
		{"originator", false},
		{"x-magpie-session", false},
		{"authorization", true},
		{"chatgpt-account-id", true},
		{"accept", true},
		{"content-type", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			h.Set(tt.name, "value")
			sanitizeNonCodexHeaders(h)
			got := h.Get(tt.name)
			if tt.kept && got != "value" {
				t.Errorf("%s was taken away from the request", tt.name)
			}
			if !tt.kept && got != "" {
				t.Errorf("%s reached the backend as %q", tt.name, got)
			}
		})
	}
}

// A turn from a caller that is not Codex, sent on the caller's own
// sign-in: the caller's client, terminal and Codex session are taken away
// and magpie's own name is sent, while the sign-in the request is sent
// with stays.
func TestNonCodexTurnReachesOpenAIWithoutItsCodexHeaders(t *testing.T) {
	codexSignedIn(t)
	var heads []http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		heads = append(heads, r.Header.Clone())
		w.WriteHeader(429)
		io.WriteString(w, `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached","resets_in_seconds":7200}}`)
	}))
	t.Cleanup(up.Close)
	was := provider.CodexBase
	provider.CodexBase = up.URL + "/backend-api/codex"
	t.Cleanup(func() { provider.CodexBase = was })

	s := New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", CodexPath+"/responses", strings.NewReader(`{"model":"gpt-5.5","stream":true,"input":"ping"}`))
	req.Header.Set("Authorization", "Bearer chatgpt-token")
	req.Header.Set("chatgpt-account-id", "acct-1")
	req.Header.Set("User-Agent", "SomeOtherApp/1.2")
	req.Header.Set("Originator", "some-other-app")
	req.Header.Set("session-id", "client-session")
	req.Header.Set("x-client-request-id", "client-req-1")
	req.Header.Set("x-openai-subagent", "review")
	req.Header.Set("x-codex-turn-metadata", `{"turn_id":"t1"}`)
	req.Header.Set("x-codex-turn-state", "state-1")
	req.Header.Set("x-openai-codex-luna-reserve", "true")
	req.Header.Set("X-OpenAI-Internal-Codex-Responses-Lite", "true")
	req.Header.Set("version", "0.159.0")
	req.Header.Set("x-magpie-session", "magpie-1")
	s.Handler().ServeHTTP(rec, req)
	if len(heads) == 0 {
		t.Fatalf("no request went upstream: %d %s", rec.Code, rec.Body.String())
	}
	h := heads[0]
	for _, name := range []string{
		"Originator", "session-id", "x-client-request-id", "x-openai-subagent",
		"x-codex-turn-metadata", "version", "x-magpie-session",
	} {
		if got := h.Get(name); got != "" {
			t.Errorf("%s reached OpenAI as %q", name, got)
		}
	}
	if got := h.Get("User-Agent"); got != "magpie/"+Version {
		t.Errorf("User-Agent = %q, want magpie/%s", got, Version)
	}
	if got := h.Get("Authorization"); got != "Bearer chatgpt-token" {
		t.Errorf("Authorization = %q, want the caller's own sign-in", got)
	}
	if got := h.Get("x-codex-turn-state"); got != "state-1" {
		t.Errorf("x-codex-turn-state = %q, want the account's own routing", got)
	}
	if got := h.Get("x-openai-codex-luna-reserve"); got != "true" {
		t.Errorf("x-openai-codex-luna-reserve = %q, want the account's own plan", got)
	}
	if got := h.Get("X-OpenAI-Internal-Codex-Responses-Lite"); got != "true" {
		t.Errorf("X-OpenAI-Internal-Codex-Responses-Lite = %q, want the request's own", got)
	}
}

// A turn from Codex itself, on its own sign-in: it is relayed as it came,
// the headers the backend reads a Codex turn by included.
func TestCodexTurnReachesOpenAIAsItCame(t *testing.T) {
	codexSignedIn(t)
	var heads []http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		heads = append(heads, r.Header.Clone())
		w.WriteHeader(429)
		io.WriteString(w, `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached","resets_in_seconds":7200}}`)
	}))
	t.Cleanup(up.Close)
	was := provider.CodexBase
	provider.CodexBase = up.URL + "/backend-api/codex"
	t.Cleanup(func() { provider.CodexBase = was })

	s := New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", CodexPath+"/responses", strings.NewReader(`{"model":"gpt-5.5","stream":true,"input":"ping"}`))
	req.Header.Set("Authorization", "Bearer chatgpt-token")
	req.Header.Set("User-Agent", "codex_cli_rs/0.163.0 (Mac OS 27.0.1; arm64) Terminal/455")
	req.Header.Set("Originator", "codex_cli_rs")
	req.Header.Set("session-id", "codex-session")
	req.Header.Set("x-openai-subagent", "review")
	req.Header.Set("x-codex-turn-metadata", `{"turn_id":"t1"}`)
	s.Handler().ServeHTTP(rec, req)
	if len(heads) == 0 {
		t.Fatalf("no request went upstream: %d %s", rec.Code, rec.Body.String())
	}
	h := heads[0]
	for name, want := range map[string]string{
		"User-Agent":            "codex_cli_rs/0.163.0 (Mac OS 27.0.1; arm64) Terminal/455",
		"Originator":            "codex_cli_rs",
		"session-id":            "codex-session",
		"x-openai-subagent":     "review",
		"x-codex-turn-metadata": `{"turn_id":"t1"}`,
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}
