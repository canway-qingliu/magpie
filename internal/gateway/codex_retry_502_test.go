package gateway

import (
	"testing"

	"github.com/yetone/magpie/internal/provider"
)

func TestCodexBusyWithRetryOn502(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		msg        []byte
		retryOn502 bool
		expected   bool
	}{
		{
			name:       "502 with RetryOn502 enabled",
			status:     502,
			msg:        []byte("Bad Gateway"),
			retryOn502: true,
			expected:   true,
		},
		{
			name:       "502 with RetryOn502 disabled",
			status:     502,
			msg:        []byte("Bad Gateway"),
			retryOn502: false,
			expected:   true, // busy() returns true for 502 by default
		},
		{
			name:       "503 with RetryOn502 enabled",
			status:     503,
			msg:        []byte("Service Unavailable"),
			retryOn502: true,
			expected:   true,
		},
		{
			name:       "503 with RetryOn502 disabled",
			status:     503,
			msg:        []byte("Service Unavailable"),
			retryOn502: false,
			expected:   true,
		},
		{
			name:       "429 with RetryOn502 enabled",
			status:     429,
			msg:        []byte("Too Many Requests"),
			retryOn502: true,
			expected:   false,
		},
		{
			name:       "429 with RetryOn502 disabled",
			status:     429,
			msg:        []byte("Too Many Requests"),
			retryOn502: false,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := codexBusy(tt.status, tt.msg, tt.retryOn502)
			if got != tt.expected {
				t.Errorf("codexBusy(%d, %q, %v) = %v, expected %v", tt.status, tt.msg, tt.retryOn502, got, tt.expected)
			}
		})
	}
}

func TestRuleRetryOn502(t *testing.T) {
	rule := provider.Rule{
		Use:        "openai/gpt-4",
		RetryOn502: true,
	}

	if !rule.RetryOn502 {
		t.Error("Expected RetryOn502 to be true")
	}

	rule2 := provider.Rule{
		Use: "openai/gpt-4",
	}

	if rule2.RetryOn502 {
		t.Error("Expected RetryOn502 to be false")
	}
}
