package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/yetone/magpie/internal/netproxy"
)

// codexTLSConfig returns a TLS configuration that mimics Codex CLI's fingerprint.
// Codex CLI is written in Rust and uses rustls with its default configuration.
// We use uTLS to fully mimic rustls's TLS handshake.
//
// Codex's TLS configuration (from codex-rs/http-client/src/client_builder.rs):
//   - Uses reqwest with rustls backend
//   - Uses rustls's default cipher suites and curves
//   - Supports TLS 1.2 and 1.3
//   - Uses ALPN protocols: h2, http/1.1
func codexTLSConfig() *tls.Config {
	// Start with upstreamTLS if it's set (for tests)
	config := &tls.Config{}
	if upstreamTLS != nil {
		config = upstreamTLS.Clone()
	}

	// rustls's default TLS configuration (as of rustls 0.23+)
	// This matches what Codex CLI uses
	config.MinVersion = tls.VersionTLS12
	config.MaxVersion = tls.VersionTLS13

	// rustls's default cipher suites (from rustls::crypto::aws_lc_rs::default_provider)
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

	// rustls's default curves (from rustls::crypto::aws_lc_rs::default_provider)
	config.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}

	// rustls's ALPN protocols (from reqwest's default configuration)
	// Codex supports both HTTP/2 and HTTP/1.1
	config.NextProtos = []string{"h2", "http/1.1"}

	return config
}

// codexUTLSConfig returns a uTLS configuration that fully mimics rustls's handshake.
// This provides a more accurate fingerprint than Go's crypto/tls.
func codexUTLSConfig() *utls.Config {
	// Start with upstreamTLS if it's set (for tests)
	config := &utls.Config{}
	if upstreamTLS != nil {
		config = &utls.Config{
			RootCAs:    upstreamTLS.RootCAs,
			ServerName: upstreamTLS.ServerName,
		}
	}

	// rustls's default configuration
	config.MinVersion = utls.VersionTLS12
	config.MaxVersion = tls.VersionTLS13

	// rustls's default cipher suites
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

	// rustls's default curves
	config.CurvePreferences = []utls.CurveID{
		utls.X25519,
		utls.CurveP256,
		utls.CurveP384,
	}

	// rustls's ALPN protocols
	config.NextProtos = []string{"h2", "http/1.1"}

	return config
}

// codexUTLSClientHelloID returns the ClientHelloID that best matches rustls's fingerprint.
// rustls uses a similar fingerprint to Chrome, as both use BoringSSL/aws-lc-rs.
func codexUTLSClientHelloID() utls.ClientHelloID {
	// Use Chrome's fingerprint as it's the closest to rustls
	// Both use BoringSSL/aws-lc-rs as the crypto provider
	return utls.HelloChrome_Auto
}

// codexHTTP2Config returns HTTP/2 settings that mimic Codex CLI's behavior.
// Codex CLI uses HTTP/2 with specific settings for the ChatGPT backend.
func codexHTTP2Config() *http.HTTP2Config {
	return &http.HTTP2Config{
		// Codex CLI's HTTP/2 settings
		MaxConcurrentStreams: 100,
		MaxReadFrameSize:     16384, // 16KB
	}
}

// codexTransport returns an http.Transport configured to mimic Codex CLI's
// network behavior, including TLS fingerprint and HTTP/2 settings.
func codexTransport(wait time.Duration) *http.Transport {
	// Check if uTLS is enabled via environment variable
	if os.Getenv("MAGPIE_CODEX_UTLS") == "1" {
		return codexTransportWithUTLS(wait)
	}

	return &http.Transport{
		Proxy:                 netproxy.Func,
		ResponseHeaderTimeout: wait,
		// Codex CLI uses a larger connection pool
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     120 * time.Second,
		// Enable HTTP/2
		ForceAttemptHTTP2: true,
		TLSClientConfig:   codexTLSConfig(),
		HTTP2:             codexHTTP2Config(),
		// Codex CLI's TCP keep-alive
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
}

// codexUTLSDialer returns a DialContext function that uses uTLS for the TLS handshake.
// This provides a more accurate rustls fingerprint than Go's crypto/tls.
func codexUTLSDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Dial TCP connection
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		// Wrap with uTLS
		config := codexUTLSConfig()
		clientHelloID := codexUTLSClientHelloID()
		uconn := utls.UClient(conn, config, clientHelloID)

		// Perform handshake
		if err := uconn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("uTLS handshake failed: %w", err)
		}

		return uconn, nil
	}
}

// codexTransportWithUTLS returns an http.Transport that uses uTLS for TLS handshakes.
// This provides the most accurate rustls fingerprint.
func codexTransportWithUTLS(wait time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:                 netproxy.Func,
		ResponseHeaderTimeout: wait,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       120 * time.Second,
		ForceAttemptHTTP2:     true,
		// Use uTLS dialer instead of TLSClientConfig
		DialContext: codexUTLSDialer(),
		HTTP2:       codexHTTP2Config(),
	}
}

// mimicCodexHeaders adjusts request headers to match Codex CLI's fingerprint.
// This helps avoid detection by Cloudflare and other bot protection services.
//
// Codex CLI's User-Agent format (from codex-rs/login/src/auth/default_client.rs):
//
//	{originator}/{version} ({os_type} {os_version}; {arch}) {terminal}
//
// Example:
//
//	codex_cli_rs/0.163.0 (Mac OS 15.8.1; arm64) iTerm.app/3.5.0
func mimicCodexHeaders(h http.Header) {
	// Remove Go's default User-Agent to avoid revealing we're a Go program
	// Codex CLI's User-Agent format: {originator}/{version} ({os_type} {os_version}; {arch}) {terminal}
	ua := h.Get("User-Agent")
	if ua == "" || strings.HasPrefix(ua, "Go-http-client/") {
		// Default to codex_cli_rs originator (from DEFAULT_ORIGINATOR)
		// OS info should match the actual system
		h.Set("User-Agent", buildCodexUserAgent())
	}

	// Codex CLI always sends these headers
	if h.Get("Accept") == "" {
		h.Set("Accept", "application/json")
	}

	// Codex CLI's Accept-Language (from system locale)
	if h.Get("Accept-Language") == "" {
		h.Set("Accept-Language", "en-US,en;q=0.9")
	}

	// Remove Go's default Accept-Encoding to avoid revealing we're a Go program
	// Codex CLI doesn't send Accept-Encoding (let the transport handle it)
	h.Del("Accept-Encoding")

	// Codex CLI's Cache-Control
	if h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", "no-cache")
	}

	// Codex CLI's Pragma
	if h.Get("Pragma") == "" {
		h.Set("Pragma", "no-cache")
	}

	// Codex CLI sends an "originator" header (from DEFAULT_ORIGINATOR)
	if h.Get("originator") == "" {
		h.Set("originator", "codex_cli_rs")
	}

	// Remove headers that might reveal magpie's presence
	h.Del("X-Magpie-Version")
	h.Del("X-Magpie-Build")
}

// isCodexClient returns true if the request is from Codex CLI itself.
// This is determined by checking the User-Agent header for Codex's signature.
func isCodexClient(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")
	// Codex CLI's User-Agent starts with "codex_cli_rs/" or contains "codex"
	// (from codex-rs/login/src/auth/default_client.rs)
	return strings.HasPrefix(ua, "codex_cli_rs/") ||
		strings.Contains(strings.ToLower(ua), "codex")
}

// buildCodexUserAgent constructs a User-Agent string that matches Codex CLI's format.
// Format: {originator}/{version} ({os_type} {os_version}; {arch}) {terminal}
// Based on codex-rs/login/src/auth/default_client.rs:get_codex_user_agent()
func buildCodexUserAgent() string {
	// Use runtime info to build a realistic User-Agent
	osType := runtime.GOOS
	arch := runtime.GOARCH

	// Map Go's GOOS to Codex's os_type format (from os_info crate)
	osTypeMap := map[string]string{
		"darwin":  "Mac OS",
		"linux":   "Linux",
		"windows": "Windows",
	}
	if mapped, ok := osTypeMap[osType]; ok {
		osType = mapped
	}

	// Get OS version (simplified - could use syscall for more accuracy)
	osVersion := getOSVersion()

	// Map Go's GOARCH to Codex's arch format (from os_info crate)
	archMap := map[string]string{
		"amd64": "x86_64",
		"arm64": "arm64",
		"386":   "x86",
	}
	if mapped, ok := archMap[arch]; ok {
		arch = mapped
	}

	// Terminal info (from codex-rs/terminal-detection/src/lib.rs)
	terminal := detectTerminal()

	// Build the User-Agent string
	// Format: codex_cli_rs/0.163.0 (Mac OS 15.8.1; arm64) iTerm.app/3.5.0
	return fmt.Sprintf("codex_cli_rs/0.163.0 (%s %s; %s) %s",
		osType, osVersion, arch, terminal)
}

// getOSVersion returns the OS version in Codex's format.
// This is a simplified version; for production, consider using syscall or os/exec.
func getOSVersion() string {
	switch runtime.GOOS {
	case "darwin":
		// macOS version (e.g., "15.8.1")
		// Could use syscall.Sysctl("kern.osproductversion") for accuracy
		return "15.8.1"
	case "linux":
		// Linux kernel version (e.g., "6.5.0")
		// Could use syscall.Uname() for accuracy
		return "6.5.0"
	case "windows":
		// Windows version (e.g., "10.0.22631")
		// Could use golang.org/x/sys/windows for accuracy
		return "10.0.22631"
	default:
		return "unknown"
	}
}

// detectTerminal returns the terminal name in Codex's format.
// Based on codex-rs/terminal-detection/src/lib.rs
func detectTerminal() string {
	// Check TERM_PROGRAM environment variable
	if termProgram := os.Getenv("TERM_PROGRAM"); termProgram != "" {
		version := os.Getenv("TERM_PROGRAM_VERSION")
		if version != "" {
			return fmt.Sprintf("%s/%s", termProgram, version)
		}
		return termProgram
	}

	// Check TERM environment variable
	if term := os.Getenv("TERM"); term != "" {
		return term
	}

	// Default to a common terminal
	return "iTerm.app/3.5.0"
}
