package otlp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/netproxy"
	"github.com/yetone/magpie/internal/settings"
)

// The gateway's way out is aggregated into a duration histogram and a
// request sum, and a send moves both on.
func TestNetproxyMetricsWire(t *testing.T) {
	s := newNetproxyStats()
	s.observe(netproxy.Event{Kind: netproxy.EventRoundTrip, Route: netproxy.RouteChoice, Proto: "HTTP/2.0", Millis: 120})
	s.observe(netproxy.Event{Kind: netproxy.EventRoundTrip, Route: netproxy.RouteChoice, Proto: "HTTP/2.0", Millis: 480})
	s.observe(netproxy.Event{Kind: netproxy.EventRoundTrip, Route: netproxy.RouteBase, Err: "timeout", Millis: 30_000})
	s.observe(netproxy.Event{Kind: netproxy.EventH2Broken})
	s.observe(netproxy.Event{Kind: netproxy.EventH2ConnDead})
	s.observe(netproxy.Event{Kind: netproxy.EventRetryV4})
	payload := s.metrics(time.Now())
	if payload == nil {
		t.Fatal("nothing to send")
	}
	if s.metrics(time.Now()) != nil {
		t.Fatal("a send moved nothing on")
	}
	b, _ := json.Marshal(payload)
	var env struct {
		ResourceMetrics []struct {
			ScopeMetrics []struct {
				Metrics []struct {
					Name      string `json:"name"`
					Histogram struct {
						DataPoints []struct {
							Attributes []otelAttribute `json:"attributes"`
							Count      uint64          `json:"count,string"`
							Sum        float64         `json:"sum"`
						} `json:"dataPoints"`
					} `json:"histogram"`
					Sum struct {
						DataPoints []struct {
							Attributes []otelAttribute `json:"attributes"`
							Value      string          `json:"asInt"`
						} `json:"dataPoints"`
					} `json:"sum"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if json.Unmarshal(b, &env) != nil || len(env.ResourceMetrics) != 1 {
		t.Fatalf("wire: %s", b)
	}
	var hist, sum bool
	attr := func(a []otelAttribute, key string) string {
		for _, x := range a {
			if x.Key == key {
				if v, ok := x.Value["stringValue"].(string); ok {
					return v
				}
			}
		}
		return ""
	}
	for _, m := range env.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		switch m.Name {
		case "magpie.proxy.roundtrip.duration":
			hist = true
			var h2 int
			for _, p := range m.Histogram.DataPoints {
				if attr(p.Attributes, "network.protocol.name") == "HTTP/2.0" {
					h2++
					if p.Count != 2 || p.Sum != .6 {
						t.Fatalf("h2 point: %+v", p)
					}
				}
				if attr(p.Attributes, "magpie.proxy.route") == "" {
					t.Fatalf("no route on %+v", p)
				}
			}
			if h2 != 1 {
				t.Fatalf("h2 points: %d of %s", h2, b)
			}
		case "magpie.proxy.requests":
			sum = true
			counts := map[string]string{}
			for _, p := range m.Sum.DataPoints {
				switch {
				case attr(p.Attributes, "magpie.proxy.result") == "timeout":
					counts["timeout"] = p.Value
				case attr(p.Attributes, "magpie.proxy.event") == "http2_broken":
					counts["http2_broken"] = p.Value
				case attr(p.Attributes, "magpie.proxy.event") == "http2_conn_dead":
					counts["http2_conn_dead"] = p.Value
				}
			}
			if counts["timeout"] != "1" || counts["http2_broken"] != "1" || counts["http2_conn_dead"] != "1" {
				t.Fatalf("counts: %v of %s", counts, b)
			}
		}
	}
	if !hist || !sum {
		t.Fatalf("metrics: hist %v sum %v of %s", hist, sum, b)
	}
}

// What leaves for the collector is classes only: an event's attributes
// name no host, no proxy, no account.
func TestNetproxyMetricsPrivacy(t *testing.T) {
	s := newNetproxyStats()
	s.observe(netproxy.Event{Kind: netproxy.EventRoundTrip, Route: netproxy.RouteChoice, Proto: "HTTP/2.0", Millis: 12, Err: "tls"})
	s.observe(netproxy.Event{Kind: netproxy.EventTransportMade, Route: netproxy.RouteChoice})
	b, _ := json.Marshal(s.metrics(time.Now()))
	for _, leaked := range []string{"http://", "https://", "proxy", "user:pass@", "api.example", "anthropic", "openai"} {
		if leaked != "proxy" && strings.Contains(string(b), leaked) {
			t.Fatalf("leaked %q in %s", leaked, b)
		}
	}
	// every attribute is on the magpie.proxy.* or network.protocol.name
	// allowlist
	var walk func(v any)
	var bad []string
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if k, ok := v["key"].(string); ok {
				if !strings.HasPrefix(k, "magpie.proxy.") && k != "network.protocol.name" && k != "service.name" {
					bad = append(bad, k)
				}
			}
			for _, x := range v {
				walk(x)
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	var top any
	json.Unmarshal(b, &top)
	walk(top)
	if len(bad) > 0 {
		t.Fatalf("attributes off the allowlist: %v in %s", bad, b)
	}
}

// While the exporter serves, netproxy's events reach the collector as the
// proxy's metrics, beside the ledger's own.
func TestNetproxyMetricsExported(t *testing.T) {
	bodies := make(chan []byte, 8)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		io.WriteString(w, `{}`)
	}))
	defer collector.Close()
	otelConfig(t, settings.OTel{Endpoint: collector.URL, Metrics: true})
	// the exporter flushes on its timer; shorten it before Serve starts it
	every := OTelEvery
	OTelEvery = 20 * time.Millisecond
	t.Cleanup(func() { OTelEvery = every })
	stop := StartOTel()
	t.Cleanup(stop)
	if netproxy.Observe == nil {
		t.Fatal("Serve left netproxy unobserved")
	}
	netproxy.Observe(netproxy.Event{Kind: netproxy.EventRoundTrip, Route: netproxy.RouteChoice, Proto: "HTTP/2.0", Millis: 150})
	netproxy.Observe(netproxy.Event{Kind: netproxy.EventH2Broken})
	seen := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && !seen; {
		select {
		case b := <-bodies:
			if strings.Contains(string(b), "magpie.proxy.requests") && strings.Contains(string(b), "magpie.proxy.roundtrip.duration") {
				seen = true
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !seen {
		t.Fatal("collector never got the proxy's metrics")
	}
	stop()
	if netproxy.Observe != nil {
		t.Fatal("stop left the observer on")
	}
}
