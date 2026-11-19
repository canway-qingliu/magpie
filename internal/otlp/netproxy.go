package otlp

import (
	"encoding/json"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/netproxy"
)

// netproxyStats aggregates the gateway's way out (netproxy.Observe) into
// OTLP metrics: how long a request to a vendor took, how it ended, and
// the pool's own turns (an HTTP/2 host given up on, a transport made or
// dropped, an IPv4 retry). It holds classes only, as the events carry:
// no host, no proxy, no account. Flush sends them with the batch's own
// metrics when settings' Metrics is on.
type netproxyStats struct {
	mu       sync.Mutex
	last     time.Time
	duration map[string]*otelHistogram
	counts   map[string]uint64
}

var durationBounds = []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120}

func newNetproxyStats() *netproxyStats {
	return &netproxyStats{last: time.Now(), duration: map[string]*otelHistogram{}, counts: map[string]uint64{}}
}

// observe is the exporter's netproxy.Observe: never blocks, as a slow one
// holds every request the gateway sends.
func (s *netproxyStats) observe(e netproxy.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := func(attrs []otelAttribute) string {
		b, _ := json.Marshal(attrs)
		return string(b)
	}
	switch e.Kind {
	case netproxy.EventRoundTrip:
		a := []otelAttribute{otelString("magpie.proxy.route", string(e.Route))}
		if e.Proto != "" {
			a = append(a, otelString("network.protocol.name", e.Proto))
		}
		s.addDuration(key(a), a, float64(e.Millis)/1000)
		result := "ok"
		switch {
		case e.Err != "":
			result = e.Err
		case e.Status >= 500:
			result = "5xx"
		case e.Status >= 400:
			result = "4xx"
		}
		c := []otelAttribute{otelString("magpie.proxy.route", string(e.Route)), otelString("magpie.proxy.result", result)}
		s.counts[key(c)]++
	case netproxy.EventRetryV4:
		s.counts[key([]otelAttribute{otelString("magpie.proxy.event", "ipv4_retry")})]++
	case netproxy.EventH2Broken:
		s.counts[key([]otelAttribute{otelString("magpie.proxy.event", "http2_broken")})]++
	case netproxy.EventTransportMade:
		c := []otelAttribute{otelString("magpie.proxy.event", "transport_made"), otelString("magpie.proxy.route", string(e.Route))}
		s.counts[key(c)]++
	case netproxy.EventTransportEvict:
		s.counts[key([]otelAttribute{otelString("magpie.proxy.event", "transport_evict")})]++
	case netproxy.EventH2ConnDead:
		s.counts[key([]otelAttribute{otelString("magpie.proxy.event", "http2_conn_dead")})]++
	}
}

func (s *netproxyStats) addDuration(key string, attrs []otelAttribute, seconds float64) {
	h := s.duration[key]
	if h == nil {
		h = &otelHistogram{Attributes: attrs, Bounds: durationBounds, Buckets: make([]uint64, len(durationBounds)+1)}
		s.duration[key] = h
	}
	h.Count++
	h.Sum += seconds
	h.Buckets[sort.SearchFloat64s(durationBounds, seconds)]++
}

// metrics is the OTLP metrics payload of what was observed since the last
// send, or nil when nothing was. Counters and histograms move on, so a
// collector down a window sees only what it missed, as the ledger's own
// metrics do.
func (s *netproxyStats) metrics(end time.Time) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.duration) == 0 && len(s.counts) == 0 {
		return nil
	}
	start := s.last
	s.last = end
	nano := func(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }
	var out []any
	if len(s.duration) > 0 {
		keys := make([]string, 0, len(s.duration))
		for k := range s.duration {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		points := make([]*otelHistogram, 0, len(keys))
		for _, k := range keys {
			h := s.duration[k]
			h.Start, h.Time = nano(start), nano(end)
			points = append(points, h)
		}
		out = append(out, map[string]any{"name": "magpie.proxy.roundtrip.duration", "unit": "s",
			"histogram": map[string]any{"aggregationTemporality": 1, "dataPoints": points}})
		s.duration = map[string]*otelHistogram{}
	}
	if len(s.counts) > 0 {
		type point struct {
			Attributes []otelAttribute `json:"attributes"`
			Start      string          `json:"startTimeUnixNano"`
			Time       string          `json:"timeUnixNano"`
			Value      string          `json:"asInt"`
		}
		keys := make([]string, 0, len(s.counts))
		for k := range s.counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		points := make([]point, 0, len(keys))
		for _, k := range keys {
			var attrs []otelAttribute
			json.Unmarshal([]byte(k), &attrs)
			points = append(points, point{Attributes: attrs, Start: nano(start), Time: nano(end), Value: strconv.FormatUint(s.counts[k], 10)})
		}
		out = append(out, map[string]any{"name": "magpie.proxy.requests", "unit": "{request}",
			"sum": map[string]any{"aggregationTemporality": 1, "isMonotonic": true, "dataPoints": points}})
		s.counts = map[string]uint64{}
	}
	if len(out) == 0 {
		return nil
	}
	return otelEnvelope("Metrics", out)
}
