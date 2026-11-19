package netproxy

import (
	"errors"
	"net"
	"strings"
)

// Event is one observable step of a request's way out, handed to Observe.
// It carries kinds and classes only — never a host, a proxy's URL, an
// account's name or an error's text — so a subscriber (internal/otlp's
// exporter) can let it leave the machine under the same allowlist the
// OTLP spans follow.
type Event struct {
	Kind  EventKind
	Route RouteClass
	// Proto is the reply's protocol ("HTTP/2.0", "HTTP/1.1"), "" when the
	// request never got one.
	Proto string
	// Millis is how long the round trip took; 0 on the pool events.
	Millis int64
	// Status is the reply's code, 0 when the request failed before one.
	Status int
	// Err is a class of the failure ("timeout", "refused", "reset",
	// "tls", "proxy", "other"), "" when it went through.
	Err string
}

// EventKind names which step an Event is.
type EventKind int

const (
	// EventRoundTrip is one request done, answered or failed.
	EventRoundTrip EventKind = iota
	// EventRetryV4 is a request sent again over IPv4 after its IPv6
	// address failed (v4Retry).
	EventRetryV4
	// EventH2Broken is a host's HTTP/2 marked broken (markH2Broken): the
	// requests after it go out over HTTP/1.1.
	EventH2Broken
	// EventTransportMade is a route's own transport made (a first request
	// of that proxy choice, HTTP/1.1 ask or TLS profile).
	EventTransportMade
	// EventTransportEvict is the route map full, every pooled transport
	// dropped.
	EventTransportEvict
	// EventH2ConnDead is a pooled HTTP/2 connection marked dead
	// (calmPool.MarkDead).
	EventH2ConnDead
)

// RouteClass says which route a request took, with nothing about the
// proxy in it.
type RouteClass string

const (
	// RouteBase is the base transport's: the global proxy, the system's
	// or direct.
	RouteBase RouteClass = "base"
	// RouteChoice is a provider's or account's own proxy (With).
	RouteChoice RouteClass = "choice"
)

// Observe is called with each Event as it happens: internal/otlp
// subscribes while its exporter serves; nil observes nothing. It is set
// once at start-up, like HTTP1, and an observer must not block — a slow
// one holds every request.
var Observe func(Event)

func observe(e Event) {
	if f := Observe; f != nil {
		f(e)
	}
}

// class is the RouteClass of r.
func (r route) class() RouteClass {
	if r.choice != "" {
		return RouteChoice
	}
	return RouteBase
}

// errClass is a coarse class of err, with none of its text.
func errClass(err error) string {
	if err == nil {
		return ""
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if refused(strings.ToLower(err.Error())) {
		return "refused"
	}
	if recordError(err) {
		return "tls"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "connection reset"), strings.Contains(s, "broken pipe"):
		return "reset"
	case strings.Contains(s, "tls"), strings.Contains(s, "certificate"):
		return "tls"
	case strings.Contains(s, "proxy"):
		return "proxy"
	default:
		return "other"
	}
}
