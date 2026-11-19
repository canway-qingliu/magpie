package netproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// A round trip through Dispatch is observed once, with its protocol,
// status and route class — and an errored one with its error's class.
func TestRoundTripObserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	var mu sync.Mutex
	var got []Event
	was := Observe
	Observe = func(e Event) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	}
	t.Cleanup(func() { Observe = was })
	d := Dispatch(&http.Transport{}).(*dispatch)
	t.Cleanup(d.CloseIdleConnections)
	req, _ := http.NewRequestWithContext(With(context.Background(), "direct"), http.MethodGet, srv.URL, nil)
	res, err := d.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	var rt *Event
	for i := range got {
		if got[i].Kind == EventRoundTrip {
			rt = &got[i]
		}
	}
	if rt == nil {
		t.Fatalf("no round trip in %v", got)
	}
	if rt.Route != RouteChoice || rt.Status != http.StatusTeapot || rt.Proto != "HTTP/1.1" || rt.Err != "" {
		t.Fatalf("got %+v", *rt)
	}
	var made bool
	for _, e := range got {
		if e.Kind == EventTransportMade && e.Route == RouteChoice {
			made = true
		}
	}
	if !made {
		t.Fatalf("no transport made in %v", got)
	}
}

// A failed round trip is observed with a class of its error, never its
// text (a refused loopback port with nothing listening).
func TestRoundTripFailureObserved(t *testing.T) {
	var mu sync.Mutex
	var got []Event
	was := Observe
	Observe = func(e Event) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	}
	t.Cleanup(func() { Observe = was })
	d := Dispatch(&http.Transport{}).(*dispatch)
	t.Cleanup(d.CloseIdleConnections)
	// a port just freed has nothing on it
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := d.RoundTrip(req); err == nil {
		t.Fatal("answered")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, e := range got {
		if e.Kind == EventRoundTrip {
			if e.Err != "refused" || e.Status != 0 || e.Route != RouteBase {
				t.Fatalf("got %+v", e)
			}
			return
		}
	}
	t.Fatalf("no round trip in %v", got)
}

// The event an observer gets carries nothing of the request: no host, no
// path, no proxy's URL.
func TestEventCarriesNoHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	var mu sync.Mutex
	var got []Event
	was := Observe
	Observe = func(e Event) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	}
	t.Cleanup(func() { Observe = was })
	d := Dispatch(&http.Transport{}).(*dispatch)
	t.Cleanup(d.CloseIdleConnections)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/some/secret/path", nil)
	res, err := d.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	for _, e := range got {
		for _, s := range []string{e.Proto, e.Err, string(e.Route)} {
			if s != "" && (s == srv.URL || s == "/some/secret/path" || len(s) > 32) {
				t.Fatalf("event leaked %q in %+v", s, e)
			}
		}
	}
	if len(got) == 0 {
		t.Fatal("nothing observed")
	}
}
