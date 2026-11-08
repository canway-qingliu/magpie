package provider

import (
	"net/http"
)

// magpieOwnUA is the User-Agent magpie's own requests go with: the ones
// magpie makes for itself, about a user's account (a sign-in, a model
// list, a revocation), and not a request magpie passes on from an agent,
// which keeps the agent's own name.
//
// Go's own default ("Go-http-client/1.1") says what magpie is written
// in, which is nothing a vendor needs to know, and every request that
// goes out with no User-Agent of its own goes with it.
const magpieOwnUA = "magpie"

// named is a transport that gives a request magpie's own User-Agent when
// the request carries none: Go's default would say what magpie is
// written in, and every request that goes out with no User-Agent of its
// own goes with it.
//
// A request that names a client of its own keeps that name: an agent's
// (the gateway sets it), a vendor's own client (the Copilot CLI's), or
// magpie's own router.
//
// Go's writer adds its default only when the canonical name is free, so
// magpie's name goes on that one: a request carrying a User-Agent under
// another name keeps it and gets magpie's beside it, never Go's default.
type named struct{ next http.RoundTripper }

func (t named) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		// a copy, as a RoundTripper leaves its caller's request as it was
		r := req.Clone(req.Context())
		r.Header.Set("User-Agent", magpieOwnUA)
		req = r
	}
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(req)
}

// CloseIdleConnections closes next's, where it keeps any: the wrapper
// would otherwise hide the transport's own.
func (t named) CloseIdleConnections() {
	if c, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// namedClient is c with magpie's own name on a request that has none.
func namedClient(c *http.Client) *http.Client {
	if c == nil {
		c = http.DefaultClient
	}
	k := *c
	k.Transport = named{k.Transport}
	return &k
}

// PassesUserAgent says a request to p goes with the User-Agent of the agent
// that sent it (#1851): p is a key+URL provider, and the user didn't set
// it to go as magpie (MagpieUserAgent). A signed-in account and a
// plugin's provider sign as their own client; OpenCode's, Cline's and
// Kilo's gateways are sent the client they serve (OwnClient), and another
// magpie is told magpie by it: none of them takes the agent's in its place.
func (p Provider) PassesUserAgent() bool {
	return !p.MagpieUserAgent && p.Account == nil && !p.OwnClient()
}

// OwnClient says magpie's requests to p go as a client the vendor serves,
// whatever agent sent them: OpenCode's gateway is sent OpenCode's
// User-Agent, Cline's Cline's, Kilo's the Kilo CLI's, and another magpie
// magpie's.
func (p Provider) OwnClient() bool {
	return p.IsOpenCode() || p.IsCline() || p.IsKilo() || p.IsRemoteMagpie()
}
