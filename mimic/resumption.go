package mimic

import (
	"sync"

	utls "github.com/refraction-networking/utls"
)

// clientSessionCache is the shared store of the TLS session tickets the
// library's clients collect.
//
// It is a package-level global on purpose: a browser keeps its tickets
// between connections, so two clients built from the same profile must see
// each other's tickets — a client created per request still resumes on the
// second request. What must NOT be shared is a ticket between two different
// profiles, so the store is keyed by (identity, server) and each profile
// only ever sees its own entries — see scopedSessionCache.
var clientSessionCache utls.ClientSessionCache = utls.NewLRUClientSessionCache(64)

// sessionScopeSeparator joins the profile scope and the server key in the
// shared store. A NUL cannot appear in a host name or an IP literal, so the
// joined key cannot be ambiguous.
const sessionScopeSeparator = "\x00"

// resumptionScope maps a profile's ClientHello name to the identity whose
// tickets that profile may present.
//
// A ticket is a bearer credential for one TLS identity. The server checks the
// binder, and the binder is computed over the ClientHello that carries it —
// so a client that speaks a different hello computes a different, still
// perfectly valid binder for the same ticket, and the server cannot tell the
// two apart. Only the library knows which identity a ticket was negotiated
// under, so the store is namespaced per identity and a ticket never crosses
// identities.
//
// Profiles that resolve to the same ClientHello share a scope: android_149
// and chrome_auto are the same uTLS preset, so a ticket from one is a valid
// offer from the other.
func resumptionScope(helloName string) string {
	switch helloName {
	case "", "chrome_auto", "android_149":
		return "chrome_auto"
	default:
		return helloName
	}
}

// scopedSessionCache is one profile's view of the shared ticket store. It
// rewrites the key uTLS uses (the server name) into (scope, server), so the
// store keeps one bounded LRU for the whole process while no profile can
// reach a ticket that was negotiated under another one.
type scopedSessionCache struct {
	scope string
}

// Get returns the ticket this profile collected for the server, if any.
func (c *scopedSessionCache) Get(key string) (*utls.ClientSessionState, bool) {
	return clientSessionCache.Get(c.scope + sessionScopeSeparator + key)
}

// Put stores a ticket this profile collected for the server.
func (c *scopedSessionCache) Put(key string, cs *utls.ClientSessionState) {
	clientSessionCache.Put(c.scope+sessionScopeSeparator+key, cs)
}

// sessionCaches memoises the scoped stores, one per identity: the key
// rewriting is then paid once per profile instead of once per connection.
var sessionCaches sync.Map

// sessionCacheFor returns the ticket store a profile may use. The profile's
// ClientHello name is the identity — the shape that decides which tickets
// belong together.
func sessionCacheFor(helloName string) utls.ClientSessionCache {
	scope := resumptionScope(helloName)
	if v, ok := sessionCaches.Load(scope); ok {
		return v.(utls.ClientSessionCache)
	}
	v, _ := sessionCaches.LoadOrStore(scope, &scopedSessionCache{scope: scope})
	return v.(utls.ClientSessionCache)
}

// withResumptionPSK appends uTLS's managed pre_shared_key placeholder to a
// spec, unless the spec already carries one.
//
// The placeholder is what makes the browser's A/B work. uTLS fills it from
// the session cache when the client holds a ticket for the server, and
// OmitEmptyPsk conceals the extension entirely when it does not — so the
// hello on the wire is the captured full-handshake form until a ticket
// exists, and a proper PSK offer (last extension, binder computed over this
// very hello) from then on.
//
// It has to be the last extension of the hello: RFC 8446 puts pre_shared_key
// last, and uTLS asserts that it is.
func withResumptionPSK(spec *utls.ClientHelloSpec) *utls.ClientHelloSpec {
	for _, ext := range spec.Extensions {
		if _, ok := ext.(utls.PreSharedKeyExtension); ok {
			return spec // the spec already carries a PSK extension
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
	return spec
}
