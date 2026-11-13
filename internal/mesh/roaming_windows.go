//go:build windows

package mesh

import (
	"log"
	"net/netip"
	"time"

	"directlan/internal/directpair"
	"directlan/internal/tunnel"
)

func newestAuthenticated(a, b authenticatedEndpoint, now time.Time) authenticatedEndpoint {
	if b.fresh(now) && (!a.fresh(now) || b.observed.After(a.observed)) {
		return b
	}
	return a
}

func (n *node) authenticatedSource(id string, now time.Time) authenticatedEndpoint {
	return newestAuthenticated(n.controlSources[id], n.wireGuardSources[id], now)
}

// WireGuard's received-byte counter increases only after it has authenticated
// a handshake or data packet. Learn its current roaming address even before
// the separate overlay echo or control cookie round trip succeeds.
func (n *node) learnWireGuardEndpoint(id string, stats tunnel.PeerStats, previousRX uint64, now time.Time) {
	if stats.RxBytes <= previousRX {
		return
	}
	endpoint, err := netip.ParseAddrPort(stats.Endpoint)
	if err != nil || !directpair.PublicEndpoint(endpoint) {
		return
	}
	if n.wireGuardSources == nil {
		n.wireGuardSources = make(map[string]authenticatedEndpoint)
	}
	old := n.wireGuardSources[id]
	n.wireGuardSources[id] = authenticatedEndpoint{endpoint: endpoint, observed: now}
	if old.endpoint != endpoint {
		log.Printf("mesh event=wireguard_source_learned peer=%s", shortID(id))
	}
	if n.p.Learned[id] == endpoint {
		return
	}
	p := n.p
	p.Learned = cloneEndpoints(p.Learned)
	p.Learned[id] = endpoint
	if n.save(p) == nil {
		n.p = p
	}
}
