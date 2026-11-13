//go:build windows

package mesh

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"directlan/internal/tunnel"
)

func TestAuthenticatedWireGuardSourceSurvivesFailedProbeWithoutControlAck(t *testing.T) {
	now := time.Now()
	n := node{path: filepath.Join(t.TempDir(), "profile.mesh.json")}
	actual := netip.MustParseAddrPort("8.8.8.8:55000")
	stale := netip.MustParseAddrPort("1.1.1.1:45000")
	n.learnWireGuardEndpoint("peer", tunnel.PeerStats{RxBytes: 148, Endpoint: actual.String()}, 0, now)
	if n.p.Learned["peer"] != actual {
		t.Fatal("authenticated initiation address was not learned")
	}
	if _, rotate := peerEndpointCandidate(n.authenticatedSource("peer", now.Add(5*time.Second)), stale, []netip.AddrPort{stale}, 12, now.Add(5*time.Second)); rotate {
		t.Fatal("failed echo replaced authenticated WireGuard roaming source")
	}
	n.learnWireGuardEndpoint("peer", tunnel.PeerStats{RxBytes: 148, Endpoint: stale.String()}, 148, now.Add(10*time.Second))
	if n.wireGuardSources["peer"].endpoint != actual {
		t.Fatal("unverified configured endpoint refreshed authentication")
	}
	if _, rotate := peerEndpointCandidate(n.authenticatedSource("peer", now.Add(time.Minute)), stale, []netip.AddrPort{stale}, 12, now.Add(time.Minute)); !rotate {
		t.Fatal("expired source prevented recovery")
	}
	control := authenticatedEndpoint{endpoint: stale, observed: now.Add(3 * time.Second)}
	if newestAuthenticated(control, n.wireGuardSources["peer"], now.Add(5*time.Second)).endpoint != stale {
		t.Fatal("newer authenticated control source did not win")
	}
	n.resetControl([16]byte{}, [32]byte{})
	if len(n.wireGuardSources) != 0 {
		t.Fatal("restarted tunnel retained obsolete WireGuard freshness")
	}
}
