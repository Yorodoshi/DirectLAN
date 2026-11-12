package mesh

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestEndpointFallbackPreservesFreshAuthenticatedSource(t *testing.T) {
	now := time.Unix(1800000000, 0)
	learned := netip.MustParseAddrPort("8.8.8.8:50001")
	signed := netip.MustParseAddrPort("1.1.1.1:50002")
	source := authenticatedEndpoint{endpoint: learned, observed: now.Add(-44 * time.Second)}
	if _, rotate := peerEndpointCandidate(source, learned, []netip.AddrPort{signed}, 12, now); rotate {
		t.Fatal("probe failure replaced a recently authenticated source with a signed candidate")
	}
	source.observed = now.Add(-authenticatedEndpointTTL)
	for _, check := range []struct {
		misses int
		want   netip.AddrPort
		rotate bool
	}{
		{2, netip.AddrPort{}, false},
		{3, learned, true},
		{4, signed, true},
		{5, learned, true},
	} {
		got, rotate := peerEndpointCandidate(source, learned, []netip.AddrPort{learned, {}, signed, signed}, check.misses, now)
		if got != check.want || rotate != check.rotate {
			t.Errorf("misses=%d selected %v, %t; want %v, %t", check.misses, got, rotate, check.want, check.rotate)
		}
	}
	if _, rotate := peerEndpointCandidate(authenticatedEndpoint{}, netip.AddrPort{}, nil, 3, now); rotate {
		t.Fatal("selected an unavailable fallback")
	}
	source.observed = now.Add(time.Second)
	if source.fresh(now) {
		t.Fatal("a future timestamp kept a source fresh across a clock rollback")
	}
}

func TestControlCandidatesPreferLearnedAndRemoveInvalidDuplicates(t *testing.T) {
	learned := netip.MustParseAddrPort("8.8.8.8:50001")
	first := netip.MustParseAddrPort("1.1.1.1:50002")
	second := netip.MustParseAddrPort("[2606:4700:4700::1111]:50003")
	signed := []netip.AddrPort{{}, first, learned, second, first, {}}
	if got := controlCandidates(learned, signed); !slices.Equal(got, []netip.AddrPort{learned, first, second}) {
		t.Fatalf("learned endpoint did not remain first or invalid duplicates remain: %v", got)
	}
	if got := controlCandidates(netip.AddrPort{}, signed); !slices.Equal(got, []netip.AddrPort{first, learned, second}) {
		t.Fatalf("invalid learned endpoint changed signed fallback order: %v", got)
	}
	if got := controlCandidates(netip.AddrPort{}, []netip.AddrPort{{}, {}}); len(got) != 0 {
		t.Fatalf("invalid endpoints became candidates: %v", got)
	}
	if signed[0].IsValid() || signed[1] != first || signed[2] != learned || len(signed) != 6 {
		t.Fatal("candidate selection modified the signed endpoint list")
	}
}

func TestAdmissionCookieBindsReturnPathAndSession(t *testing.T) {
	secret, nonce := [32]byte{1, 2, 3}, [16]byte{4, 5, 6}
	peer := strings.Repeat("a1", 32)
	source := netip.MustParseAddrPort("8.8.8.8:50001")
	want := admissionCookie(secret, peer, source, nonce)
	if got := admissionCookie(secret, peer, source, nonce); got != want {
		t.Fatal("the same return path did not produce a stable cookie")
	}
	changedSecret, changedNonce := secret, nonce
	changedSecret[31] ^= 1
	changedNonce[15] ^= 1
	for name, got := range map[string][16]byte{
		"peer":          admissionCookie(secret, strings.Repeat("b2", 32), source, nonce),
		"source IP":     admissionCookie(secret, peer, netip.MustParseAddrPort("8.8.4.4:50001"), nonce),
		"source port":   admissionCookie(secret, peer, netip.MustParseAddrPort("8.8.8.8:50002"), nonce),
		"source family": admissionCookie(secret, peer, netip.MustParseAddrPort("[2606:4700:4700::1111]:50001"), nonce),
		"nonce":         admissionCookie(secret, peer, source, changedNonce),
		"secret":        admissionCookie(changedSecret, peer, source, nonce),
	} {
		if got == want {
			t.Errorf("cookie did not bind %s", name)
		}
	}
}

func TestAdmissionHelloExactFormat(t *testing.T) {
	nonce, cookie := [16]byte{1, 3, 5}, [16]byte{2, 4, 6}
	for _, revision := range []uint64{0, 1, 0x0102030405060708, ^uint64(0)} {
		packet := admissionHello(nonce, cookie, revision)
		gotNonce, gotCookie, gotRevision, ok := parseAdmissionHello(packet)
		if !ok || gotNonce != nonce || gotCookie != cookie || gotRevision != revision || len(packet) != 41 {
			t.Fatalf("admission hello did not round trip revision %d", revision)
		}
		if !bytes.Equal(packet[:16], nonce[:]) || !bytes.Equal(packet[16:32], cookie[:]) || packet[32] != controlHelloKind {
			t.Fatal("hello layout changed")
		}
	}
	valid := admissionHello(nonce, cookie, 1)
	for _, length := range []int{0, 9, 16, 32, 40, 42, controlPayloadLimit, controlPayloadLimit + 1} {
		packet := append([]byte(nil), valid...)
		if length < len(packet) {
			packet = packet[:length]
		} else {
			packet = append(packet, make([]byte, length-len(packet))...)
		}
		if _, _, _, ok := parseAdmissionHello(packet); ok {
			t.Errorf("accepted hello with length %d", length)
		}
	}
	valid[32] = controlCookieKind
	if _, _, _, ok := parseAdmissionHello(valid); ok {
		t.Fatal("cookie packet accepted as a hello")
	}
}

func TestMaximumRosterWithAdmissionNonceFitsControlPayload(t *testing.T) {
	parts, err := rosterPackets(strings.Repeat("x", maxEncodedSize), 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, part := range parts {
		packet := append(make([]byte, 16), part...)
		if len(packet) > controlPayloadLimit {
			t.Fatalf("fragment %d plus admission nonce exceeds transport limit: %d", i, len(packet))
		}
	}
}

func TestSameAuthorizationsIgnoresMetadataButDetectsMembershipChanges(t *testing.T) {
	base, _ := testNetwork(t)
	clone := func() Code {
		code := base
		code.Members = append([]Member(nil), base.Members...)
		return code
	}
	metadata := clone()
	metadata.Revision++
	metadata.Members[0].Name = "Renamed owner"
	metadata.Members[1].Endpoints = []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:50003")}
	metadata.Members[1], metadata.Members[2] = metadata.Members[2], metadata.Members[1]
	if !sameAuthorizations(base, metadata) || !sameAuthorizations(metadata, base) {
		t.Fatal("metadata or member ordering changed authorizations")
	}
	for _, change := range []struct {
		name  string
		apply func(*Code)
	}{
		{"WireGuard key", func(code *Code) {
			code.Members[1].WireGuard = append([]byte(nil), code.Members[1].WireGuard...)
			code.Members[1].WireGuard[0] ^= 1
		}},
		{"identity", func(code *Code) {
			code.Members[1].Identity = append([]byte(nil), code.Members[1].Identity...)
			code.Members[1].Identity[0] ^= 1
		}},
		{"virtual IP", func(code *Code) { code.Members[1].IP = netip.MustParseAddr("10.213.47.100") }},
		{"member removed", func(code *Code) { code.Members = code.Members[:2] }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := clone()
			change.apply(&changed)
			if sameAuthorizations(base, changed) || sameAuthorizations(changed, base) {
				t.Fatal("membership change was treated as metadata")
			}
		})
	}
}
