package mesh

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"net/netip"
	"time"
)

const authenticatedEndpointTTL = 45 * time.Second

type authenticatedEndpoint struct {
	endpoint netip.AddrPort
	observed time.Time
}

func (source authenticatedEndpoint) fresh(now time.Time) bool {
	return source.endpoint.IsValid() && !source.observed.IsZero() && !now.Before(source.observed) && now.Sub(source.observed) < authenticatedEndpointTTL
}

// A failed application probe does not invalidate a recently authenticated UDP
// path. Once that evidence expires, try learned and signed addresses in order.
func peerEndpointCandidate(source authenticatedEndpoint, learned netip.AddrPort, signed []netip.AddrPort, misses int, now time.Time) (netip.AddrPort, bool) {
	if misses < 3 || source.fresh(now) {
		return netip.AddrPort{}, false
	}
	candidates := controlCandidates(learned, signed)
	if len(candidates) == 0 {
		return netip.AddrPort{}, false
	}
	return candidates[(misses-3)%len(candidates)], true
}

func sameAuthorizations(a, b Code) bool {
	if len(a.Members) != len(b.Members) {
		return false
	}
	for _, next := range b.Members {
		found := false
		for _, old := range a.Members {
			if bytes.Equal(old.Identity, next.Identity) {
				if !bytes.Equal(old.WireGuard, next.WireGuard) || old.IP != next.IP {
					return false
				}
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func controlCandidates(learned netip.AddrPort, signed []netip.AddrPort) []netip.AddrPort {
	var result []netip.AddrPort
	if learned.IsValid() {
		result = append(result, learned)
	}
	for _, endpoint := range signed {
		found := false
		for _, existing := range result {
			if endpoint == existing {
				found = true
				break
			}
		}
		if !found && endpoint.IsValid() {
			result = append(result, endpoint)
		}
	}
	return result
}

const controlCookieKind = 3

// The source-bound cookie proves the encrypted hello's UDP return path before
// sending a fragmented roster. Both secrets rotate whenever the tunnel opens.
func admissionCookie(secret [32]byte, peer string, source netip.AddrPort, nonce [16]byte) [16]byte {
	h := hmac.New(sha256.New, secret[:])
	h.Write([]byte("DirectLAN admission return path v1\x00"))
	h.Write([]byte(peer))
	h.Write([]byte{0})
	h.Write([]byte(source.String()))
	h.Write([]byte{0})
	h.Write(nonce[:])
	return [16]byte(h.Sum(nil)[:16])
}

func admissionHello(nonce, cookie [16]byte, revision uint64) []byte {
	packet := make([]byte, 0, 41)
	packet = append(packet, nonce[:]...)
	packet = append(packet, cookie[:]...)
	return append(packet, encodeControlHello(revision)...)
}

func parseAdmissionHello(packet []byte) (nonce, cookie [16]byte, revision uint64, ok bool) {
	if len(packet) != 41 {
		return
	}
	copy(nonce[:], packet[:16])
	copy(cookie[:], packet[16:32])
	revision, ok = parseControlHello(packet[32:])
	return
}
