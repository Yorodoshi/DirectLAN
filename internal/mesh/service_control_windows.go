//go:build windows

package mesh

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"log"
	"net/netip"
	"slices"
	"time"

	"directlan/internal/directpair"
	"directlan/internal/tunnel"
)

func shortID(id string) string { return id[:min(8, len(id))] }

func (n *node) resetControl(challenge [16]byte, secret [32]byte) {
	n.challenge, n.cookieSecret, n.ownerCookie = challenge, secret, [16]byte{}
	n.controlAttempts, n.lastOwnerControl, n.controlOwnerEndpoint = 0, time.Time{}, netip.AddrPort{}
	n.confirmed, n.lastTransfer = make(map[string]uint64), make(map[string]time.Time)
	n.assembly.reset()
}

// Called under n.mu. Only the owner can refresh the signed roster. Updating
// endpoint metadata does not change installed peer keys or virtual routes.
func (n *node) refreshControlRoster() error {
	if !n.owner() {
		return nil
	}
	code := n.roster
	changed := n.scanned && !slices.Equal(code.Members[0].Endpoints, n.endpoints)
	if !changed && time.Until(code.Expires) > 5*time.Minute {
		return nil
	}
	code.Members = append([]Member(nil), code.Members...)
	if n.scanned {
		code.Members[0].Endpoints = append([]netip.AddrPort(nil), n.endpoints...)
	}
	code.Revision++
	code, text, err := n.sign(code)
	if err != nil {
		return err
	}
	p := n.p
	p.Code = text
	if err = n.save(p); err != nil {
		return err
	}
	n.p, n.roster = p, code
	log.Printf("mesh event=roster_refreshed revision=%d members=%d", code.Revision, len(code.Members))
	return nil
}

// A new expiry, name or endpoint is not a new data-plane authorization. Keep
// existing WireGuard sessions and the adapter alive when only metadata changes.
func (n *node) updateRosterMetadata(p profile, code Code) error {
	var changed []Member
	for _, next := range code.Members {
		for _, old := range n.roster.Members {
			if bytes.Equal(old.Identity, next.Identity) && !slices.Equal(old.Endpoints, next.Endpoints) {
				delete(p.Learned, memberID(next))
				changed = append(changed, next)
				break
			}
		}
	}
	if err := n.save(p); err != nil {
		return err
	}
	n.p, n.roster = p, code
	for _, m := range changed {
		if bytes.Equal(m.Identity, n.keys.IdentityPublic()) {
			continue
		}
		ep := memberEndpoint(p, m)
		if ep.IsValid() {
			_ = n.wg.SetDirectEndpoint(memberID(m), ep)
			if bytes.Equal(m.Identity, code.Owner) {
				_ = n.wg.ConfigureControlPeer(memberID(m), m.WireGuard, ep)
			}
		}
	}
	n.requestCheck()
	log.Printf("mesh event=roster_updated revision=%d members=%d adapter_preserved=true", code.Revision, len(code.Members))
	return nil
}

func (n *node) sendHello() {
	n.mu.Lock()
	if n.wg == nil || n.p.Paused || n.owner() || len(n.roster.Members) == 0 {
		n.mu.Unlock()
		return
	}
	wg, owner := n.wg, n.roster.Members[0]
	now := time.Now()
	if !n.lastOwnerControl.IsZero() && now.Sub(n.lastOwnerControl) > 15*time.Second {
		n.controlOwnerEndpoint, n.ownerCookie = netip.AddrPort{}, [16]byte{}
	}
	ep := n.controlOwnerEndpoint
	if !ep.IsValid() {
		candidates := controlCandidates(n.p.Learned[memberID(owner)], owner.Endpoints)
		if len(candidates) > 0 {
			ep = candidates[(n.controlAttempts/2)%len(candidates)]
		}
	}
	n.controlAttempts++
	revision := n.roster.Revision
	if n.p.Pending {
		revision = 0
	}
	payload := admissionHello(n.challenge, n.ownerCookie, revision)
	if n.controlAttempts == 1 || n.controlAttempts%12 == 0 {
		log.Printf("mesh event=admission_hello attempt=%d pending=%t endpoint_available=%t", n.controlAttempts, n.p.Pending, ep.IsValid())
	}
	n.mu.Unlock()
	if !ep.IsValid() {
		return
	}
	if err := wg.ConfigureControlPeer(memberID(owner), owner.WireGuard, ep); err == nil {
		_ = wg.SendControl(memberID(owner), payload)
	}
}

func (n *node) handleControl(wg *tunnel.Tunnel, message tunnel.ControlMessage) {
	n.mu.Lock()
	if wg == nil || n.wg != wg || n.p.Paused || !directpair.PublicEndpoint(message.Endpoint) {
		n.mu.Unlock()
		return
	}
	if n.owner() {
		packets := n.ownerControl(message)
		n.mu.Unlock()
		for _, packet := range packets {
			if err := wg.SendControl(message.PeerID, packet); err != nil {
				break
			}
		}
		return
	}
	if message.PeerID != hex.EncodeToString(n.roster.Owner) || len(message.Payload) < 17 || !hmac.Equal(message.Payload[:16], n.challenge[:]) {
		n.mu.Unlock()
		return
	}
	body := message.Payload[16:]
	if len(body) == 17 && body[16] == controlCookieKind {
		changed := !hmac.Equal(n.ownerCookie[:], body[:16]) || n.controlOwnerEndpoint != message.Endpoint
		copy(n.ownerCookie[:], body[:16])
		n.lastOwnerControl, n.controlOwnerEndpoint = time.Now(), message.Endpoint
		if changed {
			log.Printf("mesh event=admission_challenge_received pending=%t", n.p.Pending)
		}
		n.mu.Unlock()
		if changed {
			n.sendHello()
		}
		return
	}
	text, revision, err := n.assembly.add(body, time.Now())
	if err != nil || text == "" {
		n.mu.Unlock()
		return
	}
	if err = n.applyControlRoster(text, revision); err != nil {
		log.Printf("mesh event=admission_rejected revision=%d error=%q", revision, err.Error())
		n.mu.Unlock()
		return
	}
	owner := n.roster.Members[0]
	n.lastOwnerControl, n.controlOwnerEndpoint = time.Now(), message.Endpoint
	if n.wg != nil {
		_ = n.wg.ConfigureControlPeer(memberID(owner), owner.WireGuard, message.Endpoint)
		if !n.p.Pending {
			_ = n.wg.SetDirectEndpoint(memberID(owner), message.Endpoint)
			n.learnControlEndpoint(memberID(owner), message.Endpoint)
		}
	}
	log.Printf("mesh event=admission_received revision=%d pending=%t", n.roster.Revision, n.p.Pending)
	n.mu.Unlock()
	n.sendHello()
}

func (n *node) learnControlEndpoint(id string, endpoint netip.AddrPort) {
	if n.p.Learned[id] == endpoint {
		return
	}
	p := n.p
	p.Learned = cloneEndpoints(p.Learned)
	p.Learned[id] = endpoint
	if err := n.save(p); err != nil {
		log.Printf("mesh event=endpoint_save_failed peer=%s", shortID(id))
		return
	}
	n.p = p
}

func (n *node) applyControlRoster(text string, revision uint64) error {
	code, err := Decode(text, time.Now())
	if err != nil {
		return err
	}
	if code.Kind != "network" || code.Revision != revision ||
		code.Session != n.roster.Session || code.Network != n.roster.Network ||
		!bytes.Equal(code.Owner, n.roster.Owner) || code.Masked != n.roster.Masked {
		return errors.New("получен недопустимый состав сети")
	}
	return n.accept(text, code)
}

// Called under n.mu. A valid owner signature remains mandatory at the guest;
// this cookie only limits reflection and establishes the current return path.
func (n *node) ownerControl(message tunnel.ControlMessage) [][]byte {
	nonce, cookie, revision, ok := parseAdmissionHello(message.Payload)
	if !ok {
		return nil
	}
	var guest Member
	for _, member := range n.roster.Members {
		if memberID(member) == message.PeerID && !bytes.Equal(member.Identity, n.roster.Owner) {
			guest = member
			break
		}
	}
	if guest.Identity == nil {
		return nil
	}
	now := time.Now()
	expected := admissionCookie(n.cookieSecret, message.PeerID, message.Endpoint, nonce)
	if !hmac.Equal(cookie[:], expected[:]) {
		key := message.PeerID + "/challenge"
		if now.Sub(n.lastTransfer[key]) < time.Second {
			return nil
		}
		if n.lastTransfer[key].IsZero() {
			log.Printf("mesh event=admission_challenge_sent peer=%s", shortID(message.PeerID))
		}
		n.lastTransfer[key] = now
		if err := n.wg.ConfigureControlPeer(message.PeerID, guest.WireGuard, message.Endpoint); err != nil {
			return nil
		}
		packet := append(append([]byte(nil), nonce[:]...), expected[:]...)
		return [][]byte{append(packet, controlCookieKind)}
	}
	if revision > n.roster.Revision {
		return nil
	}
	if err := n.wg.ConfigureControlPeer(message.PeerID, guest.WireGuard, message.Endpoint); err != nil {
		return nil
	}
	_ = n.wg.SetDirectEndpoint(message.PeerID, message.Endpoint)
	n.learnControlEndpoint(message.PeerID, message.Endpoint)
	previous := n.confirmed[message.PeerID]
	n.confirmed[message.PeerID] = revision
	if revision > previous {
		log.Printf("mesh event=admission_ack peer=%s revision=%d", shortID(message.PeerID), revision)
	}
	if err := n.refreshControlRoster(); err != nil {
		log.Printf("mesh event=roster_refresh_failed")
		return nil
	}
	if revision == n.roster.Revision {
		// A small authenticated response keeps the guest on the observed owner
		// address and confirms liveness without repeatedly transferring the roster.
		packet := append(append([]byte(nil), nonce[:]...), expected[:]...)
		return [][]byte{append(packet, controlCookieKind)}
	}
	if now.Sub(n.lastTransfer[message.PeerID]) < 2*time.Second {
		return nil
	}
	parts, err := rosterPackets(n.p.Code, n.roster.Revision)
	if err != nil {
		return nil
	}
	n.lastTransfer[message.PeerID] = now
	for i := range parts {
		parts[i] = append(append([]byte(nil), nonce[:]...), parts[i]...)
	}
	log.Printf("mesh event=admission_sent peer=%s revision=%d fragments=%d", shortID(message.PeerID), n.roster.Revision, len(parts))
	return parts
}
