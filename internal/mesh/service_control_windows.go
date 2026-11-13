//go:build windows

package mesh

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"directlan/internal/directpair"
	"directlan/internal/tunnel"
)

func shortID(id string) string { return id[:min(8, len(id))] }

func (n *node) resetControl(challenge [16]byte, secret [32]byte) {
	n.challenge, n.cookieSecret, n.ownerCookie = challenge, secret, [16]byte{}
	n.controlAttempts, n.lastOwnerControl, n.controlOwnerEndpoint = 0, time.Time{}, netip.AddrPort{}
	n.confirmed, n.lastTransfer = make(map[string]uint64), make(map[string]time.Time)
	n.controlSources = make(map[string]authenticatedEndpoint)
	n.wireGuardSources = make(map[string]authenticatedEndpoint)
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
				if !n.authenticatedSource(memberID(next), time.Now()).fresh(time.Now()) {
					delete(p.Learned, memberID(next))
				}
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
		if source := n.authenticatedSource(memberID(m), time.Now()); source.fresh(time.Now()) {
			ep = source.endpoint
		}
		if ep.IsValid() {
			if err := n.wg.SetDirectEndpoint(memberID(m), ep); err != nil {
				n.logControlError(memberID(m), "metadata_endpoint", err)
			}
			if n.owner() || bytes.Equal(m.Identity, code.Owner) {
				if err := n.wg.ConfigureControlPeer(memberID(m), m.WireGuard, ep); err != nil {
					n.logControlError(memberID(m), "metadata_control", err)
				}
			}
		}
	}
	n.requestCheck()
	log.Printf("mesh event=roster_updated revision=%d members=%d adapter_preserved=true", code.Revision, len(code.Members))
	return nil
}

func (n *node) sendHello() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.wg == nil || n.p.Paused || n.owner() || len(n.roster.Members) == 0 {
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
	if !ep.IsValid() {
		return
	}
	operation := "hello_configure"
	err := wg.ConfigureControlPeer(memberID(owner), owner.WireGuard, ep)
	if err == nil {
		operation = "hello_send"
		err = wg.SendControl(memberID(owner), payload)
	}
	if err != nil {
		if n.wg == wg {
			n.logControlError(memberID(owner), operation, err)
		}
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
				n.mu.Lock()
				if n.wg == wg {
					n.logControlError(message.PeerID, "reply_send", err)
				}
				n.mu.Unlock()
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
		n.rememberControlEndpoint(message.PeerID, message.Endpoint, time.Now())
		if !n.p.Pending && changed {
			if err := n.wg.SetDirectEndpoint(message.PeerID, message.Endpoint); err != nil {
				n.logControlError(message.PeerID, "owner_endpoint", err)
			}
			n.learnControlEndpoint(message.PeerID, message.Endpoint)
		}
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
		if err := n.wg.ConfigureControlPeer(memberID(owner), owner.WireGuard, message.Endpoint); err != nil {
			n.logControlError(memberID(owner), "roster_control", err)
		}
		if !n.p.Pending {
			if err := n.wg.SetDirectEndpoint(memberID(owner), message.Endpoint); err != nil {
				n.logControlError(memberID(owner), "roster_endpoint", err)
			}
			n.learnControlEndpoint(memberID(owner), message.Endpoint)
		}
	}
	log.Printf("mesh event=admission_received revision=%d pending=%t", n.roster.Revision, n.p.Pending)
	n.mu.Unlock()
	n.sendHello()
}

func (n *node) learnControlEndpoint(id string, endpoint netip.AddrPort) {
	n.rememberControlEndpoint(id, endpoint, time.Now())
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

func (n *node) rememberControlEndpoint(id string, endpoint netip.AddrPort, now time.Time) {
	if !directpair.PublicEndpoint(endpoint) {
		return
	}
	if n.controlSources == nil {
		n.controlSources = make(map[string]authenticatedEndpoint)
	}
	n.controlSources[id] = authenticatedEndpoint{endpoint: endpoint, observed: now}
}

// Called under n.mu. A fresh authenticated control source is stronger evidence
// than a failed overlay probe, which may be blocked separately by the host.
func (n *node) rotatePeerEndpoint(wg *tunnel.Tunnel, m Member, misses int) {
	if wg == nil || n.wg != wg {
		return
	}
	id := memberID(m)
	ep, rotate := peerEndpointCandidate(n.authenticatedSource(id, time.Now()), n.p.Learned[id], m.Endpoints, misses, time.Now())
	if !rotate {
		return
	}
	if err := wg.SetDirectEndpoint(id, ep); err != nil {
		n.logControlError(id, "rotate_endpoint", err)
		return
	}
	if misses == 3 || misses%12 == 0 {
		log.Printf("mesh event=endpoint_candidate_rotated misses=%d", misses)
	}
}

// Raw network errors can contain public addresses. Keep logs bounded and emit
// only the operation, error category and numeric OS status.
func (n *node) logControlError(id, operation string, err error) {
	if err == nil {
		return
	}
	if n.lastTransfer == nil {
		n.lastTransfer = make(map[string]time.Time)
	}
	key, now := id+"/error/"+operation, time.Now()
	if previous := n.lastTransfer[key]; !previous.IsZero() && now.Sub(previous) < 30*time.Second {
		return
	}
	n.lastTransfer[key] = now
	reason := "transport_error"
	var status syscall.Errno
	var network net.Error
	switch {
	case errors.Is(err, tunnel.ErrNotStarted), errors.Is(err, tunnel.ErrStopped):
		reason = "tunnel_stopped"
	case errors.Is(err, tunnel.ErrUnknownPeer):
		reason = "unknown_peer"
	case errors.As(err, &network) && network.Timeout():
		reason = "timeout"
	case errors.As(err, &status):
		reason = "os_error"
	}
	log.Printf("mesh event=control_failed operation=%s reason=%s os_code=%d", operation, reason, uint64(status))
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
			n.logControlError(message.PeerID, "challenge_configure", err)
			return nil
		}
		packet := append(append([]byte(nil), nonce[:]...), expected[:]...)
		return [][]byte{append(packet, controlCookieKind)}
	}
	if revision > n.roster.Revision {
		return nil
	}
	if err := n.wg.ConfigureControlPeer(message.PeerID, guest.WireGuard, message.Endpoint); err != nil {
		n.logControlError(message.PeerID, "ack_configure", err)
		return nil
	}
	if err := n.wg.SetDirectEndpoint(message.PeerID, message.Endpoint); err != nil {
		n.logControlError(message.PeerID, "ack_endpoint", err)
	}
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
