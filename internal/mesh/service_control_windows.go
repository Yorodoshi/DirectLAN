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

// A recipient nonce is usable for pushes only after its source-bound cookie
// proved this return path. Entries never outlive their signed member/key.
type controlGuest struct {
	nonce     [16]byte
	public    [32]byte
	endpoint  netip.AddrPort
	validated time.Time
	revision  uint64
}

func (guest controlGuest) fresh(now time.Time) bool {
	return directpair.PublicEndpoint(guest.endpoint) && !guest.validated.IsZero() &&
		!now.Before(guest.validated) && now.Sub(guest.validated) < authenticatedEndpointTTL
}

func (n *node) resetControl(challenge [16]byte, secret [32]byte) {
	n.challenge, n.cookieSecret, n.ownerCookie = challenge, secret, [16]byte{}
	n.controlAttempts, n.lastOwnerControl, n.controlOwnerEndpoint = 0, time.Time{}, netip.AddrPort{}
	n.lastControlHello = time.Time{}
	n.confirmed, n.lastTransfer = make(map[string]uint64), make(map[string]time.Time)
	n.controlGuests = make(map[string]controlGuest)
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

func (n *node) sendHello() { n.sendHelloAt(time.Now(), false) }

func (n *node) sendHelloNow() { n.sendHelloAt(time.Now(), true) }

func (n *node) sendHelloAt(now time.Time, immediate bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.wg == nil || n.p.Paused || n.owner() || len(n.roster.Members) == 0 {
		return
	}
	if !immediate && !n.lastControlHello.IsZero() && !now.Before(n.lastControlHello) && now.Sub(n.lastControlHello) < 5*time.Second {
		return
	}
	n.lastControlHello = now
	wg, owner := n.wg, n.roster.Members[0]
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

func (n *node) handleControl(wg meshTunnel, message tunnel.ControlMessage) {
	n.mu.Lock()
	if wg == nil || n.wg != wg || n.p.Paused || !directpair.PublicEndpoint(message.Endpoint) {
		n.mu.Unlock()
		return
	}
	if n.owner() {
		packets := n.ownerControl(message)
		n.sendControlPackets(wg, message.PeerID, packets)
		n.mu.Unlock()
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
			n.sendHelloNow()
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
	n.sendHelloNow()
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
func (n *node) rotatePeerEndpoint(wg meshTunnel, m Member, misses int) {
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

// Called under n.mu. Only the owner may publish this extra candidate. An
// endpoint observed by the owner may be destination-dependent under NAT; keep
// the member's other signed candidates rather than calling it a global route.
func (n *node) publishGuestEndpoint(id string, endpoint, previous netip.AddrPort) error {
	if !n.owner() || !directpair.PublicEndpoint(endpoint) {
		return nil
	}
	code := n.roster
	for index, member := range code.Members {
		if index == 0 || memberID(member) != id {
			continue
		}
		if slices.Contains(member.Endpoints, endpoint) {
			return nil
		}
		candidates := []netip.AddrPort{endpoint}
		for _, candidate := range member.Endpoints {
			// Replace a known superseded observation first when all four
			// slots are occupied; otherwise retain useful alternate routes.
			if len(member.Endpoints) >= 4 && candidate == previous {
				continue
			}
			if len(candidates) < 4 {
				candidates = append(candidates, candidate)
			}
		}
		code.Members = append([]Member(nil), code.Members...)
		code.Members[index].Endpoints = candidates
		code.Revision++
		code, text, err := n.sign(code)
		if err != nil {
			return err
		}
		p := n.p
		p.Code = text
		if err := n.save(p); err != nil {
			return err
		}
		n.p, n.roster = p, code
		n.requestCheck()
		log.Printf("mesh event=peer_endpoint_published peer=%s revision=%d candidates=%d", shortID(id), code.Revision, len(candidates))
		return nil
	}
	return nil
}

// mesh.sync calls this while holding n.mu. A manual retry does not reset the
// tunnel, source-bound cookies, or the admission request a guest already sent.
func (n *node) syncControlRoster() error {
	if n.wg == nil || n.p.Paused {
		return tunnel.ErrNotStarted
	}
	if n.owner() {
		if err := n.refreshControlRoster(); err != nil {
			return err
		}
		for id, guest := range n.controlGuests {
			guest.revision = 0
			n.controlGuests[id] = guest
			delete(n.lastTransfer, id)
		}
	}
	n.lastControlHello = time.Time{}
	n.controlAttempts = 0
	n.requestCheck()
	return nil
}

func (n *node) driveOwnerControl() { n.driveOwnerControlAt(time.Now()) }

// Exposed to the package's deterministic service harness: retries use this
// supplied time, without sleeps or changes to the host's network.
func (n *node) driveOwnerControlAt(now time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.wg == nil || n.p.Paused || !n.owner() {
		return
	}
	if err := n.refreshControlRoster(); err != nil {
		log.Printf("mesh event=roster_refresh_failed")
		return
	}
	for id, guest := range n.controlGuests {
		valid := false
		for _, member := range n.roster.Members[1:] {
			if memberID(member) == id && bytes.Equal(member.WireGuard, guest.public[:]) {
				valid = true
				break
			}
		}
		if !valid {
			delete(n.controlGuests, id)
		}
	}
	for _, member := range n.roster.Members[1:] {
		id := memberID(member)
		guest, ok := n.controlGuests[id]
		if !ok || guest.revision >= n.roster.Revision {
			continue
		}
		n.sendControlPackets(n.wg, id, n.ownerRosterPackets(id, guest, now))
	}
}

// Called under n.mu. Configure+send stay serialized so a small challenge to an
// unproven source cannot redirect a simultaneous large roster transfer.
func (n *node) sendControlPackets(wg meshTunnel, id string, packets [][]byte) {
	for _, packet := range packets {
		if err := wg.SendControl(id, packet); err != nil {
			if n.wg == wg {
				n.logControlError(id, "reply_send", err)
			}
			return
		}
	}
}

func (n *node) ownerRosterPackets(id string, guest controlGuest, now time.Time) [][]byte {
	if !guest.fresh(now) || guest.revision >= n.roster.Revision {
		return nil
	}
	if n.lastTransfer == nil {
		n.lastTransfer = make(map[string]time.Time)
	}
	if previous := n.lastTransfer[id]; !previous.IsZero() && !now.Before(previous) && now.Sub(previous) < 2*time.Second {
		return nil
	}
	parts, err := rosterPackets(n.p.Code, n.roster.Revision)
	if err != nil {
		return nil
	}
	// Always restore the proven address: a later hello with an invalid cookie
	// may have used another source for its small challenge response.
	if err := n.wg.ConfigureControlPeer(id, guest.public[:], guest.endpoint); err != nil {
		n.logControlError(id, "push_configure", err)
		return nil
	}
	n.lastTransfer[id] = now
	for i := range parts {
		parts[i] = append(append([]byte(nil), guest.nonce[:]...), parts[i]...)
	}
	log.Printf("mesh event=admission_sent peer=%s revision=%d fragments=%d push=true", shortID(id), n.roster.Revision, len(parts))
	return parts
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
	if n.lastTransfer == nil {
		n.lastTransfer = make(map[string]time.Time)
	}
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
	if n.controlGuests == nil {
		n.controlGuests = make(map[string]controlGuest)
	}
	previousSource := n.controlGuests[message.PeerID].endpoint
	validated := controlGuest{nonce: nonce, endpoint: message.Endpoint, validated: now, revision: revision}
	copy(validated.public[:], guest.WireGuard)
	n.controlGuests[message.PeerID] = validated
	if err := n.wg.ConfigureControlPeer(message.PeerID, guest.WireGuard, message.Endpoint); err != nil {
		n.logControlError(message.PeerID, "ack_configure", err)
		return nil
	}
	if err := n.wg.SetDirectEndpoint(message.PeerID, message.Endpoint); err != nil {
		n.logControlError(message.PeerID, "ack_endpoint", err)
	}
	n.learnControlEndpoint(message.PeerID, message.Endpoint)
	if n.confirmed == nil {
		n.confirmed = make(map[string]uint64)
	}
	previous := n.confirmed[message.PeerID]
	n.confirmed[message.PeerID] = revision
	if revision > previous {
		log.Printf("mesh event=admission_ack peer=%s revision=%d", shortID(message.PeerID), revision)
	}
	if err := n.refreshControlRoster(); err != nil {
		log.Printf("mesh event=roster_refresh_failed")
		return nil
	}
	if err := n.publishGuestEndpoint(message.PeerID, message.Endpoint, previousSource); err != nil {
		log.Printf("mesh event=peer_endpoint_publish_failed peer=%s", shortID(message.PeerID))
	}
	if revision == n.roster.Revision {
		// A small authenticated response keeps the guest on the observed owner
		// address and confirms liveness without repeatedly transferring the roster.
		packet := append(append([]byte(nil), nonce[:]...), expected[:]...)
		return [][]byte{append(packet, controlCookieKind)}
	}
	return n.ownerRosterPackets(message.PeerID, validated, now)
}
