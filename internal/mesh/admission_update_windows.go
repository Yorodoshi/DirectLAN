//go:build windows

package mesh

import (
	"bytes"
	"errors"
	"log"
	"slices"
	"strings"
	"time"
)

func sameMemberAuthorization(a, b Member) bool {
	return bytes.Equal(a.Identity, b.Identity) && bytes.Equal(a.WireGuard, b.WireGuard) && a.IP == b.IP
}

func rosterMembers(code Code) map[string]Member {
	result := make(map[string]Member, len(code.Members))
	for _, member := range code.Members {
		result[memberID(member)] = member
	}
	return result
}

func memberNeedsControl(code Code, self, member Member) bool {
	return bytes.Equal(self.Identity, code.Owner) || bytes.Equal(member.Identity, code.Owner)
}

// The caller has verified the owner's signature. Remove revoked authorization
// before adding replacements; leave unchanged peer objects and sessions intact.
// Addition-only failures restore the preceding roster. Once an old key has
// been revoked, a failure requires stopping instead of reauthorizing that key.
func installRosterUpdate(wg admissionTunnel, previous profile, oldRoster, next Code, self Member, save func() error) (err error) {
	oldSelf, oldOK := localMember(oldRoster, self.Identity)
	nextSelf, nextOK := localMember(next, self.Identity)
	if !oldOK || !nextOK || !sameMemberAuthorization(oldSelf, self) || !sameMemberAuthorization(nextSelf, self) ||
		oldRoster.Session != next.Session || oldRoster.Network != next.Network || !bytes.Equal(oldRoster.Owner, next.Owner) || oldRoster.Masked != next.Masked {
		return errors.New("изменение адреса или ключа этого ПК требует отдельной перенастройки")
	}
	old, current := rosterMembers(oldRoster), rosterMembers(next)
	candidate := previous
	candidate.Learned = cloneEndpoints(previous.Learned)
	var removed []Member
	var added []string
	defer func() {
		if err == nil || errors.Is(err, errAdmissionRollback) {
			return
		}
		var rollback error
		for i := len(added) - 1; i >= 0; i-- {
			rollback = errors.Join(rollback, wg.RemovePeer(added[i]))
		}
		if len(removed) > 0 || rollback != nil {
			err = errors.Join(err, errAdmissionRollback, rollback)
		}
	}()
	for _, member := range oldRoster.Members {
		id := memberID(member)
		if bytes.Equal(member.Identity, self.Identity) {
			continue
		}
		if newer, ok := current[id]; ok && sameMemberAuthorization(member, newer) {
			continue
		}
		delete(candidate.Learned, id)
		if remove := wg.RemovePeer(id); remove != nil {
			return errors.Join(remove, errAdmissionRollback)
		}
		removed = append(removed, member)
	}
	for _, member := range next.Members {
		id := memberID(member)
		if bytes.Equal(member.Identity, self.Identity) {
			continue
		}
		if known, ok := old[id]; ok && sameMemberAuthorization(known, member) {
			continue
		}
		delete(candidate.Learned, id)
		if err = wg.AddSecureDirectPeer(id, member.WireGuard, member.IP.AsSlice(), memberEndpoint(candidate, member)); err != nil {
			return err
		}
		added = append(added, id)
		if memberNeedsControl(next, self, member) {
			if err = wg.ConfigureControlPeer(id, member.WireGuard, memberEndpoint(candidate, member)); err != nil {
				return err
			}
		}
	}
	return save()
}

func (n *node) updateRosterWithoutRestart(p profile, next Code, self Member) error {
	public, err := n.keys.WireGuardPublic()
	if err != nil || !bytes.Equal(public, self.WireGuard) {
		return errors.New("ключ этого ПК не совпадает с допуском в сеть")
	}
	previous := n.p
	previous.Learned, p.Learned = cloneEndpoints(previous.Learned), cloneEndpoints(p.Learned)
	old, current := rosterMembers(n.roster), rosterMembers(next)
	for id, member := range old {
		newer, ok := current[id]
		if !ok || !sameMemberAuthorization(member, newer) {
			delete(p.Learned, id)
			continue
		}
		if source := n.authenticatedSource(id, time.Now()); source.fresh(time.Now()) {
			previous.Learned[id], p.Learned[id] = source.endpoint, source.endpoint
		} else if !slices.Equal(member.Endpoints, newer.Endpoints) {
			delete(p.Learned, id)
		}
	}
	for id, member := range current {
		if known, ok := old[id]; !ok || !sameMemberAuthorization(known, member) {
			delete(p.Learned, id)
		}
	}
	err = installRosterUpdate(n.wg, previous, n.roster, next, self, func() error { return n.save(p) })
	if err != nil {
		if errors.Is(err, errAdmissionRollback) {
			_ = n.wg.Stop()
			n.wg = nil
			n.detail = "Туннель остановлен. Устраните ошибку и повторите обновление состава сети."
		}
		return err
	}
	for id, member := range old {
		newer, ok := current[id]
		if ok && sameMemberAuthorization(member, newer) {
			continue
		}
		delete(n.members, id)
		delete(n.confirmed, id)
		delete(n.controlSources, id)
		delete(n.wireGuardSources, id)
		delete(n.controlGuests, id)
		for key := range n.lastTransfer {
			if key == id || strings.HasPrefix(key, id+"/") {
				delete(n.lastTransfer, key)
			}
		}
	}
	// Refresh endpoint metadata on preserved peers without reinstalling keys.
	for id, member := range current {
		known, ok := old[id]
		if !ok || !sameMemberAuthorization(known, member) || slices.Equal(known.Endpoints, member.Endpoints) || bytes.Equal(member.Identity, self.Identity) {
			continue
		}
		endpoint := memberEndpoint(p, member)
		if endpoint.IsValid() {
			if err := n.wg.SetDirectEndpoint(id, endpoint); err != nil {
				n.logControlError(id, "roster_endpoint", err)
			}
			if memberNeedsControl(next, self, member) {
				if err := n.wg.ConfigureControlPeer(id, member.WireGuard, endpoint); err != nil {
					n.logControlError(id, "roster_control", err)
				}
			}
		}
	}
	n.p, n.roster = p, next
	if n.members == nil {
		n.members = make(map[string]memberStatus)
	}
	n.requestCheck()
	log.Printf("mesh event=roster_membership_updated revision=%d members=%d adapter_preserved=true", next.Revision, len(next.Members))
	return nil
}
