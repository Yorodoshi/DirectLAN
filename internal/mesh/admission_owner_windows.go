//go:build windows

package mesh

import (
	"errors"
	"log"
)

// Existing members, the listener and return-path secrets remain intact while
// the owner installs one newly approved peer. Commit only after saving its
// signed authorization; an unsuccessful install revokes only that new peer.
func installOwnerMember(wg admissionTunnel, previous profile, member Member, save func() error) (err error) {
	id := memberID(member)
	if err = wg.AddSecureDirectPeer(id, member.WireGuard, member.IP.AsSlice(), memberEndpoint(previous, member)); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if rollback := wg.RemovePeer(id); rollback != nil {
				err = errors.Join(err, errAdmissionRollback, rollback)
			}
		}
	}()
	if err = wg.ConfigureControlPeer(id, member.WireGuard, memberEndpoint(previous, member)); err != nil {
		return err
	}
	return save()
}

// Called under n.mu after the new roster has been signed by this owner.
func (n *node) addOwnerMemberLive(p profile, next Code, member Member) error {
	err := installOwnerMember(n.wg, p, member, func() error { return n.save(p) })
	if err != nil {
		if errors.Is(err, errAdmissionRollback) {
			_ = n.wg.Stop()
			n.wg = nil
			n.detail = "Не удалось отменить добавление участника. Перезапустите сеть."
		}
		return err
	}
	n.p, n.roster = p, next
	if n.members == nil {
		n.members = make(map[string]memberStatus)
	}
	n.requestCheck()
	log.Printf("mesh event=member_installed revision=%d members=%d adapter_preserved=true", next.Revision, len(next.Members))
	return nil
}
