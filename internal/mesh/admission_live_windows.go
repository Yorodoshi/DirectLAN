//go:build windows

package mesh

import (
	"bytes"
	"errors"
	"log"
	"net"
	"net/netip"
	"time"
)

var errAdmissionRollback = errors.New("admission rollback failed")

type admissionTunnel interface {
	AddSecureDirectPeer(string, []byte, net.IP, netip.AddrPort) error
	ConfigureControlPeer(string, []byte, netip.AddrPort) error
	RemovePeer(string) error
}

// The provisional guest has no data peers. Add only the owner-signed peers,
// preserving the UDP socket, NAT mapping, Wintun address and control challenge.
// On a failure restore that isolated provisional state before returning.
func installAdmission(wg admissionTunnel, previous profile, oldRoster, next Code, self Member, save func() error) (err error) {
	var added []string
	defer func() {
		if err == nil {
			return
		}
		var rollback error
		for i := len(added) - 1; i >= 0; i-- {
			rollback = errors.Join(rollback, wg.RemovePeer(added[i]))
		}
		owner := oldRoster.Members[0]
		rollback = errors.Join(rollback, wg.ConfigureControlPeer(memberID(owner), owner.WireGuard, memberEndpoint(previous, owner)))
		if rollback != nil {
			err = errors.Join(err, errAdmissionRollback, rollback)
		}
	}()
	for _, member := range next.Members {
		if bytes.Equal(member.Identity, self.Identity) {
			continue
		}
		if err = wg.AddSecureDirectPeer(memberID(member), member.WireGuard, member.IP.AsSlice(), memberEndpoint(previous, member)); err != nil {
			return err
		}
		added = append(added, memberID(member))
	}
	owner := next.Members[0]
	if err = wg.ConfigureControlPeer(memberID(owner), owner.WireGuard, memberEndpoint(previous, owner)); err != nil {
		return err
	}
	return save()
}

func (n *node) admitWithoutRestart(p profile, code Code, self Member) error {
	public, err := n.keys.WireGuardPublic()
	if err != nil {
		return err
	}
	if !bytes.Equal(public, self.WireGuard) {
		return errors.New("ключ этого ПК не совпадает с допуском в сеть")
	}
	previous := n.p
	ownerID := memberID(code.Members[0])
	if source := n.controlSources[ownerID]; source.fresh(time.Now()) {
		previous.Learned = cloneEndpoints(previous.Learned)
		previous.Learned[ownerID] = source.endpoint
		p.Learned = cloneEndpoints(p.Learned)
		p.Learned[ownerID] = source.endpoint
	}
	err = installAdmission(n.wg, previous, n.roster, code, self, func() error { return n.save(p) })
	if err != nil {
		if errors.Is(err, errAdmissionRollback) {
			_ = n.wg.Stop()
			n.wg = nil
			n.detail = "Не удалось восстановить изолированное ожидание допуска. Перезапустите сеть."
		}
		return err
	}
	n.p, n.roster = p, code
	if n.members == nil {
		n.members = make(map[string]memberStatus)
	}
	n.requestCheck()
	log.Printf("mesh event=owner_roster_applied revision=%d members=%d adapter_preserved=true local_udp_port=%d", code.Revision, len(code.Members), p.Port)
	return nil
}
