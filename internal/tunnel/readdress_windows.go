//go:build windows

package tunnel

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/windows"
)

var errReaddressRollback = errors.New("pending address rollback failed")

type pendingAddressOps struct {
	add    func(uint64, net.IP) (windows.MibUnicastIpAddressRow, error)
	remove func(*windows.MibUnicastIpAddressRow) error
	listen func(net.IP) (*net.UDPConn, error)
}

// ReaddressPending changes only a provisional overlay address and its probe
// listener. It requires zero data peers and preserves the native UDP socket,
// control keys, WireGuard device and adapter. Failed rollback stops the tunnel.
func (t *Tunnel) ReaddressPending(ip net.IP) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	err := t.readdressPendingLocked(ip, pendingAddressOps{addOverlayAddress, removeOverlayAddress, listenOverlayEcho})
	if errors.Is(err, errReaddressRollback) {
		return errors.Join(err, ErrStopped, t.stopLocked())
	}
	return err
}

func listenOverlayEcho(ip net.IP) (*net.UDPConn, error) {
	var socket *net.UDPConn
	var err error
	for attempt := 0; attempt < 30; attempt++ {
		socket, err = net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: ProbePort})
		if err == nil || !errors.Is(err, windows.WSAEADDRNOTAVAIL) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return socket, err
}

func (t *Tunnel) readdressPendingLocked(ip net.IP, ops pendingAddressOps) error {
	if !t.running || !t.native || t.address == nil || t.policy == nil {
		return ErrNotStarted
	}
	if len(t.peers) != 0 {
		return errors.New("cannot change a provisional address after installing data peers")
	}
	next := ip.To4()
	if next == nil || !next.IsPrivate() || t.groupCIDR == nil || !t.groupCIDR.Contains(next) || unusableHost(next, t.groupCIDR) {
		return errors.New("assigned address must be a usable private IPv4 host in the existing overlay prefix")
	}
	if next.Equal(t.localIP) {
		return nil
	}
	row, err := ops.add(t.luid, next)
	if err != nil {
		return fmt.Errorf("add assigned overlay address: %w", err)
	}
	rollback := func(cause error) error {
		if cleanup := ops.remove(&row); cleanup != nil {
			return errors.Join(cause, errReaddressRollback, cleanup)
		}
		return cause
	}
	echo, err := ops.listen(next)
	if err != nil {
		return rollback(fmt.Errorf("bind assigned overlay probe: %w", err))
	}
	if err := ops.remove(t.address); err != nil {
		_ = echo.Close()
		return rollback(fmt.Errorf("remove provisional overlay address: %w", err))
	}
	oldEcho, oldDone := t.echo, t.echoDone
	t.localIP, t.address = append(net.IP(nil), next...), &row
	t.policy.mu.Lock()
	copy(t.policy.local[:], next)
	t.policy.mu.Unlock()
	t.echo, t.echoDone = echo, make(chan struct{})
	go serveEcho(echo, t.echoDone, func(ip net.IP) bool { _, ok := t.echoPeers.Load(ip.String()); return ok }, t.policy.recordEcho, t.policy.recordEchoReadError)
	if oldEcho != nil {
		_ = oldEcho.Close()
		if oldDone != nil {
			<-oldDone
		}
	}
	return nil
}
