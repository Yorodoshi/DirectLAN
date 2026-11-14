//go:build windows

package tunnel

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

func readdressFixture(t *testing.T) (*Tunnel, pendingAddressOps, *int, *int) {
	t.Helper()
	oldIP := net.IPv4(10, 213, 47, 2).To4()
	_, prefix, _ := net.ParseCIDR("10.213.47.0/24")
	node := &Tunnel{running: true, native: true, localIP: oldIP, groupCIDR: prefix, policy: newPolicy(oldIP),
		address: &windows.MibUnicastIpAddressRow{}, direct: &stunBind{}, control: newControlTransport(), port: 54321, peers: make(map[string]*peer)}
	listen := func(net.IP) (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	var err error
	node.echo, err = listen(oldIP)
	if err != nil {
		t.Fatal(err)
	}
	node.echoDone = make(chan struct{})
	go serveEcho(node.echo, node.echoDone, func(net.IP) bool { return false }, node.policy.recordEcho, node.policy.recordEchoReadError)
	t.Cleanup(func() {
		if node.echo != nil {
			_ = node.echo.Close()
			<-node.echoDone
		}
	})
	adds, removes := new(int), new(int)
	ops := pendingAddressOps{
		add: func(uint64, net.IP) (windows.MibUnicastIpAddressRow, error) {
			*adds++
			return windows.MibUnicastIpAddressRow{}, nil
		},
		remove: func(*windows.MibUnicastIpAddressRow) error { *removes++; return nil }, listen: listen}
	return node, ops, adds, removes
}

func TestPendingReaddressPreservesSocketControlAndAdapterIdentity(t *testing.T) {
	node, ops, adds, removes := readdressFixture(t)
	bind, control, policy, oldEcho, oldDone := node.direct, node.control, node.policy, node.echo, node.echoDone
	next := net.IPv4(10, 213, 47, 4).To4()
	if err := node.readdressPendingLocked(next, ops); err != nil {
		t.Fatal(err)
	}
	if !node.localIP.Equal(next) || node.policy.local != [4]byte(next) || node.direct != bind || node.control != control || node.policy != policy || node.port != 54321 || node.stopped || !node.running {
		t.Fatal("readdress replaced the native UDP/control runtime or failed to update its local policy")
	}
	if node.echo == oldEcho || *adds != 1 || *removes != 1 {
		t.Fatal("probe listener/address was not replaced exactly once")
	}
	select {
	case <-oldDone:
	default:
		t.Fatal("old probe listener was left running")
	}
	if err := node.readdressPendingLocked(net.IPv4(10, 213, 47, 2), ops); err != nil {
		t.Fatal(err)
	}
	if node.direct != bind || node.control != control {
		t.Fatal("rollback changed the UDP/control identity")
	}
}

func TestPendingReaddressRejectsDataPeersAndInvalidAddressesBeforeOSChanges(t *testing.T) {
	for _, ip := range []net.IP{nil, net.IPv4(8, 8, 8, 8), net.IPv4(10, 213, 48, 2), net.IPv4(10, 213, 47, 0), net.IPv4(10, 213, 47, 255), net.ParseIP("fd00::1")} {
		node, ops, adds, removes := readdressFixture(t)
		if err := node.readdressPendingLocked(ip, ops); err == nil || *adds != 0 || *removes != 0 {
			t.Fatal("invalid reassignment reached OS operations")
		}
	}
	node, ops, adds, removes := readdressFixture(t)
	node.peers["data"] = &peer{}
	if err := node.readdressPendingLocked(net.IPv4(10, 213, 47, 4), ops); err == nil || *adds != 0 || *removes != 0 {
		t.Fatal("active data peers allowed provisional readdress")
	}
}

func TestPendingReaddressFailureKeepsPreviousStateOrRequiresFailClosedStop(t *testing.T) {
	for _, failure := range []string{"add", "listen", "remove_old", "rollback"} {
		t.Run(failure, func(t *testing.T) {
			node, ops, _, _ := readdressFixture(t)
			oldIP, oldAddress, oldEcho, oldControl := append(net.IP(nil), node.localIP...), node.address, node.echo, node.control
			switch failure {
			case "add":
				ops.add = func(uint64, net.IP) (windows.MibUnicastIpAddressRow, error) {
					return windows.MibUnicastIpAddressRow{}, errors.New("add failure")
				}
			case "listen", "rollback":
				ops.listen = func(net.IP) (*net.UDPConn, error) { return nil, errors.New("listen failure") }
			case "remove_old":
				ops.remove = func(row *windows.MibUnicastIpAddressRow) error {
					if row == oldAddress {
						return errors.New("delete failure")
					}
					return nil
				}
			}
			if failure == "rollback" {
				ops.remove = func(*windows.MibUnicastIpAddressRow) error { return errors.New("cleanup failure") }
			}
			err := node.readdressPendingLocked(net.IPv4(10, 213, 47, 4), ops)
			if err == nil || errors.Is(err, errReaddressRollback) != (failure == "rollback") {
				t.Fatalf("unexpected rollback result: %v", err)
			}
			if !node.localIP.Equal(oldIP) || node.address != oldAddress || node.echo != oldEcho || node.control != oldControl {
				t.Fatal("failed readdress committed partial local state")
			}
		})
	}
}
