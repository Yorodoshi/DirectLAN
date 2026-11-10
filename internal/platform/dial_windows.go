//go:build windows

package platform

import (
	"errors"
	"math/bits"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// BoundTCPDialer fails instead of falling back to another local interface.
func BoundTCPDialer(adapter Adapter, source net.IP) (*net.Dialer, error) {
	if source.To4() == nil || adapter.Index == 0 {
		return nil, errors.New("IPv4 adapter and source required")
	}
	found := false
	for _, address := range adapter.Addresses {
		if net.ParseIP(address).Equal(source) {
			found = true
		}
	}
	if !found {
		return nil, errors.New("source address does not belong to selected adapter")
	}
	return &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 25 * time.Second, LocalAddr: &net.TCPAddr{IP: source}, Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(bits.ReverseBytes32(adapter.Index)))
		})
		if err != nil {
			return err
		}
		return socketErr
	}}, nil
}
