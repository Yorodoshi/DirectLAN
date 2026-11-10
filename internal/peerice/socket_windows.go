//go:build windows

package peerice

import (
	"math/bits"
	"net"

	"golang.org/x/sys/windows"
)

const windowsUnicastInterfaceOption = 31 // IP_UNICAST_IF / IPV6_UNICAST_IF

func bindSocketToInterface(socket *net.UDPConn, index int, ipv6 bool) error {
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		if ipv6 {
			socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windowsUnicastInterfaceOption, index)
		} else {
			// Winsock's IPv4 IP_UNICAST_IF takes the index in network byte order.
			socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windowsUnicastInterfaceOption, int(bits.ReverseBytes32(uint32(index))))
		}
	})
	if err != nil {
		return err
	}
	return socketErr
}
