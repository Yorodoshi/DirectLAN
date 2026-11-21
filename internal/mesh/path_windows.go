//go:build windows

package mesh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
)

// pathPacket inspects only IPv4 and UDP headers. Ignore non-initial fragments.
func pathPacket(p []byte, local netip.Addr, port uint16) (remote netip.AddrPort, outbound bool) {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 || binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		return
	}
	h := int(p[0]&15) * 4
	if h < 20 || len(p) < h+8 {
		return
	}
	src := netip.AddrFrom4([4]byte(p[12:16]))
	dst := netip.AddrFrom4([4]byte(p[16:20]))
	sp := binary.BigEndian.Uint16(p[h:])
	dp := binary.BigEndian.Uint16(p[h+2:])
	if src == local && sp == port {
		return netip.AddrPortFrom(dst, dp), true
	}
	if dst == local && dp == port {
		return netip.AddrPortFrom(src, sp), false
	}
	return
}

func (n *node) startPathCheck(id string) error {
	if n.pathBusy {
		return errors.New("проверка уже выполняется")
	}
	if n.wg == nil || n.p.Paused || n.interfaces.IPv4 == 0 {
		return errors.New("для проверки требуется активная сеть с физическим IPv4-адаптером")
	}
	peers := map[netip.Addr]bool{}
	for _, m := range n.roster.Members {
		if memberID(m) != id || m.IP == n.p.LocalIP {
			continue
		}
		for _, ep := range controlCandidates(n.p.Learned[id], m.Endpoints) {
			if ep.Addr().Is4() {
				peers[ep.Addr()] = true
			}
		}
		if stats, err := n.wg.Stats(id); err == nil {
			if ep, err := netip.ParseAddrPort(stats.Endpoint); err == nil && ep.Addr().Is4() {
				peers[ep.Addr()] = true
			}
		}
	}
	if len(peers) == 0 {
		return errors.New("у выбранного участника пока нет известного IPv4-адреса")
	}
	iface, err := net.InterfaceByIndex(int(n.interfaces.IPv4))
	if err != nil {
		return err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return err
	}
	var local netip.Addr
	for _, a := range addresses {
		if p, e := netip.ParsePrefix(a.String()); e == nil && p.Addr().Is4() {
			local = p.Addr()
			break
		}
	}
	if !local.IsValid() {
		return errors.New("у адаптера нет IPv4-адреса")
	}
	wg, port := n.wg, n.p.Port
	n.pathBusy = true
	n.pathResult = "Проверяем IPv4 на " + iface.Name + " в течение 30 секунд…"
	go func() {
		sent, received, err := countPhysical(local, port, peers)
		n.mu.Lock()
		defer n.mu.Unlock()
		n.pathBusy = false
		switch {
		case n.wg != wg:
			n.pathResult = "Сеть изменилась во время проверки. Повторите проверку."
		case err != nil:
			n.pathResult = "Ошибка проверки адаптера: " + err.Error()
		default:
			n.pathResult = fmt.Sprintf("%s · IPv4 · к участнику: %d, от участника: %d. Скопируйте журнал.", iface.Name, sent, received)
		}
		log.Printf("mesh event=physical_path_result peer=%s interface=%d local_port=%d result=%q", shortID(id), iface.Index, port, n.pathResult)
	}()
	n.requestCheck()
	return nil
}

func countPhysical(local netip.Addr, port uint16, peers map[netip.Addr]bool) (sent, received int, err error) {
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return 0, 0, err
	}
	defer windows.Closesocket(fd)
	if err = windows.Bind(fd, &windows.SockaddrInet4{Addr: local.As4()}); err != nil {
		return
	}
	mode := [4]byte{1}
	var size uint32
	if err = windows.WSAIoctl(fd, 0x98000001, &mode[0], 4, nil, 0, &size, nil, 0); err != nil {
		return
	}
	if err = windows.SetsockoptInt(fd, windows.SOL_SOCKET, windows.SO_RCVTIMEO, 500); err != nil {
		return
	}
	var buf [65535]byte
	counts := map[netip.AddrPort][2]int{}
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); {
		n, _, e := windows.Recvfrom(fd, buf[:], 0)
		if errors.Is(e, windows.WSAETIMEDOUT) {
			continue
		}
		if e != nil {
			return sent, received, e
		}
		ep, out := pathPacket(buf[:n], local, port)
		if !peers[ep.Addr()] {
			continue
		}
		pair := counts[ep]
		if out {
			sent++
			pair[0]++
		} else {
			received++
			pair[1]++
		}
		if _, ok := counts[ep]; ok || len(counts) < 16 {
			counts[ep] = pair
		}
	}
	for ep, c := range counts {
		log.Printf("mesh event=physical_path_endpoint remote=%s sent=%d received=%d", ep, c[0], c[1])
	}
	return
}
