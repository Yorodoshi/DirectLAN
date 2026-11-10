package coordinator

import (
	"encoding/base64"
	"encoding/binary"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

func validLabel(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validWGPublicKey(s string) bool {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != s {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return true
		}
	}
	return false
}

func validNetworkCIDR(s string) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 28 || prefix.Masked() != prefix {
		return netip.Prefix{}, false
	}
	private := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	for _, p := range private {
		if prefix.Bits() >= p.Bits() && p.Contains(prefix.Addr()) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

func validOverlayIP(cidr, ip string) bool {
	prefix, ok := validNetworkCIDR(cidr)
	if !ok {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() || !prefix.Contains(addr) {
		return false
	}
	base := prefix.Addr().As4()
	value := addr.As4()
	network := binary.BigEndian.Uint32(base[:])
	host := binary.BigEndian.Uint32(value[:])
	broadcast := network | (uint32(1)<<(32-prefix.Bits()) - 1)
	return host != network && host != broadcast
}
