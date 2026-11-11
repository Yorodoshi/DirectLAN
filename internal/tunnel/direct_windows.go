//go:build windows

package tunnel

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type DirectInterfaces struct {
	IPv4 uint32
	IPv6 uint32
}

// NewDirect uses WireGuard's own UDP bind and authenticated endpoint roaming.
func NewDirect(privateKey []byte, ip net.IP, prefix *net.IPNet, port uint16, interfaces DirectInterfaces) (*Tunnel, error) {
	t, err := New(privateKey, ip, prefix)
	if err != nil {
		return nil, err
	}
	t.native = true
	t.port = port
	t.interfaces = interfaces
	return t, nil
}

// NewSecureDirect keeps WireGuard's normal handshake and derives pairwise
// additional keys in the supplied authenticated network domain.
func NewSecureDirect(privateKey []byte, ip net.IP, prefix *net.IPNet, port uint16, interfaces DirectInterfaces, networkID string, masked bool) (*Tunnel, error) {
	if networkID == "" || len(networkID) > 256 {
		return nil, errors.New("invalid secure network domain")
	}
	t, err := NewDirect(privateKey, ip, prefix, port, interfaces)
	if err != nil {
		return nil, err
	}
	t.secureContext, t.masked = networkID, masked
	t.control = newControlTransport()
	if masked {
		t.mtu = maskedMTU
	}
	return t, nil
}

func (t *Tunnel) AddDirectPeer(id string, key []byte, ip net.IP, endpoint netip.AddrPort) error {
	if !t.native || t.secureContext != "" {
		return ErrNotStarted
	}
	return t.addPeer(id, key, ip, nil, endpoint, nil)
}

func (t *Tunnel) AddSecureDirectPeer(id string, key []byte, ip net.IP, endpoint netip.AddrPort) error {
	if !t.native || t.secureContext == "" {
		return ErrNotStarted
	}
	keys, err := derivePeerCrypto(t.privateKey[:], key, t.secureContext)
	if err != nil {
		return err
	}
	return t.addPeer(id, key, ip, nil, endpoint, keys)
}

func (t *Tunnel) DirectPort() (uint16, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.native || !t.running {
		return 0, ErrNotStarted
	}
	config, err := t.device.IpcGet()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(config, "\n") {
		if raw, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.ParseUint(raw, 10, 16)
			if err == nil && port != 0 {
				return uint16(port), nil
			}
		}
	}
	return 0, ErrNotStarted
}

func (t *Tunnel) DiscoverDirectEndpoint(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
	t.mu.Lock()
	bind := t.direct
	t.mu.Unlock()
	if bind == nil {
		return netip.AddrPort{}, ErrNotStarted
	}
	return bind.discover(ctx, server)
}

func (t *Tunnel) SetDirectEndpoint(id string, endpoint netip.AddrPort) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.native || !t.running || !endpoint.IsValid() || endpoint.Port() == 0 {
		return ErrNotStarted
	}
	p := t.peers[id]
	if p == nil {
		return ErrUnknownPeer
	}
	if err := t.device.IpcSet("public_key=" + hex.EncodeToString(p.publicKey[:]) + "\nupdate_only=true\nendpoint=" + directEndpoint(id, endpoint.String(), t.masked) + "\n"); err != nil {
		return err
	}
	p.endpoint = endpoint
	return nil
}
