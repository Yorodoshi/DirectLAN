//go:build windows

package tunnel

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	ControlPayloadLimit = 1100
	controlTagSize      = 8
	controlHeaderSize   = controlTagSize + chacha20poly1305.NonceSizeX
	controlPacketLimit  = controlHeaderSize + ControlPayloadLimit + chacha20poly1305.Overhead
	controlReplayWindow = 256
)

// ControlMessage is delivered only after authentication by a configured peer.
// Endpoint is the observed UDP source, not proof that this peer currently owns
// the return route. The service must validate its nonce/cookie before approving
// that source with ConfigureControlPeer. Signed-roster checks also belong there.
type ControlMessage struct {
	PeerID   string
	Payload  []byte
	Endpoint netip.AddrPort
}

type controlPeer struct {
	id                     string
	public                 [32]byte
	send                   cipher.AEAD
	receive                cipher.AEAD
	sendTag                [controlTagSize]byte
	recvTag                [controlTagSize]byte
	endpoint               netip.AddrPort
	seen                   map[[chacha20poly1305.NonceSizeX]byte]bool
	recent                 [controlReplayWindow][chacha20poly1305.NonceSizeX]byte
	next                   int
	authIn, sent, rejected atomic.Uint64
}

type controlTransport struct {
	mu       sync.RWMutex
	peers    map[string]*controlPeer
	tags     map[[controlTagSize]byte]*controlPeer
	messages chan ControlMessage
}

func newControlTransport() *controlTransport {
	return &controlTransport{
		peers: make(map[string]*controlPeer), tags: make(map[[controlTagSize]byte]*controlPeer),
		messages: make(chan ControlMessage, 128),
	}
}

func deriveControlPeer(private, remote []byte, networkID string) (*controlPeer, error) {
	localKey, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	remoteKey, err := ecdh.X25519().NewPublicKey(remote)
	if err != nil {
		return nil, err
	}
	local := localKey.PublicKey().Bytes()
	order := bytes.Compare(local, remote)
	if order == 0 {
		return nil, errors.New("control peer uses the local identity")
	}
	shared, err := localKey.ECDH(remoteKey)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	first, second := local, remote
	if order > 0 {
		first, second = remote, local
	}
	domain := networkID + "\x00" + hex.EncodeToString(first) + hex.EncodeToString(second)
	salt := sha256.Sum256([]byte("DirectLAN bootstrap control v1\x00" + domain))
	material, err := hkdf.Key(sha256.New, shared, salt[:], "DirectLAN control AEAD and directional tags v1", 80)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	sendKey, recvKey := material[:32], material[32:64]
	sendTag, recvTag := material[64:72], material[72:80]
	if order > 0 {
		sendKey, recvKey = recvKey, sendKey
		sendTag, recvTag = recvTag, sendTag
	}
	send, err := chacha20poly1305.NewX(sendKey)
	if err != nil {
		return nil, err
	}
	receive, err := chacha20poly1305.NewX(recvKey)
	if err != nil {
		return nil, err
	}
	p := &controlPeer{send: send, receive: receive, seen: make(map[[chacha20poly1305.NonceSizeX]byte]bool)}
	copy(p.public[:], remote)
	copy(p.sendTag[:], sendTag)
	copy(p.recvTag[:], recvTag)
	return p, nil
}

func (c *controlTransport) configure(id string, p *controlPeer, endpoint netip.AddrPort) error {
	if id == "" || len(id) > 128 || endpoint.IsValid() && (endpoint.Port() == 0 || endpoint.Addr().IsUnspecified()) {
		return errors.New("invalid control peer or endpoint")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing := c.peers[id]; existing != nil {
		if existing.public != p.public {
			return errors.New("control peer key changed")
		}
		if endpoint.IsValid() {
			existing.endpoint = endpoint
		}
		return nil
	}
	if len(c.peers) >= 9 || c.tags[p.recvTag] != nil {
		return errors.New("control peer limit or duplicate tag")
	}
	p.id, p.endpoint = id, endpoint
	c.peers[id], c.tags[p.recvTag] = p, p
	return nil
}

func (c *controlTransport) remove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.peers[id]; p != nil {
		delete(c.tags, p.recvTag)
		delete(c.peers, id)
	}
}

func (c *controlTransport) seal(id string, payload []byte) ([]byte, netip.AddrPort, error) {
	if len(payload) == 0 || len(payload) > ControlPayloadLimit {
		return nil, netip.AddrPort{}, errors.New("invalid control payload size")
	}
	c.mu.RLock()
	p := c.peers[id]
	if p == nil {
		c.mu.RUnlock()
		return nil, netip.AddrPort{}, ErrUnknownPeer
	}
	endpoint := p.endpoint
	c.mu.RUnlock()
	if !endpoint.IsValid() {
		return nil, endpoint, errors.New("control peer endpoint is unavailable")
	}
	packet := make([]byte, controlHeaderSize, controlPacketLimit)
	copy(packet, p.sendTag[:])
	if _, err := rand.Read(packet[controlTagSize:]); err != nil {
		return nil, endpoint, err
	}
	packet = p.send.Seal(packet, packet[controlTagSize:controlHeaderSize], payload, packet[:controlTagSize])
	return packet, endpoint, nil
}

// receive consumes recognized control tags, including malformed packets.
// Unknown tags continue to the WireGuard receive path. Nonces are retained in a
// bounded recent-replay window; the service must also correlate transfers and
// reject stale signed network revisions across restarts.
func (c *controlTransport) receive(packet []byte, from conn.Endpoint) bool {
	if len(packet) < controlTagSize {
		return false
	}
	tag := [controlTagSize]byte(packet[:controlTagSize])
	c.mu.RLock()
	p := c.tags[tag]
	c.mu.RUnlock()
	if p == nil {
		return false
	}
	if len(packet) <= controlHeaderSize+chacha20poly1305.Overhead || len(packet) > controlPacketLimit || from == nil {
		p.rejected.Add(1)
		return true
	}
	endpoint, err := netip.ParseAddrPort(from.DstToString())
	if err != nil || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() {
		p.rejected.Add(1)
		return true
	}
	nonce := [chacha20poly1305.NonceSizeX]byte(packet[controlTagSize:controlHeaderSize])
	c.mu.RLock()
	replayed := p.seen[nonce]
	c.mu.RUnlock()
	if replayed {
		p.rejected.Add(1)
		return true
	}
	payload, err := p.receive.Open(nil, packet[controlTagSize:controlHeaderSize], packet[controlHeaderSize:], packet[:controlTagSize])
	if err != nil {
		p.rejected.Add(1)
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peers[p.id] != p || p.seen[nonce] {
		p.rejected.Add(1)
		return true
	}
	delete(p.seen, p.recent[p.next])
	p.recent[p.next], p.seen[nonce] = nonce, true
	p.next = (p.next + 1) % len(p.recent)
	p.authIn.Add(1)
	select {
	case c.messages <- ControlMessage{PeerID: p.id, Payload: payload, Endpoint: endpoint}:
	default:
	}
	return true
}

// ConfigureControlPeer authorizes only the bootstrap channel, without adding
// any WireGuard key, virtual route, or application-data permission. Its endpoint
// is a service-approved return address; receive never changes it automatically.
func (t *Tunnel) ConfigureControlPeer(id string, key []byte, endpoint netip.AddrPort) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.secureContext == "" || !t.running || t.control == nil {
		return ErrNotStarted
	}
	p, err := deriveControlPeer(t.privateKey[:], key, t.secureContext)
	if err != nil {
		return err
	}
	return t.control.configure(id, p, endpoint)
}

func (t *Tunnel) SendControl(id string, payload []byte) error {
	t.mu.Lock()
	bind, control, running := t.direct, t.control, t.running
	t.mu.Unlock()
	if !running || bind == nil || control == nil {
		return ErrNotStarted
	}
	packet, address, err := control.seal(id, payload)
	if err != nil {
		return err
	}
	endpoint, err := bind.Bind.ParseEndpoint(address.String())
	if err != nil {
		return err
	}
	if err := bind.Bind.Send([][]byte{packet}, endpoint); err != nil {
		return err
	}
	bind.transport.rawOut.Add(1)
	control.mu.RLock()
	if p := control.peers[id]; p != nil {
		p.sent.Add(1)
	}
	control.mu.RUnlock()
	return nil
}

func (t *Tunnel) ControlMessages() <-chan ControlMessage {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.control == nil {
		return nil
	}
	return t.control.messages
}
