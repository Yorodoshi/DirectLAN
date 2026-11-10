//go:build windows

package tunnel

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	// 1072 + 32 WireGuard + 113 envelope + 48 IPv6/UDP = 1265 bytes.
	// 1072 is already aligned to WireGuard's 16-byte padding boundary.
	maskedMTU             = 1072
	maskTagSize           = 8
	maskHeaderSize        = maskTagSize + chacha20poly1305.NonceSizeX
	maxMaskedWireDatagram = maskedMTU + 32
	maxMaskPadding        = 63
	maxMaskedDatagram     = maskHeaderSize + 2 + maxMaskedWireDatagram + maxMaskPadding + chacha20poly1305.Overhead
)

type peerCrypto struct {
	preshared [32]byte
	send      cipher.AEAD
	receive   cipher.AEAD
	sendTag   [maskTagSize]byte
	recvTag   [maskTagSize]byte
}

// These keys are derived from the existing static X25519 identities. They
// separate groups and packet purposes; they add no independent quantum secret.
func derivePeerCrypto(private, remote []byte, networkID string) (*peerCrypto, error) {
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
		return nil, errors.New("peer uses the local WireGuard identity")
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
	context := networkID + "\x00" + hex.EncodeToString(first) + hex.EncodeToString(second)
	salt := sha256.Sum256([]byte("DirectLAN mesh keys v1\x00" + context))
	material, err := hkdf.Key(sha256.New, shared, salt[:], "DirectLAN PSK and directional UDP masking v1", 112)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	sendKey, recvKey := material[32:64], material[64:96]
	sendTag, recvTag := material[96:104], material[104:112]
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
	keys := &peerCrypto{send: send, receive: receive}
	copy(keys.preshared[:], material[:32])
	copy(keys.sendTag[:], sendTag)
	copy(keys.recvTag[:], recvTag)
	return keys, nil
}

type maskPeer struct {
	id   string
	keys *peerCrypto
}

type udpMask struct {
	mu    sync.RWMutex
	peers map[string]*maskPeer
	tags  map[[maskTagSize]byte]*maskPeer
}

func newUDPMask() *udpMask {
	return &udpMask{peers: make(map[string]*maskPeer), tags: make(map[[maskTagSize]byte]*maskPeer)}
}

func (m *udpMask) add(id string, keys *peerCrypto) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.peers[id] != nil || m.tags[keys.recvTag] != nil {
		return errors.New("duplicate UDP masking identity")
	}
	p := &maskPeer{id: id, keys: keys}
	m.peers[id], m.tags[keys.recvTag] = p, p
	return nil
}

func (m *udpMask) remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.peers[id]; p != nil {
		delete(m.tags, p.keys.recvTag)
		delete(m.peers, id)
	}
}

func (m *udpMask) has(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peers[id] != nil
}

func (m *udpMask) seal(id string, packet []byte) ([]byte, error) {
	if len(packet) == 0 || len(packet) > maxMaskedWireDatagram {
		return nil, errors.New("invalid masked WireGuard datagram length")
	}
	m.mu.RLock()
	p := m.peers[id]
	m.mu.RUnlock()
	if p == nil {
		return nil, ErrUnknownPeer
	}
	var random [chacha20poly1305.NonceSizeX + 1]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	plain := make([]byte, 2+len(packet)+int(random[len(random)-1]&maxMaskPadding))
	binary.BigEndian.PutUint16(plain, uint16(len(packet)))
	copy(plain[2:], packet)
	if _, err := rand.Read(plain[2+len(packet):]); err != nil {
		return nil, err
	}
	header := make([]byte, maskHeaderSize, maskHeaderSize+len(plain)+chacha20poly1305.Overhead)
	copy(header, p.keys.sendTag[:])
	copy(header[maskTagSize:], random[:chacha20poly1305.NonceSizeX])
	return p.keys.send.Seal(header, header[maskTagSize:maskHeaderSize], plain, header[:maskTagSize]), nil
}

// open copies the authenticated payload over its envelope. Replays are still
// rejected by WireGuard's per-session replay window after decryption.
func (m *udpMask) open(packet []byte) (string, int, error) {
	if len(packet) < maskHeaderSize+2+chacha20poly1305.Overhead || len(packet) > maxMaskedDatagram {
		return "", 0, errors.New("invalid masked UDP length")
	}
	tag := [maskTagSize]byte(packet[:maskTagSize])
	m.mu.RLock()
	p := m.tags[tag]
	m.mu.RUnlock()
	if p == nil {
		return "", 0, ErrUnknownPeer
	}
	plain, err := p.keys.receive.Open(packet[maskHeaderSize:maskHeaderSize], packet[maskTagSize:maskHeaderSize], packet[maskHeaderSize:], packet[:maskTagSize])
	if err != nil {
		return "", 0, err
	}
	n := int(binary.BigEndian.Uint16(plain))
	if n == 0 || n > maxMaskedWireDatagram || n > len(plain)-2 || len(plain)-2-n > maxMaskPadding {
		return "", 0, errors.New("invalid masked UDP payload")
	}
	copy(packet, plain[2:2+n])
	return p.id, n, nil
}

type maskedEndpoint struct {
	conn.Endpoint
	peerID string
}

func directEndpoint(id string, endpoint string, masked bool) string {
	if masked {
		return fmt.Sprintf("%s@%s", id, endpoint)
	}
	return endpoint
}
