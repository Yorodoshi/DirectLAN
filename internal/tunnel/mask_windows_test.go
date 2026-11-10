//go:build windows

package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func cryptoPair(t *testing.T, network string) (*ecdh.PrivateKey, *ecdh.PrivateKey, *peerCrypto, *peerCrypto) {
	t.Helper()
	a, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ka, err := derivePeerCrypto(a.Bytes(), b.PublicKey().Bytes(), network)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := derivePeerCrypto(b.Bytes(), a.PublicKey().Bytes(), network)
	if err != nil {
		t.Fatal(err)
	}
	return a, b, ka, kb
}

func TestMaskedDatagramAuthenticationAndDomains(t *testing.T) {
	if maxMaskedDatagram+48 > 1280 {
		t.Fatal("masked UDP exceeds the minimum IPv6 path MTU")
	}
	a, b, ka, kb := cryptoPair(t, "test-network")
	if ka.preshared != kb.preshared || ka.sendTag != kb.recvTag || ka.recvTag != kb.sendTag {
		t.Fatal("directional keys or PSK disagree")
	}
	ma, mb := newUDPMask(), newUDPMask()
	if err := ma.add("peer", ka); err != nil {
		t.Fatal(err)
	}
	if err := mb.add("peer", kb); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{4, 0, 0, 0}, 260)
	packet, err := ma.seal("peer", payload)
	if err != nil || len(packet) > maxMaskedDatagram || bytes.Contains(packet, payload[:32]) {
		t.Fatalf("seal failed or exposed payload: %v", err)
	}
	second, err := ma.seal("peer", payload)
	if err != nil || bytes.Equal(packet, second) {
		t.Fatalf("nonce and padding were reused: %v", err)
	}
	opened := append([]byte(nil), packet...)
	id, n, err := mb.open(opened)
	if err != nil || id != "peer" || n != len(payload) || !bytes.Equal(opened[:n], payload) {
		t.Fatalf("masked round trip: %s, %d, %v", id, n, err)
	}
	for _, index := range []int{0, maskTagSize, len(packet) - 1} {
		modified := append([]byte(nil), packet...)
		modified[index] ^= 1
		if _, _, err := mb.open(modified); err == nil {
			t.Fatalf("tampering at offset %d accepted", index)
		}
	}
	if _, _, err := ma.open(append([]byte(nil), packet...)); err == nil {
		t.Fatal("reflection accepted")
	}
	otherKeys, err := derivePeerCrypto(b.Bytes(), a.PublicKey().Bytes(), "another-network")
	if err != nil {
		t.Fatal(err)
	}
	other := newUDPMask()
	if err := other.add("peer", otherKeys); err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.open(append([]byte(nil), packet...)); err == nil {
		t.Fatal("another network accepted packet")
	}
	mb.remove("peer")
	if _, _, err := mb.open(append([]byte(nil), packet...)); err == nil {
		t.Fatal("removed peer accepted")
	}
	if _, err := derivePeerCrypto(a.Bytes(), make([]byte, 32), "test-network"); err == nil {
		t.Fatal("low-order X25519 identity accepted")
	}
}

type maskTestTUN struct {
	outgoing, incoming chan []byte
	stop               chan struct{}
	events             chan tun.Event
	once               sync.Once
}

func newMaskTestTUN() *maskTestTUN {
	return &maskTestTUN{outgoing: make(chan []byte, 4), incoming: make(chan []byte, 4), stop: make(chan struct{}), events: make(chan tun.Event)}
}
func (*maskTestTUN) File() *os.File { return nil }
func (m *maskTestTUN) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-m.stop:
		return 0, net.ErrClosed
	case packet := <-m.outgoing:
		sizes[0] = copy(packets[0][offset:], packet)
		return 1, nil
	}
}
func (m *maskTestTUN) Write(packets [][]byte, offset int) (int, error) {
	for _, packet := range packets {
		select {
		case <-m.stop:
			return 0, net.ErrClosed
		case m.incoming <- append([]byte(nil), packet[offset:]...):
		}
	}
	return len(packets), nil
}
func (*maskTestTUN) MTU() (int, error)          { return maskedMTU, nil }
func (*maskTestTUN) Name() (string, error)      { return "mask-test", nil }
func (m *maskTestTUN) Events() <-chan tun.Event { return m.events }
func (m *maskTestTUN) Close() error {
	m.once.Do(func() { close(m.stop); close(m.events) })
	return nil
}
func (*maskTestTUN) BatchSize() int { return 1 }

func TestWireGuardHandshakeAndDataOverMaskedUDP(t *testing.T) {
	const participants = 3
	var keys [participants]*ecdh.PrivateKey
	var binds [participants]*stunBind
	var adapters [participants]*maskTestTUN
	var devices [participants]*device.Device
	var ports [participants]uint16
	logger := device.NewLogger(device.LogLevelSilent, "")
	for i := range participants {
		var err error
		keys[i], err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		binds[i] = &stunBind{Bind: conn.NewDefaultBind(), mask: newUDPMask()}
		adapters[i] = newMaskTestTUN()
		devices[i] = device.NewDevice(adapters[i], binds[i], logger)
		defer devices[i].Close()
		if err := devices[i].IpcSet("private_key=" + hex.EncodeToString(keys[i].Bytes()) + "\nlisten_port=0\n"); err != nil {
			t.Fatal(err)
		}
		if err := devices[i].Up(); err != nil {
			t.Fatal(err)
		}
		raw, err := devices[i].IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(raw, "\n") {
			if value, ok := strings.CutPrefix(line, "listen_port="); ok {
				port, err := strconv.ParseUint(value, 10, 16)
				if err == nil && port != 0 {
					ports[i] = uint16(port)
					break
				}
			}
		}
		if ports[i] == 0 {
			t.Fatal("UDP port missing")
		}
	}
	for i := range participants {
		for j := range participants {
			if i == j {
				continue
			}
			crypto, err := derivePeerCrypto(keys[i].Bytes(), keys[j].PublicKey().Bytes(), "wireguard-mask-test")
			if err != nil {
				t.Fatal(err)
			}
			id := fmt.Sprintf("peer%d", j)
			if err := binds[i].mask.add(id, crypto); err != nil {
				t.Fatal(err)
			}
			config := fmt.Sprintf("public_key=%x\npreshared_key=%x\nendpoint=%s@127.0.0.1:%d\nallowed_ip=10.233.75.%d/32\n",
				keys[j].PublicKey().Bytes(), crypto.preshared, id, ports[j], j+1)
			if err := devices[i].IpcSet(config); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := range participants {
		for j := range participants {
			if i == j {
				continue
			}
			packet := make([]byte, 32)
			packet[0], packet[8], packet[9] = 0x45, 64, 17
			binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
			copy(packet[12:16], []byte{10, 233, 75, byte(i + 1)})
			copy(packet[16:20], []byte{10, 233, 75, byte(j + 1)})
			copy(packet[28:], "ping")
			adapters[i].outgoing <- packet
			select {
			case received := <-adapters[j].incoming:
				if !bytes.Equal(received, packet) {
					t.Fatalf("peer %d to %d packet differs", i, j)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("peer %d to %d handshake or data delivery failed", i, j)
			}
		}
	}
	for _, wg := range devices {
		stats, err := wg.IpcGet()
		if err != nil || strings.Contains(stats, "@") {
			t.Fatalf("internal peer identifier leaked into public endpoint stats: %v", err)
		}
	}
}
