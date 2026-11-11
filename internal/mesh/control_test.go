package mesh

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestControlHello(t *testing.T) {
	for _, revision := range []uint64{0, 1, 500, ^uint64(0)} {
		packet := encodeControlHello(revision)
		if value, ok := parseControlHello(packet); !ok || value != revision {
			t.Fatalf("hello revision = %d, %t", value, ok)
		}
	}
	for _, packet := range [][]byte{nil, {1}, make([]byte, 9), append(encodeControlHello(1), 0)} {
		if _, ok := parseControlHello(packet); ok {
			t.Fatal("malformed hello accepted")
		}
	}
}

func TestRosterFragmentsOutOfOrderAndRepeated(t *testing.T) {
	text := strings.Repeat("roster-", 700)
	packets, err := rosterPackets(text, 5)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	var assembly rosterAssembly
	for pass := 0; pass < 2; pass++ {
		for i := len(packets) - 1; i >= 0; i-- {
			if i != 0 {
				for duplicate := 0; duplicate < 2; duplicate++ {
					got, revision, err := assembly.add(packets[i], now)
					if err != nil || got != "" || revision != 0 {
						t.Fatalf("incomplete fragment returned text %t, revision %d, error %v", got != "", revision, err)
					}
				}
				continue
			}
			got, revision, err := assembly.add(packets[i], now)
			if err != nil || got != text || revision != 5 {
				t.Fatalf("complete roster mismatch, revision %d, error %v", revision, err)
			}
		}
		if len(assembly.parts) != 0 || assembly.size != 0 {
			t.Fatal("completed assembly retained fragment memory")
		}
	}
}

func TestRosterFragmentsMaximumAndBounds(t *testing.T) {
	text := strings.Repeat("x", maxEncodedSize)
	packets, err := rosterPackets(text, 1)
	if err != nil || len(packets) != 44 {
		t.Fatalf("maximum roster rejected: %d packets, %v", len(packets), err)
	}
	var assembly rosterAssembly
	for i, packet := range packets {
		if len(packet) > controlPayloadLimit {
			t.Fatal("fragment exceeds control datagram limit")
		}
		got, _, err := assembly.add(packet, time.Unix(1000, 0))
		if err != nil || i == len(packets)-1 && got != text {
			t.Fatalf("maximum roster reassembly failed: %v", err)
		}
	}
	for _, invalid := range []struct {
		text     string
		revision uint64
	}{{"", 1}, {"valid", 0}, {text + "x", 1}} {
		if _, err := rosterPackets(invalid.text, invalid.revision); err == nil {
			t.Fatal("invalid outgoing roster accepted")
		}
	}

	valid, _ := rosterPackets(strings.Repeat("a", 1025), 1)
	invalid := [][]byte{nil, {2}, make([]byte, rosterHeaderSize), make([]byte, controlPayloadLimit+1)}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0] = controlHelloKind },
		func(p []byte) { clear(p[1:9]) },
		func(p []byte) { binary.BigEndian.PutUint16(p[43:45], 0) },
		func(p []byte) { binary.BigEndian.PutUint16(p[43:45], maxRosterParts+1) },
		func(p []byte) { binary.BigEndian.PutUint16(p[41:43], 2) },
	} {
		packet := append([]byte(nil), valid[0]...)
		mutate(packet)
		invalid = append(invalid, packet)
	}
	invalid = append(invalid, valid[0][:len(valid[0])-1])
	for _, packet := range invalid {
		var a rosterAssembly
		if _, _, err := a.add(packet, time.Unix(1000, 0)); err == nil {
			t.Fatal("malformed incoming fragment accepted")
		}
		if len(a.parts) != 0 {
			t.Fatal("malformed fragment allocated assembly memory")
		}
	}
}

func TestRosterFragmentsTamperingAndConflict(t *testing.T) {
	packets, _ := rosterPackets(strings.Repeat("x", 1500), 3)
	now := time.Unix(1000, 0)
	var assembly rosterAssembly
	if _, _, err := assembly.add(packets[0], now); err != nil {
		t.Fatal(err)
	}
	conflict := append([]byte(nil), packets[0]...)
	conflict[rosterHeaderSize] ^= 1
	if _, _, err := assembly.add(conflict, now); err == nil {
		t.Fatal("different duplicate fragment accepted")
	}
	conflict = append([]byte(nil), packets[1]...)
	conflict[9] ^= 1
	if _, _, err := assembly.add(conflict, now); err == nil {
		t.Fatal("different hash for same revision accepted")
	}
	tampered := append([]byte(nil), packets[1]...)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := assembly.add(tampered, now); err == nil {
		t.Fatal("bad full roster hash accepted")
	}
	if len(assembly.parts) != 0 {
		t.Fatal("bad full hash retained assembly")
	}
}

func TestRosterAssemblyExpiresAndNewerRevisionSupersedes(t *testing.T) {
	old, _ := rosterPackets(strings.Repeat("o", 1200), 1)
	next, _ := rosterPackets(strings.Repeat("n", 1200), 2)
	start := time.Unix(1000, 0)
	var assembly rosterAssembly
	if _, _, err := assembly.add(old[0], start); err != nil {
		t.Fatal(err)
	}
	if got, _, err := assembly.add(old[1], start.Add(rosterAssemblyTTL)); err != nil || got != "" {
		t.Fatal("expired fragment was combined with old state")
	}
	if !bytes.Equal(assembly.parts[1], old[1][rosterHeaderSize:]) || assembly.received != 1 {
		t.Fatal("expiry did not begin a fresh bounded assembly")
	}
	if _, _, err := assembly.add(next[1], start.Add(rosterAssemblyTTL+time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := assembly.add(old[0], start.Add(rosterAssemblyTTL+time.Second)); err == nil {
		t.Fatal("old revision displaced newer assembly")
	}
	got, revision, err := assembly.add(next[0], start.Add(rosterAssemblyTTL+time.Second))
	if err != nil || revision != 2 || got != strings.Repeat("n", 1200) {
		t.Fatalf("newer revision did not finish: %v", err)
	}
}
