package mesh

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const (
	controlPayloadLimit = 1100
	controlHelloKind    = 1
	controlRosterKind   = 2
	rosterChunkSize     = 1024
	rosterHeaderSize    = 1 + 8 + sha256.Size + 2 + 2
	maxRosterParts      = maxEncodedSize / rosterChunkSize
	rosterAssemblyTTL   = 20 * time.Second
)

func encodeControlHello(revision uint64) []byte {
	packet := make([]byte, 9)
	packet[0] = controlHelloKind
	binary.BigEndian.PutUint64(packet[1:], revision)
	return packet
}

func parseControlHello(payload []byte) (uint64, bool) {
	if len(payload) != 9 || payload[0] != controlHelloKind {
		return 0, false
	}
	return binary.BigEndian.Uint64(payload[1:]), true
}

// Roster fragments travel inside the separately authenticated control channel.
// The service still verifies the complete owner's signature before admission.
func rosterPackets(text string, revision uint64) ([][]byte, error) {
	if len(text) == 0 || len(text) > maxEncodedSize || revision == 0 {
		return nil, errors.New("invalid control roster size or revision")
	}
	hash := sha256.Sum256([]byte(text))
	count := (len(text) + rosterChunkSize - 1) / rosterChunkSize
	packets := make([][]byte, count)
	for index := range count {
		offset := index * rosterChunkSize
		chunk := text[offset:min(offset+rosterChunkSize, len(text))]
		packet := make([]byte, rosterHeaderSize+len(chunk))
		packet[0] = controlRosterKind
		binary.BigEndian.PutUint64(packet[1:9], revision)
		copy(packet[9:41], hash[:])
		binary.BigEndian.PutUint16(packet[41:43], uint16(index))
		binary.BigEndian.PutUint16(packet[43:45], uint16(count))
		copy(packet[rosterHeaderSize:], chunk)
		packets[index] = packet
	}
	return packets, nil
}

type rosterAssembly struct {
	revision uint64
	hash     [sha256.Size]byte
	parts    [][]byte
	received int
	size     int
	started  time.Time
}

func (a *rosterAssembly) reset() {
	*a = rosterAssembly{}
}

func (a *rosterAssembly) add(payload []byte, now time.Time) (string, uint64, error) {
	if len(payload) <= rosterHeaderSize || len(payload) > rosterHeaderSize+rosterChunkSize ||
		len(payload) > controlPayloadLimit || payload[0] != controlRosterKind {
		return "", 0, errors.New("invalid control roster fragment")
	}
	revision := binary.BigEndian.Uint64(payload[1:9])
	hash := [sha256.Size]byte(payload[9:41])
	index := int(binary.BigEndian.Uint16(payload[41:43]))
	count := int(binary.BigEndian.Uint16(payload[43:45]))
	chunk := payload[rosterHeaderSize:]
	if revision == 0 || count == 0 || count > maxRosterParts || index >= count ||
		index < count-1 && len(chunk) != rosterChunkSize {
		return "", 0, errors.New("invalid control roster fragment parameters")
	}
	if len(a.parts) != 0 && (now.Before(a.started) || now.Sub(a.started) >= rosterAssemblyTTL) {
		a.reset()
	}
	if len(a.parts) != 0 {
		if revision < a.revision {
			return "", 0, errors.New("stale control roster fragment")
		}
		if revision == a.revision && (hash != a.hash || count != len(a.parts)) {
			return "", 0, errors.New("conflicting control roster fragments")
		}
		if revision > a.revision {
			a.reset()
		}
	}
	if len(a.parts) == 0 {
		a.revision, a.hash, a.parts, a.started = revision, hash, make([][]byte, count), now
	}
	if previous := a.parts[index]; previous != nil {
		if !bytes.Equal(previous, chunk) {
			return "", 0, errors.New("conflicting duplicate control roster fragment")
		}
		return "", 0, nil
	}
	if a.size+len(chunk) > maxEncodedSize {
		a.reset()
		return "", 0, errors.New("control roster exceeds size limit")
	}
	a.parts[index] = append([]byte(nil), chunk...)
	a.received++
	a.size += len(chunk)
	if a.received != len(a.parts) {
		return "", 0, nil
	}
	body := make([]byte, 0, a.size)
	for _, part := range a.parts {
		body = append(body, part...)
	}
	expected := a.hash
	a.reset()
	if sha256.Sum256(body) != expected {
		return "", 0, errors.New("control roster hash mismatch")
	}
	return string(body), revision, nil
}
