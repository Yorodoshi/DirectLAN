package coordinator

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store persists coordinator metadata, not keys or tunnel traffic. A Store must
// be used by only one coordinator process at a time.
type Store struct {
	mu        sync.RWMutex
	path      string
	data      state
	readNonce map[string]int64
	changed   chan struct{}
}

func OpenStore(path string) (*Store, error) {
	s := &Store{
		path:      path,
		data:      state{Groups: make(map[string]*group), Registered: make(map[string]Registration), Replay: make(map[string]int64)},
		readNonce: make(map[string]int64),
		changed:   make(chan struct{}),
	}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.data); err != nil {
		return nil, fmt.Errorf("decode coordinator state: %w", err)
	}
	if s.data.Groups == nil {
		s.data.Groups = make(map[string]*group)
	}
	if s.data.Registered == nil {
		s.data.Registered = make(map[string]Registration)
	}
	if s.data.Replay == nil {
		s.data.Replay = make(map[string]int64)
	}
	return s, nil
}

func (s *Store) mutate(fn func(*state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	encoded, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	var next state
	if err := json.Unmarshal(encoded, &next); err != nil {
		return err
	}
	if err := fn(&next); err != nil {
		return err
	}
	if err := s.persist(next); err != nil {
		return err
	}
	s.data = next
	close(s.changed)
	s.changed = make(chan struct{})
	return nil
}

// A signed write nonce is durable before the write is applied. This prevents
// replay after a coordinator restart within the clock-skew window.
func (s *Store) reserveNonce(key string, expiresAt int64, write bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for k, expiry := range s.readNonce {
		if expiry <= now {
			delete(s.readNonce, k)
		}
	}
	for k, expiry := range s.data.Replay {
		if expiry <= now {
			delete(s.data.Replay, k)
		}
	}
	if s.readNonce[key] > now || s.data.Replay[key] > now {
		return errAPI(409, "REPLAY", "request nonce was already used")
	}
	if len(s.data.Replay)+len(s.readNonce) >= 100000 {
		return errAPI(429, "RATE_LIMITED", "too many recent requests")
	}
	if !write {
		s.readNonce[key] = expiresAt
		return nil
	}
	s.data.Replay[key] = expiresAt
	if err := s.persist(s.data); err != nil {
		delete(s.data.Replay, key)
		return err
	}
	return nil
}

func (s *Store) persist(data state) error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	contents, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if len(contents) > 32<<20 {
		return errAPI(429, "CAPACITY", "coordinator state capacity reached")
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".directlan-state-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(temp, s.path)
}

func randomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
