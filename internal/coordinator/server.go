package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBodySize = 64 << 10

type Server struct {
	Store            *Store
	AllowDevHTTP     bool
	EnableHTTPSRelay bool
	relay            relayHub
	rate             rateLimiter
}

type identity struct {
	Key         ed25519.PublicKey
	EncodedKey  string
	DeviceID    string
	Fingerprint string
}

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]visitor
}

type visitor struct {
	Tokens float64
	At     time.Time
}

func NewServer(store *Store, allowDevHTTP bool) *Server {
	return &Server{Store: store, AllowDevHTTP: allowDevHTTP,
		rate: rateLimiter{visitors: make(map[string]visitor)}}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if r.TLS == nil && !s.AllowDevHTTP {
		writeError(w, errAPI(http.StatusForbidden, "TLS_REQUIRED", "HTTPS is required"))
		return
	}
	if !s.rate.allow(r.RemoteAddr) {
		writeError(w, errAPI(http.StatusTooManyRequests, "RATE_LIMITED", "request rate exceeded"))
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil {
		writeError(w, errAPI(http.StatusBadRequest, "INVALID_BODY", "cannot read request body"))
		return
	}
	if len(body) > maxBodySize {
		writeError(w, errAPI(http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body exceeds 64 KiB"))
		return
	}
	id, err := s.authenticate(r, body)
	if err != nil {
		writeError(w, err)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 5 && parts[0] == "v1" && parts[1] == "groups" && parts[3] == "relay" && r.Method == http.MethodGet {
		s.serveRelay(w, r, id, parts[2], parts[4])
		return
	}
	value, status, err := s.route(r, body, id)
	if err != nil {
		var api *apiError
		if !errors.As(err, &api) {
			slog.Error("coordinator request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		}
		writeError(w, err)
		return
	}
	writeJSON(w, status, value)
}

func (l *rateLimiter) allow(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.visitors) >= 10000 {
		for key, value := range l.visitors {
			if now.Sub(value.At) > 5*time.Minute {
				delete(l.visitors, key)
			}
		}
		if _, known := l.visitors[host]; !known && len(l.visitors) >= 10000 {
			return false
		}
	}
	v, found := l.visitors[host]
	if !found {
		v = visitor{Tokens: 100, At: now}
	}
	v.Tokens += 10 * now.Sub(v.At).Seconds() // ten requests per second, burst 100
	if v.Tokens > 100 {
		v.Tokens = 100
	}
	v.At = now
	if v.Tokens < 1 {
		l.visitors[host] = v
		return false
	}
	v.Tokens--
	l.visitors[host] = v
	return true
}

func (s *Server) authenticate(r *http.Request, body []byte) (identity, error) {
	keyText := r.Header.Get("X-DirectLAN-Key")
	ts := r.Header.Get("X-DirectLAN-Timestamp")
	nonce := r.Header.Get("X-DirectLAN-Nonce")
	signatureText := r.Header.Get("X-DirectLAN-Signature")
	key, keyErr := base64.RawURLEncoding.DecodeString(keyText)
	signature, sigErr := base64.RawURLEncoding.DecodeString(signatureText)
	nonceBytes, nonceErr := base64.RawURLEncoding.DecodeString(nonce)
	seconds, timeErr := strconv.ParseInt(ts, 10, 64)
	if keyErr != nil || len(key) != ed25519.PublicKeySize || sigErr != nil || len(signature) != ed25519.SignatureSize ||
		nonceErr != nil || len(nonceBytes) < 16 || len(nonceBytes) > 32 || timeErr != nil {
		return identity{}, errAPI(http.StatusUnauthorized, "AUTH_INVALID", "invalid signature headers")
	}
	now := time.Now().Unix()
	if seconds < now-60 || seconds > now+60 {
		return identity{}, errAPI(http.StatusUnauthorized, "CLOCK_SKEW", "request timestamp is outside the 60 second window")
	}
	digest := sha256.Sum256(body)
	signed := r.Method + "\n" + r.URL.RequestURI() + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
	if !ed25519.Verify(key, []byte(signed), signature) {
		return identity{}, errAPI(http.StatusUnauthorized, "AUTH_INVALID", "signature verification failed")
	}
	nonceSum := sha256.Sum256(append(append([]byte(nil), key...), nonceBytes...))
	if err := s.Store.reserveNonce(hex.EncodeToString(nonceSum[:]), now+121, r.Method != http.MethodGet); err != nil {
		return identity{}, err
	}
	return identity{Key: key, EncodedKey: keyText, DeviceID: deviceID(key), Fingerprint: fingerprint(key)}, nil
}

func (s *Server) route(r *http.Request, body []byte, id identity) (any, int, error) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 2 && parts[0] == "v1" && parts[1] == "register" && r.Method == http.MethodPost {
		value, err := s.register(body, id)
		return value, http.StatusOK, err
	}
	if len(parts) == 2 && parts[0] == "v1" && parts[1] == "groups" && r.Method == http.MethodPost {
		value, err := s.createGroup(body, id)
		return value, http.StatusCreated, err
	}
	if len(parts) == 2 && parts[0] == "v1" && parts[1] == "join" && r.Method == http.MethodPost {
		value, err := s.join(body, id)
		return value, http.StatusAccepted, err
	}
	if len(parts) < 3 || parts[0] != "v1" || parts[1] != "groups" {
		return nil, 0, errAPI(http.StatusNotFound, "NOT_FOUND", "unknown endpoint")
	}
	networkID := parts[2]
	if len(parts) == 3 && r.Method == http.MethodGet {
		value, err := s.snapshot(networkID, id)
		return value, http.StatusOK, err
	}
	if len(parts) == 4 && parts[3] == "heartbeat" && r.Method == http.MethodGet {
		value, err := s.heartbeat(networkID, id)
		return value, http.StatusOK, err
	}
	if len(parts) == 4 && parts[3] == "invitations" && r.Method == http.MethodPost {
		value, err := s.invite(networkID, body, id)
		return value, http.StatusCreated, err
	}
	if len(parts) == 4 && parts[3] == "pending" && r.Method == http.MethodGet {
		value, err := s.listPending(networkID, id)
		return value, http.StatusOK, err
	}
	if len(parts) == 6 && parts[3] == "pending" && parts[5] == "approve" && r.Method == http.MethodPost {
		value, err := s.approve(networkID, parts[4], body, id)
		return value, http.StatusOK, err
	}
	if len(parts) == 5 && parts[3] == "members" && r.Method == http.MethodDelete {
		value, err := s.revoke(networkID, parts[4], id)
		return value, http.StatusOK, err
	}
	if len(parts) == 4 && parts[3] == "signals" && r.Method == http.MethodPost {
		value, err := s.postSignal(networkID, body, id)
		return value, http.StatusCreated, err
	}
	if len(parts) == 4 && parts[3] == "signals" && r.Method == http.MethodGet {
		value, err := s.getSignals(r.Context(), networkID, r.URL.Query(), id)
		return value, http.StatusOK, err
	}
	return nil, 0, errAPI(http.StatusNotFound, "NOT_FOUND", "unknown endpoint")
}

func decodeBody(body []byte, out any) error {
	if len(body) == 0 {
		return errAPI(http.StatusBadRequest, "INVALID_BODY", "JSON body is required")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errAPI(http.StatusBadRequest, "INVALID_BODY", "invalid JSON body")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errAPI(http.StatusBadRequest, "INVALID_BODY", "trailing JSON is not allowed")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	var api *apiError
	if errors.As(err, &api) {
		writeJSON(w, api.Status, api)
		return
	}
	writeJSON(w, http.StatusInternalServerError,
		apiError{Code: "INTERNAL", Message: "internal coordinator error"})
}

func requireOwner(g *group, id identity) error {
	if g.OwnerDeviceID != id.DeviceID {
		return errAPI(http.StatusForbidden, "OWNER_REQUIRED", "group owner authorization is required")
	}
	return requireMember(g, id)
}

func requireMember(g *group, id identity) error {
	member, ok := g.Members[id.DeviceID]
	if !ok || member.IdentityPublicKey != id.EncodedKey {
		return errAPI(http.StatusForbidden, "NOT_MEMBER", "device is not an approved member")
	}
	return nil
}

func lookupGroup(st *state, networkID string) (*group, error) {
	g, ok := st.Groups[networkID]
	if !ok {
		return nil, errAPI(http.StatusNotFound, "NETWORK_NOT_FOUND", "group does not exist")
	}
	return g, nil
}
