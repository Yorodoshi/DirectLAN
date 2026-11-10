package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type testIdentity struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
	WGKey   string
}

func makeIdentity(t *testing.T) testIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wg := make([]byte, 32)
	if _, err := rand.Read(wg); err != nil {
		t.Fatal(err)
	}
	return testIdentity{pub, priv, base64.StdEncoding.EncodeToString(wg)}
}

func signedRequest(t *testing.T, signer testIdentity, method, path string, body []byte, nonce string) *http.Request {
	t.Helper()
	if nonce == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		nonce = base64.RawURLEncoding.EncodeToString(b)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	hash := sha256.Sum256(body)
	message := method + "\n" + req.URL.RequestURI() + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(hash[:])
	req.Header.Set("X-DirectLAN-Key", base64.RawURLEncoding.EncodeToString(signer.Public))
	req.Header.Set("X-DirectLAN-Timestamp", ts)
	req.Header.Set("X-DirectLAN-Nonce", nonce)
	req.Header.Set("X-DirectLAN-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.Private, []byte(message))))
	return req
}

func call(t *testing.T, s *Server, signer testIdentity, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, signedRequest(t, signer, method, path, encoded, ""))
	return w
}

func expectStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d, want %d: %s", w.Code, want, w.Body.String())
	}
}

func decodeResponse[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func createTestGroup(t *testing.T, s *Server, owner testIdentity) Snapshot {
	t.Helper()
	w := call(t, s, owner, http.MethodPost, "/v1/groups", map[string]any{
		"name": "Friends", "network_cidr": "10.42.17.0/24",
		"public_key": owner.WGKey, "overlay_ip": "10.42.17.1", "device_name": "Owner",
	})
	expectStatus(t, w, http.StatusCreated)
	return decodeResponse[Snapshot](t, w)
}

func TestMembershipAndSignaling(t *testing.T) {
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(store, true)
	owner := makeIdentity(t)
	peer := makeIdentity(t)
	registered := call(t, s, owner, http.MethodPost, "/v1/register", map[string]any{"device_name": "Owner"})
	expectStatus(t, registered, http.StatusOK)
	registration := decodeResponse[Registration](t, registered)
	if registration.DeviceID != deviceID(owner.Public) || registration.Fingerprint != fingerprint(owner.Public) {
		t.Fatalf("unexpected registration: %+v", registration)
	}
	g := createTestGroup(t, s, owner)
	if g.Revision != 1 || len(g.Members) != 1 || g.OwnerDeviceID != deviceID(owner.Public) {
		t.Fatalf("unexpected initial snapshot: %+v", g)
	}
	heartbeat := call(t, s, owner, http.MethodGet, "/v1/groups/"+g.NetworkID+"/heartbeat", nil)
	expectStatus(t, heartbeat, http.StatusOK)

	invite := call(t, s, owner, http.MethodPost, "/v1/groups/"+g.NetworkID+"/invitations", nil)
	expectStatus(t, invite, http.StatusCreated)
	var invitation struct {
		Invitation string `json:"invitation"`
	}
	invitation = decodeResponse[struct {
		Invitation string `json:"invitation"`
	}](t, invite)
	joinBody := map[string]any{"invitation": invitation.Invitation, "public_key": peer.WGKey, "device_name": "Peer"}
	joined := call(t, s, peer, http.MethodPost, "/v1/join", joinBody)
	expectStatus(t, joined, http.StatusAccepted)
	var join struct {
		PendingID string `json:"pending_id"`
	}
	join = decodeResponse[struct {
		PendingID string `json:"pending_id"`
	}](t, joined)
	if join.PendingID == "" {
		t.Fatal("missing pending ID")
	}
	secondJoin := call(t, s, peer, http.MethodPost, "/v1/join", joinBody)
	expectStatus(t, secondJoin, http.StatusNotFound)
	preApproval := call(t, s, peer, http.MethodGet, "/v1/groups/"+g.NetworkID, nil)
	expectStatus(t, preApproval, http.StatusForbidden)

	pendingList := call(t, s, owner, http.MethodGet, "/v1/groups/"+g.NetworkID+"/pending", nil)
	expectStatus(t, pendingList, http.StatusOK)
	var pendingResult struct {
		Pending []PendingInfo `json:"pending"`
	}
	pendingResult = decodeResponse[struct {
		Pending []PendingInfo `json:"pending"`
	}](t, pendingList)
	if len(pendingResult.Pending) != 1 || pendingResult.Pending[0].Fingerprint != fingerprint(peer.Public) {
		t.Fatalf("unexpected pending request: %+v", pendingResult)
	}
	approvePath := "/v1/groups/" + g.NetworkID + "/pending/" + join.PendingID + "/approve"
	wrong := call(t, s, owner, http.MethodPost, approvePath, map[string]any{
		"fingerprint": fingerprint(owner.Public), "overlay_ip": "10.42.17.2",
	})
	expectStatus(t, wrong, http.StatusConflict)
	approved := call(t, s, owner, http.MethodPost, approvePath, map[string]any{
		"fingerprint": fingerprint(peer.Public), "overlay_ip": "10.42.17.2",
	})
	expectStatus(t, approved, http.StatusOK)
	updated := decodeResponse[Snapshot](t, approved)
	if updated.Revision != 2 || len(updated.Members) != 2 {
		t.Fatalf("unexpected approved snapshot: %+v", updated)
	}

	expiry := time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	signalBody := map[string]any{
		"to_device_id": deviceID(peer.Public), "ice_ufrag": "abcd1234", "ice_pwd": "abcdefghijklmnopqrstuvwxyz",
		"candidates": []string{"candidate:1 1 udp 1234 192.0.2.1 12345 typ host"},
		"generation": 1, "expires_at": expiry,
	}
	posted := call(t, s, owner, http.MethodPost, "/v1/groups/"+g.NetworkID+"/signals", signalBody)
	expectStatus(t, posted, http.StatusCreated)
	got := call(t, s, peer, http.MethodGet, "/v1/groups/"+g.NetworkID+"/signals?after=0&after_revision=2&wait=0", nil)
	expectStatus(t, got, http.StatusOK)
	result := decodeResponse[signalsResponse](t, got)
	if len(result.Signals) != 1 || result.Signals[0].FromDeviceID != deviceID(owner.Public) {
		t.Fatalf("unexpected signals: %+v", result)
	}
	signalBody["payload"] = "user packet"
	rejected := call(t, s, owner, http.MethodPost, "/v1/groups/"+g.NetworkID+"/signals", signalBody)
	expectStatus(t, rejected, http.StatusBadRequest)

	revoked := call(t, s, owner, http.MethodDelete, "/v1/groups/"+g.NetworkID+"/members/"+deviceID(peer.Public), nil)
	expectStatus(t, revoked, http.StatusOK)
	revokedSnapshot := decodeResponse[Snapshot](t, revoked)
	if revokedSnapshot.Revision != 3 || len(revokedSnapshot.Members) != 1 {
		t.Fatalf("unexpected revoked snapshot: %+v", revokedSnapshot)
	}
	afterRevocation := call(t, s, peer, http.MethodGet, "/v1/groups/"+g.NetworkID, nil)
	expectStatus(t, afterRevocation, http.StatusForbidden)
}

func TestReplayTamperAndDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordinator.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(store, true)
	owner := makeIdentity(t)
	body, _ := json.Marshal(map[string]any{
		"name": "Friends", "network_cidr": "10.42.17.0/24",
		"public_key": owner.WGKey, "overlay_ip": "10.42.17.1", "device_name": "Owner",
	})
	nonceBytes := bytes.Repeat([]byte{7}, 16)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	req := signedRequest(t, owner, http.MethodPost, "/v1/groups", body, nonce)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	expectStatus(t, w, http.StatusCreated)
	created := decodeResponse[Snapshot](t, w)

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewServer(reopened, true)
	replay := httptest.NewRecorder()
	restarted.ServeHTTP(replay, signedRequest(t, owner, http.MethodPost, "/v1/groups", body, nonce))
	expectStatus(t, replay, http.StatusConflict)
	read := call(t, restarted, owner, http.MethodGet, "/v1/groups/"+created.NetworkID, nil)
	expectStatus(t, read, http.StatusOK)

	tampered := signedRequest(t, owner, http.MethodPost, "/v1/groups", body, "")
	tampered.Body = ioNopCloser(bytes.NewReader([]byte(`{"name":"tampered"}`)))
	bad := httptest.NewRecorder()
	restarted.ServeHTTP(bad, tampered)
	expectStatus(t, bad, http.StatusUnauthorized)
}

// Keep the request body edit in TestReplayTamperAndDurability explicit.
func ioNopCloser(r *bytes.Reader) *readerCloser { return &readerCloser{r} }

type readerCloser struct{ *bytes.Reader }

func (*readerCloser) Close() error { return nil }

func TestOverlayValidation(t *testing.T) {
	cases := []struct {
		cidr string
		ip   string
		ok   bool
	}{
		{"10.1.0.0/24", "10.1.0.1", true},
		{"10.1.0.0/24", "10.1.0.0", false},
		{"10.1.0.0/24", "10.1.0.255", false},
		{"100.64.0.0/24", "100.64.0.1", false},
		{"192.168.1.0/28", "192.168.1.14", true},
		{"192.168.1.0/28", "192.168.1.15", false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_%s", tc.cidr, tc.ip), func(t *testing.T) {
			if got := validOverlayIP(tc.cidr, tc.ip); got != tc.ok {
				t.Fatalf("validOverlayIP(%q, %q) = %t, want %t", tc.cidr, tc.ip, got, tc.ok)
			}
		})
	}
}
