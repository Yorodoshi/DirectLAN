// Package client signs coordinator API requests with the device's Ed25519 key.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"directlan/internal/coordinator"
)

type Client struct {
	baseURL   *url.URL
	key       ed25519.PrivateKey
	http      *http.Client
	tlsConfig *tls.Config
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

func New(rawURL string, key ed25519.PrivateKey, allowLocalHTTP bool) (*Client, error) {
	base, err := url.Parse(rawURL)
	if err != nil || base.Host == "" || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return nil, errors.New("invalid coordinator URL")
	}
	if base.Scheme != "https" && !(allowLocalHTTP && base.Scheme == "http" && (base.Hostname() == "localhost" || base.Hostname() == "127.0.0.1" || base.Hostname() == "::1")) {
		return nil, errors.New("coordinator requires HTTPS")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid identity private key")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	return &Client{baseURL: base, key: append(ed25519.PrivateKey(nil), key...), tlsConfig: tlsConfig, http: &http.Client{
		Transport:     &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig},
		Timeout:       35 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *Client) SetTrustedCA(pem []byte) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("CA file contains no valid certificates")
	}
	c.tlsConfig.RootCAs = pool
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, request, response any) error {
	ref, err := url.Parse(path)
	if err != nil || ref.IsAbs() || ref.Host != "" || !strings.HasPrefix(ref.Path, "/v1/") {
		return errors.New("invalid coordinator API path")
	}
	ref.Path = strings.TrimRight(c.baseURL.Path, "/") + ref.Path
	u := c.baseURL.ResolveReference(ref)
	var payload []byte
	if request != nil {
		payload, err = json.Marshal(request)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	nonceText := base64.RawURLEncoding.EncodeToString(nonce[:])
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	digest := sha256.Sum256(payload)
	signed := method + "\n" + req.URL.RequestURI() + "\n" + ts + "\n" + nonceText + "\n" + hex.EncodeToString(digest[:])
	req.Header.Set("X-DirectLAN-Key", base64.RawURLEncoding.EncodeToString(c.key.Public().(ed25519.PublicKey)))
	req.Header.Set("X-DirectLAN-Timestamp", ts)
	req.Header.Set("X-DirectLAN-Nonce", nonceText)
	req.Header.Set("X-DirectLAN-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, []byte(signed))))
	req.Header.Set("Accept", "application/json")
	if request != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 2<<20+1))
	if err != nil {
		return err
	}
	if len(body) > 2<<20 {
		return errors.New("coordinator response exceeds 2 MiB")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var api APIError
		if json.Unmarshal(body, &api) == nil && api.Code != "" {
			return &api
		}
		return fmt.Errorf("coordinator returned HTTP %d", res.StatusCode)
	}
	if response == nil {
		return nil
	}
	return json.Unmarshal(body, response)
}

func safeID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func groupPath(id string) (string, error) {
	if !safeID(id) {
		return "", errors.New("invalid network ID")
	}
	return "/v1/groups/" + id, nil
}

func (c *Client) CreateGroup(ctx context.Context, name, cidr, wgPublicKey, overlayIP string, deviceNames ...string) (coordinator.Snapshot, error) {
	var out coordinator.Snapshot
	request := map[string]string{
		"name": name, "network_cidr": cidr, "public_key": wgPublicKey, "overlay_ip": overlayIP,
	}
	if len(deviceNames) > 0 {
		request["device_name"] = deviceNames[0]
	}
	err := c.do(ctx, http.MethodPost, "/v1/groups", request, &out)
	return out, err
}

func (c *Client) Register(ctx context.Context, name string) (coordinator.Registration, error) {
	var out coordinator.Registration
	err := c.do(ctx, http.MethodPost, "/v1/register", map[string]string{"device_name": name}, &out)
	return out, err
}

type Heartbeat struct {
	NetworkID  string    `json:"network_id"`
	Revision   uint64    `json:"revision"`
	ServerTime time.Time `json:"server_time"`
}

func (c *Client) Heartbeat(ctx context.Context, networkID string) (Heartbeat, error) {
	path, err := groupPath(networkID)
	if err != nil {
		return Heartbeat{}, err
	}
	var out Heartbeat
	err = c.do(ctx, http.MethodGet, path+"/heartbeat", nil, &out)
	return out, err
}

type Invitation struct {
	Invitation string    `json:"invitation"`
	NetworkID  string    `json:"network_id"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (c *Client) CreateInvitation(ctx context.Context, networkID string) (Invitation, error) {
	path, err := groupPath(networkID)
	if err != nil {
		return Invitation{}, err
	}
	var out Invitation
	err = c.do(ctx, http.MethodPost, path+"/invitations", struct{}{}, &out)
	return out, err
}

type JoinResult struct {
	PendingID              string    `json:"pending_id"`
	NetworkID              string    `json:"network_id"`
	NetworkCIDR            string    `json:"network_cidr"`
	OwnerIdentityPublicKey string    `json:"owner_identity_public_key"`
	OwnerFingerprint       string    `json:"owner_fingerprint"`
	ExpiresAt              time.Time `json:"expires_at"`
}

func (c *Client) Join(ctx context.Context, invitation, wgPublicKey, deviceName string) (JoinResult, error) {
	var out JoinResult
	err := c.do(ctx, http.MethodPost, "/v1/join", map[string]string{
		"invitation": invitation, "public_key": wgPublicKey, "device_name": deviceName,
	}, &out)
	return out, err
}

func (c *Client) Group(ctx context.Context, networkID string) (coordinator.Snapshot, error) {
	path, err := groupPath(networkID)
	if err != nil {
		return coordinator.Snapshot{}, err
	}
	var out coordinator.Snapshot
	err = c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

func (c *Client) Pending(ctx context.Context, networkID string) ([]coordinator.PendingInfo, error) {
	path, err := groupPath(networkID)
	if err != nil {
		return nil, err
	}
	var out struct {
		Pending []coordinator.PendingInfo `json:"pending"`
	}
	err = c.do(ctx, http.MethodGet, path+"/pending", nil, &out)
	return out.Pending, err
}

func (c *Client) Approve(ctx context.Context, networkID, pendingID, fingerprint, overlayIP string) (coordinator.Snapshot, error) {
	path, err := groupPath(networkID)
	if err != nil || !safeID(pendingID) {
		return coordinator.Snapshot{}, errors.New("invalid network or pending ID")
	}
	var out coordinator.Snapshot
	err = c.do(ctx, http.MethodPost, path+"/pending/"+pendingID+"/approve", map[string]string{
		"fingerprint": fingerprint, "overlay_ip": overlayIP,
	}, &out)
	return out, err
}

func (c *Client) Revoke(ctx context.Context, networkID, deviceID string) (coordinator.Snapshot, error) {
	path, err := groupPath(networkID)
	if err != nil || !safeID(deviceID) {
		return coordinator.Snapshot{}, errors.New("invalid network or device ID")
	}
	var out coordinator.Snapshot
	err = c.do(ctx, http.MethodDelete, path+"/members/"+deviceID, nil, &out)
	return out, err
}

type SignalsResult struct {
	Revision uint64               `json:"revision"`
	Members  []coordinator.Member `json:"members"`
	Signals  []coordinator.Signal `json:"signals"`
}

func (c *Client) Signals(ctx context.Context, networkID string, after, revision uint64, waitSeconds int) (SignalsResult, error) {
	path, err := groupPath(networkID)
	if err != nil {
		return SignalsResult{}, err
	}
	if waitSeconds < 0 || waitSeconds > 25 {
		return SignalsResult{}, errors.New("invalid long-poll wait")
	}
	var out SignalsResult
	query := "?after=" + strconv.FormatUint(after, 10) + "&after_revision=" + strconv.FormatUint(revision, 10) + "&wait=" + strconv.Itoa(waitSeconds)
	err = c.do(ctx, http.MethodGet, path+"/signals"+query, nil, &out)
	return out, err
}

func (c *Client) SendSignal(ctx context.Context, networkID, to string, offer coordinator.Signal) (uint64, error) {
	path, err := groupPath(networkID)
	if err != nil || !safeID(to) {
		return 0, errors.New("invalid network or recipient ID")
	}
	var out struct {
		Seq uint64 `json:"seq"`
	}
	err = c.do(ctx, http.MethodPost, path+"/signals", map[string]any{
		"to_device_id": to,
		"ice_ufrag":    offer.ICEUfrag,
		"ice_pwd":      offer.ICEPwd,
		"candidates":   offer.Candidates,
		"generation":   offer.Generation,
		"expires_at":   offer.ExpiresAt,
	}, &out)
	return out.Seq, err
}
