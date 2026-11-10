package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"directlan/internal/httpsrelay"
	"github.com/coder/websocket"
)

// Relay opens an authenticated HTTPS WebSocket transport. WireGuard remains
// the end-to-end encryption layer; the relay sees only its ciphertext.
func (c *Client) Relay(ctx context.Context, networkID, peerID string, dialer *net.Dialer, padding bool) (net.Conn, error) {
	path, err := groupPath(networkID)
	if err != nil || !safeID(peerID) {
		return nil, errors.New("invalid relay peer")
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + path + "/relay/" + peerID
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 25 * time.Second}
	}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: c.tlsConfig.Clone()}
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	nonceText := base64.RawURLEncoding.EncodeToString(nonce[:])
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	digest := sha256.Sum256(nil)
	signed := "GET\n" + u.RequestURI() + "\n" + ts + "\n" + nonceText + "\n" + hex.EncodeToString(digest[:])
	header := make(http.Header)
	header.Set("X-DirectLAN-Key", base64.RawURLEncoding.EncodeToString(c.key.Public().(ed25519.PublicKey)))
	header.Set("X-DirectLAN-Timestamp", ts)
	header.Set("X-DirectLAN-Nonce", nonceText)
	header.Set("X-DirectLAN-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, []byte(signed))))
	ws, response, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: header, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		transport.CloseIdleConnections()
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return nil, err
	}
	return httpsrelay.New(ws, padding), nil
}
