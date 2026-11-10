package peerice

import (
	"testing"
	"time"
)

func TestOfferExpiry(t *testing.T) {
	now := time.Now()
	o := Offer{Ufrag: "u", Password: "p", Candidates: []string{"candidate:1 1 udp 1 127.0.0.1 5000 typ host"}, ExpiresAt: now.Add(-time.Second)}
	if err := o.Validate(now); err == nil {
		t.Fatal("expired ICE offer was accepted")
	}
	o.ExpiresAt = now.Add(10 * time.Minute)
	if err := o.Validate(now); err == nil {
		t.Fatal("overlong ICE offer was accepted")
	}
}
