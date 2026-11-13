//go:build windows

package mesh

import (
	"errors"
	"strings"
	"testing"
	"time"

	"directlan/internal/tunnel"
)

func TestProbeDiagnosisSeparatesObservedStages(t *testing.T) {
	now := time.Now()
	timeout := errors.New("probe: stage=reply_timeout")
	for _, tt := range []struct {
		name        string
		err         error
		stats       tunnel.PeerStats
		after       tunnel.PeerDiagnostics
		stage, text string
	}{
		{"local routing", timeout, tunnel.PeerStats{}, tunnel.PeerDiagnostics{}, "local_route", "маршрутов"},
		{"no handshake", timeout, tunnel.PeerStats{}, tunnel.PeerDiagnostics{OutboundPackets: 1}, "reply_timeout", "не получено"},
		{"fresh handshake data loss", timeout, tunnel.PeerStats{LastHandshake: now}, tunnel.PeerDiagnostics{OutboundPackets: 1}, "reply_timeout", "фильтрация"},
		{"stale handshake", timeout, tunnel.PeerStats{LastHandshake: now.Add(-4 * time.Minute)}, tunnel.PeerDiagnostics{OutboundPackets: 1}, "reply_timeout", "устарело"},
		{"windows delivery", timeout, tunnel.PeerStats{LastHandshake: now}, tunnel.PeerDiagnostics{OutboundPackets: 1, InboundPackets: 1}, "reply_timeout", "Windows не вернула"},
		{"echo request arrived", timeout, tunnel.PeerStats{LastHandshake: now}, tunnel.PeerDiagnostics{OutboundPackets: 1, InboundPackets: 1, EchoRequests: 1, EchoReplies: 1}, "reply_timeout", "от участника приходят"},
		{"Wintun write", timeout, tunnel.PeerStats{}, tunnel.PeerDiagnostics{WriteErrors: 1}, "adapter_write", "не приняла"},
		{"policy rejected", timeout, tunnel.PeerStats{}, tunnel.PeerDiagnostics{InboundDrops: 1}, "packet_policy", "адресов"},
		{"socket failure", errors.New("probe: stage=open_socket"), tunnel.PeerStats{}, tunnel.PeerDiagnostics{}, "open_socket", "не смогла"},
		{"bad reply with inbound packet", errors.New("probe: stage=bad_reply"), tunnel.PeerStats{LastHandshake: now}, tunnel.PeerDiagnostics{OutboundPackets: 1, InboundPackets: 1}, "bad_reply", "Полученный ответ"},
		{"accounting with inbound packet", errors.New("probe: stage=no_stats_delta"), tunnel.PeerStats{LastHandshake: now}, tunnel.PeerDiagnostics{OutboundPackets: 1, InboundPackets: 1}, "no_stats_delta", "счётчиками"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stage, text := describeProbeFailure(tt.err, tt.stats, tunnel.PeerDiagnostics{}, tt.after, now)
			if stage != tt.stage || !strings.Contains(text, tt.text) {
				t.Fatalf("stage=%q text=%q", stage, text)
			}
		})
	}
	if counterDelta(5, 2) != 0 || counterDelta(2, 5) != 3 {
		t.Fatal("counter reset underflow")
	}
}

func TestTransportDiagnosisUsesAuthenticatedPeerCountersOnly(t *testing.T) {
	d := tunnel.TransportDiagnostics{PeerAttributed: true, InitiationIn: 4, ResponseOut: 4}
	stage, _ := describeTransportFailure("reply_timeout", "original", tunnel.PeerStats{}, d)
	if stage != "handshake_incomplete" {
		t.Fatal(stage)
	}
	d.ResponseIn = 1
	stage, _ = describeTransportFailure("reply_timeout", "original", tunnel.PeerStats{}, d)
	if stage != "wireguard_response_unconfirmed" {
		t.Fatal(stage)
	}
	d.PeerAttributed = false
	stage, detail := describeTransportFailure("reply_timeout", "original", tunnel.PeerStats{}, d)
	if stage != "reply_timeout" || detail != "original" {
		t.Fatal("unattributed socket traffic blamed on peer")
	}
	d.PeerAttributed = true
	stage, _ = describeTransportFailure("local_route", "original", tunnel.PeerStats{}, d)
	if stage != "local_route" {
		t.Fatal("strong local evidence was hidden")
	}
	stage, _ = describeTransportFailure("reply_timeout", "original", tunnel.PeerStats{LastHandshake: time.Now()}, d)
	if stage != "reply_timeout" {
		t.Fatal("completed handshake reported as rejected")
	}
}
