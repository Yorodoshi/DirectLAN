//go:build windows

package directpair

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestSTUNSamplesBothProvidersAndDeduplicatesMappings(t *testing.T) {
	for _, different := range []bool{false, true} {
		queries, lookups := 0, 0
		lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			lookups++
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 1800*time.Millisecond {
				t.Fatal("provider lookup was not bounded")
			}
			if network != "ip4" || host == "" {
				t.Fatal("STUN provider lookup changed")
			}
			return []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("1.1.1.1")}, nil
		}
		query := func(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
			queries++
			if ctx.Err() != nil || !PublicEndpoint(server) {
				t.Fatal("invalid or expired STUN query")
			}
			port := uint16(50001)
			if different && queries == 2 {
				port++
			}
			return netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), port), nil
		}
		endpoints, report := sampleSTUNMappings(context.Background(), lookup, query)
		want, result := 1, "samples_match"
		if different {
			want, result = 2, "different_observations"
		}
		if lookups != 2 || queries != 2 || len(endpoints) != want || report.Samples != 2 || report.Distinct != want || report.Result != result {
			t.Fatalf("first success stopped sampling or duplicates were retained: %+v, calls=%d/%d", report, lookups, queries)
		}
	}
}

func TestSTUNFailedSamplesDoNotClaimMappingClassification(t *testing.T) {
	for _, mode := range []string{"lookup_error", "query_error", "private", "single"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			lookup := func(context.Context, string, string) ([]netip.Addr, error) {
				if mode == "lookup_error" {
					calls++
					return nil, errors.New("DNS failure")
				}
				return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
			}
			query := func(context.Context, netip.AddrPort) (netip.AddrPort, error) {
				calls++
				if mode == "single" && calls == 1 {
					return netip.MustParseAddrPort("8.8.8.8:50001"), nil
				}
				if mode == "private" {
					return netip.MustParseAddrPort("192.168.1.2:50001"), nil
				}
				return netip.AddrPort{}, context.DeadlineExceeded
			}
			endpoints, report := sampleSTUNMappings(context.Background(), lookup, query)
			want, result := 0, "no_reply"
			if mode == "single" {
				want, result = 1, "single_observation"
			}
			if calls != 2 || len(endpoints) != want || report.Samples != want || report.Distinct != want || report.Result != result {
				t.Fatalf("failed observations produced an unsupported classification: %+v", report)
			}
		})
	}
}

func TestSTUNSamplingRespectsParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	queries := 0
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	query := func(ctx context.Context, _ netip.AddrPort) (netip.AddrPort, error) {
		queries++
		<-ctx.Done()
		return netip.AddrPort{}, ctx.Err()
	}
	started := time.Now()
	endpoints, report := sampleSTUNMappings(ctx, lookup, query)
	if time.Since(started) > time.Second || queries != 1 || len(endpoints) != 0 || report.Result != "no_reply" || report.Samples != 0 {
		t.Fatalf("deadline was ignored or interpreted as a NAT type: %+v", report)
	}
}
