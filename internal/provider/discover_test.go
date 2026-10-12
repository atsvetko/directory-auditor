package provider

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func stubDNS(t *testing.T, records map[string][]*net.SRV, up map[string]bool) {
	t.Helper()
	oldL, oldR := lookupSRV, reachable
	t.Cleanup(func() { lookupSRV, reachable = oldL, oldR })
	lookupSRV = func(_ context.Context, name string) ([]*net.SRV, error) {
		if r, ok := records[name]; ok {
			return r, nil
		}
		return nil, errors.New("no such host")
	}
	reachable = func(_ context.Context, h string) bool { return up[h] }
}

func TestDiscoverPrefersDCRecordAndOrders(t *testing.T) {
	stubDNS(t, map[string][]*net.SRV{
		"_ldap._tcp.dc._msdcs.corp.example": {
			{Target: "dc2.corp.example.", Priority: 0, Weight: 50},
			{Target: "dc3.corp.example.", Priority: 10, Weight: 100},
			{Target: "DC1.corp.example.", Priority: 0, Weight: 100},
			{Target: "dc1.corp.example.", Priority: 0, Weight: 100}, // duplicate, other case
		},
		"_ldap._tcp.corp.example": {{Target: "ldap.corp.example."}}, // generic LDAP must not win
	}, nil)
	hosts, rec, err := DiscoverDCs(context.Background(), " Corp.Example. ")
	if err != nil {
		t.Fatal(err)
	}
	if rec != "_ldap._tcp.dc._msdcs.corp.example" {
		t.Errorf("record = %s", rec)
	}
	if got := strings.Join(hosts, ","); got != "dc1.corp.example,dc2.corp.example,dc3.corp.example" {
		t.Errorf("order = %s", got)
	}
}

func TestDiscoverFallsBackToGenericRecord(t *testing.T) {
	stubDNS(t, map[string][]*net.SRV{"_ldap._tcp.ipa.example": {{Target: "ipa1.ipa.example."}}}, nil)
	h, rec, err := DiscoverDC(context.Background(), "ipa.example")
	if err != nil || h != "ipa1.ipa.example" || rec != "_ldap._tcp.ipa.example" {
		t.Fatalf("got %q %q %v", h, rec, err)
	}
}

func TestDiscoverSkipsUnreachableDC(t *testing.T) {
	stubDNS(t, map[string][]*net.SRV{"_ldap._tcp.dc._msdcs.da.test": {
		{Target: "down.da.test.", Priority: 0}, {Target: "up.da.test.", Priority: 5},
	}}, map[string]bool{"up.da.test": true})
	if h, _, _ := DiscoverDC(context.Background(), "da.test"); h != "up.da.test" {
		t.Fatalf("picked %s, want the reachable DC", h)
	}
	// none reachable: first in SRV order, the dial then reports the real error
	stubDNS(t, map[string][]*net.SRV{"_ldap._tcp.dc._msdcs.da.test": {{Target: "a.da.test."}, {Target: "b.da.test.", Priority: 1}}}, nil)
	if h, _, _ := DiscoverDC(context.Background(), "da.test"); h != "a.da.test" {
		t.Fatalf("picked %s, want first in SRV order", h)
	}
}

func TestDiscoverNoRecordsExplains(t *testing.T) {
	stubDNS(t, nil, nil)
	_, _, err := DiscoverDC(context.Background(), "nowhere.test")
	if err == nil || !strings.Contains(err.Error(), "--server") || !strings.Contains(err.Error(), "_ldap._tcp.dc._msdcs.nowhere.test") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveServer(t *testing.T) {
	stubDNS(t, map[string][]*net.SRV{"_ldap._tcp.dc._msdcs.da.test": {{Target: "da-dc01.da.test."}}}, map[string]bool{"da-dc01.da.test": true})
	tg := Target{Domain: "da.test"}
	note, err := ResolveServer(context.Background(), &tg)
	if err != nil || tg.Server != "da-dc01.da.test" || !strings.Contains(note, "da-dc01.da.test") {
		t.Fatalf("server=%q note=%q err=%v", tg.Server, note, err)
	}
	given := Target{Domain: "da.test", Server: "10.55.0.10"}
	if note, _ := ResolveServer(context.Background(), &given); note != "" || given.Server != "10.55.0.10" {
		t.Fatalf("an explicit --server must be kept: %q %q", given.Server, note)
	}
	if _, err := ResolveServer(context.Background(), &Target{}); err == nil {
		t.Fatal("no domain and no server must be an error")
	}
}
