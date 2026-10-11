package provider_test

import (
	"context"
	"testing"
	"time"

	"github.com/atsvetko/directory-auditor/internal/provider"
	_ "github.com/atsvetko/directory-auditor/internal/provider/ad"
	_ "github.com/atsvetko/directory-auditor/internal/provider/freeipa"
)

// ad and samba are registered as separate providers (plus freeipa).
func TestSeparateProvidersRegistered(t *testing.T) {
	have := map[string]bool{}
	for _, n := range provider.Names() {
		have[n] = true
	}
	for _, want := range []string{"ad", "samba", "freeipa"} {
		if !have[want] {
			t.Errorf("provider %q not registered; have %v", want, provider.Names())
		}
	}
	if ad, _ := provider.Get("ad"); ad == nil || ad.Name() != "ad" {
		t.Error("ad provider missing")
	}
	if sm, _ := provider.Get("samba"); sm == nil || sm.Name() != "samba" {
		t.Error("samba provider is not a separate provider")
	}
}

func TestPickUnknownProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, _, err := provider.Pick(ctx, "nope", provider.Target{Server: "127.0.0.1:1"}); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

// With an explicit provider but no reachable server, detection is inconclusive,
// so Pick honours the name as a fallback and says it could not confirm the type.
func TestPickExplicitFallbackWhenUndetected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, _, note, err := provider.Pick(ctx, "samba", provider.Target{Server: "127.0.0.1:1", TLS: "none"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil || p.Name() != "samba" {
		t.Fatalf("expected samba fallback, got %v", p)
	}
	if note == "" {
		t.Error("expected a note that the directory type could not be confirmed")
	}
}
