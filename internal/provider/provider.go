// Package provider defines the directory-provider interface and the registry.
// Providers collect snapshots; they never evaluate checks.
package provider

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// Target describes what to collect from and with which identity.
type Target struct {
	Server            string // host or host:port; empty = discover from Domain
	Domain            string // DNS domain name
	UseLDAPS          bool
	StartTLS          bool
	InsecurePlaintext bool
	PinSHA256         string
	BindUser          string // empty = current logon (Kerberos; not yet implemented)
	BindPassword      string // used once, never stored
	Tier              int    // 0 = user LDAP only (default)
	MaxQPS            int
}

// Provider is implemented per directory family (ad, samba, freeipa, openldap, entra).
type Provider interface {
	// Name is the stable identifier used in packs' `provider:` field.
	Name() string
	// Detect inspects a server (rootDSE and friends) and returns true when this
	// provider should handle it, with a dialect string for the snapshot.
	Detect(ctx context.Context, t Target) (match bool, dialect string, err error)
	// Collect performs a read-only collection and returns a snapshot.
	Collect(ctx context.Context, t Target, progress func(string)) (*snapshot.Snapshot, error)
}

var (
	mu       sync.RWMutex
	registry = map[string]Provider{}
)

// Register adds a provider; called from provider packages' init().
func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[p.Name()]; dup {
		panic(fmt.Sprintf("provider %q registered twice", p.Name()))
	}
	registry[p.Name()] = p
}

// Get returns a provider by name.
func Get(name string) (Provider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	return p, ok
}

// Names lists registered providers, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
