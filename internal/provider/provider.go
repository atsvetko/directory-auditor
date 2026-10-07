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
	BindUser          string // empty = current logon (Kerberos)
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
	// Check connects and binds without collecting — the wizard's "Connect" step.
	Check(ctx context.Context, t Target) (CheckResult, error)
	// Collect performs a read-only collection and returns a snapshot.
	Collect(ctx context.Context, t Target, progress func(string)) (*snapshot.Snapshot, error)
}

// CheckResult describes a successful test connection.
type CheckResult struct {
	Identity string // who we are bound as
	Dialect  string // ad, samba
	Domain   string // DNS domain derived from the naming context
	BaseDN   string
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

// Pick returns the provider named by name, or, for "auto" / "", the first
// registered provider whose Detect matches the server. Each Detect is one
// dial plus a rootDSE read; nothing is bound.
func Pick(ctx context.Context, name string, t Target) (Provider, string, error) {
	if name != "" && name != "auto" {
		p, ok := Get(name)
		if !ok {
			return nil, "", fmt.Errorf("unknown provider %q (have %s)", name, Names())
		}
		return p, "", nil
	}
	var errs []string
	for _, n := range Names() {
		p, _ := Get(n)
		ok, dialect, err := p.Detect(ctx, t)
		if err != nil {
			errs = append(errs, n+": "+err.Error())
			continue
		}
		if ok {
			return p, dialect, nil
		}
	}
	if len(errs) > 0 {
		return nil, "", fmt.Errorf("could not identify the directory: %s", errs[0])
	}
	return nil, "", fmt.Errorf("the server is not a directory type this build supports (%s)", Names())
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
