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
	Server            string // host, host:port or IP; empty = discover from Domain
	ServerName        string // DC name for TLS verification / Kerberos SPN when Server is an IP
	Domain            string // DNS domain name
	TLS               string // auto (default), ldaps, starttls, none — see ldapx.TLSMode
	InsecurePlaintext bool   // allow a password over an unencrypted connection (labs only)
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
	Identity  string // who we are bound as
	Dialect   string // ad, samba
	Domain    string // DNS domain derived from the naming context
	BaseDN    string
	Transport string // how the session is protected (ldapx.Conn.Transport)
	Encrypted bool   // TLS or SASL sealing
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

// identify runs each registered provider's Detect (one dial plus a rootDSE
// read, nothing bound) and returns the first whose fingerprint matches, so the
// real system type is known before any credentials are used.
func identify(ctx context.Context, t Target) (Provider, string, error) {
	var firstErr error
	for _, n := range Names() {
		p, _ := Get(n)
		ok, dialect, err := p.Detect(ctx, t)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if ok {
			return p, dialect, nil
		}
	}
	return nil, "", firstErr
}

// Pick chooses the provider for a target. It always fingerprints the server
// first (Detect), so the directory's actual type decides the provider and the
// right check list applies — a binding credential is never enough on its own.
//
//   - auto / "": the detected provider, or an error if none matches.
//   - an explicit name that matches the detected type: that provider (confirmed).
//   - an explicit name that CONFLICTS with the detected type: the detected
//     provider is used instead (the report must reflect reality) and note says so.
//   - an explicit name when detection is inconclusive: the named provider, as a
//     fallback, with note explaining detection could not confirm it.
//
// note is a human-readable message for the caller to surface; it is empty when
// the choice is unambiguous.
func Pick(ctx context.Context, name string, t Target) (p Provider, dialect, note string, err error) {
	det, dialect, derr := identify(ctx, t)

	if name != "" && name != "auto" {
		req, ok := Get(name)
		if !ok {
			return nil, "", "", fmt.Errorf("unknown provider %q (have %s)", name, Names())
		}
		switch {
		case det != nil && det.Name() == name:
			return det, dialect, "", nil
		case det != nil:
			return det, dialect, fmt.Sprintf("requested --provider %s, but the server is %s — using %s so the right checks apply", name, det.Name(), det.Name()), nil
		default:
			msg := fmt.Sprintf("could not confirm the directory type; using --provider %s as given", name)
			if derr != nil {
				msg += " (" + derr.Error() + ")"
			}
			return req, "", msg, nil
		}
	}

	if det != nil {
		return det, dialect, "", nil
	}
	if derr != nil {
		return nil, "", "", fmt.Errorf("could not identify the directory: %s", derr.Error())
	}
	return nil, "", "", fmt.Errorf("the server is not a directory type this build supports (%s)", Names())
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
