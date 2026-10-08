// Package ad is the Active Directory / Samba AD DC provider. The two share a
// schema; Detect distinguishes them by rootDSE fingerprint and the snapshot
// records the dialect so packs can be gated.
//
// The collection plan (collect.go) reads only what committed catalogue entries
// need; every query names the entries it serves.
package ad

import (
	"context"
	"fmt"
	"strings"

	"github.com/atsvetko/directory-auditor/internal/buildinfo"
	"github.com/atsvetko/directory-auditor/internal/ldapx"
	"github.com/atsvetko/directory-auditor/internal/provider"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

type Provider struct{}

func init() { provider.Register(Provider{}) }

func (Provider) Name() string { return "ad" }

// Detect connects, reads rootDSE and classifies the server.
func (p Provider) Detect(ctx context.Context, t provider.Target) (bool, string, error) {
	c, err := dial(ctx, t)
	if err != nil {
		return false, "", err
	}
	defer c.Close()
	root, err := c.RootDSE(ctx)
	if err != nil {
		return false, "", err
	}
	d := Fingerprint(root)
	return d != "", d, nil
}

// Fingerprint classifies a rootDSE as "ad", "samba" or "" (not an AD-schema directory).
// Samba AD DC publishes vendorName "Samba Team" and vendorVersion; Windows DCs do not
// publish vendorName but do publish forest/domain functionality levels.
func Fingerprint(root map[string]string) string {
	vendor := strings.ToLower(root["vendorName"])
	switch {
	case strings.Contains(vendor, "samba"):
		return "samba"
	case root["forestFunctionality"] != "" || root["domainControllerFunctionality"] != "":
		if strings.Contains(strings.ToLower(root["supportedCapabilities"]), "1.2.840.113556.1.4.800") {
			return "ad"
		}
		return "ad"
	}
	return ""
}

// Check dials, binds and reads the rootDSE — proof that a scan will be able to start.
func (p Provider) Check(ctx context.Context, t provider.Target) (provider.CheckResult, error) {
	c, err := dial(ctx, t)
	if err != nil {
		return provider.CheckResult{}, err
	}
	defer c.Close()
	id, err := bind(c, t)
	if err != nil {
		return provider.CheckResult{}, err
	}
	root, err := c.RootDSE(ctx)
	if err != nil {
		return provider.CheckResult{}, fmt.Errorf("ad: rootDSE: %w", err)
	}
	return provider.CheckResult{Identity: id, Dialect: Fingerprint(root), BaseDN: root["defaultNamingContext"],
		Domain: DomainFromDN(root["defaultNamingContext"]), Transport: c.Transport(), Encrypted: c.Encrypted()}, nil
}

// DomainFromDN turns DC=corp,DC=example,DC=com into corp.example.com.
func DomainFromDN(dn string) string {
	var parts []string
	for _, rdn := range strings.Split(dn, ",") {
		kv := strings.SplitN(strings.TrimSpace(rdn), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], "DC") {
			parts = append(parts, kv[1])
		}
	}
	return strings.Join(parts, ".")
}

// Collect binds and runs the read-only collection plan (see Plan).
func (p Provider) Collect(ctx context.Context, t provider.Target, progress func(string)) (*snapshot.Snapshot, error) {
	if progress == nil {
		progress = func(string) {}
	}
	c, err := dial(ctx, t)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	identity, err := bind(c, t)
	if err != nil {
		return nil, err
	}
	return collect(ctx, connSearcher(c), snapshot.Meta{
		Provider: p.Name(),
		Target:   t.Server,
		Domain:   t.Domain,
		Identity: identity,
		Tier:     t.Tier,
		Tool:     "dirauditor " + buildinfo.Version,
		Extra:    map[string]string{"transport": c.Transport(), "encrypted": fmt.Sprint(c.Encrypted())},
	}, progress)
}

// bind authenticates. Kerberos is preferred: the current logon when no
// account is given, otherwise a ticket obtained with the password at the DC's
// KDC — so the password never crosses the network and an unencrypted
// connection still ends up sealed. A simple bind is the fallback for an
// account Kerberos cannot serve (and is refused without TLS unless the lab
// flag is set). The identity string says which path was taken.
func bind(c *ldapx.Conn, t provider.Target) (string, error) {
	if t.BindUser == "" {
		id, err := c.BindCurrentUser()
		if err != nil {
			return "", fmt.Errorf("ad: %w", err)
		}
		return id + " (Kerberos)", nil
	}
	id, kerr := c.BindKerberos(t.BindUser, t.BindPassword)
	if kerr == nil {
		return id + " (Kerberos)", nil
	}
	if err := c.BindSimple(t.BindUser, t.BindPassword); err != nil {
		return "", fmt.Errorf("ad: bind as %s: %w (Kerberos was tried first: %v)", t.BindUser, err, kerr)
	}
	return t.BindUser + " (simple bind)", nil
}

func dial(ctx context.Context, t provider.Target) (*ldapx.Conn, error) {
	if t.Server == "" {
		return nil, fmt.Errorf("ad: --server is required in this skeleton (DNS SRV discovery arrives with doctor)")
	}
	return ldapx.Dial(ctx, ldapx.Options{
		Server:            t.Server,
		TLS:               ldapx.TLSMode(t.TLS),
		InsecurePlaintext: t.InsecurePlaintext,
		PinSHA256:         t.PinSHA256,
		MaxQPS:            t.MaxQPS,
		Domain:            t.Domain,
	})
}
