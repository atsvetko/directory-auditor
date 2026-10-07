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
	}, progress)
}

// bind authenticates with an explicit identity when one is given; otherwise it
// uses the current logon via Kerberos.
func bind(c *ldapx.Conn, t provider.Target) (string, error) {
	if t.BindUser != "" {
		if err := c.BindSimple(t.BindUser, t.BindPassword); err != nil {
			return "", fmt.Errorf("ad: bind as %s: %w", t.BindUser, err)
		}
		return t.BindUser, nil
	}
	return "", fmt.Errorf("ad: Kerberos (current logon) bind is not implemented yet; pass --user for a lab")
}

func dial(ctx context.Context, t provider.Target) (*ldapx.Conn, error) {
	if t.Server == "" {
		return nil, fmt.Errorf("ad: --server is required in this skeleton (DNS SRV discovery arrives with doctor)")
	}
	return ldapx.Dial(ctx, ldapx.Options{
		Server:            t.Server,
		UseLDAPS:          t.UseLDAPS,
		StartTLS:          t.StartTLS,
		InsecurePlaintext: t.InsecurePlaintext,
		PinSHA256:         t.PinSHA256,
		MaxQPS:            t.MaxQPS,
	})
}
