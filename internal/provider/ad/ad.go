// Package ad is the Active Directory / Samba AD DC provider. The two share a
// schema; Detect distinguishes them by rootDSE fingerprint and the snapshot
// records the dialect so packs can be gated.
//
// Collection scope in this skeleton is intentionally tiny (rootDSE + domain
// object). Attribute sets per check domain arrive with the catalogue (K1) and
// are generated into the query manifest; nothing here may be written before
// the catalogue is committed (docs/clean-room.md).
package ad

import (
	"context"
	"fmt"
	"strings"
	"time"

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

// Collect gathers the skeleton snapshot: rootDSE and the domain head object.
func (p Provider) Collect(ctx context.Context, t provider.Target, progress func(string)) (*snapshot.Snapshot, error) {
	if progress == nil {
		progress = func(string) {}
	}
	c, err := dial(ctx, t)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if t.BindUser != "" {
		if err := c.BindSimple(t.BindUser, t.BindPassword); err != nil {
			return nil, fmt.Errorf("ad: bind as %s: %w", t.BindUser, err)
		}
	} else {
		return nil, fmt.Errorf("ad: Kerberos (current logon) bind is not implemented yet; pass --user and --password for a lab, or wait for milestone K3")
	}
	progress("reading rootDSE")
	root, err := c.RootDSE(ctx)
	if err != nil {
		return nil, fmt.Errorf("ad: rootDSE: %w", err)
	}
	base := root["defaultNamingContext"]
	if base == "" {
		return nil, fmt.Errorf("ad: rootDSE has no defaultNamingContext — not an AD-schema directory?")
	}
	snap := &snapshot.Snapshot{
		Schema:    snapshot.SchemaVersion,
		Collected: time.Now().UTC(),
		Meta: snapshot.Meta{
			Provider: p.Name(),
			Dialect:  Fingerprint(root),
			Target:   t.Server,
			Domain:   t.Domain,
			BaseDN:   base,
			Identity: t.BindUser,
			Tier:     t.Tier,
			Tool:     "dirauditor " + buildinfo.Version,
			RootDSE:  root,
		},
	}
	progress("reading domain object")
	entries, err := c.Search(ctx, base, ldapx.ScopeBase, "(objectClass=domainDNS)", []string{
		"objectClass", "name", "objectSid", "ms-DS-MachineAccountQuota", "minPwdLength", "pwdHistoryLength",
		"maxPwdAge", "minPwdAge", "lockoutThreshold", "lockoutDuration", "pwdProperties",
		"whenCreated", "msDS-Behavior-Version", "fSMORoleOwner",
	})
	if err != nil {
		snap.Skipped = append(snap.Skipped, snapshot.Skipped{Query: "domain-head", Reason: "error", Detail: err.Error()})
	}
	for _, e := range entries {
		snap.Objects = append(snap.Objects, snapshot.Object{DN: e.DN, Class: e.Attrs["objectClass"], Attrs: e.Attrs})
	}
	snap.Meta.QueryCount = c.Queries()
	return snap, nil
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
