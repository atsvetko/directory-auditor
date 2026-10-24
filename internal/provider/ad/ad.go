// Package ad is the Active Directory / Samba AD DC provider. The two share the
// AD LDAP schema, so collection is identical; Detect distinguishes them by
// rootDSE fingerprint and the snapshot records the dialect. The dialect gates
// the Samba-specific catalogue checks (domain: samba) on top of the
// directory-core checks, which apply to both.
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

// Provider is the Active Directory provider.
type Provider struct{}

// Samba is the Samba AD DC provider. A Samba AD DC serves the same LDAP schema
// as Active Directory, so it reuses the AD collection unchanged; only the
// recorded dialect differs ("samba"), which turns on the Samba catalogue
// checks in addition to the directory-core ones that apply to both.
type Samba struct{}

func init() {
	provider.Register(Provider{})
	provider.Register(Samba{})
}

func (Provider) Name() string { return "ad" }
func (Samba) Name() string    { return "samba" }

// Detect connects, reads rootDSE and reports whether this is the directory the
// provider handles. Under `auto` each provider claims only its own dialect, so
// a Windows DC goes to the ad provider and a Samba AD DC to the samba provider.
func (Provider) Detect(ctx context.Context, t provider.Target) (bool, string, error) {
	d, err := fingerprintOf(ctx, t)
	if err != nil {
		return false, "", err
	}
	return d == "ad", "ad", nil
}

// Detect for Samba matches a rootDSE fingerprinted as Samba.
func (Samba) Detect(ctx context.Context, t provider.Target) (bool, string, error) {
	d, err := fingerprintOf(ctx, t)
	if err != nil {
		return false, "", err
	}
	return d == "samba", "samba", nil
}

// fingerprintOf dials, reads the rootDSE and classifies it (no bind).
func fingerprintOf(ctx context.Context, t provider.Target) (string, error) {
	c, err := dial(ctx, t)
	if err != nil {
		return "", err
	}
	defer c.Close()
	root, err := c.RootDSE(ctx)
	if err != nil {
		return "", err
	}
	return Fingerprint(root), nil
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

// Check dials, binds and reads the rootDSE — proof that a scan will be able to
// start. Both providers share it; the dialect in the result comes from the
// rootDSE fingerprint, so it reports "ad" or "samba" correctly either way.
func (Provider) Check(ctx context.Context, t provider.Target) (provider.CheckResult, error) {
	return doCheck(ctx, t)
}

// Check for Samba is the same test connection as AD.
func (Samba) Check(ctx context.Context, t provider.Target) (provider.CheckResult, error) {
	return doCheck(ctx, t)
}

func doCheck(ctx context.Context, t provider.Target) (provider.CheckResult, error) {
	c, id, note, err := connect(ctx, t)
	if err != nil {
		return provider.CheckResult{}, err
	}
	defer c.Close()
	root, err := c.RootDSE(ctx)
	if err != nil {
		return provider.CheckResult{}, fmt.Errorf("rootDSE: %w", err)
	}
	return provider.CheckResult{Identity: id, Dialect: Fingerprint(root), BaseDN: root["defaultNamingContext"],
		Domain: DomainFromDN(root["defaultNamingContext"]), Transport: c.Transport(), Encrypted: c.Encrypted(), AuthNote: note}, nil
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

// Collect binds and runs the read-only collection plan (see Plan). AD and Samba
// collect identically; only the recorded provider/dialect differs.
func (Provider) Collect(ctx context.Context, t provider.Target, progress func(string)) (*snapshot.Snapshot, error) {
	return collectAs(ctx, t, progress, "ad", "ad")
}

// Collect for Samba records the snapshot as the samba dialect so the Samba
// catalogue checks apply; the LDAP collection itself is unchanged.
func (Samba) Collect(ctx context.Context, t provider.Target, progress func(string)) (*snapshot.Snapshot, error) {
	return collectAs(ctx, t, progress, "samba", "samba")
}

func collectAs(ctx context.Context, t provider.Target, progress func(string), name, dialect string) (*snapshot.Snapshot, error) {
	if progress == nil {
		progress = func(string) {}
	}
	c, identity, note, err := connect(ctx, t)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	extra := map[string]string{"transport": c.Transport(), "encrypted": fmt.Sprint(c.Encrypted())}
	if note != "" {
		extra["auth_note"] = note
	}
	return collect(ctx, connSearcher(c), snapshot.Meta{
		Provider: name,
		Dialect:  dialect,
		Target:   t.Server,
		Domain:   t.Domain,
		Identity: identity,
		Tier:     t.Tier,
		Tool:     "dirauditor " + buildinfo.Version,
		Extra:    extra,
	}, progress)
}

// connect dials and authenticates. Kerberos is preferred: the current logon
// when no account is given, otherwise a ticket obtained with the password at
// the DC's KDC — so the password never crosses the network and an unencrypted
// connection still ends up sealed.
//
// Samba (ldap server require strong auth = yes, its default) refuses a
// Kerberos bind over TLS that selects no SASL layer, which is what Windows
// requires. In auto mode connect then reconnects over plain LDAP, where the
// bind negotiates sealing. A simple bind is the last resort, for an account
// Kerberos cannot serve (refused without TLS unless the lab flag is set).
//
// The identity string says which path was taken; note, when not empty, says
// why Kerberos over the first connection did not succeed, for the run log and
// the report.
func connect(ctx context.Context, t provider.Target) (*ldapx.Conn, string, string, error) {
	c, err := dial(ctx, t)
	if err != nil {
		return nil, "", "", err
	}
	id, kerr := kerberos(c, t)
	if kerr == nil {
		return c, id + " (Kerberos)", "", nil
	}
	note := "Kerberos over " + c.Transport() + " refused: " + kerr.Error()
	if c.TLS() && ldapx.NeedsSASLLayer(kerr) && (t.TLS == "" || t.TLS == string(ldapx.TLSAuto)) {
		plain := t
		plain.TLS = string(ldapx.TLSNone)
		pc, err := dial(ctx, plain)
		if err != nil {
			note += "; plain LDAP for Kerberos sealing unreachable: " + err.Error()
		} else if id, err := kerberos(pc, plain); err != nil {
			pc.Close()
			note += "; Kerberos-sealed LDAP also failed: " + err.Error()
		} else {
			c.Close()
			return pc, id + " (Kerberos)", note + "; reconnected over plain LDAP with Kerberos sealing", nil
		}
	}
	if t.BindUser == "" {
		c.Close()
		return nil, "", "", fmt.Errorf("ad: %w", kerr)
	}
	if err := c.BindSimple(t.BindUser, t.BindPassword); err != nil {
		c.Close()
		return nil, "", "", fmt.Errorf("bind as %s: %w (Kerberos was tried first: %v)", t.BindUser, err, kerr)
	}
	return c, t.BindUser + " (simple bind)", note + "; used a simple bind — the password was sent to the DC inside the " + c.Transport() + " session", nil
}

// kerberos binds as the current logon, or as t.BindUser with its password.
func kerberos(c *ldapx.Conn, t provider.Target) (string, error) {
	if t.BindUser == "" {
		return c.BindCurrentUser()
	}
	return c.BindKerberos(t.BindUser, t.BindPassword)
}

func dial(ctx context.Context, t provider.Target) (*ldapx.Conn, error) {
	if t.Server == "" {
		return nil, fmt.Errorf("ad: no domain controller: pass --domain (found through DNS) or --server")
	}
	return ldapx.Dial(ctx, ldapx.Options{
		Server:            t.Server,
		ServerName:        t.ServerName,
		TLS:               ldapx.TLSMode(t.TLS),
		InsecurePlaintext: t.InsecurePlaintext,
		PinSHA256:         t.PinSHA256,
		MaxQPS:            t.MaxQPS,
		Domain:            t.Domain,
	})
}
