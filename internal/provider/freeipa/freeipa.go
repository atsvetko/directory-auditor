// Package freeipa is the FreeIPA / Red Hat IdM / ALD Pro provider. FreeIPA is
// 389 Directory Server plus the IPA schema and plugins; the rootDSE is
// fingerprinted by the IPA extended operations it advertises.
//
// Everything here is read-only and reads only what committed catalogue entries
// need (catalogue/freeipa). Containers FreeIPA restricts to privileged readers
// (password policies, delegation rules, DNS, permissions) are attempted and,
// when empty for a container that always has defaults, recorded as "not
// collected (permission)" so checks on them show as skipped, never as passed.
package freeipa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/atsvetko/directory-auditor/internal/buildinfo"
	"github.com/atsvetko/directory-auditor/internal/ldapx"
	"github.com/atsvetko/directory-auditor/internal/provider"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// Extended-operation OIDs registered by FreeIPA's 389-ds plugins
// (daemons/ipa-slapi-plugins in the FreeIPA source). Their presence in the
// rootDSE supportedExtension list identifies a FreeIPA server.
const (
	OIDKeytabSet  = "2.16.840.1.113730.3.8.10.1" // ipa-pwd-extop KEYTAB_SET_OID
	OIDKeytabRet  = "2.16.840.1.113730.3.8.10.2" // ipa-pwd-extop KEYTAB_RET_OID
	OIDEnrollJoin = "2.16.840.1.113730.3.8.10.3" // ipa-enrollment JOIN_OID
)

type Provider struct{}

func init() { provider.Register(Provider{}) }

func (Provider) Name() string { return "freeipa" }

// Fingerprint returns "freeipa" when the rootDSE advertises IPA extended
// operations, "389ds" for a plain 389 Directory Server, "" otherwise.
func Fingerprint(root map[string]string) string {
	ext := root["supportedExtension"]
	if strings.Contains(ext, OIDKeytabSet) || strings.Contains(ext, OIDEnrollJoin) || strings.Contains(ext, OIDKeytabRet) {
		return "freeipa"
	}
	if strings.Contains(strings.ToLower(root["vendorName"]), "389") {
		return "389ds"
	}
	return ""
}

// BaseDN picks the IPA suffix: defaultNamingContext when published, otherwise
// the first namingContext that is not cn=config or the CA tree.
func BaseDN(root map[string]string) string {
	if b := root["defaultNamingContext"]; b != "" {
		return b
	}
	for _, nc := range strings.Split(root["namingContexts"], ";") {
		l := strings.ToLower(strings.TrimSpace(nc))
		if l == "" || l == "cn=config" || l == "cn=schema" || strings.HasPrefix(l, "o=ipaca") || l == "cn=changelog" {
			continue
		}
		return strings.TrimSpace(nc)
	}
	return ""
}

// BindDN turns what the user typed into a bind DN: a DN is used as is; "admin"
// or "admin@REALM" becomes uid=admin,cn=users,cn=accounts,<base>.
func BindDN(user, base string) string {
	if strings.Contains(user, "=") {
		return user
	}
	if i := strings.IndexByte(user, '@'); i > 0 {
		user = user[:i]
	}
	return "uid=" + user + ",cn=users,cn=accounts," + base
}

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
	return d == "freeipa", d, nil
}

func (p Provider) Check(ctx context.Context, t provider.Target) (provider.CheckResult, error) {
	c, err := dial(ctx, t)
	if err != nil {
		return provider.CheckResult{}, err
	}
	defer c.Close()
	root, err := c.RootDSE(ctx)
	if err != nil {
		return provider.CheckResult{}, fmt.Errorf("freeipa: rootDSE: %w", err)
	}
	base := BaseDN(root)
	id, err := bind(c, t, base)
	if err != nil {
		return provider.CheckResult{}, err
	}
	return provider.CheckResult{Identity: id, Dialect: Fingerprint(root), BaseDN: base, Domain: domainFromDN(base), Transport: c.Transport(), Encrypted: c.Encrypted()}, nil
}

func (p Provider) Collect(ctx context.Context, t provider.Target, progress func(string)) (*snapshot.Snapshot, error) {
	if progress == nil {
		progress = func(string) {}
	}
	c, err := dial(ctx, t)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	progress("reading rootDSE")
	root, err := c.RootDSE(ctx)
	if err != nil {
		return nil, fmt.Errorf("freeipa: rootDSE: %w", err)
	}
	base := BaseDN(root)
	if base == "" {
		return nil, errors.New("freeipa: rootDSE publishes no naming context")
	}
	meta := snapshot.Meta{Provider: p.Name(), Dialect: Fingerprint(root), Target: t.Server, Domain: t.Domain,
		Tier: t.Tier, Tool: "dirauditor " + buildinfo.Version, RootDSE: root, BaseDN: base,
		Extra: map[string]string{"transport": c.Transport(), "encrypted": fmt.Sprint(c.Encrypted())}}
	if meta.Domain == "" {
		meta.Domain = domainFromDN(base)
	}

	// Tier-1 probe, before any bind: can an unauthenticated client list users?
	var probe *snapshot.Object
	if t.Tier >= 1 {
		progress("probing anonymous user enumeration")
		probe = anonymousProbe(ctx, c, base)
	}

	id, err := bind(c, t, base)
	if err != nil {
		return nil, err
	}
	meta.Identity = id
	snap, err := collect(ctx, connSearcher(c), meta, progress)
	if err != nil {
		return nil, err
	}
	if probe != nil {
		snap.Objects = append(snap.Objects, *probe)
	}
	return snap, nil
}

// anonymousProbe asks for at most three user entries without binding. It is a
// read; it writes nothing and uses no credentials.
func anonymousProbe(ctx context.Context, c *ldapx.Conn, base string) *snapshot.Object {
	o := &snapshot.Object{DN: "cn=anonymous-ldap-probe,cn=dirauditor", Class: []string{"dirauditorProbe"},
		Attrs: map[string][]string{"probe": {"anonymous-user-enumeration"}}}
	entries, err := c.SearchWith(ctx, "cn=users,cn=accounts,"+base, ldapx.ScopeOneLevel, "(uid=*)", []string{"uid"}, ldapx.SearchOptions{SizeLimit: 3})
	switch {
	case err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded):
		o.Attrs["result"] = []string{"denied"}
		o.Attrs["detail"] = []string{err.Error()}
	case len(entries) == 0:
		o.Attrs["result"] = []string{"denied"}
	default:
		o.Attrs["result"] = []string{"allowed"}
		var sample []string
		for _, e := range entries {
			sample = append(sample, e.Attrs["uid"]...)
		}
		o.Attrs["sample"] = sample
	}
	return o
}

func bind(c *ldapx.Conn, t provider.Target, base string) (string, error) {
	if t.BindUser != "" {
		dn := BindDN(t.BindUser, base)
		if err := c.BindSimple(dn, t.BindPassword); err != nil {
			return "", fmt.Errorf("freeipa: bind as %s: %w", dn, err)
		}
		return dn, nil
	}
	id, err := c.BindCurrentUser()
	if err != nil {
		return "", fmt.Errorf("freeipa: %w", err)
	}
	return id + " (Kerberos)", nil
}

func dial(ctx context.Context, t provider.Target) (*ldapx.Conn, error) {
	if t.Server == "" {
		return nil, errors.New("freeipa: --server is required")
	}
	return ldapx.Dial(ctx, ldapx.Options{Server: t.Server, TLS: ldapx.TLSMode(t.TLS),
		InsecurePlaintext: t.InsecurePlaintext, PinSHA256: t.PinSHA256, MaxQPS: t.MaxQPS, Timeout: 20 * time.Second, Domain: t.Domain})
}

func domainFromDN(dn string) string {
	var parts []string
	for _, rdn := range strings.Split(dn, ",") {
		kv := strings.SplitN(strings.TrimSpace(rdn), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], "DC") {
			parts = append(parts, kv[1])
		}
	}
	return strings.Join(parts, ".")
}
