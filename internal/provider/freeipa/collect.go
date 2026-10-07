package freeipa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/atsvetko/directory-auditor/internal/ldapx"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// Query is one entry of the FreeIPA collection plan (printed by
// `dirauditor manifest --queries`).
type Query struct {
	Name    string
	Base    string // relative to the IPA suffix; "" = the suffix itself
	Scope   ldapx.Scope
	Filter  string
	Attrs   []string
	Purpose string
	Classes []string // object classes returned, for honest "not collected" states
	// Defaults marks containers that always hold entries on a FreeIPA server;
	// an empty result there means the account may not read them.
	Defaults bool
	// Privilege names the IPA privilege that grants read access when the
	// default ("all authenticated users") does not.
	Privilege string
}

// Plan is the FreeIPA collection plan. Each query names the catalogue entries it serves.
var Plan = []Query{
	{Name: "config", Base: "cn=ipaConfig,cn=etc", Scope: ldapx.ScopeBase, Filter: "(objectClass=ipaGuiConfig)", Defaults: true,
		Attrs:   []string{"objectClass", "cn", "ipaUserAuthType", "ipaMigrationEnabled", "ipaConfigString", "ipaKrbAuthzData", "ipaDefaultLoginShell"},
		Classes: []string{"ipaGuiConfig"}, Purpose: "global auth types, migration mode, KDC switches (DSA-0105, 0108, 0117, 0120)"},
	{Name: "realm", Base: "cn=kerberos", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=krbRealmContainer)", Defaults: true, Privilege: "Kerberos Ticket Policy Readers",
		Attrs:   []string{"objectClass", "cn", "krbMaxTicketLife", "krbMaxRenewableAge", "krbSupportedEncSaltTypes", "krbDefaultEncSaltTypes"},
		Classes: []string{"krbRealmContainer", "krbTicketPolicyAux"}, Purpose: "ticket lifetimes and encryption types (DSA-0113, 0114)"},
	{Name: "pwpolicies", Base: "cn=kerberos", Scope: ldapx.ScopeSubtree, Filter: "(objectClass=krbPwdPolicy)", Defaults: true, Privilege: "Password Policy Readers",
		Attrs: []string{"objectClass", "cn", "krbMinPwdLife", "krbMaxPwdLife", "krbPwdMinLength", "krbPwdMinDiffChars", "krbPwdHistoryLength",
			"krbPwdMaxFailure", "krbPwdFailureCountInterval", "krbPwdLockoutDuration", "passwordGraceLimit", "ipaPwdMaxRepeat", "ipaPwdMaxSequence", "ipaPwdDictCheck", "ipaPwdUserCheck"},
		Classes: []string{"krbPwdPolicy", "ipaPwdPolicy"}, Purpose: "password length and lockout policy (DSA-0107, 0108)"},
	{Name: "hbac", Base: "cn=hbac", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=ipaHBACRule)", Defaults: true,
		Attrs: []string{"objectClass", "cn", "accessRuleType", "ipaEnabledFlag", "userCategory", "hostCategory", "serviceCategory", "sourceHostCategory",
			"memberUser", "memberHost", "memberService", "description"},
		Classes: []string{"ipaHBACRule"}, Purpose: "host-based access rules (DSA-0101, 0102)"},
	{Name: "sudo", Base: "cn=sudorules,cn=sudo", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=ipaSudoRule)",
		Attrs: []string{"objectClass", "cn", "ipaEnabledFlag", "userCategory", "hostCategory", "cmdCategory", "ipaSudoRunAsUserCategory", "ipaSudoRunAsGroupCategory",
			"ipaSudoOpt", "memberUser", "memberHost", "memberAllowCmd", "memberDenyCmd", "ipaSudoRunAs", "description"},
		Classes: []string{"ipaSudoRule"}, Purpose: "sudo rules (DSA-0103, 0104)"},
	{Name: "users", Base: "cn=users,cn=accounts", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=posixAccount)", Defaults: true,
		Attrs: []string{"objectClass", "uid", "krbPrincipalName", "memberOf", "ipaUserAuthType", "krbLastPwdChange", "krbPasswordExpiration",
			"krbPrincipalExpiration", "nsAccountLock", "krbTicketFlags", "krbLastSuccessfulAuth"},
		Classes: []string{"posixAccount", "person", "ipaUser"}, Purpose: "admins without a second factor, built-in admin password age, pre-auth (DSA-0105, 0106, 0111)"},
	{Name: "groups", Base: "cn=groups,cn=accounts", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=groupOfNames)", Defaults: true,
		Attrs:   []string{"objectClass", "cn", "member", "memberOf", "description"},
		Classes: []string{"groupOfNames", "ipaUserGroup"}, Purpose: "admins and trust admins membership (DSA-0105, 0118)"},
	{Name: "hosts", Base: "cn=computers,cn=accounts", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=ipaHost)", Defaults: true,
		Attrs:   []string{"objectClass", "fqdn", "krbPrincipalName", "krbTicketFlags", "krbPrincipalAuthInd", "memberOf", "managedBy", "enrolledBy", "krbLastPwdChange"},
		Classes: []string{"ipaHost"}, Purpose: "delegation flags on hosts (DSA-0109, 0110, 0111)"},
	{Name: "services", Base: "cn=services,cn=accounts", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=ipaService)", Defaults: true,
		Attrs:   []string{"objectClass", "krbPrincipalName", "krbCanonicalName", "krbTicketFlags", "krbPrincipalAuthInd", "managedBy", "memberPrincipal", "ipaKrbAuthzData"},
		Classes: []string{"ipaService"}, Purpose: "delegation flags and pre-auth on services (DSA-0109, 0110, 0111)"},
	{Name: "delegation", Base: "cn=s4u2proxy,cn=etc", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=groupOfPrincipals)", Defaults: true, Privilege: "Service Administrators",
		Attrs:   []string{"objectClass", "cn", "memberPrincipal", "ipaAllowedTarget"},
		Classes: []string{"groupOfPrincipals", "ipaKrb5DelegationACL"}, Purpose: "constrained-delegation rules and targets (DSA-0112)"},
	{Name: "caacls", Base: "cn=caacls,cn=ca", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=ipaCaAcl)", Defaults: true,
		Attrs: []string{"objectClass", "cn", "ipaEnabledFlag", "userCategory", "hostCategory", "serviceCategory", "ipaCertProfileCategory", "ipaCaCategory",
			"ipaMemberCertProfile", "ipaMemberCa", "memberUser", "memberHost", "memberService"},
		Classes: []string{"ipaCaAcl"}, Purpose: "certificate issuance rules (DSA-0115)"},
	{Name: "trusts", Base: "cn=trusts", Scope: ldapx.ScopeSubtree, Filter: "(objectClass=ipaNTTrustedDomain)",
		Attrs:   []string{"objectClass", "cn", "ipaNTTrustPartner", "ipaNTFlatName", "ipaNTTrustDirection", "ipaNTTrustedDomainSID", "ipaNTSIDBlacklistIncoming", "ipaNTSIDBlacklistOutgoing"},
		Classes: []string{"ipaNTTrustedDomain"}, Purpose: "AD trust SID filtering (DSA-0116)"},
	{Name: "dnszones", Base: "cn=dns", Scope: ldapx.ScopeSubtree, Filter: "(objectClass=idnsZone)", Privilege: "DNS Administrators",
		Attrs:   []string{"objectClass", "idnsName", "idnsZoneActive", "idnsAllowDynUpdate", "idnsUpdatePolicy", "idnsAllowTransfer", "idnsAllowQuery", "idnsSecInlineSigning"},
		Classes: []string{"idnsZone"}, Purpose: "dynamic-update and zone-transfer policy (DSA-0118, 0119)"},
	{Name: "permissions", Base: "cn=permissions,cn=pbac", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=ipaPermission)", Defaults: true, Privilege: "RBAC Readers",
		Attrs:   []string{"objectClass", "cn", "ipaPermBindRuleType", "ipaPermRight", "ipaPermTargetFilter", "ipaPermDefaultAttr", "ipaPermIncludedAttr", "ipaPermLocation", "ipaPermTarget", "member", "ipaPermissionType"},
		Classes: []string{"ipaPermission", "ipaPermissionV2"}, Purpose: "permissions granted to anonymous or all users (DSA-0121)"},
	{Name: "roles", Base: "cn=roles,cn=accounts", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=groupOfNames)", Defaults: true, Privilege: "RBAC Readers",
		Attrs:   []string{"objectClass", "cn", "member", "memberOf", "description"},
		Classes: []string{"groupOfNames"}, Purpose: "roles held by every user (DSA-0122)"},
	{Name: "privileges", Base: "cn=privileges,cn=pbac", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=groupOfNames)", Defaults: true, Privilege: "RBAC Readers",
		Attrs:   []string{"objectClass", "cn", "member", "memberOf", "description"},
		Classes: []string{"groupOfNames"}, Purpose: "privileges held by every user (DSA-0122)"},
	{Name: "masters", Base: "cn=masters,cn=ipa,cn=etc", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=*)", Defaults: true,
		Attrs:   []string{"objectClass", "cn"},
		Classes: []string{"ipaConfigObject"}, Purpose: "IPA server list, to exclude the servers' own delegation rules (DSA-0112)"},
}

// searcher is a struct of method values on purpose: converting *ldapx.Conn to
// an interface would make the linker keep *ldap.Conn's write methods and fail
// scripts/readonly-check.sh (see provider/ad).
type searcher struct {
	SearchWith func(ctx context.Context, base string, scope ldapx.Scope, filter string, attrs []string, o ldapx.SearchOptions) ([]ldapx.Entry, error)
	Queries    func() int
	Requests   func() int
}

func connSearcher(c *ldapx.Conn) searcher {
	return searcher{SearchWith: c.SearchWith, Queries: c.Queries, Requests: c.Requests}
}

func collect(ctx context.Context, c searcher, meta snapshot.Meta, progress func(string)) (*snapshot.Snapshot, error) {
	start := time.Now()
	snap := &snapshot.Snapshot{Schema: snapshot.SchemaVersion, Collected: start.UTC(), Meta: meta}
	for _, q := range Plan {
		progress("reading " + q.Name)
		base := meta.BaseDN
		if q.Base != "" {
			base = q.Base + "," + meta.BaseDN
		}
		entries, err := c.SearchWith(ctx, base, q.Scope, q.Filter, q.Attrs, ldapx.SearchOptions{})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			snap.Skipped = append(snap.Skipped, skipped(q, err))
			continue
		}
		if len(entries) == 0 && q.Defaults {
			detail := "container returned nothing; the account cannot read it"
			if q.Privilege != "" {
				detail += " (needs the '" + q.Privilege + "' privilege)"
			}
			snap.Skipped = append(snap.Skipped, snapshot.Skipped{Query: q.Name, Reason: "permission", Detail: detail, Classes: q.Classes})
			continue
		}
		for _, e := range entries {
			o := snapshot.Object{DN: e.DN, Attrs: e.Attrs}
			if o.Attrs == nil {
				o.Attrs = map[string][]string{}
			}
			for k, v := range o.Attrs {
				if strings.EqualFold(k, "objectClass") {
					o.Class = v
				}
			}
			snap.Objects = append(snap.Objects, o)
		}
	}
	snap.Meta.QueryCount = c.Queries()
	snap.Meta.Requests = c.Requests()
	snap.Meta.Duration = time.Since(start).Round(time.Millisecond).String()
	return snap, nil
}

func skipped(q Query, err error) snapshot.Skipped {
	reason := "error"
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights):
		reason = "permission"
	case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		reason = "absent" // e.g. no DNS or no trusts installed
	}
	detail := err.Error()
	if reason == "permission" && q.Privilege != "" {
		detail += fmt.Sprintf(" (needs the '%s' privilege)", q.Privilege)
	}
	return snapshot.Skipped{Query: q.Name, Reason: reason, Detail: detail, Classes: q.Classes}
}
