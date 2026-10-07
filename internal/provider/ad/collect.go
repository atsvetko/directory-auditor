package ad

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/atsvetko/directory-auditor/internal/ldapx"
	"github.com/atsvetko/directory-auditor/internal/secdesc"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
	"github.com/atsvetko/directory-auditor/internal/tier0"
)

// Query is one entry of the collection plan. The plan is static and printed by
// `dirauditor manifest --queries`, so an approver sees every LDAP search the
// binary can issue before it runs (review pack, approach §6.1).
type Query struct {
	Name    string
	Base    string // "default", "" (rootDSE) or a relative DN prefix joined to the default NC
	Scope   ldapx.Scope
	Filter  string
	Attrs   []string
	SD      bool     // read nTSecurityDescriptor (DACL only)
	Purpose string   // which catalogue entries need it
	Classes []string // object classes the query returns (for honest "not collected" states)
}

var (
	sidAttrs  = []string{"objectSid", "sIDHistory", "securityIdentifier", "ms-DS-CreatorSID"}
	guidAttrs = []string{"objectGUID"}
	sdAttrs   = []string{"nTSecurityDescriptor", "msDS-AllowedToActOnBehalfOfOtherIdentity"}
)

var accountAttrs = []string{
	"objectClass", "sAMAccountName", "userPrincipalName", "objectSid", "objectGUID", "sIDHistory",
	"userAccountControl", "pwdLastSet", "lastLogonTimestamp", "whenCreated", "whenChanged",
	"adminCount", "primaryGroupID", "memberOf", "servicePrincipalName",
	"msDS-SupportedEncryptionTypes", "msDS-AllowedToDelegateTo",
	"msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KrbTgtLinkBl",
}

// Plan is the tier-0 (ordinary user) collection plan.
var Plan = []Query{
	{Name: "domain-head", Base: "default", Scope: ldapx.ScopeBase, Filter: "(objectClass=domainDNS)", SD: true, Classes: []string{"domainDNS", "domain"},
		Attrs: []string{"objectClass", "name", "objectSid", "ms-DS-MachineAccountQuota", "minPwdLength",
			"pwdHistoryLength", "maxPwdAge", "minPwdAge", "lockoutThreshold", "lockoutDuration",
			"pwdProperties", "whenCreated", "msDS-Behavior-Version", "fSMORoleOwner", "gPLink"},
		Purpose: "password policy, MAQ (DSA-0013), replication rights on the head (DSA-0014, DSA-0015)"},
	{Name: "users", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(sAMAccountType=805306368)", Classes: []string{"user"},
		Attrs:   accountAttrs,
		Purpose: "account flags, SPNs, delegation, password age, SID history (DSA-0001…0012, 0017, 0019)"},
	{Name: "computers", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(sAMAccountType=805306369)", Classes: []string{"computer"},
		Attrs:   append(append([]string{}, accountAttrs...), "operatingSystem", "operatingSystemVersion", "dNSHostName", "ms-DS-CreatorSID"),
		Purpose: "delegation, RBCD, DCs, machine-account creators (DSA-0004…0006, 0013)"},
	{Name: "groups", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(objectClass=group)", Classes: []string{"group"},
		Attrs:   []string{"objectClass", "sAMAccountName", "objectSid", "objectGUID", "sIDHistory", "member", "groupType", "adminCount", "whenChanged"},
		Purpose: "Tier-0 membership resolution (catalogue/TIER0.md)"},
	{Name: "trusts", Base: "CN=System", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=trustedDomain)", Classes: []string{"trustedDomain"},
		Attrs:   []string{"objectClass", "name", "trustPartner", "trustDirection", "trustType", "trustAttributes", "securityIdentifier", "whenCreated", "whenChanged"},
		Purpose: "trust posture (DSA-0018), trusted-domain SIDs (DSA-0017)"},
	{Name: "adminsdholder", Base: "CN=AdminSDHolder,CN=System", Scope: ldapx.ScopeBase, Filter: "(objectClass=*)", SD: true,
		Attrs:   []string{"objectClass", "whenChanged"},
		Purpose: "AdminSDHolder ACL (DSA-0016)"},
	{Name: "dc-ou", Base: "OU=Domain Controllers", Scope: ldapx.ScopeBase, Filter: "(objectClass=*)", SD: true,
		Attrs:   []string{"objectClass", "gPLink", "whenChanged"},
		Purpose: "Tier-0 object ACL (DSA-0015)"},
	{Name: "protected-sd", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(adminCount=1)", SD: true,
		Attrs:   []string{"objectClass"},
		Purpose: "ACLs and inheritance state of protected objects (DSA-0015, DSA-0019)"},
}

// SDBaseQuery describes the follow-up per-object reads of Tier-0 objects whose
// descriptor was not already collected (members that SDProp does not cover).
var SDBaseQuery = Query{Name: "tier0-sd", Base: "<each Tier-0 DN>", Scope: ldapx.ScopeBase, Filter: "(objectClass=*)", SD: true,
	Attrs: []string{"objectClass"}, Purpose: "ACLs of Tier-0 objects not marked adminCount=1 (DSA-0015)"}

// searcher is the subset of *ldapx.Conn the collector uses; tests supply a fake.
//
// It is a struct of method values, not an interface, on purpose: converting
// *ldapx.Conn to an interface makes the linker keep every method of the
// embedded *ldap.Conn — including Modify/Add/Del — which the read-only gate
// (scripts/readonly-check.sh) rightly rejects.
type searcher struct {
	RootDSE    func(ctx context.Context) (map[string]string, error)
	SearchWith func(ctx context.Context, base string, scope ldapx.Scope, filter string, attrs []string, o ldapx.SearchOptions) ([]ldapx.Entry, error)
	Queries    func() int
	Requests   func() int
}

func connSearcher(c *ldapx.Conn) searcher {
	return searcher{RootDSE: c.RootDSE, SearchWith: c.SearchWith, Queries: c.Queries, Requests: c.Requests}
}

// collect runs the plan against an authenticated session and returns the snapshot.
func collect(ctx context.Context, c searcher, meta snapshot.Meta, progress func(string)) (*snapshot.Snapshot, error) {
	start := time.Now()
	progress("reading rootDSE")
	root, err := c.RootDSE(ctx)
	if err != nil {
		return nil, fmt.Errorf("ad: rootDSE: %w", err)
	}
	base := root["defaultNamingContext"]
	if base == "" {
		return nil, errors.New("ad: rootDSE has no defaultNamingContext — not an AD-schema directory?")
	}
	meta.Dialect = Fingerprint(root)
	meta.BaseDN = base
	meta.RootDSE = root
	snap := &snapshot.Snapshot{Schema: snapshot.SchemaVersion, Collected: start.UTC(), Meta: meta}

	// Objects are merged by DN: later queries add attributes (descriptors) to
	// objects an earlier query already returned.
	index := map[string]int{}
	merge := func(e ldapx.Entry) {
		o := convert(e)
		k := strings.ToLower(o.DN)
		if i, ok := index[k]; ok {
			for a, v := range o.Attrs {
				snap.Objects[i].Attrs[a] = v
			}
			if len(snap.Objects[i].Class) == 0 {
				snap.Objects[i].Class = o.Class
			}
			return
		}
		index[k] = len(snap.Objects)
		snap.Objects = append(snap.Objects, o)
	}
	sdSeen := map[string]bool{}

	for _, q := range Plan {
		progress("reading " + q.Name)
		entries, err := run(ctx, c, q, resolveBase(q.Base, base))
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			snap.Skipped = append(snap.Skipped, skipped(q, err))
			continue
		}
		for _, e := range entries {
			merge(e)
			if q.SD {
				sdSeen[strings.ToLower(e.DN)] = true
			}
		}
	}

	// Domain SID from the head object; needed for Tier-0 resolution.
	if i, ok := index[strings.ToLower(base)]; ok {
		snap.Meta.DomainSID = snap.Objects[i].Attr("objectSid")
	}

	// Second pass: descriptors of Tier-0 objects not covered by adminCount=1.
	t0 := tier0.Resolve(snap.Objects, snap.Meta.DomainSID)
	var missing []string
	for _, dn := range t0.DNs() {
		if !sdSeen[dn] {
			missing = append(missing, snap.Objects[index[dn]].DN)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		progress(fmt.Sprintf("reading descriptors of %d further Tier-0 objects", len(missing)))
	}
	var sdErrs int
	for _, dn := range missing {
		entries, err := run(ctx, c, SDBaseQuery, dn)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			sdErrs++
			if sdErrs <= 5 {
				sk := skipped(SDBaseQuery, err)
				sk.Query += " " + dn
				snap.Skipped = append(snap.Skipped, sk)
			}
			continue
		}
		for _, e := range entries {
			merge(e)
			sdSeen[strings.ToLower(e.DN)] = true
		}
	}
	if sdErrs > 5 {
		snap.Skipped = append(snap.Skipped, snapshot.Skipped{Query: SDBaseQuery.Name, Reason: "error",
			Detail: fmt.Sprintf("%d further objects not read", sdErrs-5)})
	}

	// Honest state: say when descriptors came back empty (no read access).
	if n := countWithout(snap.Objects, sdSeen, "nTSecurityDescriptor"); n > 0 {
		snap.Skipped = append(snap.Skipped, snapshot.Skipped{Query: "descriptors", Reason: "permission",
			Detail: fmt.Sprintf("%d objects returned no nTSecurityDescriptor; ACL checks on them are incomplete", n)})
	}

	snap.Meta.QueryCount = c.Queries()
	snap.Meta.Requests = c.Requests()
	snap.Meta.Duration = time.Since(start).Round(time.Millisecond).String()
	return snap, nil
}

func run(ctx context.Context, c searcher, q Query, base string) ([]ldapx.Entry, error) {
	attrs := q.Attrs
	opts := ldapx.SearchOptions{Binary: append(append(append([]string{}, sidAttrs...), guidAttrs...), sdAttrs...)}
	if q.SD {
		attrs = append(append([]string{}, attrs...), "nTSecurityDescriptor")
		opts.SDFlags = ldapx.SDFlagsDACL
	}
	return c.SearchWith(ctx, base, q.Scope, q.Filter, attrs, opts)
}

func resolveBase(b, defaultNC string) string {
	switch b {
	case "default":
		return defaultNC
	case "":
		return ""
	}
	return b + "," + defaultNC
}

// convert turns raw binary values into the snapshot's text encodings.
func convert(e ldapx.Entry) snapshot.Object {
	o := snapshot.Object{DN: e.DN, Attrs: e.Attrs}
	if o.Attrs == nil {
		o.Attrs = map[string][]string{}
	}
	for name, vals := range e.Bin {
		out := make([]string, 0, len(vals))
		switch {
		case in(name, sidAttrs):
			for _, v := range vals {
				if s, err := secdesc.SIDString(v); err == nil {
					out = append(out, s)
				}
			}
		case in(name, guidAttrs):
			for _, v := range vals {
				if g := secdesc.GUIDString(v); g != "" {
					out = append(out, g)
				}
			}
		default: // descriptors and anything else binary
			for _, v := range vals {
				out = append(out, base64.StdEncoding.EncodeToString(v))
			}
		}
		o.Attrs[name] = out
	}
	for k, v := range o.Attrs {
		if strings.EqualFold(k, "objectClass") {
			o.Class = v
		}
	}
	return o
}

func skipped(q Query, err error) snapshot.Skipped {
	reason := "error"
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		reason = "permission"
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		reason = "absent"
	}
	return snapshot.Skipped{Query: q.Name, Reason: reason, Detail: err.Error(), Classes: q.Classes}
}

func countWithout(objs []snapshot.Object, sdSeen map[string]bool, attr string) int {
	n := 0
	for _, o := range objs {
		if sdSeen[strings.ToLower(o.DN)] && o.Attr(attr) == "" {
			n++
		}
	}
	return n
}

func in(s string, list []string) bool {
	for _, x := range list {
		if strings.EqualFold(s, x) {
			return true
		}
	}
	return false
}
