package ad

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
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
	SD      bool     // read nTSecurityDescriptor (owner and DACL, see sdFlags)
	Purpose string   // which catalogue entries need it
	Classes []string // object classes the query returns (for honest "not collected" states)
}

var (
	sidAttrs  = []string{"objectSid", "sIDHistory", "securityIdentifier", "ms-DS-CreatorSID"}
	guidAttrs = []string{"objectGUID", "schemaIDGUID"}
	sdAttrs   = []string{"nTSecurityDescriptor", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-GroupMSAMembership"}
)

var accountAttrs = []string{
	"objectClass", "objectCategory", "sAMAccountType", "sAMAccountName", "userPrincipalName", "objectSid", "objectGUID", "sIDHistory",
	"userAccountControl", "pwdLastSet", "lastLogonTimestamp", "whenCreated", "whenChanged",
	"adminCount", "primaryGroupID", "memberOf", "servicePrincipalName",
	"msDS-SupportedEncryptionTypes", "msDS-AllowedToDelegateTo",
	"msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KrbTgtLinkBl",
	// Readable free-text and credential-bearing attributes (DSA-0028): secrets
	// are routinely parked in these where any authenticated user can read them.
	"description", "info", "comment", "userPassword", "unixUserPassword", "ms-Mcs-AdmPwd",
	// Explicit certificate mappings (DSA-0052, DSA-0053).
	"altSecurityIdentities",
	// dMSA migration back-link on the superseded account (DSA-0074): with the
	// August 2025 fix the KDC honours a dMSA succession only when the target
	// carries these too, so their presence is what makes a link effective.
	"msDS-SupersededManagedAccountLink", "msDS-SupersededServiceAccountState",
	// Raw public keys accepted for PKINIT logon as the account (DSA-0075). An
	// ordinary user may not be allowed to read it; absence then means "not
	// readable", not "no keys".
	"msDS-KeyCredentialLink",
}

// sdFlags selects the descriptor parts every SD read asks for: the owner
// (DSA-0076) and the DACL. Both are readable with READ_CONTROL, which an
// ordinary user holds on most objects; the SACL is never requested. Every SD
// query uses the same flags because objects are merged by DN, and a later
// DACL-only read would otherwise overwrite an earlier descriptor that carried
// the owner (OU=Domain Controllers is read by dc-ou and again by ou-sd).
const sdFlags = ldapx.SDFlagsOwner | ldapx.SDFlagsDACL

// rodcAttrs is the password replication policy of a read-only DC (DSA-0089).
// msDS-RevealedList may need more than ordinary user rights: an RODC that
// returns none is noted in the inventory (see collect), never assumed clean.
var rodcAttrs = []string{"msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup", "msDS-RevealedList"}

// Plan is the tier-0 (ordinary user) collection plan.
var Plan = []Query{
	{Name: "domain-head", Base: "default", Scope: ldapx.ScopeBase, Filter: "(objectClass=domainDNS)", SD: true, Classes: []string{"domainDNS", "domain"},
		Attrs: []string{"objectClass", "name", "objectSid", "ms-DS-MachineAccountQuota", "minPwdLength",
			"pwdHistoryLength", "maxPwdAge", "minPwdAge", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
			"pwdProperties", "whenCreated", "msDS-Behavior-Version", "fSMORoleOwner", "gPLink",
			"msDS-ExpirePasswordsOnSmartCardOnlyAccounts"},
		Purpose: "password and lockout policy (DSA-0020…0023, DSA-0082), MAQ (DSA-0013), smart-card NT-hash rolling (DSA-0085), " +
			"replication and reanimation rights on the head (DSA-0014, DSA-0015, DSA-0078)"},
	{Name: "users", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(sAMAccountType=805306368)", Classes: []string{"user"},
		Attrs:   accountAttrs,
		Purpose: "account flags, SPNs, delegation, password age, SID history, key credentials (DSA-0001…0012, 0017, 0019, 0075, 0083…0086)"},
	{Name: "computers", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(sAMAccountType=805306369)", Classes: []string{"computer"},
		Attrs: append(append(append([]string{}, accountAttrs...), "operatingSystem", "operatingSystemVersion", "dNSHostName", "ms-DS-CreatorSID",
			"msDS-GroupMSAMembership"), rodcAttrs...),
		Purpose: "delegation, RBCD, DCs, machine-account creators, gMSA password readers, member OS support, " +
			"replication SPNs on non-DCs, RODC password replication policy (DSA-0004…0006, 0013, 0055, 0084, 0087, 0088, 0089)"},
	{Name: "groups", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(objectClass=group)", Classes: []string{"group"},
		Attrs:   []string{"objectClass", "sAMAccountName", "objectSid", "objectGUID", "sIDHistory", "member", "groupType", "adminCount", "whenChanged"},
		Purpose: "Tier-0 membership resolution (catalogue/TIER0.md), Allowed/Denied RODC Password Replication Groups (DSA-0089)"},
	{Name: "trusts", Base: "CN=System", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=trustedDomain)", Classes: []string{"trustedDomain"},
		Attrs:   []string{"objectClass", "name", "trustPartner", "trustDirection", "trustType", "trustAttributes", "securityIdentifier", "whenCreated", "whenChanged"},
		Purpose: "trust posture (DSA-0018), trusted-domain SIDs (DSA-0017)"},
	{Name: "adminsdholder", Base: "CN=AdminSDHolder,CN=System", Scope: ldapx.ScopeBase, Filter: "(objectClass=*)", SD: true,
		Attrs:   []string{"objectClass", "whenChanged"},
		Purpose: "AdminSDHolder ACL and owner (DSA-0016, DSA-0076)"},
	{Name: "dc-ou", Base: "OU=Domain Controllers", Scope: ldapx.ScopeBase, Filter: "(objectClass=*)", SD: true,
		Attrs:   []string{"objectClass", "gPLink", "whenChanged"},
		Purpose: "Tier-0 object ACL and owner (DSA-0015, DSA-0076)"},
	{Name: "ds-heuristics", Base: "CN=Directory Service,CN=Windows NT,CN=Services,<config>", Scope: ldapx.ScopeBase, Filter: "(objectClass=*)", Classes: []string{"nTDSService"},
		Attrs:   []string{"objectClass", "dSHeuristics", "tombstoneLifetime", "whenChanged"},
		Purpose: "directory-wide switches such as anonymous LDAP operations and anonymous NSPI (DSA-0025, DSA-0066, DSA-0077)"},
	{Name: "dnsadmins-sd", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(&(objectClass=group)(sAMAccountName=DnsAdmins))", SD: true,
		Attrs:   []string{"objectClass", "sAMAccountName"},
		Purpose: "who can change DnsAdmins membership (DSA-0059)"},
	{Name: "ou-sd", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(objectClass=organizationalUnit)", SD: true, Classes: []string{"organizationalUnit"},
		Attrs:   []string{"objectClass", "gPLink", "gPOptions", "whenChanged"},
		Purpose: "GPO-link and control rights on OUs holding Tier-0 objects, LAPS read delegation (DSA-0056, DSA-0058)"},
	{Name: "container-sd", Base: "default", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=container)", SD: true, Classes: []string{"container"},
		Attrs:   []string{"objectClass", "whenChanged"},
		Purpose: "control rights on top-level containers holding Tier-0 objects (DSA-0056, DSA-0058)"},
	{Name: "sites", Base: "CN=Sites,<config>", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=site)", SD: true, Classes: []string{"site"},
		Attrs:   []string{"objectClass", "gPLink", "gPOptions", "whenChanged"},
		Purpose: "who can link GPOs to AD sites (DSA-0058)"},
	{Name: "site-servers", Base: "CN=Sites,<config>", Scope: ldapx.ScopeSubtree, Filter: "(|(objectClass=server)(objectClass=nTDSDSA))",
		Classes: []string{"server", "nTDSDSA"},
		Attrs:   []string{"objectClass", "serverReference", "dNSHostName", "whenCreated"},
		Purpose: "DC registrations in the configuration partition: server objects, their NTDS Settings and the computer each names (DSA-0088)"},
	{Name: "schema-laps", Base: "<schema>", Scope: ldapx.ScopeOneLevel, Classes: []string{"attributeSchema"},
		Filter:  "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password)(lDAPDisplayName=msLAPS-EncryptedPassword)(lDAPDisplayName=msLAPS-EncryptedPasswordHistory)(lDAPDisplayName=msLAPS-EncryptedDSRMPassword)(lDAPDisplayName=msLAPS-EncryptedDSRMPasswordHistory))",
		Attrs:   []string{"objectClass", "lDAPDisplayName", "searchFlags", "schemaIDGUID"},
		Purpose: "LAPS password attributes: confidentiality flag and schema GUIDs for ACL matching (DSA-0056, DSA-0057)"},
	{Name: "schema-dmsa", Base: "<schema>", Scope: ldapx.ScopeOneLevel, Classes: []string{"classSchema"},
		Filter:  "(lDAPDisplayName=msDS-DelegatedManagedServiceAccount)",
		Attrs:   []string{"objectClass", "lDAPDisplayName", "schemaIDGUID"},
		Purpose: "dMSA class GUID for create-child ACL matching; absent before the Windows Server 2025 schema (DSA-0073)"},
	{Name: "dmsa", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(objectClass=msDS-DelegatedManagedServiceAccount)", SD: true,
		Classes: []string{"msDS-DelegatedManagedServiceAccount"},
		Attrs: []string{"objectClass", "sAMAccountName", "objectSid", "msDS-ManagedAccountPrecededByLink", "msDS-DelegatedMSAState",
			"whenCreated", "whenChanged"},
		Purpose: "delegated MSAs and the account each one claims to supersede (DSA-0074)"},
	{Name: "trust-accounts", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(sAMAccountType=805306370)", Classes: []string{"user"},
		Attrs:   []string{"objectClass", "sAMAccountName", "objectSid", "pwdLastSet", "whenCreated", "userAccountControl"},
		Purpose: "interdomain trust (TRUSTDOMAIN$) account password age (DSA-0065)"},
	{Name: "dpapi-keys", Base: "CN=System", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=secret)", SD: true, Classes: []string{"secret"},
		Attrs:   []string{"objectClass", "cn"},
		Purpose: "who can read the DPAPI domain backup keys (DSA-0067)"},
	{Name: "kds-root-keys", Base: "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,<config>", Scope: ldapx.ScopeOneLevel,
		Filter: "(objectClass=msKds-ProvRootKey)", SD: true, Classes: []string{"msKds-ProvRootKey"},
		Attrs:   []string{"objectClass", "cn"},
		Purpose: "who can read the KDS root keys that derive every gMSA password (DSA-0068)"},
	{Name: "schema-head", Base: "<schema>", Scope: ldapx.ScopeBase, Filter: "(objectClass=dMD)", SD: true, Classes: []string{"dMD"},
		Attrs:   []string{"objectClass", "objectVersion"},
		Purpose: "schema version — whether the forest was prepared for a supported OS (DSA-0069); write rights on the schema head (DSA-0079)"},
	{Name: "dfsr-global", Base: "CN=DFSR-GlobalSettings,CN=System", Scope: ldapx.ScopeBase, Filter: "(objectClass=*)",
		Attrs:   []string{"objectClass", "msDFSR-Flags"},
		Purpose: "SYSVOL FRS→DFSR migration state (DSA-0070)"},
	{Name: "frs-replica", Base: "CN=File Replication Service,CN=System", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=nTFRSReplicaSet)", Classes: []string{"nTFRSReplicaSet"},
		Attrs:   []string{"objectClass", "name"},
		Purpose: "legacy NTFRS SYSVOL replica set — present only before migration (DSA-0070)"},
	{Name: "pso", Base: "CN=Password Settings Container,CN=System", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=msDS-PasswordSettings)", Classes: []string{"msDS-PasswordSettings"},
		Attrs:   []string{"objectClass", "cn", "msDS-MinimumPasswordLength", "msDS-PSOAppliesTo", "msDS-PasswordSettingsPrecedence"},
		Purpose: "fine-grained password policies applied to privileged members (DSA-0071)"},
	{Name: "gpo", Base: "CN=Policies,CN=System", Scope: ldapx.ScopeOneLevel, Filter: "(objectClass=groupPolicyContainer)", SD: true, Classes: []string{"groupPolicyContainer"},
		Attrs:   []string{"objectClass", "displayName", "gPCFileSysPath"},
		Purpose: "control rights and owners of GPOs linked to Tier-0 scope (DSA-0072, DSA-0076)"},
	{Name: "protected-sd", Base: "default", Scope: ldapx.ScopeSubtree, Filter: "(adminCount=1)", SD: true,
		Attrs:   []string{"objectClass"},
		Purpose: "ACLs, owners and inheritance state of protected objects (DSA-0015, DSA-0019, DSA-0076)"},
}

// SDBaseQuery describes the follow-up per-object reads of Tier-0 objects whose
// descriptor was not already collected (members that SDProp does not cover).
var SDBaseQuery = Query{Name: "tier0-sd", Base: "<each Tier-0 DN>", Scope: ldapx.ScopeBase, Filter: "(objectClass=*)", SD: true,
	Attrs: []string{"objectClass"}, Purpose: "ACLs and owners of Tier-0 objects not marked adminCount=1 (DSA-0015, DSA-0076)"}

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
	snap.Objects = append(snap.Objects, snapshot.RootDSEObject(meta.RootDSE))

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

	configNC, schemaNC := root["configurationNamingContext"], root["schemaNamingContext"]
	for _, q := range Plan {
		progress("reading " + q.Name)
		entries, err := run(ctx, c, q, resolveBase(q.Base, base, configNC, schemaNC))
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

	// Honest state for DSA-0089 condition (3): an empty msDS-RevealedList and
	// one this account may not read look the same, so say how many RODCs gave none.
	if n := rodcsWithout(snap.Objects, "msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup"); n > 0 {
		snap.Skipped = append(snap.Skipped, snapshot.Skipped{Query: "rodc-prp", Reason: "permission",
			Detail: fmt.Sprintf("%d read-only DC accounts returned neither msDS-RevealOnDemandGroup nor msDS-NeverRevealGroup; "+
				"their password replication policy (DSA-0089) was not checked", n)})
	}
	if n := rodcsWithout(snap.Objects, "msDS-RevealedList"); n > 0 {
		snap.Skipped = append(snap.Skipped, snapshot.Skipped{Query: "rodc-revealed-list", Reason: "permission",
			Detail: fmt.Sprintf("%d read-only DC accounts returned no msDS-RevealedList (nothing cached, or not readable by this account); "+
				"cached Tier-0 credentials (DSA-0089) cannot be ruled out on them", n)})
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
		opts.SDFlags = sdFlags
	}
	return c.SearchWith(ctx, base, q.Scope, q.Filter, attrs, opts)
}

func resolveBase(b, defaultNC, configNC, schemaNC string) string {
	if configNC == "" {
		configNC = "CN=Configuration," + defaultNC
	}
	if schemaNC == "" {
		schemaNC = "CN=Schema," + configNC
	}
	switch {
	case b == "default":
		return defaultNC
	case b == "":
		return ""
	case b == "<schema>":
		return schemaNC
	case strings.HasSuffix(b, "<config>"):
		return strings.TrimSuffix(b, "<config>") + configNC
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

// rodcsWithout counts read-only DC computer accounts (PARTIAL_SECRETS_ACCOUNT)
// that carry a value for none of attrs.
func rodcsWithout(objs []snapshot.Object, attrs ...string) int {
	n := 0
	for _, o := range objs {
		uac, err := strconv.ParseInt(o.Attr("userAccountControl"), 10, 64)
		if err != nil || uint32(uac)&0x4000000 == 0 || o.Attr("sAMAccountType") != "805306369" {
			continue
		}
		has := false
		for _, a := range attrs {
			has = has || o.Attr(a) != ""
		}
		if !has {
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
