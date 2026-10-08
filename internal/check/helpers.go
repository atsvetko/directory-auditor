package check

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/atsvetko/directory-auditor/internal/secdesc"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
	"github.com/atsvetko/directory-auditor/internal/tier0"
)

// Helper functions available to pack conditions, in addition to attr, attrs,
// intattr and hasattr. CEL has no bitwise operators and no notion of AD time
// formats or security descriptors; these fill exactly those gaps and nothing
// more. Time is always measured against the snapshot's collection time, so an
// analysis re-run next month gives the same answer.
//
//	flags(obj, "userAccountControl", 0x400000)   all bits of the mask set
//	anyflag(obj, "trustAttributes", 0x40|0x800)   at least one bit set
//	mask_has(m, 0x40000)                          bits on a plain int (ACE masks)
//	age_days(obj, "pwdLastSet")                   days before collection; -1 when absent/never
//	sid_rid("S-1-5-21-…-512")                     512
//	sid_domain("S-1-5-21-…-512")                  "S-1-5-21-…"
//	tier0(obj)                                    principal or object is Tier 0 (catalogue/TIER0.md)
//	tier0_sid("S-1-5-…")                          SID is Tier 0
//	sd_protected(obj)                             DACL inheritance disabled
//	aces(obj)                                     list of ACE maps from nTSecurityDescriptor:
//	                                              {trustee, mask, allow, inherited, effective,
//	                                               object_type, inherited_object_type, trustee_tier0}
//	aces_of(obj, "msDS-AllowedToActOnBehalfOfOtherIdentity")  same, for another SD attribute
//	sd_readable(obj)                              descriptor was collected (honest-state guard)
//	objattr("cn=ipaConfig,cn=etc,<default>", "ipaUserAuthType")   first value of an attribute on
//	                                              another snapshot object ("" when absent); <default>
//	                                              is the base DN of the snapshot
//	objattrs(dn, "attr")                          all values of that attribute
//	objexists(dn)                                 the object was collected
//	smbbool(obj, "server schannel", true)         Samba boolean (yes/true/1/on) with a default for absent
//	version_lt("4.17.3", "4.17.4")                dotted-numeric version compare; "" is never less
//	intval("0x1c")                                decimal or 0x-hex string to int; 0 when not numeric
//	schema_guid("ms-Mcs-AdmPwd")                  schemaIDGUID of a collected attributeSchema/classSchema
//	                                              object by lDAPDisplayName ("" when not collected)
//	holds_tier0(obj)                              a Tier-0 object lies below obj in the tree
//	spn_known("cifs/fs01.lab.example")            the SPN's host belongs to a collected account; hosts
//	                                              outside the snapshot's DNS domain count as known
//	reaches_tier0(obj)                            a non-Tier-0 principal has a control path to a Tier-0
//	                                              object (transitive ACL + group membership graph)
func helperOptions() []cel.EnvOption {
	mapT := cel.MapType(cel.StringType, cel.DynType)
	aceList := cel.ListType(cel.MapType(cel.StringType, cel.DynType))
	return []cel.EnvOption{
		cel.Function("flags",
			cel.Overload("flags_map_string_int", []*cel.Type{mapT, cel.StringType, cel.IntType}, cel.BoolType,
				cel.FunctionBinding(func(a ...ref.Val) ref.Val {
					v, ok := intOf(a[0], string(a[1].(types.String)))
					m := uint64(a[2].(types.Int))
					return types.Bool(ok && v&m == m)
				}))),
		cel.Function("anyflag",
			cel.Overload("anyflag_map_string_int", []*cel.Type{mapT, cel.StringType, cel.IntType}, cel.BoolType,
				cel.FunctionBinding(func(a ...ref.Val) ref.Val {
					v, ok := intOf(a[0], string(a[1].(types.String)))
					return types.Bool(ok && v&uint64(a[2].(types.Int)) != 0)
				}))),
		cel.Function("mask_has",
			cel.Overload("mask_has_int_int", []*cel.Type{cel.IntType, cel.IntType}, cel.BoolType,
				cel.BinaryBinding(func(m, b ref.Val) ref.Val {
					mm, bb := uint64(m.(types.Int)), uint64(b.(types.Int))
					return types.Bool(mm&bb == bb)
				}))),
		cel.Function("age_days",
			cel.Overload("age_days_map_string", []*cel.Type{mapT, cel.StringType}, cel.IntType,
				cel.BinaryBinding(func(o, name ref.Val) ref.Val {
					t, ok := timeOf(firstAttr(o, string(name.(types.String))))
					if !ok {
						return types.Int(-1)
					}
					return types.Int(int64(nowOf(o).Sub(t).Hours() / 24))
				}))),
		cel.Function("sid_rid",
			cel.Overload("sid_rid_string", []*cel.Type{cel.StringType}, cel.IntType,
				cel.UnaryBinding(func(s ref.Val) ref.Val {
					str := string(s.(types.String))
					n, _ := strconv.ParseInt(str[strings.LastIndexByte(str, '-')+1:], 10, 64)
					return types.Int(n)
				}))),
		cel.Function("sid_domain",
			cel.Overload("sid_domain_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(s ref.Val) ref.Val {
					str := string(s.(types.String))
					if i := strings.LastIndexByte(str, '-'); i > 0 {
						return types.String(str[:i])
					}
					return s
				}))),
		cel.Function("tier0",
			cel.Overload("tier0_map", []*cel.Type{mapT}, cel.BoolType,
				cel.UnaryBinding(func(o ref.Val) ref.Val {
					m, _ := o.Value().(map[string]any)
					b, _ := m["tier0"].(bool)
					return types.Bool(b)
				}))),
		cel.Function("tier0_sid",
			cel.Overload("tier0_sid_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(s ref.Val) ref.Val {
					if currentTier0 == nil {
						return types.False
					}
					ok, _ := currentTier0.IsSID(string(s.(types.String)))
					return types.Bool(ok)
				}))),
		cel.Function("sd_readable",
			cel.Overload("sd_readable_map", []*cel.Type{mapT}, cel.BoolType,
				cel.UnaryBinding(func(o ref.Val) ref.Val {
					_, err := descriptorOf(o, "nTSecurityDescriptor")
					return types.Bool(err == nil)
				}))),
		cel.Function("sd_protected",
			cel.Overload("sd_protected_map", []*cel.Type{mapT}, cel.BoolType,
				cel.UnaryBinding(func(o ref.Val) ref.Val {
					d, err := descriptorOf(o, "nTSecurityDescriptor")
					return types.Bool(err == nil && d.Protected())
				}))),
		cel.Function("objattr",
			cel.Overload("objattr_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(dn, name ref.Val) ref.Val {
					vals := lookupAttr(string(dn.(types.String)), string(name.(types.String)))
					if len(vals) == 0 {
						return types.String("")
					}
					return types.String(vals[0])
				}))),
		cel.Function("objattrs",
			cel.Overload("objattrs_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.ListType(cel.StringType),
				cel.BinaryBinding(func(dn, name ref.Val) ref.Val {
					vals := lookupAttr(string(dn.(types.String)), string(name.(types.String)))
					out := make([]ref.Val, len(vals))
					for i, v := range vals {
						out[i] = types.String(v)
					}
					return types.NewRefValList(types.DefaultTypeAdapter, out)
				}))),
		// sidexists(sid): an object with this objectSid was collected. Lets a
		// check look for a well-known account or group by RID instead of by a
		// DN that an administrator can rename or move.
		cel.Function("sidexists",
			cel.Overload("sidexists_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(s ref.Val) ref.Val {
					return types.Bool(currentSIDs[strings.ToUpper(string(s.(types.String)))])
				}))),
		cel.Function("objexists",
			cel.Overload("objexists_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(dn ref.Val) ref.Val {
					_, ok := lookupObject(string(dn.(types.String)))
					return types.Bool(ok)
				}))),
		cel.Function("smbbool",
			cel.Overload("smbbool_map_string_bool", []*cel.Type{mapT, cel.StringType, cel.BoolType}, cel.BoolType,
				cel.FunctionBinding(func(a ...ref.Val) ref.Val {
					v := strings.ToLower(strings.TrimSpace(firstAttr(a[0], string(a[1].(types.String)))))
					switch v {
					case "":
						return a[2]
					case "yes", "true", "1", "on":
						return types.True
					}
					return types.False
				}))),
		cel.Function("intval",
			cel.Overload("intval_string", []*cel.Type{cel.StringType}, cel.IntType,
				cel.UnaryBinding(func(a ref.Val) ref.Val {
					v := strings.TrimSpace(string(a.(types.String)))
					if n, err := strconv.ParseInt(v, 0, 64); err == nil {
						return types.Int(n)
					}
					return types.Int(0)
				}))),
		cel.Function("version_lt",
			cel.Overload("version_lt_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(a, b ref.Val) ref.Val {
					return types.Bool(versionLess(string(a.(types.String)), string(b.(types.String))))
				}))),
		cel.Function("schema_guid",
			cel.Overload("schema_guid_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(s ref.Val) ref.Val {
					return types.String(currentSchemaGUIDs[strings.ToLower(string(s.(types.String)))])
				}))),
		cel.Function("holds_tier0",
			cel.Overload("holds_tier0_map", []*cel.Type{mapT}, cel.BoolType,
				cel.UnaryBinding(func(o ref.Val) ref.Val {
					m, _ := o.Value().(map[string]any)
					dn, _ := m["dn"].(string)
					return types.Bool(currentT0Parents[strings.ToLower(dn)])
				}))),
		cel.Function("spn_known",
			cel.Overload("spn_known_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(s ref.Val) ref.Val {
					return types.Bool(spnKnown(string(s.(types.String))))
				}))),
		cel.Function("reaches_tier0",
			cel.Overload("reaches_tier0_map", []*cel.Type{mapT}, cel.BoolType,
				cel.UnaryBinding(func(o ref.Val) ref.Val {
					sid := firstAttr(o, "objectSid")
					return types.Bool(sid != "" && currentReachers[strings.ToUpper(sid)])
				}))),
		cel.Function("aces",
			cel.Overload("aces_map", []*cel.Type{mapT}, aceList,
				cel.UnaryBinding(func(o ref.Val) ref.Val { return aceVals(o, "nTSecurityDescriptor") }))),
		cel.Function("aces_of",
			cel.Overload("aces_of_map_string", []*cel.Type{mapT, cel.StringType}, aceList,
				cel.BinaryBinding(func(o, name ref.Val) ref.Val { return aceVals(o, string(name.(types.String))) }))),
	}
}

// intOf reads an attribute as an unsigned bit field. AD stores 32-bit flag
// attributes as signed decimals (userAccountControl can be negative in LDIF
// exports); the value is reinterpreted as uint32 in that case.
func intOf(o ref.Val, name string) (uint64, bool) {
	s := firstAttr(o, name)
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	if n < 0 && n >= -1<<31 {
		return uint64(uint32(int32(n))), true
	}
	return uint64(n), true
}

// timeOf parses the two AD time encodings: FILETIME integers (pwdLastSet,
// lastLogonTimestamp, accountExpires — 100 ns since 1601-01-01 UTC) and
// GeneralizedTime (whenCreated "20240131120000.0Z"). 0 and the "never" value
// 0x7FFFFFFFFFFFFFFF are reported as absent.
func timeOf(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n <= 0 || n == 0x7FFFFFFFFFFFFFFF {
			return time.Time{}, false
		}
		const epochDiff = 116444736000000000 // 1601→1970 in 100 ns
		return time.Unix(0, (n-epochDiff)*100).UTC(), true
	}
	for _, layout := range []string{"20060102150405.0Z0700", "20060102150405Z0700", "20060102150405.0Z", "20060102150405Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func nowOf(o ref.Val) time.Time {
	m, _ := o.Value().(map[string]any)
	if n, ok := m["now"].(int64); ok {
		return time.Unix(n, 0).UTC()
	}
	return time.Now().UTC()
}

func descriptorOf(o ref.Val, attr string) (*secdesc.Descriptor, error) {
	s := firstAttr(o, attr)
	if s == "" {
		return nil, errNoSD
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return secdesc.Parse(raw)
}

type sdErr string

func (e sdErr) Error() string { return string(e) }

const errNoSD = sdErr("no security descriptor collected")

func aceVals(o ref.Val, attr string) ref.Val {
	d, err := descriptorOf(o, attr)
	if err != nil {
		return types.NewDynamicList(types.DefaultTypeAdapter, []map[string]any{})
	}
	out := make([]map[string]any, 0, len(d.DACL))
	for _, a := range d.DACL {
		t0 := false
		if currentTier0 != nil {
			t0, _ = currentTier0.IsSID(a.Trustee)
		}
		out = append(out, map[string]any{
			"trustee": a.Trustee, "mask": int64(a.Mask), "allow": a.Allow(),
			"inherited": a.Inherited(), "effective": a.Effective(),
			"object_type": a.ObjectType, "inherited_object_type": a.InheritedObjectType,
			"trustee_tier0": t0,
		})
	}
	return types.NewDynamicList(types.DefaultTypeAdapter, out)
}

// Snapshot index for the objattr/objattrs/objexists helpers; set per evaluation
// under evalMu like currentTier0.
var (
	currentIndex       map[string]*snapshot.Object
	currentSIDs        map[string]bool
	currentBase        string
	currentSchemaGUIDs map[string]string // lower(lDAPDisplayName) -> schemaIDGUID
	currentT0Parents   map[string]bool   // lower(DN) of every ancestor of a Tier-0 object
	currentHosts       map[string]bool   // lower host names and short names of collected accounts
	currentDNSDomain   string            // DNS domain derived from the base DN
	currentNames       map[string]string // upper(SID) -> display name (sAMAccountName or CN)
	currentReachers    map[string]bool   // upper(SID) -> has a control path to a Tier-0 object
	currentReachPath   map[string]string // upper(SID) -> that path, for the finding evidence
)

func indexSnapshot(snap *snapshot.Snapshot) map[string]*snapshot.Object {
	idx := make(map[string]*snapshot.Object, len(snap.Objects))
	sids := make(map[string]bool, len(snap.Objects))
	currentNames = map[string]string{}
	for i := range snap.Objects {
		idx[strings.ToLower(snap.Objects[i].DN)] = &snap.Objects[i]
		if sid := snap.Objects[i].Attr("objectSid"); sid != "" {
			sids[strings.ToUpper(sid)] = true
			name := snap.Objects[i].Attr("sAMAccountName")
			if name == "" {
				name = shortDN(snap.Objects[i].DN)
			}
			currentNames[strings.ToUpper(sid)] = name
		}
	}
	currentSIDs = sids

	currentSchemaGUIDs = map[string]string{}
	currentHosts = map[string]bool{}
	for i := range snap.Objects {
		o := &snap.Objects[i]
		if n, g := o.Attr("lDAPDisplayName"), o.Attr("schemaIDGUID"); n != "" && g != "" {
			currentSchemaGUIDs[strings.ToLower(n)] = strings.ToLower(g)
		}
		if h := o.Attr("dNSHostName"); h != "" {
			currentHosts[strings.ToLower(h)] = true
		}
		if sam := o.Attr("sAMAccountName"); strings.HasSuffix(sam, "$") {
			currentHosts[strings.ToLower(strings.TrimSuffix(sam, "$"))] = true
		}
		for k, vals := range o.Attrs {
			if !strings.EqualFold(k, "servicePrincipalName") {
				continue
			}
			for _, v := range vals {
				if h := spnHost(v); h != "" {
					currentHosts[h] = true
				}
			}
		}
	}
	currentDNSDomain = dnsDomainOf(snap.Meta.BaseDN)
	return idx
}

// tier0Parents marks every ancestor DN of every Tier-0 object, so a check can
// ask whether a container (OU, CN=Users, the domain head) holds Tier-0 objects.
func tier0Parents(dns []string) map[string]bool {
	out := map[string]bool{}
	for _, dn := range dns {
		for p := parentDN(dn); p != ""; p = parentDN(p) {
			out[strings.ToLower(p)] = true
		}
	}
	return out
}

// parentDN strips the first RDN, honouring backslash-escaped commas.
func parentDN(dn string) string {
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++
		case ',':
			return strings.TrimSpace(dn[i+1:])
		}
	}
	return ""
}

func dnsDomainOf(base string) string {
	var parts []string
	for _, rdn := range strings.Split(base, ",") {
		rdn = strings.TrimSpace(rdn)
		if len(rdn) > 3 && strings.EqualFold(rdn[:3], "dc=") {
			parts = append(parts, strings.ToLower(rdn[3:]))
		}
	}
	return strings.Join(parts, ".")
}

// spnHost returns the lower-case host part of service/host[:port][/name].
func spnHost(spn string) string {
	i := strings.IndexByte(spn, '/')
	if i < 0 {
		return ""
	}
	h := spn[i+1:]
	if j := strings.IndexAny(h, ":/"); j >= 0 {
		h = h[:j]
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// spnKnown reports whether the host of an SPN belongs to an account in the
// snapshot. A host in another DNS domain cannot be judged from one domain's
// data and counts as known, so the check never fires on what it cannot see.
func spnKnown(spn string) bool {
	h := spnHost(spn)
	if h == "" || currentHosts[h] {
		return true
	}
	short, suffix, dotted := strings.Cut(h, ".")
	if dotted && currentDNSDomain != "" && suffix != currentDNSDomain {
		return true
	}
	return currentHosts[short]
}

func lookupObject(dn string) (*snapshot.Object, bool) {
	if currentIndex == nil {
		return nil, false
	}
	dn = strings.ReplaceAll(dn, "<default>", currentBase)
	o, ok := currentIndex[strings.ToLower(dn)]
	return o, ok
}

func lookupAttr(dn, name string) []string {
	o, ok := lookupObject(dn)
	if !ok {
		return nil
	}
	for k, v := range o.Attrs {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// versionLess compares dotted numeric prefixes ("4.21.3-Debian" < "4.22.0").
// An empty or non-numeric a is never less, so unknown versions do not fire checks.
func versionLess(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func versionParts(s string) []int {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "-+ _"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			if len(out) == 0 {
				return nil
			}
			break
		}
		out = append(out, n)
	}
	return out
}

// --- Principal naming, secret masking and the Tier-0 control graph ----------

// wellKnownName labels the built-in SIDs that appear as trustees but are not
// collected objects, so a finding names them instead of printing a bare SID.
var wellKnownName = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-5-7":      "Anonymous Logon",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-9":      "Enterprise Domain Controllers",
	"S-1-5-10":     "SELF",
	"S-1-3-0":      "CREATOR OWNER",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-544": "BUILTIN\\Administrators",
}

// resolvePrincipal turns a SID into "name (SID)" using the snapshot's accounts
// and the well-known table; an unknown SID is returned unchanged.
func resolvePrincipal(sid string) string {
	up := strings.ToUpper(sid)
	if n := currentNames[up]; n != "" {
		return n + " (" + sid + ")"
	}
	// Domain-relative RID of a domain SID with no collected object, e.g. a
	// group that was not read; name it by its RID so it is still actionable.
	if n := wellKnownName[up]; n != "" {
		return n + " (" + sid + ")"
	}
	if strings.HasPrefix(up, "S-1-5-32-") {
		return "BUILTIN\\" + up[len("S-1-5-32-"):] + " (" + sid + ")"
	}
	return sid
}

// maskSecret hides a credential that was found in a readable attribute while
// keeping enough context to locate it: any leading words before the final
// whitespace-separated token are kept, the token is reduced to its first two
// characters plus bullets, and its true length is shown.
func maskSecret(v string) string {
	v = strings.TrimRight(v, " \t")
	if v == "" {
		return ""
	}
	prefix, secret := "", v
	if i := strings.LastIndexAny(v, " \t"); i >= 0 {
		prefix, secret = v[:i+1], v[i+1:]
	}
	r := []rune(secret)
	keep := 2
	if len(r) <= keep {
		keep = 0
	}
	bullets := len(r) - keep
	if bullets < 3 {
		bullets = 3
	}
	if bullets > 12 {
		bullets = 12
	}
	return prefix + string(r[:keep]) + strings.Repeat("•", bullets) + fmt.Sprintf(" (%d chars)", len(r))
}

// shortDN returns the value of the first RDN of a DN (its CN), honouring
// backslash-escaped commas, for compact path and name display.
func shortDN(dn string) string {
	end := len(dn)
	for i := 0; i < len(dn); i++ {
		if dn[i] == '\\' {
			i++
			continue
		}
		if dn[i] == ',' {
			end = i
			break
		}
	}
	rdn := dn[:end]
	if j := strings.IndexByte(rdn, '='); j >= 0 {
		return rdn[j+1:]
	}
	return rdn
}

// controlRight reports whether an ACE grants a right that lets its trustee take
// control of the object (rewrite its ACL, owner, membership or password, or run
// all extended rights), with a short label for the path. It is the same right
// set DSA-0015 uses, kept in one place.
func controlRight(a secdesc.ACE) (string, bool) {
	m := a.Mask
	switch {
	case m&0x10000000 == 0x10000000:
		return "GenericAll", true
	case m&0x000F01FF == 0x000F01FF:
		return "FullControl", true
	case m&0x40000000 == 0x40000000:
		return "GenericWrite", true
	case m&0x40000 != 0:
		return "WriteDacl", true
	case m&0x80000 != 0:
		return "WriteOwner", true
	case m&0x20 != 0 && (a.ObjectType == "" || a.ObjectType == "bf9679c0-0de6-11d0-a285-00aa003049e2"):
		return "Write-Member", true
	case m&0x100 != 0 && a.ObjectType == "":
		return "AllExtendedRights", true
	case m&0x100 != 0 && a.ObjectType == "00299570-246d-11d0-a768-00aa006e0529":
		return "ResetPassword", true
	}
	return "", false
}

// controlGraph computes, for one snapshot, every non-Tier-0 principal that can
// reach a Tier-0 object through a chain of control edges (dangerous ACLs) and
// group memberships, with a readable path for each. It works backwards from the
// Tier-0 set (plus the domain head and the Domain Controllers OU, controlling
// either of which yields Tier 0) to a fixpoint: a principal that controls a
// reachable object becomes reachable, and so does every member of a reachable
// group. It is read-only graph arithmetic over data already collected.
func controlGraph(snap *snapshot.Snapshot, t0 *tier0.Set) (map[string]bool, map[string]string) {
	sidToDN := map[string]string{} // upper(SID) -> DN (lower)
	type ctl struct{ trustee, right string }
	controllers := map[string][]ctl{} // lower(DN) -> who controls it
	members := map[string][]string{}  // lower(group DN) -> member DNs (lower)
	dnToSID := map[string]string{}    // lower(DN) -> upper(SID)
	disp := map[string]string{}       // lower(DN) -> display name (original-case CN)
	name := func(ldn string) string {
		if d := disp[ldn]; d != "" {
			return d
		}
		return shortDN(ldn)
	}

	for i := range snap.Objects {
		o := &snap.Objects[i]
		ldn := strings.ToLower(o.DN)
		disp[ldn] = shortDN(o.DN)
		if sid := o.Attr("objectSid"); sid != "" {
			sidToDN[strings.ToUpper(sid)] = ldn
			dnToSID[ldn] = strings.ToUpper(sid)
		}
		for k, vals := range o.Attrs {
			if strings.EqualFold(k, "member") {
				for _, m := range vals {
					members[ldn] = append(members[ldn], strings.ToLower(m))
				}
			}
		}
		raw := o.Attr("nTSecurityDescriptor")
		if raw == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			continue
		}
		d, err := secdesc.Parse(b)
		if err != nil {
			continue
		}
		for _, a := range d.DACL {
			if !a.Allow() || !a.Effective() || a.Trustee == "S-1-5-10" || a.Trustee == "S-1-3-0" {
				continue
			}
			if label, ok := controlRight(a); ok {
				controllers[ldn] = append(controllers[ldn], ctl{strings.ToUpper(a.Trustee), label})
			}
		}
	}

	// Seed the frontier: controlling any of these yields Tier 0.
	reason := map[string]string{} // lower(DN) -> path from controlling it to Tier 0
	seed := func(dn, why string) {
		l := strings.ToLower(dn)
		if _, ok := reason[l]; !ok {
			reason[l] = why
		}
	}
	for _, dn := range t0.DNs() { // t0.DNs returns lower-cased DNs
		seed(dn, "Tier 0")
	}
	seed(snap.Meta.BaseDN, "domain root")
	for i := range snap.Objects {
		if strings.HasPrefix(strings.ToLower(snap.Objects[i].DN), "ou=domain controllers,") {
			seed(snap.Objects[i].DN, "Domain Controllers OU")
		}
	}

	reachers := map[string]bool{}
	path := map[string]string{}
	addReacher := func(sid, p string) bool {
		if reachers[sid] {
			return false
		}
		if ok, _ := t0.IsSID(sid); ok { // a Tier-0 trustee holding the right is legitimate
			return false
		}
		reachers[sid] = true
		path[sid] = p
		if dn, ok := sidToDN[sid]; ok {
			if _, seen := reason[dn]; !seen {
				reason[dn] = p // controlling this principal now reaches Tier 0 too
				return true
			}
		}
		return false
	}

	for changed := true; changed; {
		changed = false
		for dn, why := range reason {
			for _, c := range controllers[dn] {
				if addReacher(c.trustee, c.right+" on "+name(dn)+" → "+why) {
					changed = true
				}
			}
		}
		// A member of a group that can reach Tier 0 inherits that reach.
		for gdn, ms := range members {
			gsid := dnToSID[gdn]
			if gsid == "" || !reachers[gsid] {
				continue
			}
			for _, mdn := range ms {
				msid := dnToSID[mdn]
				if msid == "" {
					continue
				}
				if addReacher(msid, "member of "+name(gdn)+" → "+path[gsid]) {
					changed = true
				}
			}
		}
	}
	return reachers, path
}
