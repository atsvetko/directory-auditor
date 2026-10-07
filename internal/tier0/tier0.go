// Package tier0 answers "is this principal or object Tier 0?" for a snapshot,
// following catalogue/TIER0.md exactly. It resolves group membership
// transitively — nested groups, primaryGroupID and foreign security
// principals — and records the path that made each principal Tier 0 so the
// report can show why, not just that.
//
// adminCount is deliberately ignored: it is evidence (DSA-0019), never proof.
package tier0

import (
	"sort"
	"strconv"
	"strings"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// Built-in aliases that are Tier 0 (S-1-5-32-x).
var builtinRIDs = map[uint32]string{
	544: "Administrators", 548: "Account Operators", 549: "Server Operators",
	550: "Print Operators", 551: "Backup Operators", 552: "Replicator",
}

// Domain-relative group RIDs that are Tier 0. 518, 519 and 527 exist only in the
// forest-root domain; in a child domain they surface as cross-domain members.
var domainGroupRIDs = map[uint32]string{
	512: "Domain Admins", 516: "Domain Controllers", 518: "Schema Admins",
	519: "Enterprise Admins", 521: "Read-only Domain Controllers",
	526: "Key Admins", 527: "Enterprise Key Admins",
}

// Well-known SIDs that are Tier 0 without being group members.
var wellKnown = map[string]string{
	"S-1-5-18": "SYSTEM",
	"S-1-5-9":  "Enterprise Domain Controllers",
}

// Set is the resolved Tier-0 population of one snapshot.
type Set struct {
	DomainSID string
	// Reason maps a lower-cased DN to the membership path that makes it Tier 0,
	// e.g. "Domain Admins > IT-Ops-Admins".
	Reason map[string]string
	// SIDs maps every Tier-0 SID (objects, foreign principals, well-known) to its reason.
	SIDs map[string]string
	// Unresolved lists member DNs of Tier-0 groups that are not in the snapshot
	// (other domains, phantoms). They are reported, never assumed harmless.
	Unresolved []string
}

// IsDN reports whether the object with this DN is Tier 0, with the reason.
func (s *Set) IsDN(dn string) (bool, string) {
	r, ok := s.Reason[strings.ToLower(dn)]
	return ok, r
}

// IsSID reports whether a SID is Tier 0, with the reason. Built-in Tier-0
// aliases are matched by SID even when the alias object was not collected.
func (s *Set) IsSID(sid string) (bool, string) {
	if r, ok := s.SIDs[sid]; ok {
		return true, r
	}
	if r, ok := wellKnown[sid]; ok {
		return true, r
	}
	if strings.HasPrefix(sid, "S-1-5-32-") {
		if rid, err := strconv.ParseUint(sid[len("S-1-5-32-"):], 10, 32); err == nil {
			if n, ok := builtinRIDs[uint32(rid)]; ok {
				return true, n
			}
		}
	}
	return false, ""
}

// Resolve computes the Tier-0 set. domainSID is the objectSid of the domain head.
func Resolve(objs []snapshot.Object, domainSID string) *Set {
	s := &Set{DomainSID: domainSID, Reason: map[string]string{}, SIDs: map[string]string{}}
	byDN := make(map[string]*snapshot.Object, len(objs))
	byPrimary := map[string][]*snapshot.Object{} // primaryGroupID -> objects
	for i := range objs {
		o := &objs[i]
		byDN[strings.ToLower(o.DN)] = o
		if pg := o.Attr("primaryGroupID"); pg != "" {
			byPrimary[pg] = append(byPrimary[pg], o)
		}
	}

	type item struct {
		o    *snapshot.Object
		path string
	}
	var queue []item
	mark := func(o *snapshot.Object, path string) bool {
		k := strings.ToLower(o.DN)
		if _, seen := s.Reason[k]; seen {
			return false
		}
		s.Reason[k] = path
		if sid := o.Attr("objectSid"); sid != "" {
			s.SIDs[sid] = path
		}
		return true
	}

	// Seeds: Tier-0 groups by SID, built-in Administrator, krbtgt accounts.
	for i := range objs {
		o := &objs[i]
		sid := o.Attr("objectSid")
		name := o.Attr("sAMAccountName")
		var seed string
		switch {
		case strings.HasPrefix(sid, "S-1-5-32-"):
			if rid, err := strconv.ParseUint(sid[len("S-1-5-32-"):], 10, 32); err == nil {
				seed = builtinRIDs[uint32(rid)]
			}
		case domainSID != "" && strings.HasPrefix(sid, domainSID+"-"):
			rid, _ := strconv.ParseUint(sid[len(domainSID)+1:], 10, 32)
			if n, ok := domainGroupRIDs[uint32(rid)]; ok {
				seed = n
			} else if rid == 500 {
				seed = "built-in Administrator account"
			}
		}
		if seed == "" && (strings.EqualFold(name, "krbtgt") || strings.HasPrefix(strings.ToLower(name), "krbtgt_")) {
			seed = "krbtgt account" // matched by name: see TIER0.md open points
		}
		if seed != "" && mark(o, seed) {
			queue = append(queue, item{o, seed})
		}
	}

	// Breadth-first expansion: member values and primaryGroupID back-links.
	unresolved := map[string]bool{}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if !isGroup(it.o) {
			continue
		}
		for _, m := range attrAll(it.o, "member") {
			mo, ok := byDN[strings.ToLower(m)]
			if !ok {
				if sid := fspSID(m); sid != "" {
					if _, seen := s.SIDs[sid]; !seen {
						s.SIDs[sid] = it.path + " > " + sid
					}
					continue
				}
				unresolved[m] = true
				continue
			}
			p := it.path + " > " + display(mo)
			if mark(mo, p) {
				queue = append(queue, item{mo, p})
			}
		}
		if sid := it.o.Attr("objectSid"); domainSID != "" && strings.HasPrefix(sid, domainSID+"-") {
			rid := sid[len(domainSID)+1:]
			for _, mo := range byPrimary[rid] {
				p := it.path + " > " + display(mo) + " (primary group)"
				if mark(mo, p) {
					queue = append(queue, item{mo, p})
				}
			}
		}
	}
	for dn := range unresolved {
		s.Unresolved = append(s.Unresolved, dn)
	}
	sort.Strings(s.Unresolved)
	return s
}

// DNs returns the Tier-0 DNs in stable order (lower-cased).
func (s *Set) DNs() []string {
	out := make([]string, 0, len(s.Reason))
	for k := range s.Reason {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func isGroup(o *snapshot.Object) bool {
	for _, c := range o.Class {
		if strings.EqualFold(c, "group") {
			return true
		}
	}
	return false
}

func display(o *snapshot.Object) string {
	if n := o.Attr("sAMAccountName"); n != "" {
		return n
	}
	return o.DN
}

func attrAll(o *snapshot.Object, name string) []string {
	for k, v := range o.Attrs {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// fspSID extracts the SID from a foreign-security-principal DN
// (CN=S-1-5-21-…,CN=ForeignSecurityPrincipals,DC=…).
func fspSID(dn string) string {
	l := strings.ToLower(dn)
	if !strings.Contains(l, ",cn=foreignsecurityprincipals,") || !strings.HasPrefix(l, "cn=s-1-") {
		return ""
	}
	return dn[3:strings.IndexByte(dn, ',')]
}

// ResolveFor picks the Tier-0 model by provider: the AD model (groups by SID)
// or the FreeIPA model (the admins and trust admins groups, nested through
// member, plus the IPA servers themselves).
func ResolveFor(provider string, objs []snapshot.Object, domainSID string) *Set {
	if provider == "freeipa" {
		return resolveFreeIPA(objs)
	}
	return Resolve(objs, domainSID)
}

func resolveFreeIPA(objs []snapshot.Object) *Set {
	s := &Set{Reason: map[string]string{}, SIDs: map[string]string{}}
	byDN := make(map[string]*snapshot.Object, len(objs))
	for i := range objs {
		byDN[strings.ToLower(objs[i].DN)] = &objs[i]
	}
	type item struct {
		o    *snapshot.Object
		path string
	}
	var queue []item
	mark := func(o *snapshot.Object, path string) bool {
		k := strings.ToLower(o.DN)
		if _, seen := s.Reason[k]; seen {
			return false
		}
		s.Reason[k] = path
		return true
	}
	for i := range objs {
		o := &objs[i]
		l := strings.ToLower(o.DN)
		switch {
		case strings.HasPrefix(l, "cn=admins,cn=groups,cn=accounts,"):
			if mark(o, "admins") {
				queue = append(queue, item{o, "admins"})
			}
		case strings.HasPrefix(l, "cn=trust admins,cn=groups,cn=accounts,"):
			if mark(o, "trust admins") {
				queue = append(queue, item{o, "trust admins"})
			}
		case strings.Contains(l, ",cn=masters,cn=ipa,cn=etc,"):
			// cn=<fqdn>,cn=masters → the host object and its service principals
			name := o.Attr("cn")
			if h, ok := byDN["fqdn="+strings.ToLower(name)+",cn=computers,cn=accounts,"+suffixAfter(l, ",cn=masters,cn=ipa,cn=etc,")]; ok {
				mark(h, "IPA server")
			}
			for j := range objs {
				p := strings.ToLower(objs[j].Attr("krbPrincipalName"))
				if strings.Contains(p, "/"+strings.ToLower(name)+"@") && strings.Contains(strings.ToLower(objs[j].DN), ",cn=services,cn=accounts,") {
					mark(&objs[j], "service on IPA server "+name)
				}
			}
		}
	}
	unresolved := map[string]bool{}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		for _, m := range attrAll(it.o, "member") {
			mo, ok := byDN[strings.ToLower(m)]
			if !ok {
				unresolved[m] = true
				continue
			}
			p := it.path + " > " + displayIPA(mo)
			if mark(mo, p) {
				queue = append(queue, item{mo, p})
			}
		}
	}
	for dn := range unresolved {
		s.Unresolved = append(s.Unresolved, dn)
	}
	sort.Strings(s.Unresolved)
	return s
}

func displayIPA(o *snapshot.Object) string {
	if n := o.Attr("uid"); n != "" {
		return n
	}
	if n := o.Attr("cn"); n != "" {
		return n
	}
	return o.DN
}

func suffixAfter(dn, marker string) string {
	if i := strings.Index(dn, marker); i >= 0 {
		return dn[i+len(marker):]
	}
	return ""
}
