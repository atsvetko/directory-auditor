package tier0

import (
	"testing"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

const dom = "S-1-5-21-1-2-3"

func obj(dn, class, sam, sid string, kv ...string) snapshot.Object {
	o := snapshot.Object{DN: dn, Class: []string{"top", class}, Attrs: map[string][]string{
		"sAMAccountName": {sam}, "objectSid": {sid},
	}}
	for i := 0; i+1 < len(kv); i += 2 {
		o.Attrs[kv[i]] = append(o.Attrs[kv[i]], kv[i+1])
	}
	return o
}

func TestResolve(t *testing.T) {
	objs := []snapshot.Object{
		obj("CN=Administrators,CN=Builtin,DC=lab", "group", "Administrators", "S-1-5-32-544",
			"member", "CN=Domain Admins,CN=Users,DC=lab",
			"member", "CN=S-1-5-21-9-9-9-1001,CN=ForeignSecurityPrincipals,DC=lab"),
		obj("CN=Domain Admins,CN=Users,DC=lab", "group", "Domain Admins", dom+"-512",
			"member", "CN=IT Admins,OU=Groups,DC=lab",
			"member", "CN=Gone,DC=other,DC=lab"),
		obj("CN=IT Admins,OU=Groups,DC=lab", "group", "IT Admins", dom+"-1200",
			"member", "CN=alice,OU=Staff,DC=lab",
			"member", "CN=Domain Admins,CN=Users,DC=lab"), // cycle
		obj("CN=alice,OU=Staff,DC=lab", "user", "alice", dom+"-1300"),
		obj("CN=bob,OU=Staff,DC=lab", "user", "bob", dom+"-1301", "adminCount", "1"),
		obj("CN=Domain Controllers,CN=Users,DC=lab", "group", "Domain Controllers", dom+"-516"),
		obj("CN=DC1,OU=Domain Controllers,DC=lab", "computer", "DC1$", dom+"-1000", "primaryGroupID", "516"),
		obj("CN=WS1,OU=Computers,DC=lab", "computer", "WS1$", dom+"-1400", "primaryGroupID", "515"),
		obj("CN=krbtgt,CN=Users,DC=lab", "user", "krbtgt", dom+"-502"),
		obj("CN=Administrator,CN=Users,DC=lab", "user", "Administrator", dom+"-500"),
	}
	s := Resolve(objs, dom)

	want := map[string]string{
		"CN=alice,OU=Staff,DC=lab":            "Administrators > Domain Admins > IT Admins > alice",
		"CN=DC1,OU=Domain Controllers,DC=lab": "Domain Controllers > DC1$ (primary group)",
		"CN=krbtgt,CN=Users,DC=lab":           "krbtgt account",
		"CN=Administrator,CN=Users,DC=lab":    "built-in Administrator account",
	}
	for dn, reason := range want {
		ok, r := s.IsDN(dn)
		if !ok {
			t.Errorf("%s not Tier 0", dn)
			continue
		}
		// alice may be reached via Domain Admins seed first; accept either path that ends correctly.
		if dn == "CN=alice,OU=Staff,DC=lab" {
			if r != reason && r != "Domain Admins > IT Admins > alice" {
				t.Errorf("alice reason %q", r)
			}
			continue
		}
		if r != reason {
			t.Errorf("%s reason %q, want %q", dn, r, reason)
		}
	}
	for _, dn := range []string{"CN=bob,OU=Staff,DC=lab", "CN=WS1,OU=Computers,DC=lab"} {
		if ok, r := s.IsDN(dn); ok {
			t.Errorf("%s wrongly Tier 0 (%s); adminCount and ordinary primary groups must not count", dn, r)
		}
	}
	if ok, _ := s.IsSID("S-1-5-21-9-9-9-1001"); !ok {
		t.Error("foreign security principal in Administrators not Tier 0")
	}
	if ok, _ := s.IsSID("S-1-5-18"); !ok {
		t.Error("SYSTEM not Tier 0")
	}
	if ok, _ := s.IsSID("S-1-5-32-551"); !ok {
		t.Error("Backup Operators (not collected) not matched by SID")
	}
	if ok, _ := s.IsSID(dom + "-1301"); ok {
		t.Error("bob's SID Tier 0")
	}
	if len(s.Unresolved) != 1 || s.Unresolved[0] != "CN=Gone,DC=other,DC=lab" {
		t.Errorf("unresolved = %v", s.Unresolved)
	}
}

func TestResolveFreeIPA(t *testing.T) {
	snap, err := snapshot.ReadFile("../../testdata/synthetic-freeipa.json.zst")
	if err != nil {
		t.Fatal(err)
	}
	s := ResolveFor("freeipa", snap.Objects, "")
	want := map[string]string{
		"uid=admin,cn=users,cn=accounts,dc=ipa,dc=example":                                            "admins > admin",
		"uid=carol,cn=users,cn=accounts,dc=ipa,dc=example":                                            "admins > carol",
		"fqdn=ipa.ipa.example,cn=computers,cn=accounts,dc=ipa,dc=example":                             "IPA server",
		"krbprincipalname=ldap/ipa.ipa.example@IPA.EXAMPLE,cn=services,cn=accounts,dc=ipa,dc=example": "service on IPA server ipa.ipa.example",
	}
	for dn, reason := range want {
		ok, r := s.IsDN(dn)
		if !ok || r != reason {
			t.Errorf("%s: ok=%v reason=%q, want %q", dn, ok, r, reason)
		}
	}
	for _, dn := range []string{"uid=bob,cn=users,cn=accounts,dc=ipa,dc=example", "fqdn=web01.ipa.example,cn=computers,cn=accounts,dc=ipa,dc=example"} {
		if ok, r := s.IsDN(dn); ok {
			t.Errorf("%s wrongly Tier 0 (%s)", dn, r)
		}
	}
	if len(s.Unresolved) != 0 {
		t.Errorf("unresolved: %v", s.Unresolved)
	}
}
