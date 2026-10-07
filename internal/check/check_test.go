package check

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// testPack is a format fixture only. It is deliberately not a security check:
// real checks arrive with the catalogue (K1) and never before it.
const testPack = `id: TEST-0001
title: { en: "Fixture: object carries a description", ru: "Фикстура: у объекта есть описание" }
provider: [ad, samba]
domain: test
tier: 0
severity: info
quick: true
query:
  base: default
  scope: subtree
  filter: "(&(objectClass=user)(description=*))"
  attributes: [sAMAccountName, description]
condition: 'size(attrs(obj, "description")) > 0 && attr(obj, "sAMAccountName") != ""'
evidence: [sAMAccountName, description]
attack: []
bdu: []
remediation:
  en: { why: "fixture", abuse: "fixture", fix: "fixture", verify: "fixture" }
  ru: { why: "фикстура", abuse: "фикстура", fix: "фикстура", verify: "фикстура" }
references:
  - { title: "Engine test fixture", url: "https://example.invalid/fixture" }
`

func synthetic() *snapshot.Snapshot {
	return &snapshot.Snapshot{
		Schema: snapshot.SchemaVersion, Collected: time.Now(),
		Meta: snapshot.Meta{Provider: "ad", Dialect: "samba", Target: "lab", Tier: 0},
		Objects: []snapshot.Object{
			{DN: "CN=a,DC=lab", Class: []string{"top", "user"}, Attrs: map[string][]string{"sAMAccountName": {"a"}, "description": {"svc account"}}},
			{DN: "CN=b,DC=lab", Class: []string{"top", "user"}, Attrs: map[string][]string{"sAMAccountName": {"b"}}},
			{DN: "CN=g,DC=lab", Class: []string{"top", "group"}, Attrs: map[string][]string{"description": {"group"}}},
		},
	}
}

func writePack(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidateEvaluate(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "test-0001.yaml", testPack)
	packs, err := LoadDir(dir, LoadOptions{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 1 || packs[0].Signed {
		t.Fatalf("unexpected packs: %+v", packs)
	}
	res, err := Evaluate(synthetic(), packs)
	if err != nil {
		t.Fatal(err)
	}
	c := res.Checks[0]
	if c.Status != "fail" || c.Matched != 1 || len(c.Findings) != 1 || c.Findings[0].DN != "CN=a,DC=lab" {
		t.Fatalf("unexpected result: %+v", c)
	}
	if res.Counts.Checked != 1 || res.Counts.Failed != 1 || !res.Unsigned {
		t.Fatalf("counts: %+v unsigned=%v", res.Counts, res.Unsigned)
	}
}

func TestUnsignedRefusedByDefault(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "test-0001.yaml", testPack)
	if _, err := LoadDir(dir, LoadOptions{}); err == nil {
		t.Fatal("unsigned pack must be refused without --allow-unsigned")
	}
}

func TestSignatureRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := writePack(t, dir, "test-0001.yaml", testPack)
	sig, err := Sign(priv, []byte(testPack))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p+".sig", []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	packs, err := LoadDir(dir, LoadOptions{PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	if !packs[0].Signed {
		t.Fatal("expected signed pack")
	}
	// Tamper: one byte changed → signature invalid → refused.
	if err := os.WriteFile(p, []byte(testPack+"\n# tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir, LoadOptions{PublicKey: pub}); err == nil {
		t.Fatal("tampered pack must be refused")
	}
}

func TestSkipReasons(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "test-0001.yaml", testPack)
	packs, _ := LoadDir(dir, LoadOptions{AllowUnsigned: true})
	snap := synthetic()
	snap.Meta.Provider, snap.Meta.Dialect = "freeipa", ""
	res, _ := Evaluate(snap, packs)
	if res.Checks[0].Status != "skipped" || res.Checks[0].Skip != "provider" {
		t.Fatalf("expected provider skip, got %+v", res.Checks[0])
	}
	packs[0].Tier = 2
	snap = synthetic()
	res, _ = Evaluate(snap, packs)
	if res.Checks[0].Skip != "tier" {
		t.Fatalf("expected tier skip, got %+v", res.Checks[0])
	}
}

func TestValidateRejectsIncompletePack(t *testing.T) {
	bad := Pack{ID: "x", Severity: "huge", Domain: "nope", Tier: 5}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected validation errors")
	}
}

func TestFilterSemantics(t *testing.T) {
	o := snapshot.Object{DN: "CN=x", Class: []string{"top", "user"}, Attrs: map[string][]string{
		"userAccountControl": {"66048"}, "sAMAccountName": {"svc_backup"}, "pwdLastSet": {"0"},
	}}
	cases := map[string]bool{
		"(objectClass=user)":                                                     true,
		"(objectclass=USER)":                                                     true,
		"(objectClass=computer)":                                                 false,
		"(sAMAccountName=svc_*)":                                                 true,
		"(sAMAccountName=*backup)":                                               true,
		"(sAMAccountName=*c_b*)":                                                 true,
		"(sAMAccountName=adm*)":                                                  false,
		"(userAccountControl:1.2.840.113556.1.4.803:=65536)":                     true,  // DONT_EXPIRE_PASSWORD set
		"(userAccountControl:1.2.840.113556.1.4.803:=2)":                         false, // ACCOUNTDISABLE not set
		"(userAccountControl:1.2.840.113556.1.4.804:=3)":                         false,
		"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))": true,
		"(|(pwdLastSet=0)(pwdLastSet>=1))":                                       true,
		"(pwdLastSet<=0)":                                                        true,
		"(description=*)":                                                        false,
	}
	for f, want := range cases {
		pf, err := ParseFilter(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if got := pf.Match(o); got != want {
			t.Errorf("%s: got %v want %v", f, got, want)
		}
	}
	for _, bad := range []string{"", "(", "(a)", "(&)", "(a=b)(c=d)", "(a:dn:1.2.3:=x)"} {
		if _, err := ParseFilter(bad); err == nil {
			t.Errorf("expected parse error for %q", bad)
		}
	}
}
