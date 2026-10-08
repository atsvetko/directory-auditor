package catalogue

import (
	"strings"
	"testing"

	"github.com/atsvetko/directory-auditor/internal/check"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// TestRepositoryCatalogue validates every entry committed under catalogue/.
func TestRepositoryCatalogue(t *testing.T) {
	entries, err := LoadDir("../../catalogue")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no catalogue entries found")
	}
	for _, e := range entries {
		if f, ok := e.QuerySketch["filter"].(string); ok && f != "" {
			if _, err := check.ParseFilter(f); err != nil {
				t.Errorf("%s: query_sketch.filter does not parse: %v", e.ID, err)
			}
		}
		if e.ConditionCEL != "" {
			if _, err := check.CompileCondition(e.ConditionCEL); err != nil {
				t.Errorf("%s: condition_cel does not compile: %v", e.ID, err)
			}
		}
	}
	t.Logf("%d catalogue entries valid", len(entries))
}

// TestImplementedEntries runs every entry that carries condition_cel against the
// synthetic snapshots of its domain and compares the union of firing DNs with
// `expect`. This is how a check is proven before a pack is written from the
// verified entry.
func TestImplementedEntries(t *testing.T) {
	entries, err := LoadDir("../../catalogue")
	if err != nil {
		t.Fatal(err)
	}
	labs := map[string][]string{
		"freeipa":        {"../../testdata/synthetic-freeipa.json.zst"},
		"samba":          {"../../testdata/synthetic-samba.json.zst"},
		"directory-core": {"../../testdata/synthetic-lab.json.zst", "../../testdata/synthetic-samba.json.zst"},
	}
	loaded := map[string]*snapshot.Snapshot{}
	ran := 0
	for _, e := range entries {
		if e.ConditionCEL == "" {
			continue
		}
		paths, ok := labs[e.Domain]
		if !ok {
			paths = labs["directory-core"]
		}
		filter, _ := e.QuerySketch["filter"].(string)
		if filter == "" {
			filter = "(objectClass=*)"
		}
		got := map[string]bool{}
		for _, path := range paths {
			snap := loaded[path]
			if snap == nil {
				snap, err = snapshot.ReadFile(path)
				if err != nil {
					t.Fatalf("%s: %v", e.ID, err)
				}
				loaded[path] = snap
			}
			res, err := check.EvaluateWith(snap, []check.Pack{{ID: e.ID, Provider: []string{snap.Meta.Provider, snap.Meta.Dialect},
				Severity: e.Severity, Tier: e.Tier, Query: check.Query{Filter: filter}, Condition: e.ConditionCEL, Signed: true}}, check.EvalOptions{})
			if err != nil {
				t.Fatalf("%s: %v", e.ID, err)
			}
			cr := res.Checks[0]
			if cr.Status == "skipped" {
				t.Errorf("%s on %s: skipped (%s): %v", e.ID, path, cr.Skip, cr.Findings)
				continue
			}
			for _, f := range cr.Findings {
				got[f.DN] = true
			}
		}
		want := map[string]bool{}
		for _, dn := range e.Expect {
			want[dn] = true
		}
		for dn := range want {
			if !got[dn] {
				t.Errorf("%s: expected finding on %s, none", e.ID, dn)
			}
		}
		for dn := range got {
			if !want[dn] {
				t.Errorf("%s: unexpected finding on %s", e.ID, dn)
			}
		}
		ran++
	}
	t.Logf("%d implemented entries exercised", ran)
}

// TestHardenedLabIsClean is the negative control: on a Samba DC configured at
// or above every recommended value, no implemented Samba or directory-core
// entry may fire, except informational ones listed here.
func TestHardenedLabIsClean(t *testing.T) {
	entries, err := LoadDir("../../catalogue")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.ReadFile("../../testdata/synthetic-samba-hardened.json.zst")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.ConditionCEL == "" || (e.Domain != "samba" && e.Domain != "directory-core") {
			continue
		}
		filter, _ := e.QuerySketch["filter"].(string)
		if filter == "" {
			filter = "(objectClass=*)"
		}
		res, err := check.EvaluateWith(snap, []check.Pack{{ID: e.ID, Provider: []string{"ad", "samba"}, Severity: e.Severity, Tier: e.Tier,
			Query: check.Query{Filter: filter}, Condition: e.ConditionCEL, Signed: true}}, check.EvalOptions{})
		if err != nil {
			t.Fatalf("%s: %v", e.ID, err)
		}
		if cr := res.Checks[0]; cr.Status == "fail" {
			t.Errorf("%s fired on the hardened lab: %v", e.ID, cr.Findings)
		}
	}
}

// TestEmbeddedMatchesWorkingTree guards the go:embed pattern: every entry on
// disk is in the binary, and every embedded entry still parses and validates.
func TestEmbeddedMatchesWorkingTree(t *testing.T) {
	disk, err := Packs("../../catalogue")
	if err != nil {
		t.Fatal(err)
	}
	built, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(disk) == 0 || len(disk) != len(built) {
		t.Fatalf("working tree has %d implemented entries, binary has %d", len(disk), len(built))
	}
	for i := range disk {
		if disk[i].ID != built[i].ID || disk[i].Condition != built[i].Condition || !built[i].Preview || built[i].Signed {
			t.Errorf("%s: embedded copy differs (preview=%v signed=%v)", disk[i].ID, built[i].Preview, built[i].Signed)
		}
	}
	if !strings.HasPrefix(built[0].Source, "catalogue:catalogue/") {
		t.Errorf("source = %q", built[0].Source)
	}
}

// TestCriticalObjectsFires covers DSA-0037's positive path, which no lab
// reproduces (every lab holds krbtgt, Domain Admins and AdminSDHolder): drop
// each object in turn and the entry must fire on the domain head, and stay
// silent when all three are present.
func TestCriticalObjectsFires(t *testing.T) {
	entries, err := LoadDir("../../catalogue")
	if err != nil {
		t.Fatal(err)
	}
	var e Entry
	for _, x := range entries {
		if x.ID == "DSA-0037" {
			e = x
		}
	}
	if e.ID == "" {
		t.Fatal("DSA-0037 not found")
	}
	pack, _ := e.Pack()
	pack.Signed, pack.Provider = true, []string{"ad"}
	run := func(drop func(snapshot.Object) bool) []string {
		snap, err := snapshot.ReadFile("../../testdata/synthetic-lab.json.zst")
		if err != nil {
			t.Fatal(err)
		}
		kept := snap.Objects[:0]
		for _, o := range snap.Objects {
			if !drop(o) {
				kept = append(kept, o)
			}
		}
		snap.Objects = kept
		res, err := check.EvaluateWith(snap, []check.Pack{pack}, check.EvalOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var dns []string
		for _, f := range res.Checks[0].Findings {
			dns = append(dns, f.DN)
		}
		return dns
	}
	if got := run(func(snapshot.Object) bool { return false }); len(got) != 0 {
		t.Errorf("complete lab: fired on %v", got)
	}
	cases := map[string]func(snapshot.Object) bool{
		"krbtgt":        func(o snapshot.Object) bool { return strings.HasSuffix(o.Attr("objectSid"), "-502") },
		"Domain Admins": func(o snapshot.Object) bool { return strings.HasSuffix(o.Attr("objectSid"), "-512") },
		"AdminSDHolder": func(o snapshot.Object) bool { return strings.HasPrefix(strings.ToLower(o.DN), "cn=adminsdholder,") },
	}
	for name, drop := range cases {
		if got := run(drop); len(got) != 1 || got[0] != "DC=lab,DC=example" {
			t.Errorf("without %s: fired on %v, want the domain head", name, got)
		}
	}
}
