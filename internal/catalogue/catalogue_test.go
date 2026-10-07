package catalogue

import (
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
// synthetic snapshot of its provider and compares the firing DNs with `expect`.
// This is how a check is proven before a pack is written from the verified entry.
func TestImplementedEntries(t *testing.T) {
	entries, err := LoadDir("../../catalogue")
	if err != nil {
		t.Fatal(err)
	}
	snaps := map[string]string{"freeipa": "../../testdata/synthetic-freeipa.json.zst"}
	loaded := map[string]*snapshot.Snapshot{}
	ran := 0
	for _, e := range entries {
		if e.ConditionCEL == "" {
			continue
		}
		path, ok := snaps[e.Domain]
		if !ok {
			path = "../../testdata/synthetic-lab.json.zst"
		}
		snap := loaded[path]
		if snap == nil {
			snap, err = snapshot.ReadFile(path)
			if err != nil {
				t.Fatalf("%s: %v", e.ID, err)
			}
			loaded[path] = snap
		}
		filter, _ := e.QuerySketch["filter"].(string)
		if filter == "" {
			filter = "(objectClass=*)"
		}
		res, err := check.EvaluateWith(snap, []check.Pack{{ID: e.ID, Provider: []string{snap.Meta.Provider, snap.Meta.Dialect},
			Severity: e.Severity, Tier: 0, Query: check.Query{Filter: filter}, Condition: e.ConditionCEL, Signed: true}}, check.EvalOptions{})
		if err != nil {
			t.Fatalf("%s: %v", e.ID, err)
		}
		cr := res.Checks[0]
		if cr.Status == "skipped" {
			t.Errorf("%s: skipped (%s): %v", e.ID, cr.Skip, cr.Findings)
			continue
		}
		got := map[string]bool{}
		for _, f := range cr.Findings {
			got[f.DN] = true
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

func TestRejectsForbiddenReference(t *testing.T) {
	e := Entry{ID: "DSA-0999", Title: map[string]string{"en": "x", "ru": "x"}, Domain: "directory-core",
		Severity: "low", Status: "draft", Object: "x", Attributes: []string{"x"}, Condition: "x", Rationale: "x",
		Remediation: map[string]string{"en": "x", "ru": "x"}, Attack: []Technique{{"T1098", "Account Manipulation"}},
		Engine: "declarative", References: []Reference{{"PingCastle rules", "https://www.pingcastle.com/x"}}}
	if err := e.Validate(); err == nil {
		t.Fatal("a PingCastle reference must be rejected")
	}
}
