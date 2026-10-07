package check

import (
	"testing"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// TestSyntheticLab exercises the helpers end to end on the committed synthetic
// snapshot (tools/mksynth). Engine test only — the expressions are not packs.
func TestSyntheticLab(t *testing.T) {
	snap, err := snapshot.ReadFile("../../testdata/synthetic-lab.json.zst")
	if err != nil {
		t.Fatal(err)
	}
	pack := func(id, filter, cond string) Pack {
		return Pack{ID: id, Provider: []string{"ad"}, Severity: "info", Query: Query{Filter: filter}, Condition: cond, Signed: true}
	}
	res, err := EvaluateWith(snap, []Pack{
		pack("T-1", "(objectClass=user)", `tier0(obj)`),
		pack("T-2", "(adminCount=1)", `!tier0(obj) && sd_protected(obj)`),
		pack("T-3", "(objectClass=group)", `tier0(obj) && aces(obj).exists(a, a.allow && !a.trustee_tier0 && mask_has(a.mask, 0x40000))`),
		pack("T-4", "(objectClass=user)", `age_days(obj, "pwdLastSet") > 1000`),
	}, EvalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dns := func(i int) map[string]bool {
		out := map[string]bool{}
		for _, f := range res.Checks[i].Findings {
			out[f.DN] = true
		}
		return out
	}
	base := ",CN=Users,DC=lab,DC=example"
	for _, want := range []string{"CN=Administrator" + base, "CN=svc_backup" + base, "CN=krbtgt" + base, "CN=DC01,OU=Domain Controllers,DC=lab,DC=example"} {
		if !dns(0)[want] {
			t.Errorf("T-1: %s not Tier 0; got %v", want, dns(0))
		}
	}
	if len(dns(0)) != 4 {
		t.Errorf("T-1: unexpected Tier-0 users %v", dns(0))
	}
	if d := dns(1); len(d) != 1 || !d["CN=old.admin"+base] {
		t.Errorf("T-2: %v", d)
	}
	if d := dns(2); len(d) != 1 || !d["CN=Domain Admins"+base] {
		t.Errorf("T-3: %v", d)
	}
	if d := dns(3); len(d) != 2 || !d["CN=svc_backup"+base] || !d["CN=krbtgt"+base] {
		t.Errorf("T-4: %v", d)
	}
}
