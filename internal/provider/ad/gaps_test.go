package ad

import (
	"testing"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// The Windows Server 2025 dMSA class default security descriptor, as read from
// the KVM lab's schema: no allow ACE gives Authenticated Users or Everyone read.
const dmsaDefaultSD = "D:(OD;;CR;00299570-246d-11d0-a768-00aa006e0529;;WD)(OD;;RP;e362ed86-b728-0842-b27d-2dea7a9df218;;WD)" +
	"(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)" +
	"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AO)(A;;LCRPDTLOCRSDRC;;;CO)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"

func dmsaClass(sd string) snapshot.Object {
	return snapshot.Object{DN: "CN=ms-DS-Delegated-Managed-Service-Account,CN=Schema,CN=Configuration,DC=da,DC=test",
		Class: []string{"top", "classSchema"},
		Attrs: map[string][]string{"lDAPDisplayName": {"msDS-DelegatedManagedServiceAccount"}, "defaultSecurityDescriptor": {sd}}}
}

func gapQueries(gaps []snapshot.Skipped) map[string]bool {
	m := map[string]bool{}
	for _, g := range gaps {
		m[g.Query] = true
	}
	return m
}

func TestSilentGapsPSO(t *testing.T) {
	da := snapshot.Object{DN: "CN=Domain Admins,CN=Users,DC=da,DC=test", Class: []string{"group"},
		Attrs: map[string][]string{"msDS-PSOApplied": {"CN=WeakAdminPSO,CN=Password Settings Container,CN=System,DC=da,DC=test"}}}
	// The PSO is named but was not read: not collected.
	if !gapQueries(silentGaps(&snapshot.Snapshot{Objects: []snapshot.Object{da}}, 0))["pso"] {
		t.Error("an unreadable PSO named by msDS-PSOApplied must be reported not collected")
	}
	// The PSO was read: no gap.
	pso := snapshot.Object{DN: "CN=WeakAdminPSO,CN=Password Settings Container,CN=System,DC=da,DC=test", Class: []string{"msDS-PasswordSettings"}}
	if gapQueries(silentGaps(&snapshot.Snapshot{Objects: []snapshot.Object{da, pso}}, 0))["pso"] {
		t.Error("a PSO that was collected is not a gap")
	}
	// No PSO applies anywhere: an empty result is real, not a gap.
	if gapQueries(silentGaps(&snapshot.Snapshot{}, 0))["pso"] {
		t.Error("no msDS-PSOApplied anywhere is not a gap")
	}
}

func TestSilentGapsDMSA(t *testing.T) {
	cls := dmsaClass(dmsaDefaultSD)
	if !gapQueries(silentGaps(&snapshot.Snapshot{Objects: []snapshot.Object{cls}}, 0))["dmsa"] {
		t.Error("tier 0, dMSA class unreadable by Authenticated Users, none found: must be not collected")
	}
	if gapQueries(silentGaps(&snapshot.Snapshot{Objects: []snapshot.Object{cls}}, 2))["dmsa"] {
		t.Error("an administrator (tier 2) scan that finds no dMSA has seen there are none")
	}
	readable := dmsaClass(dmsaDefaultSD + "(A;;RPLCLORC;;;AU)")
	if gapQueries(silentGaps(&snapshot.Snapshot{Objects: []snapshot.Object{readable}}, 0))["dmsa"] {
		t.Error("a class readable by Authenticated Users is not a gap")
	}
	if gapQueries(silentGaps(&snapshot.Snapshot{}, 0))["dmsa"] {
		t.Error("no dMSA class in the schema (pre-2025) is not a gap")
	}
	found := snapshot.Object{DN: "CN=dmsa-evil,OU=ServiceDelegation,DC=da,DC=test", Class: []string{"msDS-DelegatedManagedServiceAccount"}}
	if gapQueries(silentGaps(&snapshot.Snapshot{Objects: []snapshot.Object{cls, found}}, 0))["dmsa"] {
		t.Error("dMSAs that were read are not a gap")
	}
}
