package ad

import (
	"fmt"
	"strings"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// silentGaps finds reads that succeeded but returned nothing because the
// account may not see the objects — no LDAP error, so skipped() never fires
// (ADR-0019). Each gap is recorded as not collected, so the checks that need
// the objects say "not collected" instead of "passed". Both cases were found
// scanning a Windows Server 2025 DC as an ordinary user.
func silentGaps(snap *snapshot.Snapshot, tier int) []snapshot.Skipped {
	var gaps []snapshot.Skipped
	has := func(class string) bool {
		for _, o := range snap.Objects {
			if hasClass(o, class) {
				return true
			}
		}
		return false
	}

	// Password Settings Objects: the container grants ordinary users no read,
	// but msDS-PSOApplied on the principals a PSO applies to is readable. A PSO
	// named there and missing from the snapshot is unreadable, not absent.
	collected := map[string]bool{}
	for _, o := range snap.Objects {
		if hasClass(o, "msDS-PasswordSettings") {
			collected[strings.ToLower(o.DN)] = true
		}
	}
psoApplied:
	for _, o := range snap.Objects {
		for _, pso := range attrValues(o, "msDS-PSOApplied") {
			if !collected[strings.ToLower(pso)] {
				gaps = append(gaps, snapshot.Skipped{Query: "pso", Reason: "permission",
					Detail:  fmt.Sprintf("msDS-PSOApplied on %s names %s, which this account cannot read", o.DN, pso),
					Classes: []string{"msDS-PasswordSettings"}})
				break psoApplied
			}
		}
	}

	// dMSAs: the class's default security descriptor grants Authenticated
	// Users and Everyone no read, so an ordinary user's search finds none even
	// when they exist. Below tier 2 (administrator) an empty result is
	// therefore unknown, not "no dMSAs".
	if tier < 2 && !has("msDS-DelegatedManagedServiceAccount") {
		for _, o := range snap.Objects {
			if !hasClass(o, "classSchema") || !strings.EqualFold(firstValue(o, "lDAPDisplayName"), "msDS-DelegatedManagedServiceAccount") {
				continue
			}
			if sddl := firstValue(o, "defaultSecurityDescriptor"); !grantsRead(sddl, "AU", "WD") {
				gaps = append(gaps, snapshot.Skipped{Query: "dmsa", Reason: "permission",
					Detail:  "dMSA objects are not readable by ordinary users (the class default security descriptor grants Authenticated Users no read); scan as an administrator (tier 2) to assess",
					Classes: []string{"msDS-DelegatedManagedServiceAccount"}})
			}
		}
	}
	return gaps
}

// grantsRead reports whether an SDDL string has an allow ACE (not object
// specific) that gives one of the trustees read-property or generic read/all.
func grantsRead(sddl string, trustees ...string) bool {
	for _, ace := range strings.Split(sddl, "(") {
		ace = strings.TrimSuffix(strings.TrimSpace(ace), ")")
		f := strings.Split(ace, ";")
		if len(f) != 6 || f[0] != "A" {
			continue
		}
		rights, sid := f[2], f[5]
		for _, t := range trustees {
			if sid == t && (strings.Contains(rights, "RP") || strings.Contains(rights, "GR") || strings.Contains(rights, "GA")) {
				return true
			}
		}
	}
	return false
}

func attrValues(o snapshot.Object, name string) []string {
	for k, v := range o.Attrs {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

func firstValue(o snapshot.Object, name string) string {
	if v := attrValues(o, name); len(v) > 0 {
		return v[0]
	}
	return ""
}
