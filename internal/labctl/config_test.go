package labctl

import "testing"

func base(m Machine) *Lab {
	return &Lab{RepoDir: `C:\src\directory-auditor`, Machines: []Machine{m}}
}

// A windows-dc may carry adcs: true (install the lab Enterprise CA).
func TestValidate_ADCSOnWindowsDC(t *testing.T) {
	l := base(Machine{Name: "DA-DC", Kind: "windows-dc", Domain: "da.test", IP: "10.55.0.10", Prefix: 24, ADCS: true})
	if err := l.Validate(); err != nil {
		t.Fatalf("windows-dc with adcs should be valid, got: %v", err)
	}
}

// adcs on anything other than a windows-dc is rejected.
func TestValidate_ADCSOnAltDCRejected(t *testing.T) {
	l := base(Machine{Name: "DA-ALT", Kind: "alt-dc", Domain: "alt.test", IP: "10.55.0.12", Prefix: 24, ADCS: true})
	err := l.Validate()
	if err == nil {
		t.Fatal("adcs on an alt-dc must be rejected")
	}
}

// Without adcs, an alt-dc is still fine (no regression).
func TestValidate_AltDCWithoutADCS(t *testing.T) {
	l := base(Machine{Name: "DA-ALT", Kind: "alt-dc", Domain: "alt.test", IP: "10.55.0.12", Prefix: 24})
	if err := l.Validate(); err != nil {
		t.Fatalf("alt-dc without adcs should be valid, got: %v", err)
	}
}
