package adcs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

func TestIngestSampleFixture(t *testing.T) {
	r, err := Ingest(filepath.Join("testdata", "tier2-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	if r.CAs != 3 || r.DCs != 2 || r.Host != "CA01" {
		t.Fatalf("result: CAs=%d DCs=%d host=%q", r.CAs, r.DCs, r.Host)
	}

	snap := &snapshot.Snapshot{Meta: snapshot.Meta{Provider: "ad"}}
	AugmentOffline(snap, r)
	if snap.Meta.Tier != 2 {
		t.Errorf("tier = %d, want 2", snap.Meta.Tier)
	}
	if len(snap.Objects) != 5 {
		t.Fatalf("want 5 objects, got %d", len(snap.Objects))
	}

	by := map[string]snapshot.Object{}
	for _, o := range snap.Objects {
		by[o.DN] = o
		// The filter engine matches Object.Class; every object must carry it.
		if len(o.Class) == 0 {
			t.Errorf("object %s has no Class", o.DN)
		}
		if o.Attr("objectClass") != o.Class[0] {
			t.Errorf("object %s: objectClass attr %q != Class %q", o.DN, o.Attr("objectClass"), o.Class[0])
		}
	}

	// Vulnerable CA (ESC6 + ESC16) lands with its facts intact.
	esc6 := by["cn=esc6-CA,cn=certsvc,cn=dirauditor"]
	if !contains(esc6.Attrs["EditFlags"], "EDITF_ATTRIBUTESUBJECTALTNAME2") {
		t.Errorf("esc6 EditFlags = %v", esc6.Attrs["EditFlags"])
	}
	if !contains(esc6.Attrs["DisableExtensionList"], "1.3.6.1.4.1.311.25.2") {
		t.Errorf("esc6 DisableExtensionList = %v", esc6.Attrs["DisableExtensionList"])
	}
	// Clean CA carries the enforcement flag and Tier-0-only roles.
	clean := by["cn=lab-CA,cn=certsvc,cn=dirauditor"]
	if !contains(clean.Attrs["InterfaceFlags"], "IF_ENFORCEENCRYPTICERTREQUEST") {
		t.Errorf("clean InterfaceFlags = %v", clean.Attrs["InterfaceFlags"])
	}
	// Vulnerable DC (ESC10): strong binding disabled.
	old := by["cn=OLDDC,cn=kdc,cn=dirauditor"]
	if old.Attr("StrongCertificateBindingEnforcement") != "0" {
		t.Errorf("OLDDC StrongCertificateBindingEnforcement = %q", old.Attr("StrongCertificateBindingEnforcement"))
	}
}

func TestIngestRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"wrong schema":      `{"schema":"nope","objects":[]}`,
		"empty":             `{"schema":"dirauditor-adcs-offline/1","objects":[]}`,
		"unknown class":     `{"schema":"dirauditor-adcs-offline/1","objects":[{"dn":"cn=x,cn=certsvc,cn=dirauditor","class":["dirauditorBogus"],"attrs":{}}]}`,
		"dn/class mismatch": `{"schema":"dirauditor-adcs-offline/1","objects":[{"dn":"cn=x,cn=kdc,cn=dirauditor","class":["dirauditorCaConfig"],"attrs":{}}]}`,
		"unknown field":     `{"schema":"dirauditor-adcs-offline/1","objects":[],"evil":1}`,
	}
	for name, body := range cases {
		p := filepath.Join(t.TempDir(), "doc.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Ingest(p); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
	if _, err := Ingest(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file: expected an error")
	}
}

// TestIngestAcceptsScalarValues proves the ingest tolerates the JSON that
// PowerShell's ConvertTo-Json emits: single-valued attributes become scalars,
// not one-element arrays, and a bool/number may appear bare.
func TestIngestAcceptsScalarValues(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scalar.json")
	body := `{"schema":"dirauditor-adcs-offline/1","host":"CA9","objects":[
	  {"dn":"cn=c,cn=certsvc,cn=dirauditor","class":"dirauditorCaConfig",
	   "attrs":{"caName":"c","InterfaceFlags":"IF_ENFORCEENCRYPTICERTREQUEST","ManageCA":["S-1-5-18"]}},
	  {"dn":"cn=d,cn=kdc,cn=dirauditor","class":["dirauditorDcConfig"],
	   "attrs":{"dcName":"d","StrongCertificateBindingEnforcement":2,"CertificateMappingMethods":"0x18"}}]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Ingest(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.CAs != 1 || r.DCs != 1 {
		t.Fatalf("CAs=%d DCs=%d", r.CAs, r.DCs)
	}
	snap := &snapshot.Snapshot{}
	AugmentOffline(snap, r)
	var ca, dc snapshot.Object
	for _, o := range snap.Objects {
		switch o.Attr("objectClass") {
		case ClassCa:
			ca = o
		case ClassDc:
			dc = o
		}
	}
	if !contains(ca.Attrs["InterfaceFlags"], "IF_ENFORCEENCRYPTICERTREQUEST") {
		t.Errorf("scalar InterfaceFlags not parsed: %v", ca.Attrs["InterfaceFlags"])
	}
	if ca.Attr("caName") != "c" {
		t.Errorf("scalar caName = %q", ca.Attr("caName"))
	}
	if dc.Attr("StrongCertificateBindingEnforcement") != "2" {
		t.Errorf("numeric StrongCertificateBindingEnforcement = %q", dc.Attr("StrongCertificateBindingEnforcement"))
	}
}

func TestIngestAcceptsBOM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bom.json")
	body := `{"schema":"dirauditor-adcs-offline/1","objects":[{"dn":"cn=c,cn=certsvc,cn=dirauditor","class":["dirauditorCaConfig"],"attrs":{"caName":["c"]}}]}`
	// UTF-8 BOM, as the ru-RU PowerShell script writes.
	out := append([]byte{0xEF, 0xBB, 0xBF}, body...)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Ingest(p)
	if err != nil {
		t.Fatalf("BOM-prefixed (UTF-8 with BOM, as the ru-RU script writes): %v", err)
	}
	if r.CAs != 1 {
		t.Errorf("CAs = %d", r.CAs)
	}
}
