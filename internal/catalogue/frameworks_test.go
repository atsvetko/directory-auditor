package catalogue

import "testing"

// TestANSSIMapping keeps every entry's anssi: tags tied to the official list:
// a typo or a point ANSSI withdrew fails the build instead of silently
// inflating the coverage matrix.
func TestANSSIMapping(t *testing.T) {
	fw, err := LoadANSSIDir("../../catalogue")
	if err != nil {
		t.Fatal(err)
	}
	if len(fw.Points) < 70 {
		t.Fatalf("only %d ANSSI points loaded", len(fw.Points))
	}
	idx := fw.Index()
	entries, err := LoadDir("../../catalogue")
	if err != nil {
		t.Fatal(err)
	}
	tagged := 0
	for _, e := range entries {
		for _, a := range e.ANSSI {
			if _, ok := idx[a]; !ok {
				t.Errorf("%s: anssi %q is not in frameworks/anssi.yaml (%s %s)", e.ID, a, fw.Source, fw.Version)
			}
			tagged++
		}
	}
	cov := Coverage(entries)
	t.Logf("ANSSI %s %s: %d points, %d mapped by %d tags", fw.Source, fw.Version, len(fw.Points), len(cov), tagged)

	emb, err := EmbeddedANSSI()
	if err != nil {
		t.Fatal(err)
	}
	if emb.Version != fw.Version || len(emb.Points) != len(fw.Points) {
		t.Errorf("embedded ANSSI framework differs from the working tree")
	}
}
