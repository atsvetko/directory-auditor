package packset

import (
	"strings"
	"testing"

	"github.com/atsvetko/directory-auditor/internal/catalogue"
)

func TestLoad(t *testing.T) {
	builtIn, err := catalogue.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(builtIn) == 0 {
		t.Fatal("no built-in preview checks")
	}
	cases := []struct {
		name              string
		o                 Options
		wantDir, wantPv   int
		wantErr, wantNote string
	}{
		{"default prototype layout: no packs dir", Options{PacksDir: "packs"}, 0, len(builtIn), "", "no packs directory"},
		{"no packs dir and no preview", Options{PacksDir: "packs", NoPreview: true}, 0, 0, "preview checks are off", ""},
		{"fixture pack plus preview", Options{PacksDir: "../../testdata/packs", AllowUnsigned: true}, 1, len(builtIn), "", "--allow-unsigned"},
		{"fixture pack only", Options{PacksDir: "../../testdata/packs", AllowUnsigned: true, NoPreview: true}, 1, 0, "", ""},
		{"preview from a working tree", Options{CatalogueDir: "../../catalogue"}, 0, len(builtIn), "", "source: ../../catalogue"},
		{"unsigned fixture refused without the flag", Options{PacksDir: "../../testdata/packs"}, 0, 0, "unsigned", ""},
		{"nothing at all", Options{NoPreview: true}, 0, 0, "", ""},
	}
	for _, c := range cases {
		s, err := Load(c.o)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: err = %v, want %q", c.name, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if s.FromDir != c.wantDir || s.Preview != c.wantPv || len(s.Packs) != c.wantDir+c.wantPv {
			t.Errorf("%s: dir %d preview %d packs %d", c.name, s.FromDir, s.Preview, len(s.Packs))
		}
		if c.wantNote != "" && !strings.Contains(strings.Join(s.Notes, "\n"), c.wantNote) {
			t.Errorf("%s: notes %q lack %q", c.name, s.Notes, c.wantNote)
		}
		for _, p := range s.Packs {
			if p.Preview != strings.HasPrefix(p.ID, "DSA-") {
				t.Errorf("%s: %s preview=%v", c.name, p.ID, p.Preview)
			}
		}
	}
}
