package catalogue

import (
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	embedded "github.com/atsvetko/directory-auditor/catalogue"
)

// ANSSIPoint is one published ANSSI / CERT-FR Active Directory control point.
type ANSSIPoint struct {
	ID      string `yaml:"id"`
	Levels  []int  `yaml:"levels"`
	TitleEN string `yaml:"title_en"`
	TitleFR string `yaml:"title_fr"`
}

// MinLevel is the most urgent level the point applies at (1 = critical).
func (p ANSSIPoint) MinLevel() int {
	m := 0
	for _, l := range p.Levels {
		if m == 0 || l < m {
			m = l
		}
	}
	return m
}

// ANSSIFramework is frameworks/anssi.yaml: the official index of control points.
type ANSSIFramework struct {
	Source  string       `yaml:"source"`
	Version string       `yaml:"version"`
	Count   int          `yaml:"count"`
	Points  []ANSSIPoint `yaml:"points"`
}

// Index returns the points keyed by identifier.
func (f ANSSIFramework) Index() map[string]ANSSIPoint {
	m := make(map[string]ANSSIPoint, len(f.Points))
	for _, p := range f.Points {
		m[p.ID] = p
	}
	return m
}

const anssiPath = "frameworks/anssi.yaml"

// LoadANSSI reads frameworks/anssi.yaml from a catalogue tree.
func LoadANSSI(fsys fs.FS) (ANSSIFramework, error) {
	var f ANSSIFramework
	b, err := fs.ReadFile(fsys, anssiPath)
	if err != nil {
		return f, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("%s: %w", anssiPath, err)
	}
	if f.Count != len(f.Points) {
		return f, fmt.Errorf("%s: count %d but %d points", anssiPath, f.Count, len(f.Points))
	}
	seen := map[string]bool{}
	for _, p := range f.Points {
		if !anssiRe.MatchString(p.ID) || len(p.Levels) == 0 || p.TitleEN == "" {
			return f, fmt.Errorf("%s: point %q incomplete", anssiPath, p.ID)
		}
		if seen[p.ID] {
			return f, fmt.Errorf("%s: duplicate point %s", anssiPath, p.ID)
		}
		seen[p.ID] = true
	}
	return f, nil
}

// LoadANSSIDir reads the framework from a catalogue working tree.
func LoadANSSIDir(dir string) (ANSSIFramework, error) { return LoadANSSI(os.DirFS(dir)) }

// EmbeddedANSSI reads the framework built into the binary.
func EmbeddedANSSI() (ANSSIFramework, error) { return LoadANSSI(embedded.Files) }

// Coverage maps each ANSSI point to the catalogue entries that declare it.
func Coverage(entries []Entry) map[string][]string {
	m := map[string][]string{}
	for _, e := range entries {
		for _, a := range e.ANSSI {
			m[a] = append(m[a], e.ID)
		}
	}
	for k := range m {
		sort.Strings(m[k])
	}
	return m
}
