// Package catalogue loads and validates the clean-room check catalogue
// (catalogue/<domain>/DSA-NNNN.yaml). The catalogue is the spec packs are
// implemented from; see docs/clean-room.md.
package catalogue

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	embedded "github.com/atsvetko/directory-auditor/catalogue"
	"github.com/atsvetko/directory-auditor/internal/check"
)

// Entry is one catalogue record.
type Entry struct {
	ID          string            `yaml:"id"`
	Title       map[string]string `yaml:"title"`
	Domain      string            `yaml:"domain"`
	Tier        int               `yaml:"tier"`
	Severity    string            `yaml:"severity"`
	Quick       bool              `yaml:"quick"`
	Status      string            `yaml:"status"` // draft | verified | retired
	VerifiedBy  string            `yaml:"verified_by"`
	VerifiedOn  string            `yaml:"verified_on"`
	Object      string            `yaml:"object"`
	Attributes  []string          `yaml:"attributes"`
	Condition   string            `yaml:"condition"`
	Threshold   string            `yaml:"threshold"`
	Rationale   string            `yaml:"rationale"`
	Remediation map[string]string `yaml:"remediation"`
	Attack      []Technique       `yaml:"attack"`
	// ANSSI lists the CERT-FR "Points de contrôle Active Directory" this entry
	// implements (CERTFR-2020-DUR-001), by identifier (vuln_…). See
	// frameworks/anssi.yaml and ANSSI-COVERAGE.md.
	ANSSI       []string       `yaml:"anssi"`
	Engine      string         `yaml:"engine"`
	QuerySketch map[string]any `yaml:"query_sketch"`
	References  []Reference    `yaml:"references"`
	Notes       string         `yaml:"notes"`

	// Implementation, written alongside the spec so the engine can run and test
	// the check before a pack exists. ConditionCEL is the pack condition; Expect
	// lists the DNs in the matching synthetic snapshot (testdata/) that must fire
	// and nothing else may. Both are optional for entries still being designed.
	ConditionCEL string   `yaml:"condition_cel"`
	Expect       []string `yaml:"expect"`

	Path string `yaml:"-"`
}

// Technique is a MITRE ATT&CK mapping.
type Technique struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

// Reference is a primary source.
type Reference struct {
	Title string `yaml:"title"`
	URL   string `yaml:"url"`
}

var (
	idRe     = regexp.MustCompile(`^DSA-[0-9]{4}$`)
	attackRe = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	anssiRe  = regexp.MustCompile(`^vuln_[a-z0-9_]+$`)
	sev      = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	status   = map[string]bool{"draft": true, "verified": true, "retired": true}
	domains  = map[string]bool{"directory-core": true, "dns": true, "gpo": true, "pki": true, "kerberos": true, "credentials": true, "replication": true, "integrated-apps": true, "host": true, "freeipa": true, "samba": true}
	// Sources that may never be cited as a reference (docs/clean-room.md rule 2).
	forbiddenRef = []string{"pingcastle", "purple-knight", "purpleknight", "semperis.com", "netwrix.com"}
)

// Validate enforces the catalogue contract.
func (e *Entry) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if !idRe.MatchString(e.ID) {
		add("id %q must be DSA-NNNN", e.ID)
	}
	if base := strings.TrimSuffix(filepath.Base(e.Path), ".yaml"); e.Path != "" && base != e.ID {
		add("file name %s does not match id %s", base, e.ID)
	}
	if e.Title["en"] == "" || e.Title["ru"] == "" {
		add("title.en and title.ru are required")
	}
	if !domains[e.Domain] {
		add("unknown domain %q", e.Domain)
	} else if e.Path != "" && filepath.Base(filepath.Dir(e.Path)) != e.Domain {
		add("entry is in folder %s but domain is %s", filepath.Base(filepath.Dir(e.Path)), e.Domain)
	}
	if e.Tier < 0 || e.Tier > 2 {
		add("tier must be 0, 1 or 2")
	}
	if !sev[e.Severity] {
		add("severity %q invalid", e.Severity)
	}
	if !status[e.Status] {
		add("status must be draft|verified|retired")
	}
	if e.Status == "verified" && (e.VerifiedBy == "" || e.VerifiedOn == "") {
		add("verified entries need verified_by and verified_on")
	}
	if strings.TrimSpace(e.Object) == "" || len(e.Attributes) == 0 {
		add("object and attributes are required")
	}
	if strings.TrimSpace(e.Condition) == "" || strings.TrimSpace(e.Rationale) == "" {
		add("condition and rationale are required")
	}
	if strings.TrimSpace(e.Remediation["en"]) == "" || strings.TrimSpace(e.Remediation["ru"]) == "" {
		add("remediation.en and remediation.ru are required")
	}
	if len(e.Attack) == 0 {
		add("at least one MITRE ATT&CK technique is required")
	}
	for _, t := range e.Attack {
		if !attackRe.MatchString(t.ID) || t.Name == "" {
			add("attack entry %q/%q invalid (want T1234 or T1234.001 with a name)", t.ID, t.Name)
		}
	}
	for _, a := range e.ANSSI {
		if !anssiRe.MatchString(a) {
			add("anssi entry %q invalid (want an ANSSI control identifier such as vuln_krbtgt)", a)
		}
	}
	if e.Engine == "" || !(e.Engine == "declarative" || strings.HasPrefix(e.Engine, "complex:")) {
		add("engine must be 'declarative' or 'complex:<name>'")
	}
	if len(e.References) == 0 {
		add("at least one primary reference is required")
	}
	for _, r := range e.References {
		if r.Title == "" || !strings.HasPrefix(r.URL, "https://") {
			add("reference %q needs a title and an https URL", r.URL)
		}
		lu := strings.ToLower(r.URL + " " + r.Title)
		for _, f := range forbiddenRef {
			if strings.Contains(lu, f) {
				add("reference %q cites a forbidden source (clean room)", r.URL)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s: %s", e.Path, strings.Join(errs, "; "))
	}
	return nil
}

// LoadDir loads every entry under dir, validates each, and checks ID uniqueness.
func LoadDir(dir string) ([]Entry, error) {
	return LoadFS(os.DirFS(dir), filepath.ToSlash(dir))
}

// LoadFS loads every *.yaml entry in fsys. display is prefixed to each
// entry's Path for messages (the directory on disk, or "catalogue" for the
// embedded copy). Paths are slash-separated on every OS, as fs.FS paths are.
func LoadFS(fsys fs.FS, display string) ([]Entry, error) {
	var out []Entry
	seen := map[string]string{}
	var errs []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Only DSA-NNNN.yaml files are entries; reference data such as
		// frameworks/anssi.yaml lives beside them and is loaded separately.
		if d.IsDir() || !strings.HasSuffix(p, ".yaml") || !strings.HasPrefix(path.Base(p), "DSA-") {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		shown := path.Join(display, p)
		var e Entry
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&e); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", shown, err))
			return nil
		}
		e.Path = shown
		if err := e.Validate(); err != nil {
			errs = append(errs, err.Error())
		}
		if prev, dup := seen[e.ID]; dup {
			errs = append(errs, fmt.Sprintf("duplicate id %s in %s and %s", e.ID, prev, shown))
		}
		seen[e.ID] = shown
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		return out, fmt.Errorf("catalogue invalid:\n  %s", strings.Join(errs, "\n  "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Pack converts an implemented entry (one with condition_cel) into a preview
// check: an unsigned pack the engine evaluates exactly as a signed one, so an
// entry can be tried against a real directory before anyone signs off on it.
// The result is marked Preview so reports label it. ok is false for entries
// without a condition.
func (e Entry) Pack() (check.Pack, bool) {
	if strings.TrimSpace(e.ConditionCEL) == "" {
		return check.Pack{}, false
	}
	providers := map[string][]string{"freeipa": {"freeipa"}, "samba": {"samba"}}[e.Domain]
	if providers == nil {
		providers = []string{"ad", "samba"}
	}
	filter, _ := e.QuerySketch["filter"].(string)
	if filter == "" {
		filter = "(objectClass=*)"
	}
	p := check.Pack{
		ID: e.ID, Title: check.Text{EN: e.Title["en"], RU: e.Title["ru"]}, Provider: providers, Domain: e.Domain,
		Tier: e.Tier, Severity: e.Severity, Quick: e.Quick, Query: check.Query{Filter: filter}, Condition: e.ConditionCEL,
		Evidence: e.Attributes, Source: "catalogue:" + e.Path, Signed: false, Preview: true,
		Remediation: map[string]check.Remediation{
			"en": {Why: strings.TrimSpace(e.Rationale), Fix: strings.TrimSpace(e.Remediation["en"])},
			"ru": {Why: strings.TrimSpace(e.Rationale), Fix: strings.TrimSpace(e.Remediation["ru"])},
		},
	}
	for _, a := range e.Attack {
		p.Attack = append(p.Attack, a.ID)
	}
	for _, r := range e.References {
		p.References = append(p.References, check.Reference{Title: r.Title, URL: r.URL})
	}
	if len(e.ANSSI) > 0 {
		p.Compliance = map[string][]string{"ANSSI": append([]string(nil), e.ANSSI...)}
	}
	return p, true
}

// Packs converts every implemented entry under dir (a working tree, for
// verifying entries before they are built in).
func Packs(dir string) ([]check.Pack, error) {
	entries, err := LoadDir(dir)
	if err != nil {
		return nil, err
	}
	return toPacks(entries), nil
}

// EmbeddedSource names the preview source in reports and logs.
const EmbeddedSource = "built-in catalogue"

var (
	embeddedOnce  sync.Once
	embeddedPacks []check.Pack
	embeddedErr   error
)

// Embedded returns the preview checks built into this binary: the implemented
// entries of the catalogue embedded at build time (see catalogue/embed.go).
// The copy is parsed once; a parse error is a build defect, caught by tests.
func Embedded() ([]check.Pack, error) {
	embeddedOnce.Do(func() {
		entries, err := LoadFS(embedded.Files, "catalogue")
		if err != nil {
			embeddedErr = fmt.Errorf("embedded catalogue: %w", err)
			return
		}
		embeddedPacks = toPacks(entries)
	})
	return append([]check.Pack(nil), embeddedPacks...), embeddedErr
}

func toPacks(entries []Entry) []check.Pack {
	var out []check.Pack
	for _, e := range entries {
		if p, ok := e.Pack(); ok {
			out = append(out, p)
		}
	}
	return out
}
