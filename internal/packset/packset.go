// Package packset assembles the checks one run evaluates: signed packs from a
// directory plus, unless turned off, the preview checks built into the binary
// (the implemented catalogue entries, unsigned and unverified). The CLI and
// the wizard share it so both show the same set and the same notes.
package packset

import (
	"fmt"
	"os"

	"github.com/atsvetko/directory-auditor/internal/catalogue"
	"github.com/atsvetko/directory-auditor/internal/check"
)

// Options select the sources.
type Options struct {
	PacksDir      string // directory with signed packs; "" = none
	AllowUnsigned bool   // development mode: load unsigned packs from PacksDir
	CatalogueDir  string // take preview checks from this working tree instead of the built-in copy
	NoPreview     bool   // evaluate signed packs only
}

// Set is the assembled list with what it was made of.
type Set struct {
	Packs         []check.Pack
	FromDir       int      // packs loaded from Options.PacksDir
	Preview       int      // preview checks
	PreviewSource string   // catalogue.EmbeddedSource or the directory the previews came from; "" when off
	Notes         []string // what the user should know, one line each
}

// Load assembles the set. A missing PacksDir is an error only when nothing
// else would be evaluated; otherwise it is a note, because the prototype
// ships without packs and relies on preview checks.
func Load(o Options) (Set, error) {
	var s Set
	if o.PacksDir != "" {
		if st, err := os.Stat(o.PacksDir); err == nil && st.IsDir() {
			loaded, err := check.LoadDir(o.PacksDir, check.LoadOptions{AllowUnsigned: o.AllowUnsigned})
			if err != nil {
				return s, err
			}
			s.Packs = append(s.Packs, loaded...)
			s.FromDir = len(loaded)
		} else if o.NoPreview {
			return s, fmt.Errorf("packs directory %s not found and preview checks are off", o.PacksDir)
		} else {
			s.Notes = append(s.Notes, fmt.Sprintf("no packs directory at %s; preview checks only", o.PacksDir))
		}
	}
	if o.AllowUnsigned && s.FromDir > 0 {
		s.Notes = append(s.Notes, "--allow-unsigned is set; packs were not verified (development mode)")
	}
	if o.NoPreview {
		return s, nil
	}
	var pv []check.Pack
	var err error
	if o.CatalogueDir != "" {
		pv, err = catalogue.Packs(o.CatalogueDir)
		s.PreviewSource = o.CatalogueDir
	} else {
		pv, err = catalogue.Embedded()
		s.PreviewSource = catalogue.EmbeddedSource
	}
	if err != nil {
		return s, err
	}
	s.Packs = append(s.Packs, pv...)
	s.Preview = len(pv)
	s.Notes = append(s.Notes, fmt.Sprintf("preview: %d catalogue checks evaluated (source: %s) — unsigned, status draft, not yet verified by a human; findings are leads to confirm (--no-preview turns them off)",
		s.Preview, s.PreviewSource))
	return s, nil
}
