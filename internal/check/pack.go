// Package check loads signed, declarative check packs (YAML) and evaluates them
// against a snapshot. Packs are data: the condition language is CEL, which has
// no loops, no I/O and a bounded evaluation cost (ADR-0003).
package check

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Pack is one check as written by a human and reviewed by everyone.
type Pack struct {
	ID          string                 `yaml:"id"`
	Title       Text                   `yaml:"title"`
	Provider    []string               `yaml:"provider"` // ad, samba, freeipa, openldap, entra
	Domain      string                 `yaml:"domain"`   // directory-core, dns, gpo, pki, kerberos, credentials, replication, integrated-apps, host, freeipa
	Tier        int                    `yaml:"tier"`     // 0..2
	Severity    string                 `yaml:"severity"` // critical, high, medium, low, info
	Quick       bool                   `yaml:"quick"`    // part of the ≤ 40-check quick scan
	Query       Query                  `yaml:"query"`
	Condition   string                 `yaml:"condition"` // CEL over `obj`; a finding is raised when true
	Evidence    []string               `yaml:"evidence"`  // attributes shown in the report
	Attack      []string               `yaml:"attack"`    // MITRE ATT&CK technique IDs
	BDU         []string               `yaml:"bdu"`       // БДУ ФСТЭК threat IDs (УБИ.xxx)
	Compliance  map[string][]string    `yaml:"compliance"`
	Remediation map[string]Remediation `yaml:"remediation"` // keyed by language: en, ru
	References  []Reference            `yaml:"references"`

	// Source is the file the pack was loaded from; Signed reports whether a valid signature was present.
	Source string `yaml:"-"`
	Signed bool   `yaml:"-"`
}

// Text is a bilingual string.
type Text struct {
	EN string `yaml:"en" json:"en"`
	RU string `yaml:"ru" json:"ru"`
}

// Query is what the collector issues and what the analyser re-applies to the snapshot.
type Query struct {
	Base       string   `yaml:"base"`  // default | configuration | schema | <DN>
	Scope      string   `yaml:"scope"` // base | one | subtree
	Filter     string   `yaml:"filter"`
	Attributes []string `yaml:"attributes"`
}

// Remediation carries the four mandatory fields (requirement AR-6).
type Remediation struct {
	Why    string `yaml:"why"`
	Abuse  string `yaml:"abuse"`
	Fix    string `yaml:"fix"`
	Verify string `yaml:"verify"`
}

// Reference is a primary source.
type Reference struct {
	Title string `yaml:"title"`
	URL   string `yaml:"url"`
}

var (
	idRe       = regexp.MustCompile(`^[A-Z]{2,5}-[0-9]{4}$`)
	severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	domains    = map[string]bool{"directory-core": true, "dns": true, "gpo": true, "pki": true, "kerberos": true, "credentials": true, "replication": true, "integrated-apps": true, "host": true, "freeipa": true, "test": true}
	providers  = map[string]bool{"ad": true, "samba": true, "freeipa": true, "openldap": true, "entra": true}
	scopes     = map[string]bool{"base": true, "one": true, "subtree": true}
)

// Validate checks structure, enumerations, remediation completeness and that the
// filter and condition compile. It does not check that attribute names exist in a
// schema — that is the catalogue validator's job (plan v2, stage 1).
func (p *Pack) Validate() error {
	var errs []string
	if !idRe.MatchString(p.ID) {
		errs = append(errs, "id must look like DSA-0042")
	}
	if p.Title.EN == "" || p.Title.RU == "" {
		errs = append(errs, "title.en and title.ru are required")
	}
	if len(p.Provider) == 0 {
		errs = append(errs, "provider list is required")
	}
	for _, pr := range p.Provider {
		if !providers[pr] {
			errs = append(errs, "unknown provider "+pr)
		}
	}
	if !domains[p.Domain] {
		errs = append(errs, "unknown domain "+p.Domain)
	}
	if p.Tier < 0 || p.Tier > 2 {
		errs = append(errs, "tier must be 0, 1 or 2")
	}
	if !severities[p.Severity] {
		errs = append(errs, "severity must be critical|high|medium|low|info")
	}
	if p.Query.Filter == "" {
		errs = append(errs, "query.filter is required")
	} else if _, err := ParseFilter(p.Query.Filter); err != nil {
		errs = append(errs, "query.filter: "+err.Error())
	}
	if p.Query.Scope != "" && !scopes[p.Query.Scope] {
		errs = append(errs, "query.scope must be base|one|subtree")
	}
	if len(p.Query.Attributes) == 0 {
		errs = append(errs, "query.attributes is required (the query manifest is generated from it)")
	}
	if p.Condition == "" {
		errs = append(errs, "condition is required")
	} else if _, err := CompileCondition(p.Condition); err != nil {
		errs = append(errs, "condition: "+err.Error())
	}
	for _, lang := range []string{"en", "ru"} {
		r, ok := p.Remediation[lang]
		if !ok || r.Why == "" || r.Abuse == "" || r.Fix == "" || r.Verify == "" {
			errs = append(errs, "remediation."+lang+" needs why, abuse, fix and verify")
		}
	}
	if len(p.References) == 0 {
		errs = append(errs, "at least one primary reference is required")
	}
	if len(errs) > 0 {
		return fmt.Errorf("pack %s (%s): %s", p.ID, p.Source, strings.Join(errs, "; "))
	}
	return nil
}

// LoadOptions controls signature policy.
type LoadOptions struct {
	// PublicKey verifies <pack>.sig sidecars. When nil, every pack counts as unsigned.
	PublicKey ed25519.PublicKey
	// AllowUnsigned loads packs without a valid signature (development mode).
	AllowUnsigned bool
}

// LoadDir loads every *.yaml pack under dir (recursively), validates and
// verifies signatures according to opts. IDs must be unique.
func LoadDir(dir string, opts LoadOptions) ([]Pack, error) {
	var packs []Pack
	seen := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !(strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var p Pack
		if err := yaml.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("pack %s: yaml: %w", path, err)
		}
		p.Source = path
		if err := p.Validate(); err != nil {
			return err
		}
		if prev, dup := seen[p.ID]; dup {
			return fmt.Errorf("pack id %s used twice: %s and %s", p.ID, prev, path)
		}
		seen[p.ID] = path
		p.Signed = verifySidecar(path, data, opts.PublicKey)
		if !p.Signed && !opts.AllowUnsigned {
			return fmt.Errorf("pack %s (%s) is not signed; use --allow-unsigned only for development", p.ID, path)
		}
		packs = append(packs, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].ID < packs[j].ID })
	return packs, nil
}

// verifySidecar returns true when <path>.sig holds a valid base64 Ed25519 signature of data.
func verifySidecar(path string, data []byte, pub ed25519.PublicKey) bool {
	if pub == nil {
		return false
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, data, raw)
}

// Sign produces the base64 sidecar content for a pack file (used by the maintainers' signing tool).
func Sign(priv ed25519.PrivateKey, data []byte) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("check: invalid private key size")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)), nil
}
