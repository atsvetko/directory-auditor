// Package snapshot defines the versioned, compressed snapshot that joins the
// collection and analysis stages (requirement AR-13). Checks run against a
// snapshot, never against a live directory.
//
// File format: zstd-compressed JSON. Schema version is semver; readers accept
// the same major version and migrate older minors.
//
// Attribute values are strings. Binary attributes are converted by the
// collector so snapshots stay readable and diffable:
//   - SIDs (objectSid, sIDHistory, securityIdentifier, ms-DS-CreatorSID): S-1-5-…
//   - GUIDs (objectGUID): registry form, lower case
//   - security descriptors (nTSecurityDescriptor,
//     msDS-AllowedToActOnBehalfOfOtherIdentity): standard base64 of the
//     self-relative descriptor, DACL only (collected with SD_FLAGS = DACL)
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// SchemaVersion is the schema written by this build.
const SchemaVersion = "0.2.0"

// Snapshot is the complete result of one collection run.
type Snapshot struct {
	Schema    string    `json:"schema"`
	Meta      Meta      `json:"meta"`
	Objects   []Object  `json:"objects"`
	Skipped   []Skipped `json:"skipped,omitempty"`
	Collected time.Time `json:"collected_at"`
}

// Meta describes where and how the snapshot was collected.
type Meta struct {
	Provider   string            `json:"provider"`           // "ad", "samba", "freeipa", "openldap", "entra", "synthetic"
	Dialect    string            `json:"dialect,omitempty"`  // rootDSE fingerprint result
	Target     string            `json:"target"`             // server or domain name as given
	Domain     string            `json:"domain,omitempty"`   // DNS domain
	BaseDN     string            `json:"base_dn,omitempty"`  // defaultNamingContext
	Identity   string            `json:"identity,omitempty"` // who collected (DN or UPN), never a secret
	Tier       int               `json:"tier"`               // highest privilege tier used
	Tool       string            `json:"tool"`               // "dirauditor <version>"
	RootDSE    map[string]string `json:"rootdse,omitempty"`  // selected rootDSE attributes
	Redacted   bool              `json:"redacted"`           // pseudonymised snapshot
	QueryCount int               `json:"query_count"`        // LDAP searches issued
	Requests   int               `json:"requests,omitempty"` // wire requests (pages, range chunks)
	DomainSID  string            `json:"domain_sid,omitempty"`
	Duration   string            `json:"duration,omitempty"` // collection wall time
}

// Object is one directory entry with the attributes the collector requested.
type Object struct {
	DN    string              `json:"dn"`
	Class []string            `json:"class,omitempty"`
	Attrs map[string][]string `json:"attrs"`
}

// Skipped records a query that could not be run and why — the "honest states"
// the report must show (requirement AR-12).
type Skipped struct {
	Query  string `json:"query"`
	Reason string `json:"reason"` // "tier", "permission", "provider", "error", "absent"
	Detail string `json:"detail,omitempty"`
	// Classes lists the object classes the query would have returned, so the
	// analyser can mark checks on them "not collected" instead of "pass".
	Classes []string `json:"classes,omitempty"`
}

// Attr returns the first value of an attribute (case-insensitive name) or "".
func (o Object) Attr(name string) string {
	for k, v := range o.Attrs {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// Write serialises the snapshot as zstd-compressed JSON.
func Write(w io.Writer, s *Snapshot) error {
	if s.Schema == "" {
		s.Schema = SchemaVersion
	}
	enc, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return err
	}
	if err := json.NewEncoder(enc).Encode(s); err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}

// Read parses a snapshot and validates its schema version.
func Read(r io.Reader) (*Snapshot, error) {
	dec, err := zstd.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	var s Snapshot
	if err := json.NewDecoder(dec).Decode(&s); err != nil {
		return nil, fmt.Errorf("snapshot: decode: %w", err)
	}
	if err := checkSchema(s.Schema); err != nil {
		return nil, err
	}
	return &s, nil
}

// WriteFile and ReadFile are convenience wrappers.
func WriteFile(path string, s *Snapshot) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := Write(f, s); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func ReadFile(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Hash returns the SHA-256 of the canonical (uncompressed JSON) form, used in
// reports so a reviewer can tie a report to the exact snapshot.
func Hash(s *Snapshot) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func checkSchema(v string) error {
	if v == "" {
		return errors.New("snapshot: missing schema version")
	}
	want := strings.SplitN(SchemaVersion, ".", 2)[0]
	got := strings.SplitN(v, ".", 2)[0]
	if want != got {
		return fmt.Errorf("snapshot: schema %s is not compatible with this build (%s)", v, SchemaVersion)
	}
	return nil
}
