package adcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// DNs and object classes of the CA- and DC-configuration objects the offline
// collector produces (collector contract, internal/provider/ad/collect.go).
const (
	CaBase     = "cn=certsvc,cn=dirauditor"
	DcBase     = "cn=kdc,cn=dirauditor"
	ClassCa    = "dirauditorCaConfig"
	ClassDc    = "dirauditorDcConfig"
	FileSchema = "dirauditor-adcs-offline/1"
)

// Result is what Ingest returns for AugmentOffline to merge.
type Result struct {
	Objects []snapshot.Object
	Skipped []snapshot.Skipped
	CAs     int
	DCs     int
	Host    string
}

// stringList decodes an attribute value that may be a JSON array (["a","b"]) or
// a lone scalar ("a", 2, true). The scalar form matters because the ru-RU
// PowerShell collector is generated with ConvertTo-Json, which unwraps a
// single-element array to a scalar; accepting both also makes hand-edited files
// forgiving.
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*s = nil
		return nil
	}
	if b[0] == '[' {
		var raw []json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			return err
		}
		out := make([]string, 0, len(raw))
		for _, r := range raw {
			v, err := scalarString(r)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		*s = out
		return nil
	}
	v, err := scalarString(b)
	if err != nil {
		return err
	}
	*s = []string{v}
	return nil
}

func scalarString(b json.RawMessage) (string, error) {
	t := bytes.TrimSpace(b)
	if len(t) == 0 {
		return "", nil
	}
	switch t[0] {
	case '"':
		var v string
		if err := json.Unmarshal(t, &v); err != nil {
			return "", err
		}
		return v, nil
	case 't', 'f': // bool → TRUE/FALSE, matching the https flag convention
		var v bool
		if err := json.Unmarshal(t, &v); err != nil {
			return "", err
		}
		return strings.ToUpper(strconv.FormatBool(v)), nil
	default: // number: keep it verbatim so 0x-style callers aren't surprised
		return string(t), nil
	}
}

// offlineObject mirrors snapshot.Object but accepts the scalar-or-array
// attribute form; unknown fields are rejected so a typo fails loudly.
type offlineObject struct {
	DN    string                `json:"dn"`
	Class stringList            `json:"class"`
	Attrs map[string]stringList `json:"attrs"`
}

type offlineDoc struct {
	Schema      string          `json:"schema"`
	GeneratedAt string          `json:"generated_at"`
	Host        string          `json:"host"`
	Objects     []offlineObject `json:"objects"`
}

// Ingest reads and validates the offline AD CS configuration document at path.
// It only READS the file. Every object must be a well-formed dirauditorCaConfig
// under cn=certsvc,cn=dirauditor or dirauditorDcConfig under cn=kdc,cn=dirauditor;
// anything else is a malformed document and fails the whole ingest, because the
// script we ship emits exactly these two shapes.
func Ingest(path string) (*Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("adcs: %w", err)
	}
	b = stripBOM(b)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var doc offlineDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("adcs: parse %s: %w", path, err)
	}
	if doc.Schema != FileSchema {
		return nil, fmt.Errorf("adcs: %s: unexpected schema %q (want %q)", path, doc.Schema, FileSchema)
	}
	res := &Result{Host: doc.Host}
	for i, raw := range doc.Objects {
		o, class, err := normalise(raw)
		if err != nil {
			return nil, fmt.Errorf("adcs: %s: object %d: %w", path, i, err)
		}
		switch class {
		case ClassCa:
			res.CAs++
		case ClassDc:
			res.DCs++
		}
		res.Objects = append(res.Objects, o)
	}
	if len(res.Objects) == 0 {
		return nil, fmt.Errorf("adcs: %s: no CA or DC configuration objects in the file", path)
	}
	return res, nil
}

// normalise validates one object and returns a snapshot.Object with Class and
// the objectClass attribute both set (the filter engine matches Object.Class;
// mksynth sets both, so the ingest does too).
func normalise(raw offlineObject) (snapshot.Object, string, error) {
	attrs := map[string][]string{}
	for k, v := range raw.Attrs {
		attrs[k] = append([]string{}, v...)
	}
	class := firstNonEmpty(raw.Class)
	if class == "" {
		class = firstNonEmpty(attrs["objectClass"])
	}
	if class == "" {
		return snapshot.Object{}, "", fmt.Errorf("no objectClass")
	}
	var wantSuffix string
	switch class {
	case ClassCa:
		wantSuffix = "," + CaBase
	case ClassDc:
		wantSuffix = "," + DcBase
	default:
		return snapshot.Object{}, "", fmt.Errorf("unexpected objectClass %q (want %s or %s)", class, ClassCa, ClassDc)
	}
	if !strings.HasSuffix(strings.ToLower(raw.DN), strings.ToLower(wantSuffix)) {
		return snapshot.Object{}, "", fmt.Errorf("class %s has DN %q, expected it to end with %q", class, raw.DN, wantSuffix)
	}
	attrs["objectClass"] = []string{class}
	return snapshot.Object{DN: raw.DN, Class: []string{class}, Attrs: attrs}, class, nil
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// AugmentOffline merges the offline objects into a snapshot and raises its tier
// to 2, since CA/DC registry and security data is administrator-level. It
// mirrors the smb.conf collector's Augment.
func AugmentOffline(snap *snapshot.Snapshot, r *Result) {
	snap.Objects = append(snap.Objects, r.Objects...)
	snap.Skipped = append(snap.Skipped, r.Skipped...)
	if snap.Meta.Tier < 2 {
		snap.Meta.Tier = 2
	}
	if snap.Meta.Provider == "" {
		snap.Meta.Provider = "ad"
	}
	if snap.Meta.Extra == nil {
		snap.Meta.Extra = map[string]string{}
	}
	if r.Host != "" {
		snap.Meta.Extra["adcs_offline_host"] = r.Host
	}
	snap.Meta.Extra["adcs_offline"] = fmt.Sprintf("%d CA, %d DC", r.CAs, r.DCs)
}

func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}
