package snapshot

import (
	"bytes"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	in := &Snapshot{
		Meta:      Meta{Provider: "synthetic", Target: "lab.example", Tool: "test"},
		Collected: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		Objects: []Object{{
			DN:    "CN=Administrator,CN=Users,DC=lab,DC=example",
			Class: []string{"top", "person", "user"},
			Attrs: map[string][]string{"sAMAccountName": {"Administrator"}, "userAccountControl": {"66048"}},
		}},
		Skipped: []Skipped{{Query: "sysvol", Reason: "tier", Detail: "tier 1 not requested"}},
	}
	var buf bytes.Buffer
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Schema != SchemaVersion {
		t.Fatalf("schema: got %q", out.Schema)
	}
	if len(out.Objects) != 1 || out.Objects[0].Attr("samaccountname") != "Administrator" {
		t.Fatalf("objects not preserved: %+v", out.Objects)
	}
	if len(out.Skipped) != 1 || out.Skipped[0].Reason != "tier" {
		t.Fatalf("skipped not preserved: %+v", out.Skipped)
	}
	h1, _ := Hash(in)
	h2, _ := Hash(out)
	if h1 != h2 {
		t.Fatalf("hash differs after round trip: %s vs %s", h1, h2)
	}
}

func TestSchemaMajorMismatch(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, &Snapshot{Schema: "9.0.0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(&buf); err == nil {
		t.Fatal("expected schema mismatch error")
	}
}
