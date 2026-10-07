package catalogue

import "testing"

// TestRepositoryCatalogue validates every entry committed under catalogue/.
func TestRepositoryCatalogue(t *testing.T) {
	entries, err := LoadDir("../../catalogue")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no catalogue entries found")
	}
	t.Logf("%d catalogue entries valid", len(entries))
}

func TestRejectsForbiddenReference(t *testing.T) {
	e := Entry{ID: "DSA-0999", Title: map[string]string{"en": "x", "ru": "x"}, Domain: "directory-core",
		Severity: "low", Status: "draft", Object: "x", Attributes: []string{"x"}, Condition: "x", Rationale: "x",
		Remediation: map[string]string{"en": "x", "ru": "x"}, Attack: []Technique{{"T1098", "Account Manipulation"}},
		Engine: "declarative", References: []Reference{{"PingCastle rules", "https://www.pingcastle.com/x"}}}
	if err := e.Validate(); err == nil {
		t.Fatal("a PingCastle reference must be rejected")
	}
}
