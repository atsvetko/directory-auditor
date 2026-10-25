package adcs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// challenge returns a handler that answers 401 with the given WWW-Authenticate
// schemes, as an AD CS web-enrollment endpoint with Windows auth does.
func challenge(schemes ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for _, s := range schemes {
			w.Header().Add("WWW-Authenticate", s)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func find(results []EndpointResult, url string) (EndpointResult, bool) {
	for _, r := range results {
		if r.URL == url {
			return r, true
		}
	}
	return EndpointResult{}, false
}

func TestProbeAuthAndTransport(t *testing.T) {
	// (a) NTLM (and Negotiate) over plain HTTP.
	httpNTLM := httptest.NewServer(challenge("Negotiate", "NTLM"))
	defer httpNTLM.Close()
	// (b) NTLM over HTTPS (self-signed cert; the default probe transport tolerates it).
	httpsNTLM := httptest.NewTLSServer(challenge("NTLM"))
	defer httpsNTLM.Close()
	// (c) Negotiate (Kerberos) only — no NTLM offered.
	negOnly := httptest.NewServer(challenge("Negotiate"))
	defer negOnly.Close()

	urls := []string{httpNTLM.URL, httpsNTLM.URL, negOnly.URL}
	results := Probe(context.Background(), urls, ProbeOptions{})
	if len(results) != 3 {
		t.Fatalf("want 3 results, got %d", len(results))
	}

	a, _ := find(results, httpNTLM.URL)
	if !a.Reachable || a.HTTPS || a.Status != 401 || a.EPA != EPAUnknown {
		t.Errorf("http/NTLM: %+v", a)
	}
	if !contains(a.Auth, "ntlm") || !contains(a.Auth, "negotiate") {
		t.Errorf("http/NTLM auth = %v, want ntlm+negotiate", a.Auth)
	}

	b, _ := find(results, httpsNTLM.URL)
	if !b.Reachable || !b.HTTPS || b.EPA != EPAUnknown {
		t.Errorf("https/NTLM: %+v", b)
	}
	if !contains(b.Auth, "ntlm") {
		t.Errorf("https/NTLM auth = %v, want ntlm", b.Auth)
	}

	c, _ := find(results, negOnly.URL)
	if !c.Reachable || contains(c.Auth, "ntlm") || !contains(c.Auth, "negotiate") {
		t.Errorf("negotiate-only auth = %v, want negotiate without ntlm", c.Auth)
	}

	// Emitted objects: attrs match the collector contract, tier rises to 1.
	snap := &snapshot.Snapshot{Meta: snapshot.Meta{Provider: "ad"}}
	AugmentProbe(snap, results)
	if snap.Meta.Tier != 1 {
		t.Errorf("tier = %d, want 1", snap.Meta.Tier)
	}
	var httpsObj, httpObj snapshot.Object
	for _, o := range snap.Objects {
		if o.Attr("objectClass") != ClassEndpoint {
			continue
		}
		switch o.Attr("url") {
		case httpsNTLM.URL:
			httpsObj = o
		case httpNTLM.URL:
			httpObj = o
		}
	}
	if httpObj.Attr("https") != "FALSE" || httpsObj.Attr("https") != "TRUE" {
		t.Errorf("https flags: http=%q https=%q", httpObj.Attr("https"), httpsObj.Attr("https"))
	}
	if httpsObj.Attr("epa") != EPAUnknown {
		t.Errorf("epa = %q, want unknown", httpsObj.Attr("epa"))
	}
	if httpsObj.Class[0] != ClassEndpoint {
		t.Errorf("class = %v", httpsObj.Class)
	}
	// The ESC8 condition flags any NTLM endpoint whose EPA is not "require";
	// unknown EPA (all unauthenticated probes) therefore flags for review.
	if !(contains(httpsObj.Attrs["auth"], "ntlm") && httpsObj.Attr("epa") != "require") {
		t.Errorf("https/NTLM would not be flagged for review: %+v", httpsObj.Attrs)
	}
}

func TestProbeUnreachableIsSkipped(t *testing.T) {
	// A closed port on localhost: connection refused, fast.
	s := httptest.NewServer(challenge("NTLM"))
	url := s.URL
	s.Close() // close so the port is no longer listening

	snap := &snapshot.Snapshot{Meta: snapshot.Meta{Provider: "ad"}}
	results := Probe(context.Background(), []string{url}, ProbeOptions{})
	AugmentProbe(snap, results)
	if len(snap.Objects) != 0 {
		t.Errorf("unreachable endpoint should emit no object, got %d", len(snap.Objects))
	}
	if len(snap.Skipped) != 1 || snap.Skipped[0].Classes[0] != ClassEndpoint {
		t.Errorf("want one skipped with endpoint class, got %+v", snap.Skipped)
	}
	if snap.Meta.Tier != 0 {
		t.Errorf("tier must not rise when nothing answered, got %d", snap.Meta.Tier)
	}
}

func TestCandidateURLs(t *testing.T) {
	snap := &snapshot.Snapshot{Objects: []snapshot.Object{
		{DN: "CN=lab-CA,CN=Enrollment Services", Class: []string{"pKIEnrollmentService"},
			Attrs: map[string][]string{"dNSHostName": {"ca01.lab.example"}}},
		{DN: "CN=t", Class: []string{"pKICertificateTemplate"}, Attrs: map[string][]string{}},
	}}
	got := CandidateURLs(snap)
	want := []string{"http://ca01.lab.example/certsrv/", "https://ca01.lab.example/certsrv/"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("CandidateURLs = %v, want %v", got, want)
	}
}

func TestExpandTargets(t *testing.T) {
	got := ExpandTargets([]string{"ca01.lab.example", "https://ca02/certsrv/", " "})
	want := []string{"https://ca02/certsrv/", "http://ca01.lab.example/certsrv/", "https://ca01.lab.example/certsrv/"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ExpandTargets = %v, want %v", got, want)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
