// Package adcs holds the two out-of-band AD CS collectors whose output the
// ESC6/7/8/10/11/16 checks (DSA-0506…0516) consume. Those facts do not live in
// LDAP, so they are modelled as dirauditor-namespaced snapshot objects whose
// exact shape is the collector contract documented in
// internal/provider/ad/collect.go ("Out-of-band AD CS configuration snapshot").
//
// Two independent collectors live here:
//
//   - probe.go  — the ESC8 web-enrollment HTTP probe (tier 1): a pure-Go,
//     unauthenticated network probe that reports what each enrolment endpoint
//     advertises (transport and WWW-Authenticate schemes). It never performs a
//     relay and never sends credentials.
//   - ingest.go — the ESC6/7/10/11/16 offline ingest (tier 2): it loads the
//     JSON that scripts/collect-adcs-tier2.ps1 produces on a CA/DC host and
//     merges the CA- and DC-configuration objects into the snapshot.
//
// Both follow the smb.conf collector precedent (internal/local/smbconf):
// Collect/Probe gathers facts, Augment merges them into a snapshot and raises
// its tier. Neither writes anything to disk.
package adcs

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// DNs and object class of the endpoint objects this collector adds.
const (
	EndpointBase  = "cn=adcs-web,cn=dirauditor"
	ClassEndpoint = "dirauditorAdcsEndpoint"
)

// EPA values an endpoint object can carry (collector contract). An
// unauthenticated probe cannot positively confirm Extended Protection for
// Authentication, so the probe only ever emits EPAUnknown; the ESC8 condition
// treats anything other than "require" as potentially relayable, so an
// unconfirmed-EPA endpoint is flagged for review (conservative).
const (
	EPANone    = "none"
	EPAAllow   = "allow"
	EPARequire = "require"
	EPAUnknown = "unknown"
)

// ProbeOptions control the HTTP probe.
type ProbeOptions struct {
	// PerRequestTimeout bounds each GET; 0 uses a 10 s default.
	PerRequestTimeout time.Duration
	// Transport lets tests inject a client (e.g. httptest's TLS client). When
	// nil a default transport is used that tolerates the self-signed and
	// internal-CA certificates AD CS endpoints routinely present — safe because
	// the probe is unauthenticated, read-only and never sends a credential or
	// request body; it reads only the status line and WWW-Authenticate headers.
	Transport http.RoundTripper
}

// EndpointResult is the outcome of probing one URL.
type EndpointResult struct {
	URL       string
	HTTPS     bool     // derived from the URL scheme
	Reachable bool     // the endpoint answered
	Status    int      // HTTP status code when reachable
	Auth      []string // offered auth schemes, lower-case (ntlm, negotiate, …)
	EPA       string   // always EPAUnknown from an unauthenticated probe
	Err       string   // transport error when not reachable
}

// CandidateURLs derives the endpoints to probe from a collected snapshot: for
// every pKIEnrollmentService object it builds the Web Enrollment URLs
// http://<host>/certsrv/ and https://<host>/certsrv/ from the host's
// dNSHostName. Hosts are de-duplicated; the result is sorted for a stable plan.
//
// Note: the tier-0 LDAP plan does not currently request dNSHostName on
// pKIEnrollmentService objects, so on a present-day snapshot this returns
// nothing and the operator supplies targets with --adcs-probe-url. The function
// reads dNSHostName whenever it is present, so it works unchanged once that
// attribute is added to the plan or when a hand-built snapshot carries it.
func CandidateURLs(snap *snapshot.Snapshot) []string {
	if snap == nil {
		return nil
	}
	hosts := map[string]bool{}
	for _, o := range snap.Objects {
		if !hasClass(o, "pKIEnrollmentService") {
			continue
		}
		h := strings.TrimSpace(o.Attr("dNSHostName"))
		if h != "" {
			hosts[strings.ToLower(h)] = true
		}
	}
	return urlsForHosts(hosts)
}

// ExpandTargets turns operator-supplied targets into endpoint URLs. A full URL
// (with scheme) is probed verbatim; a bare host is expanded to its http+https
// /certsrv/ Web Enrollment URLs, matching CandidateURLs.
func ExpandTargets(targets []string) []string {
	hosts := map[string]bool{}
	var explicit []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if strings.Contains(t, "://") {
			explicit = append(explicit, t)
			continue
		}
		hosts[strings.ToLower(t)] = true
	}
	out := append(explicit, urlsForHosts(hosts)...)
	return dedupe(out)
}

func urlsForHosts(hosts map[string]bool) []string {
	var names []string
	for h := range hosts {
		names = append(names, h)
	}
	sort.Strings(names)
	var out []string
	for _, h := range names {
		out = append(out, "http://"+h+"/certsrv/", "https://"+h+"/certsrv/")
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// Probe performs an unauthenticated GET against each URL and records the
// transport, the advertised auth schemes and the (unknowable) EPA state. It
// follows no redirect to a different host and writes nothing. Context
// cancellation aborts the remaining probes.
func Probe(ctx context.Context, urls []string, o ProbeOptions) []EndpointResult {
	if o.PerRequestTimeout <= 0 {
		o.PerRequestTimeout = 10 * time.Second
	}
	rt := o.Transport
	if rt == nil {
		rt = defaultTransport()
	}
	client := &http.Client{
		Transport: rt,
		// Follow same-host redirects (http→https on the same host) but never a
		// redirect to a different host, and never issue credentials on one.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			if !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	out := make([]EndpointResult, 0, len(urls))
	for _, u := range urls {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		out = append(out, probeOne(ctx, client, u, o.PerRequestTimeout))
	}
	return out
}

func probeOne(ctx context.Context, client *http.Client, raw string, timeout time.Duration) EndpointResult {
	res := EndpointResult{URL: raw, EPA: EPAUnknown}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		res.Err = "not a http(s) URL"
		return res
	}
	res.HTTPS = u.Scheme == "https"

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, raw, nil)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "dirauditor-adcs-probe")
	resp, err := client.Do(req)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer resp.Body.Close()
	res.Reachable = true
	res.Status = resp.StatusCode
	res.Auth = authSchemes(resp.Header.Values("WWW-Authenticate"))
	return res
}

// authSchemes extracts the lower-cased scheme token from each WWW-Authenticate
// header value (e.g. `NTLM`, `Negotiate`, `Basic realm="x"`), de-duplicated and
// order-preserving.
func authSchemes(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		// A single header line may list more than one challenge separated by
		// commas; the scheme is the first token of each, but challenge
		// parameters are also comma-separated, so take only the leading token.
		tok := strings.TrimSpace(v)
		if i := strings.IndexAny(tok, " \t"); i >= 0 {
			tok = tok[:i]
		}
		tok = strings.TrimSuffix(tok, ",")
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "" || seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return out
}

// Augment emits a dirauditorAdcsEndpoint object for every endpoint that
// answered and raises the snapshot's tier to at least 1 (a network probe is a
// tier-1 action). Endpoints that did not answer are recorded as skipped so the
// ESC8 check is marked "not collected" for them rather than silently passing.
func AugmentProbe(snap *snapshot.Snapshot, results []EndpointResult) {
	raised := false
	for _, r := range results {
		if !r.Reachable {
			snap.Skipped = append(snap.Skipped, snapshot.Skipped{
				Query: "adcs-probe", Reason: "error",
				Detail:  fmt.Sprintf("%s did not answer (%s); ESC8 could not be assessed for it", r.URL, r.Err),
				Classes: []string{ClassEndpoint},
			})
			continue
		}
		raised = true
		https := "FALSE"
		if r.HTTPS {
			https = "TRUE"
		}
		attrs := map[string][]string{
			"objectClass": {ClassEndpoint},
			"url":         {r.URL},
			"https":       {https},
			"epa":         {r.EPA},
			"_status":     {fmt.Sprintf("%d", r.Status)},
		}
		if len(r.Auth) > 0 {
			attrs["auth"] = append([]string{}, r.Auth...)
		}
		snap.Objects = append(snap.Objects, snapshot.Object{
			DN:    "cn=" + r.URL + "," + EndpointBase,
			Class: []string{ClassEndpoint},
			Attrs: attrs,
		})
	}
	if raised && snap.Meta.Tier < 1 {
		snap.Meta.Tier = 1
	}
}

func defaultTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil, // never route an internal probe through a proxy
		DisableKeepAlives:     true,
		MaxIdleConns:          1,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		// See ProbeOptions.Transport: unauthenticated, read-only, no credentials.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
}

func hasClass(o snapshot.Object, class string) bool {
	for _, c := range o.Class {
		if strings.EqualFold(c, class) {
			return true
		}
	}
	for _, c := range o.Attrs["objectClass"] {
		if strings.EqualFold(c, class) {
			return true
		}
	}
	return false
}
