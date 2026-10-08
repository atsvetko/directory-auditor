// Command verify compares a dirauditor report.json produced against a lab
// directory with the lab's expectation file (testdata/lab/*-expect.yaml) and
// exits non-zero on any mismatch. It is the assertion step of the CI labs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/atsvetko/directory-auditor/internal/check"
)

type expect struct {
	Lab              string              `yaml:"lab"`
	MinObjects       int                 `yaml:"min_objects"`
	AllowSkip        []string            `yaml:"allow_skip"`
	Must             map[string][]string `yaml:"must"`
	Allow            []string            `yaml:"allow"`
	Tier0MustInclude []string            `yaml:"tier0_must_include"`
	Tier0MustExclude []string            `yaml:"tier0_must_exclude"`
	CollectedQueries []string            `yaml:"collected_queries"`
	DNGlob           bool                `yaml:"dn_glob"` // expected DNs may contain '*' (generated RDNs such as ipaUniqueID)
}

func main() {
	reportPath := flag.String("report", "report.json", "dirauditor report.json")
	expectPath := flag.String("expect", "", "expectation file (yaml)")
	flag.Parse()
	if *expectPath == "" {
		fmt.Fprintln(os.Stderr, "usage: verify -report report.json -expect testdata/lab/<lab>-expect.yaml")
		os.Exit(2)
	}
	var e expect
	eb, err := os.ReadFile(*expectPath)
	must(err)
	must(yaml.Unmarshal(eb, &e))
	var r check.Result
	rb, err := os.ReadFile(*reportPath)
	must(err)
	must(json.Unmarshal(rb, &r))

	var problems []string
	bad := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }
	allowSkip := set(e.AllowSkip)
	allow := set(e.Allow)
	seen := map[string]bool{}

	fmt.Printf("lab %s: %d objects, score %d, %d checks (%d fail, %d pass, %d skipped)\n",
		e.Lab, r.Inventory.Objects, r.Score, len(r.Checks), r.Counts.Failed, r.Counts.Passed, r.Counts.Skipped)
	if r.Inventory.Objects < e.MinObjects {
		bad("only %d objects collected, expected at least %d", r.Inventory.Objects, e.MinObjects)
	}
	for _, c := range r.Checks {
		seen[c.ID] = true
		want, listed := e.Must[c.ID]
		switch c.Status {
		case "skipped":
			if !allowSkip[c.Skip] {
				bad("%s skipped (%s): %v", c.ID, c.Skip, c.Findings)
			} else if listed {
				bad("%s must fire but was skipped (%s)", c.ID, c.Skip)
			}
		case "fail":
			got := map[string]bool{}
			for _, f := range c.Findings {
				got[strings.ToLower(f.DN)] = true
			}
			if !listed {
				if !allow[c.ID] {
					bad("%s fired unexpectedly on %v", c.ID, keys(got))
				} else {
					fmt.Printf("  note: %s fired (allowed): %v\n", c.ID, keys(got))
				}
				continue
			}
			for _, dn := range want {
				if !matchDN(got, strings.ToLower(dn), e.DNGlob) {
					bad("%s did not fire on %s (fired on %v)", c.ID, dn, keys(got))
				}
			}
			if len(got) != len(want) {
				bad("%s fired on %d objects, expected %d: %v", c.ID, len(got), len(want), keys(got))
			}
		case "pass":
			if listed {
				bad("%s passed but must fire on %v", c.ID, want)
			}
		}
	}
	for id := range e.Must {
		if !seen[id] {
			bad("%s is in the expectation file but was not evaluated", id)
		}
	}
	t0 := map[string]bool{}
	for _, t := range r.Inventory.Tier0 {
		t0[strings.ToLower(t.DN)] = true
	}
	for _, dn := range e.Tier0MustInclude {
		if !t0[strings.ToLower(dn)] {
			bad("Tier 0 inventory lacks %s", dn)
		}
	}
	for _, dn := range e.Tier0MustExclude {
		if t0[strings.ToLower(dn)] {
			bad("Tier 0 inventory wrongly includes %s", dn)
		}
	}
	for _, q := range e.CollectedQueries {
		for _, sk := range r.Inventory.NotRead {
			if sk.Query == q {
				bad("query %s was not collected: %s (%s)", q, sk.Reason, sk.Detail)
			}
		}
	}
	if len(problems) > 0 {
		fmt.Println("FAILED:")
		for _, p := range problems {
			fmt.Println("  - " + p)
		}
		os.Exit(1)
	}
	fmt.Printf("OK: %d expected findings matched, Tier-0 inventory as expected\n", len(e.Must))
}

// matchDN reports whether want (lower-cased, possibly with '*' wildcards when
// glob is on) matches one of the DNs that fired.
func matchDN(got map[string]bool, want string, glob bool) bool {
	if got[want] {
		return true
	}
	if !glob || !strings.Contains(want, "*") {
		return false
	}
	for dn := range got {
		if wildcard(want, dn) {
			return true
		}
	}
	return false
}

// wildcard matches '*' against any run of characters (including commas).
func wildcard(pat, s string) bool {
	parts := strings.Split(pat, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if i == len(parts)-1 {
			return strings.HasSuffix(s, p)
		}
		j := strings.Index(s, p)
		if j < 0 {
			return false
		}
		s = s[j+len(p):]
	}
	return true
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(2)
	}
}

func set(l []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range l {
		m[s] = true
	}
	return m
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
