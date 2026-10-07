// Command mksynth writes the synthetic lab snapshot used by tests, by
// `dirauditor analyse` smoke runs and, later, by `--demo`. Every name in it is
// invented; nothing here comes from a real directory.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

func main() {
	out := flag.String("out", "testdata/synthetic-lab.json.zst", "output path")
	flag.Parse()

	base := "DC=lab,DC=example"
	s := &snapshot.Snapshot{
		Schema:    snapshot.SchemaVersion,
		Collected: time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC),
		Meta: snapshot.Meta{
			Provider: "ad", Dialect: "ad", Target: "dc01.lab.example", Domain: "lab.example", BaseDN: base,
			Identity: "audit@lab.example", Tier: 0, Tool: "mksynth", QueryCount: 3,
			RootDSE: map[string]string{"defaultNamingContext": base, "forestFunctionality": "7", "domainControllerFunctionality": "7"},
		},
	}
	add := func(dn string, class []string, attrs map[string][]string) {
		s.Objects = append(s.Objects, snapshot.Object{DN: dn, Class: class, Attrs: attrs})
	}
	add(base, []string{"top", "domain", "domainDNS"}, map[string][]string{
		"name": {"lab"}, "ms-DS-MachineAccountQuota": {"10"}, "minPwdLength": {"7"}, "lockoutThreshold": {"0"},
	})
	users := []struct{ name, desc, uac string }{
		{"Administrator", "Built-in account for administering the domain", "66048"},
		{"svc_backup", "backup service; password in wiki", "66048"},
		{"j.doe", "", "512"},
		{"m.smith", "", "514"},
		{"krbtgt", "Key Distribution Center Service Account", "514"},
	}
	for _, u := range users {
		attrs := map[string][]string{"sAMAccountName": {u.name}, "userAccountControl": {u.uac}, "pwdLastSet": {"133700000000000000"}}
		if u.desc != "" {
			attrs["description"] = []string{u.desc}
		}
		add(fmt.Sprintf("CN=%s,CN=Users,%s", u.name, base), []string{"top", "person", "organizationalPerson", "user"}, attrs)
	}
	for _, g := range []string{"Domain Admins", "Enterprise Admins", "Backup Operators", "Helpdesk"} {
		add(fmt.Sprintf("CN=%s,CN=Users,%s", g, base), []string{"top", "group"}, map[string][]string{"sAMAccountName": {g}, "description": {g + " (synthetic)"}})
	}
	add("CN=DC01,OU=Domain Controllers,"+base, []string{"top", "person", "organizationalPerson", "user", "computer"},
		map[string][]string{"sAMAccountName": {"DC01$"}, "operatingSystem": {"Windows Server 2022 Datacenter"}, "operatingSystemVersion": {"10.0 (20348)"}, "userAccountControl": {"532480"}})
	s.Skipped = []snapshot.Skipped{{Query: "sysvol", Reason: "tier", Detail: "tier 1 not requested"}}

	if err := snapshot.WriteFile(*out, s); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	h, _ := snapshot.Hash(s)
	fmt.Printf("wrote %s (%d objects, sha256 %s)\n", *out, len(s.Objects), h[:16])
}
