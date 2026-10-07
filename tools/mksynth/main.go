// Command mksynth writes the synthetic lab snapshot used by tests, by
// `dirauditor analyse` smoke runs and, later, by `--demo`. Every name in it is
// invented; nothing here comes from a real directory.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

func main() {
	out := flag.String("out", "testdata/synthetic-lab.json.zst", "output path (AD lab)")
	ipaOut := flag.String("freeipa-out", "testdata/synthetic-freeipa.json.zst", "output path (FreeIPA lab)")
	flag.Parse()
	if err := writeFreeIPA(*ipaOut); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	base := "DC=lab,DC=example"
	dom := "S-1-5-21-1111111111-2222222222-3333333333"
	collected := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	ft := func(daysAgo int) string { // FILETIME
		return strconv.FormatInt(collected.AddDate(0, 0, -daysAgo).UnixNano()/100+116444736000000000, 10)
	}
	s := &snapshot.Snapshot{
		Schema:    snapshot.SchemaVersion,
		Collected: collected,
		Meta: snapshot.Meta{
			Provider: "ad", Dialect: "ad", Target: "dc01.lab.example", Domain: "lab.example", BaseDN: base,
			Identity: "audit@lab.example", Tier: 0, Tool: "mksynth", QueryCount: 9, DomainSID: dom,
			RootDSE: map[string]string{"defaultNamingContext": base, "forestFunctionality": "7", "domainControllerFunctionality": "7"},
		},
	}
	add := func(dn string, class []string, attrs map[string][]string) {
		s.Objects = append(s.Objects, snapshot.Object{DN: dn, Class: class, Attrs: attrs})
	}
	user := []string{"top", "person", "organizationalPerson", "user"}
	add(base, []string{"top", "domain", "domainDNS"}, map[string][]string{
		"name": {"lab"}, "objectSid": {dom}, "ms-DS-MachineAccountQuota": {"10"}, "minPwdLength": {"7"}, "lockoutThreshold": {"0"},
		"nTSecurityDescriptor": {sd(false, ace{"S-1-5-18", 0x000F01FF}, ace{dom + "-512", 0x000F01FF})},
	})
	users := []struct {
		name, desc, uac, rid string
		pwdAge               int
		extra                map[string][]string
	}{
		{"Administrator", "Built-in account for administering the domain", "66048", "500", 900, nil},
		{"svc_backup", "backup service; password in wiki", "66048", "1104", 2400, map[string][]string{"servicePrincipalName": {"backup/fs01.lab.example"}, "adminCount": {"1"}}},
		{"j.doe", "", "512", "1105", 40, nil},
		{"m.smith", "", "514", "1106", 400, nil},
		{"old.admin", "", "512", "1107", 700, map[string][]string{"adminCount": {"1"}, "nTSecurityDescriptor": {sd(true, ace{"S-1-5-18", 0x000F01FF})}}},
		{"krbtgt", "Key Distribution Center Service Account", "514", "502", 1900, nil},
	}
	for _, u := range users {
		attrs := map[string][]string{"sAMAccountName": {u.name}, "userAccountControl": {u.uac}, "pwdLastSet": {ft(u.pwdAge)},
			"objectSid": {dom + "-" + u.rid}, "primaryGroupID": {"513"}, "whenCreated": {"20200115100000.0Z"}}
		if u.desc != "" {
			attrs["description"] = []string{u.desc}
		}
		for k, v := range u.extra {
			attrs[k] = v
		}
		add(fmt.Sprintf("CN=%s,CN=Users,%s", u.name, base), user, attrs)
	}
	groups := []struct {
		name, sid string
		members   []string
		sd        string
	}{
		{"Administrators", "S-1-5-32-544", []string{"CN=Domain Admins,CN=Users," + base, "CN=Administrator,CN=Users," + base}, ""},
		{"Domain Admins", dom + "-512", []string{"CN=Tier0 Ops,OU=Groups," + base},
			sd(true, ace{"S-1-5-18", 0x000F01FF}, ace{dom + "-512", 0x000F01FF}, ace{dom + "-1201", 0x00040000})},
		{"Tier0 Ops", dom + "-1200", []string{"CN=svc_backup,CN=Users," + base}, ""},
		{"Helpdesk", dom + "-1201", []string{"CN=j.doe,CN=Users," + base}, ""},
		{"Domain Controllers", dom + "-516", nil, ""},
		{"Backup Operators", "S-1-5-32-551", nil, ""},
	}
	for _, g := range groups {
		attrs := map[string][]string{"sAMAccountName": {g.name}, "objectSid": {g.sid}, "description": {g.name + " (synthetic)"}}
		if len(g.members) > 0 {
			attrs["member"] = g.members
		}
		if g.sd != "" {
			attrs["nTSecurityDescriptor"] = []string{g.sd}
			attrs["adminCount"] = []string{"1"}
		}
		dn := fmt.Sprintf("CN=%s,CN=Users,%s", g.name, base)
		if g.name == "Tier0 Ops" || g.name == "Helpdesk" {
			dn = fmt.Sprintf("CN=%s,OU=Groups,%s", g.name, base)
		}
		if strings.HasPrefix(g.sid, "S-1-5-32-") {
			dn = fmt.Sprintf("CN=%s,CN=Builtin,%s", g.name, base)
		}
		add(dn, []string{"top", "group"}, attrs)
	}
	add("CN=DC01,OU=Domain Controllers,"+base, append(append([]string{}, user...), "computer"),
		map[string][]string{"sAMAccountName": {"DC01$"}, "objectSid": {dom + "-1000"}, "primaryGroupID": {"516"},
			"operatingSystem": {"Windows Server 2022 Datacenter"}, "operatingSystemVersion": {"10.0 (20348)"}, "userAccountControl": {"532480"}, "pwdLastSet": {ft(12)}})
	s.Skipped = []snapshot.Skipped{{Query: "sysvol", Reason: "tier", Detail: "tier 1 not requested"}}

	for _, path := range []string{*out, "internal/demo/synthetic-lab.json.zst"} {
		if err := snapshot.WriteFile(path, s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	h, _ := snapshot.Hash(s)
	fmt.Printf("wrote %s (%d objects, sha256 %s)\n", *out, len(s.Objects), h[:16])
}

type ace struct {
	sid  string
	mask uint32
}

// sd encodes a minimal self-relative descriptor with allow ACEs — test data
// only; the product itself has no descriptor encoder.
func sd(protected bool, aces ...ace) string {
	var acl []byte
	for _, a := range aces {
		body := append(binary.LittleEndian.AppendUint32(nil, a.mask), sidBytes(a.sid)...)
		h := []byte{0, 0, 0, 0}
		binary.LittleEndian.PutUint16(h[2:], uint16(4+len(body)))
		acl = append(acl, append(h, body...)...)
	}
	ah := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(ah[2:], uint16(8+len(acl)))
	binary.LittleEndian.PutUint16(ah[4:], uint16(len(aces)))
	ctl := uint16(0x8004)
	if protected {
		ctl |= 0x1000
	}
	h := make([]byte, 20)
	h[0] = 1
	binary.LittleEndian.PutUint16(h[2:], ctl)
	binary.LittleEndian.PutUint32(h[16:], 20)
	return base64.StdEncoding.EncodeToString(append(append(h, ah...), acl...))
}

func sidBytes(s string) []byte {
	parts := strings.Split(s, "-")[2:]
	auth, _ := strconv.ParseUint(parts[0], 10, 48)
	b := make([]byte, 8)
	b[0], b[1] = 1, byte(len(parts)-1)
	for i := 0; i < 6; i++ {
		b[7-i] = byte(auth >> (8 * i))
	}
	for _, p := range parts[1:] {
		n, _ := strconv.ParseUint(p, 10, 32)
		b = binary.LittleEndian.AppendUint32(b, uint32(n))
	}
	return b
}
