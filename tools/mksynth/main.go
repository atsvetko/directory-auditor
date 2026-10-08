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

// oversized returns 11 placeholder member DNs: enough to exceed the DSA-0035
// threshold without turning real lab accounts into Tier-0 principals.
func oversized(base string) []string {
	out := make([]string, 11)
	for i := range out {
		out[i] = fmt.Sprintf("CN=bo-%02d,OU=Operators,%s", i+1, base)
	}
	return out
}

func main() {
	out := flag.String("out", "testdata/synthetic-lab.json.zst", "output path (AD lab)")
	ipaOut := flag.String("freeipa-out", "testdata/synthetic-freeipa.json.zst", "output path (FreeIPA lab)")
	flag.Parse()
	if err := writeFreeIPA(*ipaOut); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for name, fn := range map[string]func(string) error{"testdata/synthetic-samba.json.zst": writeSamba, "testdata/synthetic-samba-hardened.json.zst": writeSambaHardened} {
		if err := fn(name); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
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
		},
	}
	add := func(dn string, class []string, attrs map[string][]string) {
		s.Objects = append(s.Objects, snapshot.Object{DN: dn, Class: class, Attrs: attrs})
	}
	user := []string{"top", "person", "organizationalPerson", "user"}
	root := map[string]string{"defaultNamingContext": base, "configurationNamingContext": "CN=Configuration," + base,
		"forestFunctionality": "7", "domainFunctionality": "7", "domainControllerFunctionality": "7", "dnsHostName": "dc01.lab.example"}
	s.Meta.RootDSE = root
	s.Objects = append(s.Objects, snapshot.RootDSEObject(root))
	add(base, []string{"top", "domain", "domainDNS"}, map[string][]string{
		"name": {"lab"}, "objectSid": {dom}, "ms-DS-MachineAccountQuota": {"10"}, "minPwdLength": {"7"}, "lockoutThreshold": {"0"},
		"pwdProperties": {"1"}, "pwdHistoryLength": {"24"}, "maxPwdAge": {"-36288000000000"}, "minPwdAge": {"-864000000000"},
		"lockoutDuration": {"-18000000000"}, "lockOutObservationWindow": {"-18000000000"}, "msDS-Behavior-Version": {"7"},
		"nTSecurityDescriptor": {sd(false, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-512", 0x000F01FF, ""},
			ace{dom + "-1105", 0x00000100, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"}, // DSA-0014: j.doe has Get-Changes-All
			ace{"S-1-5-9", 0x00000100, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"})},   // Enterprise DCs: expected
	})
	add("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,"+base, []string{"top", "nTDSService"},
		map[string][]string{"dSHeuristics": {"0000000"}, "tombstoneLifetime": {"180"}})
	users := []struct {
		name, desc, uac, rid string
		pwdAge               int
		extra                map[string][]string
	}{
		{"Administrator", "Built-in account for administering the domain", "66048", "500", 900, nil},
		{"svc_backup", "backup service; password in wiki", "66048", "1104", 2400, map[string][]string{"servicePrincipalName": {"backup/fs01.lab.example"}, "adminCount": {"1"}}},
		{"j.doe", "", "512", "1105", 40, nil},
		{"m.smith", "", "514", "1106", 400, nil},
		{"old.admin", "", "512", "1107", 700, map[string][]string{"adminCount": {"1"}, "nTSecurityDescriptor": {sd(true, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-1201", 0x000F01FF, ""})}}}, // DSA-0019 (orphaned adminCount) + DSA-0029 (Helpdesk GenericAll over a protected, non-Tier-0 object)
		{"krbtgt", "Key Distribution Center Service Account", "514", "502", 1900, nil},
		// One object per directory-core entry that needs a positive case:
		{"j.legacy", "", "4194816", "1108", 30, nil}, // DSA-0001 DONT_REQ_PREAUTH
		{"svc_sql", "", "66048", "1109", 800, map[string][]string{"servicePrincipalName": {"MSSQLSvc/db01.lab.example:1433"}, "msDS-SupportedEncryptionTypes": {"4"}}}, // DSA-0003 (old pw, RC4-only), DSA-0012
		{"svc_web", "", "16777728", "1110", 20, map[string][]string{"msDS-AllowedToDelegateTo": {"cifs/fs01.lab.example"}}},                                            // DSA-0005 protocol transition (0x1000000)
		{"svc_dc", "", "512", "1111", 20, map[string][]string{"msDS-AllowedToDelegateTo": {"ldap/DC01.lab.example"}}},                                                  // DSA-0005 target is a DC
		{"kiosk", "", "544", "1112", 500, nil},                                                          // DSA-0010 PASSWD_NOTREQD (0x20)
		{"svc_legacy", "", "640", "1113", 100, nil},                                                     // DSA-0011 reversible (0x80)
		{"mig.user", "", "512", "1114", 60, map[string][]string{"sIDHistory": {"S-1-5-21-9-8-7-1055"}}}, // DSA-0017
		{"des.user", "", "2097664", "1115", 60, nil},                                                    // DSA-0012 USE_DES_KEY_ONLY
		{"t.contractor", "temp account, password=Welcome1!", "512", "1116", 30, nil},                    // DSA-0028 cleartext secret in description
		// ANSSI wave 1 (DSA-0030…0044). Flags chosen so each object trips only its target checks.
		{"hidden.da", "", "1049088", "1117", 10, map[string][]string{"primaryGroupID": {"512"}}},      // DSA-0034/0044: primary group = Domain Admins (NOT_DELEGATED keeps DSA-0007 quiet)
		{"dormant.user", "", "512", "1118", 30, map[string][]string{"lastLogonTimestamp": {ft(400)}}}, // DSA-0036: no logon for 400 days
		{"Guest", "", "512", "501", 30, map[string][]string{"primaryGroupID": {"514"}}},               // DSA-0042: built-in Guest enabled
	}
	for _, u := range users {
		attrs := map[string][]string{"sAMAccountName": {u.name}, "userAccountControl": {u.uac}, "pwdLastSet": {ft(u.pwdAge)},
			"objectSid": {dom + "-" + u.rid}, "primaryGroupID": {"513"}, "whenCreated": {"20200115100000.0Z"}, "sAMAccountType": {"805306368"},
			"lastLogonTimestamp": {ft(5)}}
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
			sd(true, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-512", 0x000F01FF, ""}, ace{dom + "-1201", 0x00040000, ""})},
		{"Protected Users", dom + "-525", nil, ""},
		{"Tier0 Ops", dom + "-1200", []string{"CN=svc_backup,CN=Users," + base}, ""},
		{"Helpdesk", dom + "-1201", []string{"CN=j.doe,CN=Users," + base}, ""},
		{"Domain Controllers", dom + "-516", nil, ""},
		{"Backup Operators", "S-1-5-32-551", oversized(base), ""}, // DSA-0035: 11 direct members (members are placeholders, not collected)
		{"Pre-Windows 2000 Compatible Access", "S-1-5-32-554", []string{"CN=S-1-5-7,CN=ForeignSecurityPrincipals," + base, "CN=S-1-5-11,CN=ForeignSecurityPrincipals," + base}, ""}, // DSA-0038/0039: Anonymous added
		{"DnsAdmins", dom + "-1101", []string{"CN=j.doe,CN=Users," + base}, ""},                                                                                                     // DSA-0027: DLL-load to SYSTEM on the DC
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
	computer := append(append([]string{}, user...), "computer")
	add("CN=DC01,OU=Domain Controllers,"+base, computer,
		map[string][]string{"sAMAccountName": {"DC01$"}, "objectSid": {dom + "-1000"}, "primaryGroupID": {"516"}, "sAMAccountType": {"805306369"},
			"dNSHostName": {"dc01.lab.example"}, "operatingSystem": {"Windows Server 2022 Datacenter"}, "operatingSystemVersion": {"10.0 (20348)"}, "userAccountControl": {"532480"}, "pwdLastSet": {ft(12)},
			// DSA-0006: RBCD on a DC, trustee = APP01$
			"msDS-AllowedToActOnBehalfOfOtherIdentity": {sd(false, ace{dom + "-1001", 0x000F01FF, ""})}})
	add("CN=APP01,OU=Servers,"+base, computer, // DSA-0004 unconstrained delegation
		map[string][]string{"sAMAccountName": {"APP01$"}, "objectSid": {dom + "-1001"}, "primaryGroupID": {"515"}, "sAMAccountType": {"805306369"},
			"dNSHostName": {"app01.lab.example"}, "operatingSystem": {"Windows Server 2019"}, "userAccountControl": {"528384"}, "pwdLastSet": {ft(12)}})
	for _, c := range []struct {
		name, ou, rid, pg, os, uac string
		pwd, logon                 int
	}{
		{"OLDDC", "OU=Domain Controllers", "1003", "516", "Windows Server 2012 R2 Standard", "532480", 5, 3},      // DSA-0031 obsolete OS
		{"STALEDC", "OU=Domain Controllers", "1004", "516", "Windows Server 2022 Datacenter", "532480", 200, 200}, // DSA-0032 password 200 d, DSA-0033 no logon 200 d
		{"BADDC", "OU=Domain Controllers", "1005", "516", "Windows Server 2022 Datacenter", "4096", 5, 3},         // DSA-0030 primary group 516 without SERVER_TRUST_ACCOUNT
		{"FS01", "OU=Servers", "1006", "515", "Windows Server 2022 Standard", "4096", 200, 3},                     // DSA-0043 server password 200 d
	} {
		add(fmt.Sprintf("CN=%s,%s,%s", c.name, c.ou, base), computer, map[string][]string{
			"sAMAccountName": {c.name + "$"}, "objectSid": {dom + "-" + c.rid}, "primaryGroupID": {c.pg}, "sAMAccountType": {"805306369"},
			"dNSHostName": {strings.ToLower(c.name) + ".lab.example"}, "operatingSystem": {c.os}, "userAccountControl": {c.uac},
			"pwdLastSet": {ft(c.pwd)}, "lastLogonTimestamp": {ft(c.logon)}})
	}
	add("CN=WS01,CN=Computers,"+base, computer,
		map[string][]string{"sAMAccountName": {"WS01$"}, "objectSid": {dom + "-1002"}, "primaryGroupID": {"515"}, "sAMAccountType": {"805306369"},
			"userAccountControl": {"4096"}, "pwdLastSet": {ft(5)}, "ms-DS-CreatorSID": {dom + "-1105"}})
	// DSA-0016: AdminSDHolder with a WriteDacl ACE for Helpdesk
	add("CN=AdminSDHolder,CN=System,"+base, []string{"top", "container"}, map[string][]string{
		"nTSecurityDescriptor": {sd(true, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-512", 0x000F01FF, ""}, ace{dom + "-1201", 0x00040000, ""})}})
	// DSA-0018: a forest trust with SID filtering relaxed, and a disabled stale trust
	add("CN=partner.example,CN=System,"+base, []string{"top", "leaf", "trustedDomain"}, map[string][]string{
		"trustPartner": {"partner.example"}, "trustDirection": {"3"}, "trustType": {"2"}, "trustAttributes": {"72"}, "securityIdentifier": {"S-1-5-21-9-8-7"}})
	add("CN=old.example,CN=System,"+base, []string{"top", "leaf", "trustedDomain"}, map[string][]string{
		"trustPartner": {"old.example"}, "trustDirection": {"0"}, "trustType": {"2"}, "trustAttributes": {"4"}, "securityIdentifier": {"S-1-5-21-1-1-1"}})
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
	guid string // object type GUID (registry form); "" = plain ACE
}

// sd encodes a minimal self-relative descriptor with allow ACEs — test data
// only; the product itself has no descriptor encoder.
func sd(protected bool, aces ...ace) string {
	var acl []byte
	for _, a := range aces {
		var body []byte
		typ := byte(0x00)
		if a.guid != "" {
			typ = 0x05 // ACCESS_ALLOWED_OBJECT_ACE
			body = binary.LittleEndian.AppendUint32(nil, a.mask)
			body = binary.LittleEndian.AppendUint32(body, 0x1) // ACE_OBJECT_TYPE_PRESENT
			body = append(body, guidBytes(a.guid)...)
			body = append(body, sidBytes(a.sid)...)
		} else {
			body = append(binary.LittleEndian.AppendUint32(nil, a.mask), sidBytes(a.sid)...)
		}
		h := []byte{typ, 0, 0, 0}
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

// guidBytes encodes a registry-form GUID the way AD stores it (first three
// fields little-endian).
func guidBytes(g string) []byte {
	h := strings.ReplaceAll(g, "-", "")
	raw := make([]byte, 16)
	for i := 0; i < 16; i++ {
		fmt.Sscanf(h[2*i:2*i+2], "%02x", &raw[i])
	}
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}
