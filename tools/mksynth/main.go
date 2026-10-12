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
	gt := func(daysAgo int) string { // GeneralizedTime
		return collected.AddDate(0, 0, -daysAgo).Format("20060102150405.0Z")
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
		"name": {"lab"}, "objectSid": {dom}, "ms-DS-MachineAccountQuota": {"10"}, "minPwdLength": {"7"}, "lockoutThreshold": {"50"}, // DSA-0082: lockout on, threshold 50
		"msDS-ExpirePasswordsOnSmartCardOnlyAccounts": {"TRUE"}, // DSA-0085: rolling configured (FL 2016), see sc.admin
		"pwdProperties": {"1"}, "pwdHistoryLength": {"24"}, "maxPwdAge": {"-36288000000000"}, "minPwdAge": {"-864000000000"},
		"lockoutDuration": {"-3000000000"}, "lockOutObservationWindow": {"-18000000000"}, "msDS-Behavior-Version": {"7"}, // DSA-0082: 5-min duration
		"gPLink": {"[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System," + base + ";0]"},
		"nTSecurityDescriptor": {sd(false, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-512", 0x000F01FF, ""},
			ace{dom + "-1105", 0x00000100, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"},   // DSA-0014: j.doe has Get-Changes-All
			ace{"S-1-5-9", 0x00000100, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"},       // Enterprise DCs: expected
			ace{dom + "-1201", 0x00000100, "9923a32a-3607-11d2-b9be-0000f87a36b2"},   // DSA-0049: Helpdesk may add replicas (DCs)
			ace{dom + "-527", 0x000F01FF, ""},                                        // DSA-0051: 2016-era full control for Enterprise Key Admins
			ace{dom + "-1201", 0x00000100, "45ec5156-db7e-47bb-b53f-dbeb2d03c40f"})}, // DSA-0078: Helpdesk may reanimate tombstones
	})
	add("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,"+base, []string{"top", "nTDSService"},
		map[string][]string{"dSHeuristics": {"000000010100000f"}, "tombstoneLifetime": {"180"}})
	users := []struct {
		name, desc, uac, rid string
		pwdAge               int
		extra                map[string][]string
	}{
		{"Administrator", "Built-in account for administering the domain", "66048", "500", 900, map[string][]string{ // DSA-0083: logged on 5 d ago
			"msDS-KeyCredentialLink": {keyCred("CN=Administrator,CN=Users," + base)}}}, // DSA-0075: key credential on a Tier-0 user
		{"svc_backup", "backup service; password in wiki", "66048", "1104", 2400, map[string][]string{"servicePrincipalName": {"backup/fs01.lab.example"}, "adminCount": {"1"},
			"altSecurityIdentities": {"X509:<I>DC=example,DC=lab,CN=lab-CA<S>CN=svc_backup"}}}, // DSA-0052 (Tier-0 mapping) + DSA-0053 (weak issuer+subject form)
		{"j.doe", "", "512", "1105", 40, map[string][]string{"msDS-KeyCredentialLink": {keyCred("CN=j.doe,CN=Users," + base)}}}, // negative DSA-0075: not Tier 0
		{"m.smith", "", "514", "1106", 400, nil},
		{"old.admin", "", "512", "1107", 700, map[string][]string{"adminCount": {"1"}, "nTSecurityDescriptor": {sd(true, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-1201", 0x000F01FF, ""})}}}, // DSA-0019 (orphaned adminCount) + DSA-0029 (Helpdesk GenericAll over a protected, non-Tier-0 object)
		{"krbtgt", "Key Distribution Center Service Account", "514", "502", 1900, nil},
		// One object per directory-core entry that needs a positive case:
		{"j.legacy", "", "4194816", "1108", 30, nil}, // DSA-0001 DONT_REQ_PREAUTH
		{"svc_sql", "", "66048", "1109", 800, map[string][]string{"servicePrincipalName": {"MSSQLSvc/db01.lab.example:1433"}, "msDS-SupportedEncryptionTypes": {"4"}}}, // DSA-0003 (old pw, RC4-only), DSA-0012
		{"svc_web", "", "16777728", "1110", 20, map[string][]string{"msDS-AllowedToDelegateTo": {"cifs/fs01.lab.example"}, // DSA-0005 protocol transition (0x1000000)
			"msDS-AllowedToActOnBehalfOfOtherIdentity": {sd(false, ace{dom + "-1001", 0x000F01FF, ""})}}}, // negative DSA-0086: RBCD on an ordinary user
		{"svc_dc", "", "512", "1111", 20, map[string][]string{"msDS-AllowedToDelegateTo": {"ldap/DC01.lab.example"}}}, // DSA-0005 target is a DC
		{"kiosk", "", "544", "1112", 500, nil},                                                          // DSA-0010 PASSWD_NOTREQD (0x20)
		{"svc_legacy", "", "640", "1113", 100, nil},                                                     // DSA-0011 reversible (0x80)
		{"mig.user", "", "512", "1114", 60, map[string][]string{"sIDHistory": {"S-1-5-21-9-8-7-1055"}}}, // DSA-0017
		{"des.user", "", "2097664", "1115", 60, nil},                                                    // DSA-0012 USE_DES_KEY_ONLY
		{"t.contractor", "temp account, password=Welcome1!", "512", "1116", 30, nil},                    // DSA-0028 cleartext secret in description
		// ANSSI wave 1 (DSA-0030…0044). Flags chosen so each object trips only its target checks.
		{"hidden.da", "", "1049088", "1117", 10, map[string][]string{"primaryGroupID": {"512"}, "whenCreated": {gt(10)}}}, // DSA-0034/0044: primary group = Domain Admins (NOT_DELEGATED keeps DSA-0007 quiet); DSA-0084: created 10 d ago
		{"dormant.user", "", "512", "1118", 30, map[string][]string{"lastLogonTimestamp": {ft(400)}}},                     // DSA-0036: no logon for 400 days
		{"Guest", "", "512", "501", 30, map[string][]string{"primaryGroupID": {"514"}}},                                   // DSA-0042: built-in Guest enabled
		// Wave 2a (DSA-0045…0060)
		{"svc_print", "", "512", "1119", 20, map[string][]string{"msDS-AllowedToDelegateTo": {"cifs/oldfs.lab.example"}}},          // DSA-0054: delegation to a host no account owns
		{"PARTNER$", "", "2048", "1120", 400, map[string][]string{"sAMAccountType": {"805306370"}, "lastLogonTimestamp": {ft(5)}}}, // DSA-0065: interdomain trust account, password 400 d old
		// Group A (DSA-0075…0087).
		{"krbtgt_12345", "Key Distribution Center service account for read-only DC", "514", "1140", 30, map[string][]string{ // DSA-0086: RBCD on an RODC krbtgt
			"msDS-KrbTgtLinkBl":                        {"CN=RODC01,OU=Domain Controllers," + base},
			"msDS-AllowedToActOnBehalfOfOtherIdentity": {sd(false, ace{dom + "-1105", 0x000F01FF, ""})}}},
		{"sc.admin", "", "262656", "1141", 100, nil},                                    // DSA-0085: smart card required, rolling configured but hash 100 d old (> maxPwdAge 42 d + 1)
		{"sc.fresh", "", "262656", "1142", 30, nil},                                     // negative DSA-0085: hash 30 d old
		{"sc.off", "", "262658", "1143", 300, nil},                                      // negative DSA-0085: disabled
		{"new.user", "", "512", "1144", 3, map[string][]string{"whenCreated": {gt(3)}}}, // negative DSA-0084: recent, not Tier 0
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
		{"Administrators", "S-1-5-32-544", []string{"CN=Domain Admins,CN=Users," + base, "CN=Administrator,CN=Users," + base,
			"CN=S-1-5-21-9-8-7-1500,CN=ForeignSecurityPrincipals," + base}, ""}, // DSA-0048: a partner-forest principal in Administrators
		{"Domain Admins", dom + "-512", []string{"CN=Tier0 Ops,OU=Groups," + base},
			// negative DSA-0076: owned by Domain Admins
			sdOwned(dom+"-512", true, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-512", 0x000F01FF, ""}, ace{dom + "-1201", 0x00040000, ""})},
		{"Protected Users", dom + "-525", nil, ""},
		{"Tier0 Ops", dom + "-1200", []string{"CN=svc_backup,CN=Users," + base, "CN=SQL01,OU=Servers," + base}, ""}, // DSA-0047: a member server in a Tier-0 group
		{"Helpdesk", dom + "-1201", []string{"CN=j.doe,CN=Users," + base}, ""},
		{"Domain Controllers", dom + "-516", nil, ""},
		{"Backup Operators", "S-1-5-32-551", oversized(base), ""}, // DSA-0035: 11 direct members (members are placeholders, not collected)
		{"Pre-Windows 2000 Compatible Access", "S-1-5-32-554", []string{"CN=S-1-5-7,CN=ForeignSecurityPrincipals," + base, "CN=S-1-5-11,CN=ForeignSecurityPrincipals," + base}, ""}, // DSA-0038/0039: Anonymous added
		{"DnsAdmins", dom + "-1101", []string{"CN=j.doe,CN=Users," + base}, // DSA-0027: DLL-load to SYSTEM on the DC; DSA-0059: Helpdesk can write member
			sd(false, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-512", 0x000F01FF, ""}, ace{dom + "-1201", 0x00000020, "bf9679c0-0de6-11d0-a285-00aa003049e2"})},
		{"Group Policy Creator Owners", dom + "-520", []string{"CN=Administrator,CN=Users," + base, "CN=j.doe,CN=Users," + base}, ""}, // DSA-0046: a non-Tier-0 GPO creator
		{"Schema Admins", dom + "-518", []string{"CN=Administrator,CN=Users," + base}, ""},                                            // DSA-0080: standing member
		{"Distributed COM Users", "S-1-5-32-562", []string{"CN=j.doe,CN=Users," + base}, ""},                                          // DSA-0081: a member
		{"Performance Log Users", "S-1-5-32-559", nil, ""},                                                                            // negative DSA-0081: empty
		// DSA-0089: RODC password replication groups. The allowed group holds a Tier-0 account (4); the
		// denied group has lost Schema Admins (5) — Cert Publishers and Enterprise Admins are not in this
		// lab, so they are not demanded.
		{"Read-only Domain Controllers", dom + "-521", nil, ""},
		{"Allowed RODC Password Replication Group", dom + "-571", []string{"CN=svc_backup,CN=Users," + base}, ""},
		{"Denied RODC Password Replication Group", dom + "-572", []string{"CN=krbtgt,CN=Users," + base, "CN=Domain Admins,CN=Users," + base,
			"CN=Domain Controllers,CN=Users," + base, "CN=Group Policy Creator Owners,CN=Users," + base, "CN=Read-only Domain Controllers,CN=Users," + base}, ""},
		{"Branch Users", dom + "-1160", []string{"CN=j.doe,CN=Users," + base}, ""}, // negative DSA-0089: allowed list without Tier 0
	}
	for _, g := range groups {
		attrs := map[string][]string{"sAMAccountName": {g.name}, "objectSid": {g.sid}, "description": {g.name + " (synthetic)"}}
		if len(g.members) > 0 {
			attrs["member"] = g.members
		}
		if g.sd != "" {
			attrs["nTSecurityDescriptor"] = []string{g.sd}
			if g.name == "Domain Admins" {
				attrs["adminCount"] = []string{"1"}
			}
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
			"dNSHostName": {"dc01.lab.example"}, "operatingSystem": {"Windows Server 2022 Datacenter"}, "operatingSystemVersion": {"10.0 (20348)"}, "userAccountControl": {"532480"}, "pwdLastSet": {ft(12)}, "msDS-SupportedEncryptionTypes": {"28"},
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
		{"SQL01", "OU=Servers", "1007", "515", "Windows Server 2022 Standard", "4096", 5, 3},                      // DSA-0047 (member of Tier0 Ops)
		{"AZUREADSSOACC", "CN=Computers", "1009", "515", "", "4096", 120, 120},                                    // DSA-0060 Seamless SSO key 120 d old
	} {
		add(fmt.Sprintf("CN=%s,%s,%s", c.name, c.ou, base), computer, map[string][]string{
			"sAMAccountName": {c.name + "$"}, "objectSid": {dom + "-" + c.rid}, "primaryGroupID": {c.pg}, "sAMAccountType": {"805306369"},
			"dNSHostName": {strings.ToLower(c.name) + ".lab.example"}, "operatingSystem": {c.os}, "userAccountControl": {c.uac},
			"pwdLastSet": {ft(c.pwd)}, "lastLogonTimestamp": {ft(c.logon)}})
	}
	add("CN=WS01,CN=Computers,"+base, computer,
		map[string][]string{"sAMAccountName": {"WS01$"}, "objectSid": {dom + "-1002"}, "primaryGroupID": {"515"}, "sAMAccountType": {"805306369"},
			"userAccountControl": {"4096"}, "pwdLastSet": {ft(5)}, "ms-DS-CreatorSID": {dom + "-1105"}})
	// DSA-0087: member computers by OS, logon age and state (collected 2026-10-07).
	for i, c := range []struct {
		name, os, ver, uac string
		logon              int
	}{
		{"WS-XP", "Windows XP Professional", "5.1 (2600)", "4096", 10},           // fires
		{"WS-W7", "Windows 7 Enterprise", "6.1 (7601)", "4096", 10},              // fires
		{"WS-W10", "Windows 10 Enterprise", "10.0 (19045)", "4096", 10},          // fires: servicing ended 2025-10-14
		{"WS-W10LTSC", "Windows 10 Enterprise LTSC", "10.0 (17763)", "4096", 10}, // negative: LTSC
		{"WS-W11A", "Windows 11 Enterprise", "10.0 (22000)", "4096", 10},         // fires: 21H2 ended 2024-10-08
		{"WS-W11C", "Windows 11 Enterprise", "10.0 (22631)", "4096", 10},         // negative: 23H2 ends 2026-11-10
		{"WS-W7OLD", "Windows 7 Professional", "6.1 (7601)", "4096", 200},        // negative: inactive
		{"WS-W81OFF", "Windows 8.1 Pro", "6.3 (9600)", "4098", 10},               // negative: disabled
		{"SRV2012", "Windows Server 2012 R2 Standard", "6.3 (9600)", "4096", 10}, // fires
		{"SRV2016", "Windows Server 2016 Standard", "10.0 (14393)", "4096", 10},  // negative until 2027-01-13
	} {
		add(fmt.Sprintf("CN=%s,OU=Workstations,%s", c.name, base), computer, map[string][]string{
			"sAMAccountName": {c.name + "$"}, "objectSid": {dom + "-" + strconv.Itoa(1150+i)}, "primaryGroupID": {"515"},
			"sAMAccountType": {"805306369"}, "dNSHostName": {strings.ToLower(c.name) + ".lab.example"}, "operatingSystem": {c.os},
			"operatingSystemVersion": {c.ver}, "userAccountControl": {c.uac}, "pwdLastSet": {ft(5)}, "lastLogonTimestamp": {ft(c.logon)}})
	}
	// DSA-0016: AdminSDHolder with a WriteDacl ACE for Helpdesk
	// DSA-0050: inheritance left enabled on AdminSDHolder
	// Negative DSA-0076: owned by j.doe, but an OWNER RIGHTS entry limits the owner to READ_CONTROL.
	add("CN=AdminSDHolder,CN=System,"+base, []string{"top", "container"}, map[string][]string{
		"nTSecurityDescriptor": {sdOwned(dom+"-1105", false, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-512", 0x000F01FF, ""}, ace{dom + "-1201", 0x00040000, ""},
			ace{"S-1-3-4", 0x00020000, ""})}})
	// DSA-0018: a forest trust with SID filtering relaxed, and a disabled stale trust
	add("CN=partner.example,CN=System,"+base, []string{"top", "leaf", "trustedDomain"}, map[string][]string{
		"trustPartner": {"partner.example"}, "trustDirection": {"3"}, "trustType": {"2"}, "trustAttributes": {"72"}, "securityIdentifier": {"S-1-5-21-9-8-7"}})
	add("CN=old.example,CN=System,"+base, []string{"top", "leaf", "trustedDomain"}, map[string][]string{
		"trustPartner": {"old.example"}, "trustDirection": {"0"}, "trustType": {"2"}, "trustAttributes": {"4"}, "securityIdentifier": {"S-1-5-21-1-1-1"}})
	// Wave 2c fixtures.
	add("CN=Schema,CN=Configuration,"+base, []string{"top", "dMD"}, map[string][]string{ // DSA-0069: schema 2012 R2
		"objectVersion": {"69"},
		"nTSecurityDescriptor": {sd(false, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-518", 0x000F01FF, ""},
			ace{"S-1-5-11", 0x00020094, ""},                                           // negative: Authenticated Users read
			ace{"S-1-5-11", 0x00000100, "45ec5156-db7e-47bb-b53f-dbeb2d03c40f"},       // negative: an unrelated control right
			ace{dom + "-1201", 0x00000100, "be2bb760-7f46-11d2-b9ad-00c04f79f805"})}}) // DSA-0079: Helpdesk may Update-Schema-Cache
	add("CN=DFSR-GlobalSettings,CN=System,"+base, []string{"top", "msDFSR-GlobalSettings"}, map[string][]string{ // DSA-0070: Prepared, FRS still live
		"msDFSR-Flags": {"16"}})
	add("CN=WeakAdminPSO,CN=Password Settings Container,CN=System,"+base, []string{"top", "msDS-PasswordSettings"}, map[string][]string{ // DSA-0071
		"cn": {"WeakAdminPSO"}, "msDS-MinimumPasswordLength": {"6"}, "msDS-PasswordSettingsPrecedence": {"10"},
		"msDS-PSOAppliesTo": {"CN=Domain Admins,CN=Users," + base}})
	add("CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,"+base, []string{"top", "container", "groupPolicyContainer"}, map[string][]string{ // DSA-0072
		"displayName": {"Default Domain Policy"}, "gPCFileSysPath": {"\\\\lab.example\\sysvol\\lab.example\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}"},
		"nTSecurityDescriptor": {sdOwned(dom+"-1201", false, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-512", 0x000F01FF, ""}, ace{dom + "-1201", 0x00040000, ""})}}) // Helpdesk has WriteDacl; DSA-0076: and owns it

	// Wave 2b fixtures.
	msaClass := []string{"top", "person", "organizationalPerson", "user", "computer", "msDS-ManagedServiceAccount"}
	add("CN=svc-msa,CN=Managed Service Accounts,"+base, msaClass, map[string][]string{ // DSA-0064: MSA password 200 d old
		"sAMAccountName": {"svc-msa$"}, "objectSid": {dom + "-1121"}, "primaryGroupID": {"515"}, "sAMAccountType": {"805306369"},
		"userAccountControl": {"4096"}, "pwdLastSet": {ft(200)}})
	add("CN=BCKUPKEY_PREFERRED Secret,CN=System,"+base, []string{"top", "leaf", "secret"}, map[string][]string{ // DSA-0067
		"cn":                   {"BCKUPKEY_PREFERRED Secret"},
		"nTSecurityDescriptor": {sd(false, ace{"S-1-5-18", 0x000F01FF, ""}, ace{"S-1-5-11", 0x00000010, ""})}}) // Authenticated Users may read it
	add("CN=81b4f12e-9000-0000-0000-000000000001,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,"+base,
		[]string{"top", "msKds-ProvRootKey"}, map[string][]string{ // DSA-0068
			"cn":                   {"81b4f12e-9000-0000-0000-000000000001"},
			"nTSecurityDescriptor": {sd(false, ace{"S-1-5-18", 0x000F01FF, ""}, ace{"S-1-5-11", 0x00000010, ""})}}) // Authenticated Users may read it

	// Wave 2a fixtures.
	lapsGUID := "4f1c2b8e-6d1a-4c3e-9b7a-2a5d8e9f0c11"                                                                // invented: legacy LAPS has no fixed schemaIDGUID
	add("CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,"+base, []string{"top", "attributeSchema"}, map[string][]string{ // DSA-0057: not confidential
		"lDAPDisplayName": {"ms-Mcs-AdmPwd"}, "searchFlags": {"0"}, "schemaIDGUID": {lapsGUID}})
	ou := []string{"top", "organizationalUnit"}
	add("OU=Workstations,"+base, ou, map[string][]string{ // DSA-0056: every authenticated user may read LAPS passwords
		"nTSecurityDescriptor": {sd(false, ace{dom + "-512", 0x000F01FF, ""}, ace{"S-1-5-11", 0x00000110, lapsGUID})}})
	add("OU=Groups,"+base, ou, map[string][]string{ // DSA-0058: Helpdesk holds WriteDacl over the OU of Tier0 Ops
		"nTSecurityDescriptor": {sd(false, ace{dom + "-512", 0x000F01FF, ""}, ace{dom + "-1201", 0x00040000, ""})}})
	add("CN=Default-First-Site-Name,CN=Sites,CN=Configuration,"+base, []string{"top", "site"}, map[string][]string{ // DSA-0058: Helpdesk may link GPOs to the DCs' site
		"nTSecurityDescriptor": {sd(false, ace{dom + "-519", 0x000F01FF, ""}, ace{dom + "-1201", 0x00000020, "f30e3bbe-9ff0-11d1-b603-0000f80367c1"})}})
	add("CN=gmsa-web,CN=Managed Service Accounts,"+base, append(append([]string{}, computer...), "msDS-GroupManagedServiceAccount"), map[string][]string{ // DSA-0055
		"sAMAccountName": {"gmsa-web$"}, "objectSid": {dom + "-1008"}, "primaryGroupID": {"515"}, "sAMAccountType": {"805306369"},
		"userAccountControl": {"4096"}, "pwdLastSet": {ft(5)},
		"msDS-GroupMSAMembership": {sd(false, ace{dom + "-515", 0x000F01FF, ""})}}) // every domain computer may read the password
	// Windows Server 2025 dMSA fixtures (DSA-0073, DSA-0074).
	dmsaGUID := "6c2e9a14-5b7d-4e8f-a1c3-9d0b2f4e6a87" // invented: the product reads the real GUID from the schema
	add("CN=ms-DS-Delegated-Managed-Service-Account,CN=Schema,CN=Configuration,"+base, []string{"top", "classSchema"}, map[string][]string{
		"lDAPDisplayName": {"msDS-DelegatedManagedServiceAccount"}, "schemaIDGUID": {dmsaGUID}})
	add("OU=ServiceDelegation,"+base, ou, map[string][]string{ // DSA-0073: Helpdesk may create dMSAs here
		"nTSecurityDescriptor": {sd(false, ace{dom + "-512", 0x000F01FF, ""}, ace{dom + "-1201", 0x00000001, dmsaGUID})}})
	add("OU=Staff,"+base, ou, map[string][]string{ // negative: Helpdesk may create users only, not dMSAs
		"nTSecurityDescriptor": {sd(false, ace{dom + "-512", 0x000F01FF, ""}, ace{dom + "-1201", 0x00000001, "bf967aba-0de6-11d0-a285-00aa003049e2"})}})
	dmsaClass := append(append([]string{}, computer...), "msDS-DelegatedManagedServiceAccount")
	add("CN=dmsa-evil,OU=ServiceDelegation,"+base, dmsaClass, map[string][]string{ // DSA-0074: claims to supersede the built-in Administrator
		"sAMAccountName": {"dmsa-evil$"}, "objectSid": {dom + "-1130"}, "primaryGroupID": {"515"}, "sAMAccountType": {"805306369"},
		"userAccountControl": {"4096"}, "pwdLastSet": {ft(1)}, "msDS-DelegatedMSAState": {"2"},
		"msDS-ManagedAccountPrecededByLink": {"CN=Administrator,CN=Users," + base}})
	add("CN=dmsa-app,OU=ServiceDelegation,"+base, dmsaClass, map[string][]string{ // negative: ordinary account migrated to a dMSA
		"sAMAccountName": {"dmsa-app$"}, "objectSid": {dom + "-1131"}, "primaryGroupID": {"515"}, "sAMAccountType": {"805306369"},
		"userAccountControl": {"4096"}, "pwdLastSet": {ft(1)}, "msDS-DelegatedMSAState": {"2"},
		"msDS-ManagedAccountPrecededByLink": {"CN=j.doe,CN=Users," + base}})
	// DSA-0084: whenCreated on computers (the loop above sets none).
	setAttr(s, "CN=SQL01,OU=Servers,"+base, "whenCreated", gt(12))                                                              // Tier-0 member server created 12 d ago: fires
	setAttr(s, "CN=OLDDC,OU=Domain Controllers,"+base, "whenCreated", gt(12))                                                   // negative: a DC
	setAttr(s, "CN=WS01,CN=Computers,"+base, "whenCreated", gt(12))                                                             // negative: not Tier 0
	setAttr(s, "CN=DC01,OU=Domain Controllers,"+base, "msDS-KeyCredentialLink", keyCred("CN=DC01,OU=Domain Controllers,"+base)) // negative DSA-0075: DC key trust
	// DSA-0076: a Tier-0 member server (Tier0 Ops) owned by an ordinary user.
	setAttr(s, "CN=SQL01,OU=Servers,"+base, "nTSecurityDescriptor", sdOwned(dom+"-1105", false, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-512", 0x000F01FF, ""}))
	// Negative DSA-0076: an ordinary user owned by an ordinary user (not Tier 0).
	setAttr(s, "CN=old.admin,CN=Users,"+base, "nTSecurityDescriptor", sdOwned(dom+"-1105", true, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-1201", 0x000F01FF, ""}))

	// DSA-0088: DC registrations under CN=Sites. Classes as the directory returns them.
	sites := "CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration," + base
	server := []string{"top", "server"}
	ntds := []string{"top", "applicationSettings", "nTDSDSA"}
	for _, r := range []struct{ name, ref string }{
		{"DC01", "CN=DC01,OU=Domain Controllers," + base},     // negative: a real DC
		{"RODC01", "CN=RODC01,OU=Domain Controllers," + base}, // negative: a real RODC
		{"ROGUE01", "CN=ROGUE01,CN=Computers," + base},        // fires: NTDS Settings for an ordinary computer
		{"GHOST", ""}, // fires: NTDS Settings under a server with no serverReference
		{"CHILDDC", "CN=CHILDDC,OU=Domain Controllers,DC=child," + base}, // negative: computer in another domain, not judged
	} {
		attrs := map[string][]string{"dNSHostName": {strings.ToLower(r.name) + ".lab.example"}, "whenCreated": {gt(2)}}
		if r.ref != "" {
			attrs["serverReference"] = []string{r.ref}
		}
		add("CN="+r.name+","+sites, server, attrs)
		add("CN=NTDS Settings,CN="+r.name+","+sites, ntds, map[string][]string{"whenCreated": {gt(2)}})
	}
	add("CN=WS01,"+sites, server, map[string][]string{"serverReference": {"CN=WS01,CN=Computers," + base}}) // negative: server object without NTDS Settings
	add("CN=ROGUE01,CN=Computers,"+base, computer, map[string][]string{                                     // DSA-0088 (1): replication and GC SPNs on an ordinary computer
		"sAMAccountName": {"ROGUE01$"}, "objectSid": {dom + "-1170"}, "primaryGroupID": {"515"}, "sAMAccountType": {"805306369"},
		"dNSHostName": {"rogue01.lab.example"}, "operatingSystem": {"Windows Server 2022 Standard"}, "operatingSystemVersion": {"10.0 (20348)"},
		"userAccountControl": {"4096"}, "pwdLastSet": {ft(5)}, "lastLogonTimestamp": {ft(1)},
		"servicePrincipalName": {"HOST/rogue01.lab.example", "GC/rogue01.lab.example/lab.example",
			"E3514235-4B06-11D1-AB04-00C04FC2DCD2/0f6e2a9c-1b4d-4e3a-9c77-5d2e8b1a0c41/lab.example"}})
	setAttr(s, "CN=DC01,OU=Domain Controllers,"+base, "servicePrincipalName", "GC/dc01.lab.example/lab.example", // negative: a DC
		"E3514235-4B06-11D1-AB04-00C04FC2DCD2/7a1d9c3e-2f4b-4a6c-8e15-3b9d0c7f2a64/lab.example")

	// DSA-0089: read-only DCs (PARTIAL_SECRETS_ACCOUNT | WORKSTATION_TRUST_ACCOUNT, primary group 521).
	allowed, denied := "CN=Allowed RODC Password Replication Group,CN=Users,"+base, "CN=Denied RODC Password Replication Group,CN=Users,"+base
	branch := "CN=Branch Users,CN=Users," + base
	for _, r := range []struct {
		name                    string
		reveal, never, revealed []string
	}{
		{"RODC01", []string{allowed, "CN=Tier0 Ops,OU=Groups," + base}, []string{denied, "CN=Administrators,CN=Builtin," + base}, nil},   // (1) Tier 0 directly allowed
		{"RODC02", []string{branch}, []string{"CN=Administrators,CN=Builtin," + base}, nil},                                              // (2) denied group dropped
		{"RODC03", []string{branch}, []string{denied}, []string{"S:4:0001:CN=svc_backup,CN=Users," + base, "CN=j.doe,CN=Users," + base}}, // (3) a Tier-0 password cached
		{"RODC04", []string{branch}, []string{denied}, []string{"CN=j.doe,CN=Users," + base}},                                            // negative: clean policy
		{"RODC05", nil, nil, nil}, // negative: policy not collected (older snapshot / no rights)
	} {
		attrs := map[string][]string{"sAMAccountName": {r.name + "$"}, "objectSid": {dom + "-" + strconv.Itoa(1180+int(r.name[5]-'0'))}, "primaryGroupID": {"521"},
			"sAMAccountType": {"805306369"}, "dNSHostName": {strings.ToLower(r.name) + ".lab.example"}, "operatingSystem": {"Windows Server 2022 Datacenter"},
			"operatingSystemVersion": {"10.0 (20348)"}, "userAccountControl": {"67112960"}, "pwdLastSet": {ft(5)}, "lastLogonTimestamp": {ft(1)},
			"servicePrincipalName": {"E3514235-4B06-11D1-AB04-00C04FC2DCD2/" + strings.ToLower(r.name) + "/lab.example"}} // negative DSA-0088: an RODC
		for k, v := range map[string][]string{"msDS-RevealOnDemandGroup": r.reveal, "msDS-NeverRevealGroup": r.never, "msDS-RevealedList": r.revealed} {
			if len(v) > 0 {
				attrs[k] = v
			}
		}
		add("CN="+r.name+",OU=Domain Controllers,"+base, computer, attrs)
	}
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

// setAttr sets one attribute on an object already added to the snapshot.
func setAttr(s *snapshot.Snapshot, dn, name string, vals ...string) {
	for i := range s.Objects {
		if strings.EqualFold(s.Objects[i].DN, dn) {
			s.Objects[i].Attrs[name] = vals
			return
		}
	}
	panic("setAttr: no object " + dn)
}

// keyCred returns a synthetic msDS-KeyCredentialLink value in its DN-Binary
// form (B:<hex length>:<hex>:<owner DN>). The blob is placeholder bytes, not a
// parsable KEYCREDENTIALLINK_BLOB; checks only test for presence.
func keyCred(owner string) string {
	blob := strings.Repeat("00", 4) + "0200" + strings.Repeat("ab", 26)
	return fmt.Sprintf("B:%d:%s:%s", len(blob), strings.ToUpper(blob), owner)
}

type ace struct {
	sid  string
	mask uint32
	guid string // object type GUID (registry form); "" = plain ACE
}

// sd encodes a minimal self-relative descriptor with allow ACEs and no owner
// (what a DACL-only read returns) — test data only; the product itself has no
// descriptor encoder.
func sd(protected bool, aces ...ace) string { return sdOwned("", protected, aces...) }

// sdOwned is sd with an owner SID (what an OWNER|DACL read returns); "" = none.
func sdOwned(owner string, protected bool, aces ...ace) string {
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
	b := append(append(h, ah...), acl...)
	if owner != "" {
		binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
		b = append(b, sidBytes(owner)...)
	}
	return base64.StdEncoding.EncodeToString(b)
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
