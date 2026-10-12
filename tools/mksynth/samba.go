package main

import (
	"fmt"
	"time"

	"github.com/atsvetko/directory-auditor/internal/local/smbconf"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// writeSamba builds the synthetic Samba AD DC lab used by catalogue/samba and
// the domain password-policy entries. The directory part mirrors the AD lab;
// the smb.conf part is what the local collector would add on the DC itself.
// Values follow source4/setup/provision*.ldif and docs-xml/smbdotconf defaults
// in the Samba source tree; the weak settings are deliberate.
func writeSamba(path string) error {
	return writeSambaLab(path, false)
}

// writeSambaHardened is the same domain with every setting at or above the
// recommended value; no implemented entry may fire on it (negative control).
func writeSambaHardened(path string) error {
	return writeSambaLab(path, true)
}

func writeSambaLab(path string, hardened bool) error {
	base := "DC=samba,DC=example"
	dom := "S-1-5-21-1444444444-1555555555-1666666666" // each sub-authority fits in uint32
	collected := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	ft := func(daysAgo int) string {
		return fmt.Sprintf("%d", collected.AddDate(0, 0, -daysAgo).UnixNano()/100+116444736000000000)
	}
	ver, fl := "4.19.9", "4"
	if hardened {
		ver, fl = "4.25.0", "7"
	}
	root := map[string]string{
		"defaultNamingContext": base, "configurationNamingContext": "CN=Configuration," + base,
		"vendorName": "Samba Team (https://www.samba.org)", "vendorVersion": ver,
		"domainFunctionality": fl, "forestFunctionality": fl, "domainControllerFunctionality": fl,
		"dnsHostName": "dc1.samba.example", "supportedCapabilities": "1.2.840.113556.1.4.800;1.2.840.113556.1.4.1670;1.2.840.113556.1.4.1791",
	}
	s := &snapshot.Snapshot{Schema: snapshot.SchemaVersion, Collected: collected, Meta: snapshot.Meta{
		Provider: "samba", Dialect: "samba", Target: "dc1.samba.example", Domain: "samba.example", BaseDN: base,
		Identity: "audit@samba.example", Tier: 2, Tool: "mksynth", QueryCount: 10, DomainSID: dom, RootDSE: root,
		Extra: map[string]string{"smbconf": "/etc/samba/smb.conf", "smbconf_source": "testparm", "samba_version": ver},
	}}
	add := func(dn string, class []string, attrs map[string][]string) {
		s.Objects = append(s.Objects, snapshot.Object{DN: dn, Class: class, Attrs: attrs})
	}
	s.Objects = append(s.Objects, snapshot.RootDSEObject(root))

	// Domain head: Samba provisions lockoutThreshold 0, minPwdLength 7,
	// pwdProperties 1, history 24, maxPwdAge 42 days. This lab weakens four of them.
	policy := map[string][]string{
		"name": {"samba"}, "objectSid": {dom}, "ms-DS-MachineAccountQuota": {"10"},
		"minPwdLength": {"7"}, "pwdProperties": {"0"}, "pwdHistoryLength": {"0"}, "maxPwdAge": {"0"},
		"minPwdAge": {"-864000000000"}, "lockoutThreshold": {"0"}, "lockoutDuration": {"-18000000000"},
		"lockOutObservationWindow": {"-18000000000"}, "msDS-Behavior-Version": {fl},
	}
	heur := "0000002"
	if hardened {
		policy["minPwdLength"], policy["pwdProperties"], policy["pwdHistoryLength"] = []string{"14"}, []string{"1"}, []string{"24"}
		policy["maxPwdAge"], policy["lockoutThreshold"], policy["ms-DS-MachineAccountQuota"] = []string{"-36288000000000"}, []string{"10"}, []string{"0"}
		heur = "0000000"
		policy["msDS-ExpirePasswordsOnSmartCardOnlyAccounts"] = []string{"TRUE"} // DSA-0085: NT-hash rolling on
	}
	add(base, []string{"top", "domain", "domainDNS"}, policy)
	add("CN=AdminSDHolder,CN=System,"+base, []string{"top", "container"}, map[string][]string{"whenChanged": {"20260101000000.0Z"}})
	add("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,"+base, []string{"top", "nTDSService"},
		map[string][]string{"dSHeuristics": {heur}, "tombstoneLifetime": {"180"}})

	user := []string{"top", "person", "organizationalPerson", "user"}
	adminUAC := "66048" // DONT_EXPIRE_PASSWORD, as provisioned
	svcUAC := "66048"   // service account set never to expire (DSA-0041)
	if hardened {
		adminUAC = "1049088" // NORMAL_ACCOUNT | NOT_DELEGATED, password rotated
		svcUAC = "512"       // password expires
	}
	for _, u := range []struct{ name, uac, rid string }{
		{"Administrator", adminUAC, "500"}, {"krbtgt", "514", "502"}, {"j.doe", "512", "1104"}, {"svc-backup", svcUAC, "1105"},
	} {
		add(fmt.Sprintf("CN=%s,CN=Users,%s", u.name, base), user, map[string][]string{
			"sAMAccountName": {u.name}, "userAccountControl": {u.uac}, "objectSid": {dom + "-" + u.rid}, "primaryGroupID": {"513"}, "pwdLastSet": {ft(100)}, "sAMAccountType": {"805306368"}})
	}
	for _, g := range []struct{ name, sid string }{{"Domain Admins", dom + "-512"}, {"Domain Controllers", dom + "-516"}, {"Administrators", "S-1-5-32-544"}} {
		dn := fmt.Sprintf("CN=%s,CN=Users,%s", g.name, base)
		if g.name == "Administrators" {
			dn = fmt.Sprintf("CN=%s,CN=Builtin,%s", g.name, base)
		}
		add(dn, []string{"top", "group"}, map[string][]string{"sAMAccountName": {g.name}, "objectSid": {g.sid}, "member": {"CN=Administrator,CN=Users," + base}})
	}
	if hardened {
		// Negative controls for group A: Administrator last used 60 d ago (DSA-0083);
		// a smart-card-only account whose hash rolled 20 d ago (DSA-0085); the
		// forest-root and DC-reach groups present but empty (DSA-0080, DSA-0081).
		for i := range s.Objects {
			if s.Objects[i].DN == "CN=Administrator,CN=Users,"+base {
				s.Objects[i].Attrs["lastLogonTimestamp"] = []string{ft(60)}
			}
		}
		add("CN=sc.user,CN=Users,"+base, user, map[string][]string{
			"sAMAccountName": {"sc.user"}, "userAccountControl": {"262656"}, "objectSid": {dom + "-1106"}, "primaryGroupID": {"513"},
			"pwdLastSet": {ft(20)}, "sAMAccountType": {"805306368"}})
		for _, g := range []struct{ dn, sid string }{{"CN=Schema Admins,CN=Users," + base, dom + "-518"},
			{"CN=Distributed COM Users,CN=Builtin," + base, "S-1-5-32-562"}, {"CN=Performance Log Users,CN=Builtin," + base, "S-1-5-32-559"}} {
			add(g.dn, []string{"top", "group"}, map[string][]string{"objectSid": {g.sid}})
		}
		hardenedGroupA2(s, add, base, dom, ft(5), ft(1))
	}
	add("CN=DC1,OU=Domain Controllers,"+base, append(append([]string{}, user...), "computer"), map[string][]string{
		"sAMAccountName": {"DC1$"}, "objectSid": {dom + "-1000"}, "primaryGroupID": {"516"}, "userAccountControl": {"532480"}, "sAMAccountType": {"805306369"},
		"operatingSystem": {"Samba"}, "dNSHostName": {"dc1.samba.example"}, "pwdLastSet": {ft(20)}})

	// DSA-0301, DSA-0302: Samba provisions AD-integrated zones in the same partitions as Windows.
	// The weak lab accepts nonsecure updates on its domain zone (matching "allow dns updates =
	// nonsecure" below); the hardened lab is secure-only. Zone DACLs are default-like in both.
	add("CN=DnsAdmins,CN=Users,"+base, []string{"top", "group"}, map[string][]string{"sAMAccountName": {"DnsAdmins"}, "objectSid": {dom + "-1101"}})
	update := byte(1)
	if hardened {
		update = 2
	}
	zoneSD := sdOwned(dom+"-512", false, ace{"S-1-5-18", 0x000F01FF, ""}, ace{dom + "-512", 0x000F01FF, ""}, ace{"S-1-5-9", 0x000F01FF, ""},
		ace{dom + "-1101", 0x000F01FF, ""}, ace{"S-1-5-11", 0x00000001, ""}, ace{"S-1-1-0", 0x00020094, ""})
	for _, z := range []struct{ dn, name string }{
		{"DC=samba.example,CN=MicrosoftDNS,DC=DomainDnsZones," + base, "samba.example"},
		{"DC=_msdcs.samba.example,CN=MicrosoftDNS,DC=ForestDnsZones," + base, "_msdcs.samba.example"},
	} {
		u := update
		if z.name != "samba.example" {
			u = 2 // negative DSA-0302: _msdcs stays secure-only in both labs
		}
		add(z.dn, []string{"top", "dnsZone"}, map[string][]string{"name": {z.name},
			"dNSProperty": {dnsProp(0x01, 1, 0, 0, 0), dnsProp(0x02, u)}, "nTSecurityDescriptor": {zoneSD}})
	}

	// Local configuration as the smb.conf collector would record it (testparm
	// values; parametric options as set in the file).
	global := map[string]string{
		"_path": "/etc/samba/smb.conf", "_source": "testparm",
		"server role": "active directory domain controller", "realm": "SAMBA.EXAMPLE", "workgroup": "SAMBA", "netbios name": "DC1",
		"server schannel": "auto", "allow nt4 crypto": "Yes", "reject md5 clients": "No", "server schannel require seal": "No",
		"ldap server require strong auth": "No", "server signing": "auto", "ntlm auth": "ntlmv1-permitted",
		"allow dns updates": "nonsecure", "server min protocol": "NT1", "tls enabled": "No",
		"kdc supported enctypes":                "arcfour-hmac-md5 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96",
		"kdc default domain supported enctypes": "rc4-hmac aes256-cts", "kdc force enable rc4 weak session keys": "Yes",
		"kerberos encryption types": "legacy", "old password allowed period": "1440",
		"dsdb:schema update allowed": "yes", "password hash gpg key ids": "4952E40301FAB41A", "password hash userpassword schemes": "CryptSHA256",
		"map to guest": "Bad User", "log level": "0", "kdc enable fast": "No", "nt hash store": "always",
		"kdc:user ticket lifetime": "24", "kdc:renewal lifetime": "720",
	}
	if hardened {
		global = map[string]string{
			"_path": "/etc/samba/smb.conf", "_source": "testparm",
			"server role": "active directory domain controller", "realm": "SAMBA.EXAMPLE", "workgroup": "SAMBA", "netbios name": "DC1",
			"server schannel": "Yes", "allow nt4 crypto": "No", "reject md5 clients": "Yes", "server schannel require seal": "Yes",
			"ldap server require strong auth": "Yes", "server signing": "default", "ntlm auth": "disabled", "nt hash store": "never",
			"allow dns updates": "secure only", "server min protocol": "SMB2_02", "tls enabled": "Yes",
			"kdc supported enctypes": "aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96", "kdc force enable rc4 weak session keys": "No",
			"kerberos encryption types": "strong", "old password allowed period": "60", "map to guest": "Never",
			"log level": "1 auth_audit:3 auth_json_audit:3 dsdb_audit:5 dsdb_password_audit:5 dsdb_group_audit:5", "kdc enable fast": "Yes",
		}
	}
	g := snapshot.Object{DN: smbconf.GlobalDN, Class: []string{smbconf.ClassGlobal}, Attrs: map[string][]string{"objectClass": {smbconf.ClassGlobal}}}
	for k, v := range global {
		g.Attrs[k] = []string{v}
	}
	g.Attrs["_explicit"] = []string{"server role", "realm", "workgroup", "netbios name", "server schannel", "allow nt4 crypto", "reject md5 clients",
		"server schannel require seal", "ldap server require strong auth", "server signing", "ntlm auth", "allow dns updates", "server min protocol",
		"tls enabled", "kdc supported enctypes", "kdc default domain supported enctypes", "kdc force enable rc4 weak session keys",
		"kerberos encryption types", "old password allowed period", "dsdb:schema update allowed", "password hash gpg key ids",
		"password hash userpassword schemes", "map to guest", "kdc enable fast", "kdc:user ticket lifetime", "kdc:renewal lifetime"}
	s.Objects = append(s.Objects, g)
	share := func(name string, attrs map[string]string) {
		o := snapshot.Object{DN: "cn=" + name + "," + smbconf.SharesBase, Class: []string{smbconf.ClassShare}, Attrs: map[string][]string{"objectClass": {smbconf.ClassShare}, "name": {name}}}
		for k, v := range attrs {
			o.Attrs[k] = []string{v}
		}
		s.Objects = append(s.Objects, o)
	}
	share("sysvol", map[string]string{"path": "/var/lib/samba/sysvol", "read only": "No", "guest ok": "No"})
	share("netlogon", map[string]string{"path": "/var/lib/samba/sysvol/samba.example/scripts", "read only": "No", "guest ok": "No"})
	if !hardened {
		share("public", map[string]string{"path": "/srv/public", "read only": "No", "guest ok": "Yes"})
	}
	add(smbconf.VersionDN, []string{smbconf.ClassSamba}, map[string][]string{"version": {ver}, "smbconf": {"/etc/samba/smb.conf"}, "role": {"active directory domain controller"}})

	if err := snapshot.WriteFile(path, s); err != nil {
		return err
	}
	h, _ := snapshot.Hash(s)
	fmt.Printf("wrote %s (%d objects, sha256 %s)\n", path, len(s.Objects), h[:16])
	return nil
}

// hardenedGroupA2 adds the negative controls for DSA-0076, 0079, 0088 and 0089
// to the hardened lab: Tier-0 objects owned by Tier-0 principals, a schema head
// writable by Schema Admins only, a properly registered DC, and a read-only DC
// whose password replication policy keeps the defaults.
func hardenedGroupA2(s *snapshot.Snapshot, add func(string, []string, map[string][]string), base, dom, pwd, logon string) {
	da := dom + "-512"
	full := ace{"S-1-5-18", 0x000F01FF, ""}
	for i := range s.Objects {
		switch s.Objects[i].DN {
		case base, "CN=Domain Admins,CN=Users," + base, "CN=Administrator,CN=Users," + base, "CN=AdminSDHolder,CN=System," + base:
			s.Objects[i].Attrs["nTSecurityDescriptor"] = []string{sdOwned(da, false, full, ace{da, 0x000F01FF, ""})}
		case "CN=DC1,OU=Domain Controllers," + base:
			s.Objects[i].Attrs["nTSecurityDescriptor"] = []string{sdOwned(da, false, full, ace{da, 0x000F01FF, ""})}
			s.Objects[i].Attrs["servicePrincipalName"] = []string{"GC/dc1.samba.example/samba.example",
				"E3514235-4B06-11D1-AB04-00C04FC2DCD2/3c9e1f0a-6b2d-4f8e-9a17-0d4c5b7e2f93/samba.example"}
		}
	}
	add("CN=Schema,CN=Configuration,"+base, []string{"top", "dMD"}, map[string][]string{"objectVersion": {"88"},
		"nTSecurityDescriptor": {sdOwned(dom+"-518", false, full, ace{dom + "-518", 0x000F01FF, ""}, ace{"S-1-5-9", 0x00000100, "be2bb760-7f46-11d2-b9ad-00c04f79f805"},
			ace{"S-1-5-11", 0x00020094, ""})}})
	sites := "CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration," + base
	for _, n := range []string{"DC1", "RODC1"} {
		add("CN="+n+","+sites, []string{"top", "server"}, map[string][]string{"serverReference": {"CN=" + n + ",OU=Domain Controllers," + base}})
		add("CN=NTDS Settings,CN="+n+","+sites, []string{"top", "applicationSettings", "nTDSDSA"}, map[string][]string{})
	}
	users := ",CN=Users," + base
	add("CN=Read-only Domain Controllers"+users, []string{"top", "group"}, map[string][]string{"objectSid": {dom + "-521"}})
	add("CN=Allowed RODC Password Replication Group"+users, []string{"top", "group"}, map[string][]string{"objectSid": {dom + "-571"}})
	add("CN=Denied RODC Password Replication Group"+users, []string{"top", "group"}, map[string][]string{"objectSid": {dom + "-572"},
		"member": {"CN=krbtgt" + users, "CN=Domain Admins" + users, "CN=Domain Controllers" + users, "CN=Schema Admins" + users,
			"CN=Read-only Domain Controllers" + users}})
	add("CN=RODC1,OU=Domain Controllers,"+base, []string{"top", "person", "organizationalPerson", "user", "computer"}, map[string][]string{
		"sAMAccountName": {"RODC1$"}, "objectSid": {dom + "-1010"}, "primaryGroupID": {"521"}, "userAccountControl": {"67112960"},
		"sAMAccountType": {"805306369"}, "operatingSystem": {"Windows Server 2022 Datacenter"}, "dNSHostName": {"rodc1.samba.example"},
		"pwdLastSet": {pwd}, "lastLogonTimestamp": {logon},
		"msDS-RevealOnDemandGroup": {"CN=Allowed RODC Password Replication Group" + users},
		"msDS-NeverRevealGroup":    {"CN=Denied RODC Password Replication Group" + users, "CN=Administrators,CN=Builtin," + base},
		"msDS-RevealedList":        {"CN=sc.user" + users}})
}
