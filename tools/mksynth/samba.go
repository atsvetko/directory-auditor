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
	dom := "S-1-5-21-4444444444-5555555555-6666666666"
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
		Provider: "ad", Dialect: "samba", Target: "dc1.samba.example", Domain: "samba.example", BaseDN: base,
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
	add("CN=DC1,OU=Domain Controllers,"+base, append(append([]string{}, user...), "computer"), map[string][]string{
		"sAMAccountName": {"DC1$"}, "objectSid": {dom + "-1000"}, "primaryGroupID": {"516"}, "userAccountControl": {"532480"}, "sAMAccountType": {"805306369"},
		"operatingSystem": {"Samba"}, "dNSHostName": {"dc1.samba.example"}, "pwdLastSet": {ft(20)}})

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
