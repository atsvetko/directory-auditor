package main

import (
	"fmt"
	"time"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// writeFreeIPA builds the synthetic FreeIPA lab used by catalogue/freeipa
// entries' `expect` lists. Every name is invented. Values follow the FreeIPA
// schema (install/share/*.ldif) and defaults (bootstrap-template.ldif,
// kerberos.ldif, default-hbac.ldif) in the FreeIPA source tree.
func writeFreeIPA(path string) error {
	base := "dc=ipa,dc=example"
	realm := "IPA.EXAMPLE"
	collected := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	s := &snapshot.Snapshot{Schema: snapshot.SchemaVersion, Collected: collected, Meta: snapshot.Meta{
		Provider: "freeipa", Dialect: "freeipa", Target: "ipa.ipa.example", Domain: "ipa.example", BaseDN: base,
		Identity: "uid=audit,cn=users,cn=accounts," + base, Tier: 2, Tool: "mksynth", QueryCount: 17,
		RootDSE: map[string]string{"vendorName": "389 Project", "supportedExtension": "2.16.840.1.113730.3.8.10.1;2.16.840.1.113730.3.8.10.3"},
	}}
	add := func(dn string, class []string, attrs map[string][]string) {
		s.Objects = append(s.Objects, snapshot.Object{DN: dn, Class: class, Attrs: attrs})
	}
	acc := ",cn=accounts," + base
	userDN := func(u string) string { return "uid=" + u + ",cn=users" + acc }
	groupDN := func(g string) string { return "cn=" + g + ",cn=groups" + acc }

	add("cn=ipaConfig,cn=etc,"+base, []string{"top", "nsContainer", "ipaGuiConfig", "ipaConfigObject"}, map[string][]string{
		"cn": {"ipaConfig"}, "ipaMigrationEnabled": {"TRUE"},
		"ipaConfigString": {"AllowNThash", "KDC:Disable Last Success", "KDC:Disable Lockout", "KDC:Disable Default Preauth for SPNs"},
	})
	add("cn="+realm+",cn=kerberos,"+base, []string{"top", "krbrealmcontainer", "krbticketpolicyaux"}, map[string][]string{
		"cn": {realm}, "krbMaxTicketLife": {"86400"}, "krbMaxRenewableAge": {"2592000"},
		"krbSupportedEncSaltTypes": {"aes256-sha2:special", "aes128-sha2:special", "aes256-cts:special", "aes128-cts:special", "arcfour-hmac:special"},
		"krbDefaultEncSaltTypes":   {"aes256-sha2:special", "aes128-sha2:special", "aes256-cts:special", "aes128-cts:special"},
	})
	add("cn=global_policy,cn="+realm+",cn=kerberos,"+base, []string{"top", "nsContainer", "krbPwdPolicy", "ipaPwdPolicy"}, map[string][]string{
		"cn": {"global_policy"}, "krbMinPwdLife": {"3600"}, "krbPwdMinDiffChars": {"0"}, "krbPwdMinLength": {"6"}, "krbPwdHistoryLength": {"0"},
		"krbMaxPwdLife": {"7776000"}, "krbPwdMaxFailure": {"0"}, "krbPwdFailureCountInterval": {"60"}, "krbPwdLockoutDuration": {"600"}, "passwordGraceLimit": {"-1"},
	})
	add("cn=contractors,cn="+realm+",cn=kerberos,"+base, []string{"top", "nsContainer", "krbPwdPolicy", "ipaPwdPolicy"}, map[string][]string{
		"cn": {"contractors"}, "krbPwdMinLength": {"12"}, "krbPwdMaxFailure": {"6"}, "krbPwdHistoryLength": {"5"}, "krbMaxPwdLife": {"7776000"},
	})
	hbac := func(cn string, enabled bool, attrs map[string][]string) {
		attrs["cn"] = []string{cn}
		attrs["accessRuleType"] = []string{"allow"}
		attrs["ipaEnabledFlag"] = []string{map[bool]string{true: "TRUE", false: "FALSE"}[enabled]}
		add("ipaUniqueID="+cn+",cn=hbac,"+base, []string{"ipaassociation", "ipahbacrule"}, attrs)
	}
	hbac("allow_all", true, map[string][]string{"userCategory": {"all"}, "hostCategory": {"all"}, "serviceCategory": {"all"}})
	hbac("allow_systemd-user", true, map[string][]string{"userCategory": {"all"}, "hostCategory": {"all"}, "memberService": {"cn=systemd-user,cn=hbacservices,cn=hbac," + base}})
	hbac("devs_everywhere", true, map[string][]string{"userCategory": {"all"}, "hostCategory": {"all"}, "serviceCategory": {"all"}, "description": {"temporary"}})
	hbac("old_all", false, map[string][]string{"userCategory": {"all"}, "hostCategory": {"all"}, "serviceCategory": {"all"}})
	hbac("ops_sshd", true, map[string][]string{"memberUser": {groupDN("ops")}, "hostCategory": {"all"}, "memberService": {"cn=sshd,cn=hbacservices,cn=hbac," + base}})

	sudo := func(cn string, enabled bool, attrs map[string][]string) {
		attrs["cn"] = []string{cn}
		attrs["ipaEnabledFlag"] = []string{map[bool]string{true: "TRUE", false: "FALSE"}[enabled]}
		add("ipaUniqueID="+cn+",cn=sudorules,cn=sudo,"+base, []string{"ipaassociation", "ipasudorule"}, attrs)
	}
	sudo("root_everything", true, map[string][]string{"userCategory": {"all"}, "hostCategory": {"all"}, "cmdCategory": {"all"}, "ipaSudoRunAsUserCategory": {"all"}})
	sudo("ops_nopasswd", true, map[string][]string{"memberUser": {groupDN("ops")}, "memberHost": {"cn=web,cn=hostgroups" + acc}, "cmdCategory": {"all"}, "ipaSudoOpt": {"!authenticate"}})
	sudo("disabled_all", false, map[string][]string{"userCategory": {"all"}, "hostCategory": {"all"}, "cmdCategory": {"all"}})
	sudo("dba_restart", true, map[string][]string{"memberUser": {groupDN("dba")}, "memberHost": {"cn=db,cn=hostgroups" + acc}, "memberAllowCmd": {"ipaUniqueID=cmd1,cn=sudocmds,cn=sudo," + base}})

	userClass := []string{"top", "person", "organizationalperson", "inetorgperson", "inetuser", "posixaccount", "krbprincipalaux", "krbticketpolicyaux", "ipaobject", "ipasshuser"}
	user := func(uid string, attrs map[string][]string) {
		attrs["uid"] = []string{uid}
		attrs["krbPrincipalName"] = []string{uid + "@" + realm}
		add(userDN(uid), userClass, attrs)
	}
	user("admin", map[string][]string{"memberOf": {groupDN("admins"), groupDN("trust admins")}, "krbLastPwdChange": {"20240110120000Z"}, "krbPasswordExpiration": {"20380101000000Z"}})
	user("alice", map[string][]string{"memberOf": {groupDN("admins")}, "ipaUserAuthType": {"otp"}, "krbLastPwdChange": {"20260801120000Z"}})
	user("carol", map[string][]string{"memberOf": {groupDN("admins"), groupDN("ipausers")}, "ipaUserAuthType": {"password"}, "krbLastPwdChange": {"20260901120000Z"}})
	user("bob", map[string][]string{"memberOf": {groupDN("ipausers"), groupDN("ops")}, "krbLastPwdChange": {"20260901120000Z"}})
	user("svc-legacy", map[string][]string{"memberOf": {groupDN("ipausers")}, "krbTicketFlags": {"0"}, "krbLastPwdChange": {"20200101120000Z"}})
	user("audit", map[string][]string{"memberOf": {groupDN("ipausers")}, "krbLastPwdChange": {"20260901120000Z"}})

	group := func(cn string, members ...string) {
		add(groupDN(cn), []string{"top", "groupofnames", "nestedgroup", "ipausergroup", "ipaobject", "posixgroup"}, map[string][]string{"cn": {cn}, "member": members})
	}
	group("admins", userDN("admin"), userDN("alice"), userDN("carol"))
	group("trust admins", userDN("admin"))
	group("ipausers", userDN("carol"), userDN("bob"), userDN("svc-legacy"), userDN("audit"))
	group("ops", userDN("bob"))
	group("dba")

	hostClass := []string{"top", "ipaobject", "nshost", "ipahost", "pkiuser", "ipaservice", "krbprincipalaux", "krbprincipal", "ipasshhost", "ieee802device", "ipaSshGroupOfPubKeys"}
	host := func(fqdn string, flags string) {
		attrs := map[string][]string{"fqdn": {fqdn}, "krbPrincipalName": {"host/" + fqdn + "@" + realm}}
		if flags != "" {
			attrs["krbTicketFlags"] = []string{flags}
		}
		add("fqdn="+fqdn+",cn=computers"+acc, hostClass, attrs)
	}
	host("ipa.ipa.example", "128")
	host("web01.ipa.example", "")
	host("nfs01.ipa.example", "1048704") // REQUIRES_PRE_AUTH | OK_AS_DELEGATE

	svcClass := []string{"top", "ipaobject", "ipaservice", "pkiuser", "ipakrbprincipal", "krbprincipal", "krbprincipalaux"}
	svc := func(princ string, flags string, extra map[string][]string) {
		attrs := map[string][]string{"krbPrincipalName": {princ + "@" + realm}, "krbCanonicalName": {princ + "@" + realm}}
		if flags != "" {
			attrs["krbTicketFlags"] = []string{flags}
		}
		for k, v := range extra {
			attrs[k] = v
		}
		add("krbprincipalname="+princ+"@"+realm+",cn=services"+acc, svcClass, attrs)
	}
	svc("HTTP/ipa.ipa.example", "128", nil)
	svc("ldap/ipa.ipa.example", "128", nil)
	svc("HTTP/web01.ipa.example", "2097280", nil) // REQUIRES_PRE_AUTH | OK_TO_AUTH_AS_DELEGATE
	svc("nfs/nfs01.ipa.example", "1048704", nil)
	svc("cifs/legacy.ipa.example", "0", nil) // pre-authentication not required

	deleg := func(cn string, members []string, targets []string) {
		class := []string{"top", "groupOfPrincipals"}
		attrs := map[string][]string{"cn": {cn}, "memberPrincipal": members}
		if targets != nil {
			class = []string{"top", "groupOfPrincipals", "ipaKrb5DelegationACL"}
			attrs["ipaAllowedTarget"] = targets
		}
		add("cn="+cn+",cn=s4u2proxy,cn=etc,"+base, class, attrs)
	}
	deleg("ipa-ldap-delegation-targets", []string{"ldap/ipa.ipa.example@" + realm}, nil)
	deleg("ipa-cifs-delegation-targets", []string{"cifs/ipa.ipa.example@" + realm}, nil)
	deleg("app-targets", []string{"HTTP/api01.ipa.example@" + realm}, nil)
	deleg("ipa-http-delegation", []string{"HTTP/ipa.ipa.example@" + realm},
		[]string{"cn=ipa-ldap-delegation-targets,cn=s4u2proxy,cn=etc," + base, "cn=ipa-cifs-delegation-targets,cn=s4u2proxy,cn=etc," + base})
	deleg("portal-to-ldap", []string{"HTTP/web01.ipa.example@" + realm}, []string{"cn=ipa-ldap-delegation-targets,cn=s4u2proxy,cn=etc," + base})
	deleg("portal-to-api", []string{"HTTP/web01.ipa.example@" + realm}, []string{"cn=app-targets,cn=s4u2proxy,cn=etc," + base})
	add("cn=ipa.ipa.example,cn=masters,cn=ipa,cn=etc,"+base, []string{"top", "nsContainer", "ipaConfigObject"}, map[string][]string{"cn": {"ipa.ipa.example"}})

	caacl := func(cn string, attrs map[string][]string) {
		attrs["cn"] = []string{cn}
		attrs["ipaEnabledFlag"] = []string{"TRUE"}
		add("ipaUniqueID="+cn+",cn=caacls,cn=ca,"+base, []string{"ipaassociation", "ipacaacl"}, attrs)
	}
	caacl("hosts_services_caIPAserviceCert", map[string][]string{"hostCategory": {"all"}, "serviceCategory": {"all"}, "ipaMemberCertProfile": {"cn=caIPAserviceCert,cn=certprofiles,cn=ca," + base}})
	caacl("everyone_any_profile", map[string][]string{"userCategory": {"all"}, "ipaCertProfileCategory": {"all"}, "ipaCaCategory": {"all"}})
	caacl("devs_webcert", map[string][]string{"memberUser": {groupDN("ops")}, "ipaMemberCertProfile": {"cn=webServerCert,cn=certprofiles,cn=ca," + base}})

	wellKnown := []string{"S-1-0", "S-1-1", "S-1-2", "S-1-3", "S-1-5-1", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-5", "S-1-5-6", "S-1-5-7", "S-1-5-8", "S-1-5-9", "S-1-5-10",
		"S-1-5-11", "S-1-5-12", "S-1-5-13", "S-1-5-14", "S-1-5-15", "S-1-5-16", "S-1-5-17", "S-1-5-18", "S-1-5-19", "S-1-5-20"}
	trimmed := append([]string{}, wellKnown[:17]...) // S-1-5-11 … S-1-5-20 removed
	trust := func(cn, sid string, in []string) {
		add("cn="+cn+",cn=ad,cn=trusts,"+base, []string{"top", "ipaNTTrustedDomain", "ipaIDobject"}, map[string][]string{
			"cn": {cn}, "ipaNTTrustPartner": {cn}, "ipaNTFlatName": {cn[:4]}, "ipaNTTrustDirection": {"3"}, "ipaNTTrustedDomainSID": {sid},
			"ipaNTSIDBlacklistIncoming": in, "ipaNTSIDBlacklistOutgoing": wellKnown})
	}
	trust("corp.example", "S-1-5-21-11-22-33", wellKnown)
	trust("partner.example", "S-1-5-21-44-55-66", trimmed)

	zone := func(name string, attrs map[string][]string) {
		attrs["idnsName"] = []string{name}
		attrs["idnsZoneActive"] = []string{"TRUE"}
		add("idnsname="+name+",cn=dns,"+base, []string{"top", "idnsrecord", "idnszone"}, attrs)
	}
	zone("ipa.example.", map[string][]string{"idnsAllowDynUpdate": {"TRUE"}, "idnsUpdatePolicy": {"grant IPA.EXAMPLE krb5-self * A; grant IPA.EXAMPLE krb5-self * AAAA; grant IPA.EXAMPLE krb5-self * SSHFP;"}})
	zone("lab.example.", map[string][]string{"idnsAllowDynUpdate": {"TRUE"}, "idnsUpdatePolicy": {"grant * wildcard * ANY;"}})
	zone("old.example.", map[string][]string{"idnsAllowDynUpdate": {"FALSE"}, "idnsAllowTransfer": {"any;"}})
	zone("10.in-addr.arpa.", map[string][]string{"idnsAllowDynUpdate": {"TRUE"}, "idnsUpdatePolicy": {"grant IPA.EXAMPLE krb5-subdomain 10.in-addr.arpa. PTR;"}})

	perm := func(cn string, attrs map[string][]string) {
		attrs["cn"] = []string{cn}
		add("cn="+cn+",cn=permissions,cn=pbac,"+base, []string{"top", "groupofnames", "ipapermission", "ipapermissionv2"}, attrs)
	}
	perm("System: Read User Standard Attributes", map[string][]string{"ipaPermBindRuleType": {"anonymous"}, "ipaPermRight": {"read", "search", "compare"}, "ipaPermissionType": {"SYSTEM", "V2", "MANAGED"}})
	perm("System: Read HBAC Rules", map[string][]string{"ipaPermBindRuleType": {"all"}, "ipaPermRight": {"read", "search", "compare"}, "ipaPermissionType": {"SYSTEM", "V2", "MANAGED"}})
	perm("Helpdesk reset passwords", map[string][]string{"ipaPermBindRuleType": {"all"}, "ipaPermRight": {"write"}, "ipaPermDefaultAttr": {"userPassword", "krbPasswordExpiration"}, "ipaPermLocation": {"cn=users,cn=accounts," + base}, "ipaPermissionType": {"V2"}})
	perm("Add hosts anonymously", map[string][]string{"ipaPermBindRuleType": {"anonymous"}, "ipaPermRight": {"add"}, "ipaPermLocation": {"cn=computers,cn=accounts," + base}, "ipaPermissionType": {"V2"}})
	perm("Modify Users and Reset passwords", map[string][]string{"ipaPermBindRuleType": {"permission"}, "ipaPermRight": {"write"}, "member": {"cn=User Administrators,cn=privileges,cn=pbac," + base}, "ipaPermissionType": {"SYSTEM", "V2", "MANAGED"}})

	role := func(cn string, members ...string) {
		add("cn="+cn+",cn=roles"+acc, []string{"top", "groupofnames", "nestedgroup"}, map[string][]string{"cn": {cn}, "member": members})
	}
	role("User Administrator", groupDN("ops"))
	role("helpdesk", groupDN("ipausers"))
	role("IT Security Specialist")
	priv := func(cn string, members ...string) {
		add("cn="+cn+",cn=privileges,cn=pbac,"+base, []string{"top", "groupofnames", "nestedgroup"}, map[string][]string{"cn": {cn}, "member": members})
	}
	priv("User Administrators", "cn=User Administrator,cn=roles"+acc)
	priv("Password Policy Readers", groupDN("ipausers"))

	add("cn=anonymous-ldap-probe,cn=dirauditor", []string{"dirauditorProbe"}, map[string][]string{"probe": {"anonymous-user-enumeration"}, "result": {"allowed"}, "sample": {"admin", "alice", "carol"}})

	if err := snapshot.WriteFile(path, s); err != nil {
		return err
	}
	h, _ := snapshot.Hash(s)
	fmt.Printf("wrote %s (%d objects, sha256 %s)\n", path, len(s.Objects), h[:16])
	return nil
}
