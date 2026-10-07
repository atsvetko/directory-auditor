package freeipa

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/atsvetko/directory-auditor/internal/check"
	"github.com/atsvetko/directory-auditor/internal/ldapx"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

func TestFingerprintAndBase(t *testing.T) {
	ipa := map[string]string{"vendorName": "389 Project", "vendorVersion": "389-Directory/2.4.5",
		"supportedExtension": "1.3.6.1.4.1.4203.1.11.1;2.16.840.1.113730.3.8.10.1;2.16.840.1.113730.3.8.10.3",
		"namingContexts":     "cn=changelog;dc=ipa,dc=example;o=ipaca"}
	if Fingerprint(ipa) != "freeipa" || BaseDN(ipa) != "dc=ipa,dc=example" {
		t.Errorf("fingerprint %q base %q", Fingerprint(ipa), BaseDN(ipa))
	}
	plain := map[string]string{"vendorName": "389 Project", "defaultNamingContext": "dc=corp"}
	if Fingerprint(plain) != "389ds" || BaseDN(plain) != "dc=corp" {
		t.Errorf("plain 389-ds: %q %q", Fingerprint(plain), BaseDN(plain))
	}
	if Fingerprint(map[string]string{"forestFunctionality": "7"}) != "" {
		t.Error("AD rootDSE must not match")
	}
}

func TestBindDN(t *testing.T) {
	base := "dc=ipa,dc=example"
	cases := map[string]string{
		"admin":             "uid=admin,cn=users,cn=accounts,dc=ipa,dc=example",
		"audit@IPA.EXAMPLE": "uid=audit,cn=users,cn=accounts,dc=ipa,dc=example",
		"uid=x,cn=sysaccounts,cn=etc,dc=ipa,dc=example": "uid=x,cn=sysaccounts,cn=etc,dc=ipa,dc=example",
	}
	for in, want := range cases {
		if got := BindDN(in, base); got != want {
			t.Errorf("BindDN(%q) = %q, want %q", in, got, want)
		}
	}
}

type fake struct {
	results map[string][]ldapx.Entry
	errs    map[string]error
	calls   int
}

func (f *fake) search(_ context.Context, base string, _ ldapx.Scope, filter string, _ []string, _ ldapx.SearchOptions) ([]ldapx.Entry, error) {
	f.calls++
	k := base + "|" + filter
	if e := f.errs[k]; e != nil {
		return nil, e
	}
	return f.results[k], nil
}
func (f *fake) n() int { return f.calls }

func TestCollectHonestStates(t *testing.T) {
	base := "dc=ipa,dc=example"
	f := &fake{results: map[string][]ldapx.Entry{
		"cn=ipaConfig,cn=etc," + base + "|(objectClass=ipaGuiConfig)": {{DN: "cn=ipaConfig,cn=etc," + base,
			Attrs: map[string][]string{"objectClass": {"top", "ipaGuiConfig"}, "ipaMigrationEnabled": {"TRUE"}}}},
		"cn=hbac," + base + "|(objectClass=ipaHBACRule)": {{DN: "ipaUniqueID=1,cn=hbac," + base,
			Attrs: map[string][]string{"objectClass": {"ipahbacrule"}, "cn": {"allow_all"}, "ipaEnabledFlag": {"TRUE"}, "accessRuleType": {"allow"}}}},
		// pwpolicies: empty although the container always has global_policy → not readable
	}, errs: map[string]error{
		"cn=dns," + base + "|(objectClass=idnsZone)":                      ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object")),
		"cn=permissions,cn=pbac," + base + "|(objectClass=ipaPermission)": ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("insufficient access")),
	}}
	snap, err := collect(context.Background(), searcher{SearchWith: f.search, Queries: f.n, Requests: f.n},
		snapshot.Meta{Provider: "freeipa", Dialect: "freeipa", BaseDN: base}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]snapshot.Skipped{}
	for _, s := range snap.Skipped {
		reasons[s.Query] = s
	}
	if reasons["pwpolicies"].Reason != "permission" || !strings.Contains(reasons["pwpolicies"].Detail, "Password Policy Readers") {
		t.Errorf("empty default container: %+v", reasons["pwpolicies"])
	}
	if reasons["dnszones"].Reason != "absent" || reasons["permissions"].Reason != "permission" {
		t.Errorf("skips: %+v", snap.Skipped)
	}
	if len(snap.Objects) != 2 || snap.Objects[1].Class[0] != "ipahbacrule" {
		t.Errorf("objects = %+v", snap.Objects)
	}

	// A check on a class that was not collected is reported as skipped, not passed.
	res, err := check.EvaluateWith(snap, []check.Pack{
		{ID: "T-1", Provider: []string{"freeipa"}, Severity: "medium", Query: check.Query{Filter: "(objectClass=krbPwdPolicy)"}, Condition: `intattr(obj, "krbPwdMinLength") < 8`, Signed: true},
		{ID: "T-2", Provider: []string{"freeipa"}, Severity: "medium", Query: check.Query{Filter: "(objectClass=ipaGuiConfig)"}, Condition: `attr(obj, "ipaMigrationEnabled") == "TRUE"`, Signed: true},
	}, check.EvalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Checks[0].Status != "skipped" || res.Checks[0].Skip != "not-collected" {
		t.Errorf("uncollected class: %+v", res.Checks[0])
	}
	if res.Checks[1].Status != "fail" {
		t.Errorf("collected class: %+v", res.Checks[1])
	}
}

func TestPlanFiltersParse(t *testing.T) {
	for _, q := range Plan {
		if _, err := ldap.CompileFilter(q.Filter); err != nil {
			t.Errorf("%s: %v", q.Name, err)
		}
		if q.Purpose == "" || len(q.Classes) == 0 {
			t.Errorf("%s: purpose and classes are required", q.Name)
		}
	}
}
