package ad

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/atsvetko/directory-auditor/internal/ldapx"
	"github.com/atsvetko/directory-auditor/internal/secdesc"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

type snapshotMeta = snapshot.Meta

const base = "DC=lab,DC=example"

func sid(sub ...uint32) []byte {
	b := make([]byte, 8+4*len(sub))
	b[0], b[1], b[7] = 1, byte(len(sub)), 5
	for i, s := range sub {
		binary.LittleEndian.PutUint32(b[8+4*i:], s)
	}
	return b
}

// minimal self-relative SD: owner only, empty DACL
func sd(owner []byte) []byte {
	h := make([]byte, 20)
	h[0] = 1
	binary.LittleEndian.PutUint16(h[2:], secdesc.ControlSelfRelative|secdesc.ControlDACLPresent)
	binary.LittleEndian.PutUint32(h[4:], 20)
	binary.LittleEndian.PutUint32(h[16:], uint32(20+len(owner)))
	acl := []byte{2, 0, 8, 0, 0, 0, 0, 0}
	return append(append(h, owner...), acl...)
}

type call struct {
	base, filter string
	sdflags      uint32
}

type fake struct {
	results map[string][]ldapx.Entry // key: base|filter
	errs    map[string]error
	calls   []call
}

func (f *fake) RootDSE(context.Context) (map[string]string, error) {
	return map[string]string{"defaultNamingContext": base, "forestFunctionality": "7"}, nil
}
func (f *fake) SearchWith(_ context.Context, b string, _ ldapx.Scope, filter string, attrs []string, o ldapx.SearchOptions) ([]ldapx.Entry, error) {
	f.calls = append(f.calls, call{b, filter, o.SDFlags})
	k := b + "|" + filter
	if err := f.errs[k]; err != nil {
		return nil, err
	}
	return f.results[k], nil
}
func (f *fake) Queries() int  { return len(f.calls) }
func (f *fake) Requests() int { return len(f.calls) }

func entry(dn string, attrs map[string][]string, bin map[string][][]byte) ldapx.Entry {
	return ldapx.Entry{DN: dn, Attrs: attrs, Bin: bin}
}

func TestCollect(t *testing.T) {
	dom := []uint32{21, 1, 2, 3}
	daDN := "CN=Domain Admins,CN=Users," + base
	opsDN := "CN=ops,OU=Staff," + base
	f := &fake{results: map[string][]ldapx.Entry{
		base + "|(objectClass=domainDNS)": {entry(base, map[string][]string{"objectClass": {"top", "domainDNS"}, "ms-DS-MachineAccountQuota": {"10"}},
			map[string][][]byte{"objectSid": {sid(dom...)}, "nTSecurityDescriptor": {sd(sid(5, 18))}})},
		base + "|(sAMAccountType=805306368)": {entry(opsDN, map[string][]string{"objectClass": {"top", "user"}, "sAMAccountName": {"ops"}},
			map[string][][]byte{"objectSid": {sid(append(dom, 1105)...)}, "sIDHistory": {sid(append(dom, 512)...)},
				"objectGUID": {{0xc0, 0x79, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}}})},
		base + "|(objectClass=group)": {entry(daDN, map[string][]string{"objectClass": {"top", "group"}, "sAMAccountName": {"Domain Admins"}, "member": {opsDN}},
			map[string][][]byte{"objectSid": {sid(append(dom, 512)...)}})},
		base + "|(adminCount=1)": {entry(daDN, map[string][]string{"objectClass": {"top", "group"}},
			map[string][][]byte{"nTSecurityDescriptor": {sd(sid(append(dom, 512)...))}})},
		opsDN + "|(objectClass=*)": {entry(opsDN, nil, nil)}, // descriptor not readable
	}, errs: map[string]error{
		"CN=System," + base + "|(objectClass=trustedDomain)": ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("insufficient access")),
	}}
	snap, err := collect(context.Background(), f, metaForTest(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Meta.DomainSID != "S-1-5-21-1-2-3" || snap.Meta.Dialect != "ad" {
		t.Errorf("meta = %+v", snap.Meta)
	}
	get := func(dn string) map[string][]string {
		for _, o := range snap.Objects {
			if strings.EqualFold(o.DN, dn) {
				return o.Attrs
			}
		}
		t.Fatalf("%s not collected", dn)
		return nil
	}
	ops := get(opsDN)
	if ops["objectSid"][0] != "S-1-5-21-1-2-3-1105" || ops["sIDHistory"][0] != "S-1-5-21-1-2-3-512" ||
		ops["objectGUID"][0] != "bf9679c0-0de6-11d0-a285-00aa003049e2" {
		t.Errorf("ops attrs = %v", ops)
	}
	da := get(daDN)
	if da["member"][0] != opsDN || len(da["nTSecurityDescriptor"]) != 1 {
		t.Errorf("Domain Admins not merged: %v", da)
	}
	raw, _ := base64.StdEncoding.DecodeString(da["nTSecurityDescriptor"][0])
	if d, err := secdesc.Parse(raw); err != nil || d.Owner != "S-1-5-21-1-2-3-512" {
		t.Errorf("descriptor round-trip: %v %v", d, err)
	}

	// Every SD read asks for the DACL only; the follow-up pass reached the Tier-0 member.
	var followUp bool
	for _, c := range f.calls {
		if c.base == opsDN {
			followUp = true
		}
		if strings.Contains(c.filter, "adminCount") || c.base == opsDN || c.filter == "(objectClass=domainDNS)" {
			if c.sdflags != ldapx.SDFlagsDACL {
				t.Errorf("SD query %v without DACL-only flags", c)
			}
		}
	}
	if !followUp {
		t.Error("Tier-0 member without adminCount was not read for its descriptor")
	}
	reasons := map[string]string{}
	for _, s := range snap.Skipped {
		reasons[s.Query] = s.Reason
	}
	if reasons["trusts"] != "permission" || reasons["descriptors"] != "permission" {
		t.Errorf("skipped = %+v", snap.Skipped)
	}
}

func TestPlanFiltersParse(t *testing.T) {
	for _, q := range append(Plan, SDBaseQuery) {
		if _, err := ldap.CompileFilter(q.Filter); err != nil {
			t.Errorf("%s: %v", q.Name, err)
		}
		if q.Purpose == "" {
			t.Errorf("%s: no purpose — every query must name what it serves", q.Name)
		}
	}
}

func metaForTest() snapshotMeta { return snapshotMeta{Provider: "ad", Target: "dc01"} }
