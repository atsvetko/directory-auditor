package check

import (
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	"github.com/atsvetko/directory-auditor/internal/secdesc"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
	"github.com/atsvetko/directory-auditor/internal/tier0"
)

func tsid(sub ...uint32) []byte {
	b := make([]byte, 8+4*len(sub))
	b[0], b[1], b[7] = 1, byte(len(sub)), 5
	for i, s := range sub {
		binary.LittleEndian.PutUint32(b[8+4*i:], s)
	}
	return b
}

// sdB64 builds a protected self-relative SD with allow ACEs (trustee, mask).
func sdB64(protected bool, aces ...struct {
	sid  []byte
	mask uint32
}) string {
	var acl []byte
	for _, a := range aces {
		body := append(binary.LittleEndian.AppendUint32(nil, a.mask), a.sid...)
		h := []byte{secdesc.AceAllowed, 0, 0, 0}
		binary.LittleEndian.PutUint16(h[2:], uint16(4+len(body)))
		acl = append(acl, append(h, body...)...)
	}
	ah := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(ah[2:], uint16(8+len(acl)))
	binary.LittleEndian.PutUint16(ah[4:], uint16(len(aces)))
	ctl := secdesc.ControlSelfRelative | secdesc.ControlDACLPresent
	if protected {
		ctl |= secdesc.ControlDACLProtected
	}
	h := make([]byte, 20)
	h[0] = 1
	binary.LittleEndian.PutUint16(h[2:], ctl)
	binary.LittleEndian.PutUint32(h[16:], 20)
	return base64.StdEncoding.EncodeToString(append(append(h, ah...), acl...))
}

func filetime(t time.Time) string {
	return strconv.FormatInt(t.UnixNano()/100+116444736000000000, 10)
}

func TestHelpers(t *testing.T) {
	collected := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	dom := "S-1-5-21-1-2-3"
	type ace = struct {
		sid  []byte
		mask uint32
	}
	objs := []snapshot.Object{
		{DN: "CN=Domain Admins,CN=Users,DC=lab", Class: []string{"group"}, Attrs: map[string][]string{
			"objectSid": {dom + "-512"}, "member": {"CN=alice,DC=lab"},
			"nTSecurityDescriptor": {sdB64(true, ace{tsid(18), secdesc.MappedFullControl}, ace{tsid(21, 1, 2, 3, 1105), secdesc.RightWriteDAC})},
		}},
		{DN: "CN=alice,DC=lab", Class: []string{"user"}, Attrs: map[string][]string{
			"objectSid": {dom + "-1300"}, "userAccountControl": {"4194816"},
			"pwdLastSet": {filetime(collected.AddDate(0, 0, -30))}, "whenCreated": {"20251007090000.0Z"},
		}},
		{DN: "CN=bob,DC=lab", Class: []string{"user"}, Attrs: map[string][]string{
			"objectSid": {dom + "-1301"}, "userAccountControl": {"-2147483136"}, "pwdLastSet": {"0"},
		}},
	}
	snap := &snapshot.Snapshot{Collected: collected, Meta: snapshot.Meta{DomainSID: dom}, Objects: objs}
	t0 := tier0.Resolve(objs, dom)
	currentTier0 = t0
	defer func() { currentTier0 = nil }()

	cases := []struct {
		dn, expr string
		want     bool
	}{
		{"CN=alice,DC=lab", `flags(obj, "userAccountControl", 0x400000)`, true},
		{"CN=alice,DC=lab", `flags(obj, "userAccountControl", 0x400002)`, false},
		{"CN=alice,DC=lab", `anyflag(obj, "userAccountControl", 0x400002)`, true},
		{"CN=bob,DC=lab", `flags(obj, "userAccountControl", 0x80000000)`, true}, // negative decimal reinterpreted as uint32
		{"CN=alice,DC=lab", `age_days(obj, "pwdLastSet") == 30`, true},
		{"CN=alice,DC=lab", `age_days(obj, "whenCreated") == 365`, true},
		{"CN=bob,DC=lab", `age_days(obj, "pwdLastSet") == -1`, true}, // 0 = never set
		{"CN=alice,DC=lab", `tier0(obj)`, true},
		{"CN=bob,DC=lab", `tier0(obj)`, false},
		{"CN=alice,DC=lab", `sid_rid(attr(obj, "objectSid")) == 1300 && sid_domain(attr(obj, "objectSid")) == "S-1-5-21-1-2-3"`, true},
		{"CN=Domain Admins,CN=Users,DC=lab", `sd_readable(obj) && sd_protected(obj)`, true},
		{"CN=alice,DC=lab", `sd_readable(obj)`, false},
		{"CN=Domain Admins,CN=Users,DC=lab", `size(aces(obj)) == 2`, true},
		{"CN=Domain Admins,CN=Users,DC=lab", `aces(obj).exists(a, a.allow && a.effective && !a.trustee_tier0 && mask_has(a.mask, 0x40000) && a.trustee == "S-1-5-21-1-2-3-1105")`, true},
		{"CN=Domain Admins,CN=Users,DC=lab", `aces(obj).exists(a, a.trustee == "S-1-5-18" && a.trustee_tier0)`, true},
		{"CN=alice,DC=lab", `size(aces(obj)) == 0 && tier0_sid("S-1-5-32-544") && !tier0_sid("S-1-5-21-1-2-3-1301")`, true},
	}
	for _, c := range cases {
		prog, err := CompileCondition(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		var o snapshot.Object
		for _, x := range objs {
			if x.DN == c.dn {
				o = x
			}
		}
		out, _, err := prog.Eval(map[string]any{"obj": objectToCEL(o, snap.Collected.Unix(), t0)})
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if out.Value() != c.want {
			t.Errorf("%s on %s = %v, want %v", c.expr, c.dn, out.Value(), c.want)
		}
	}
}

func TestQuickSkips(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "test-0001.yaml", testPack)
	packs, err := LoadDir(dir, LoadOptions{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	packs[0].Quick = false
	res, err := EvaluateWith(synthetic(), packs, EvalOptions{Quick: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Checks[0].Skip != "quick" || res.Counts.BySkip["quick"] != 1 {
		t.Fatalf("quick scan ran a non-quick pack: %+v", res.Checks[0])
	}
}

func TestTimeOf(t *testing.T) {
	if _, ok := timeOf("9223372036854775807"); ok {
		t.Error("accountExpires 'never' parsed as a time")
	}
	if tm, ok := timeOf("116444736000000000"); !ok || !tm.Equal(time.Unix(0, 0)) {
		t.Errorf("FILETIME epoch = %v %v", tm, ok)
	}
}
