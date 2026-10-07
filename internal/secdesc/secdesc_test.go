package secdesc

import (
	"encoding/binary"
	"testing"
)

// sidBytes encodes a SID for test fixtures only (the package itself has no encoder).
func sidBytes(auth uint64, sub ...uint32) []byte {
	b := make([]byte, 8+4*len(sub))
	b[0] = 1
	b[1] = byte(len(sub))
	for i := 0; i < 6; i++ {
		b[7-i] = byte(auth >> (8 * i))
	}
	for i, s := range sub {
		binary.LittleEndian.PutUint32(b[8+4*i:], s)
	}
	return b
}

func TestParseSID(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
		rid  uint32
		dom  string
	}{
		{sidBytes(5, 32, 544), "S-1-5-32-544", 544, "S-1-5-32"},
		{sidBytes(5, 18), "S-1-5-18", 18, "S-1-5-18"},
		{sidBytes(5, 21, 1004336348, 1177238915, 682003330, 512), "S-1-5-21-1004336348-1177238915-682003330-512", 512, "S-1-5-21-1004336348-1177238915-682003330"},
	}
	for _, c := range cases {
		s, n, err := ParseSID(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.want, err)
		}
		if n != len(c.in) || s.String() != c.want || s.RID() != c.rid || s.Domain() != c.dom {
			t.Errorf("got %s n=%d rid=%d dom=%s; want %s rid=%d dom=%s", s, n, s.RID(), s.Domain(), c.want, c.rid, c.dom)
		}
	}
	for _, bad := range [][]byte{nil, {1, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0}, {1, 16, 0, 0, 0, 0, 0, 5}} {
		if _, _, err := ParseSID(bad); err == nil {
			t.Errorf("ParseSID(%v) accepted malformed input", bad)
		}
	}
}

func TestGUIDString(t *testing.T) {
	// member attribute schemaIDGUID bf9679c0-0de6-11d0-a285-00aa003049e2 as stored on the wire.
	b := []byte{0xc0, 0x79, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	if got := GUIDString(b); got != "bf9679c0-0de6-11d0-a285-00aa003049e2" {
		t.Fatalf("GUIDString = %s", got)
	}
	if GUIDString(b[:15]) != "" {
		t.Fatal("short GUID must render empty")
	}
}

// guidBytes is the inverse of GUIDString for fixtures.
func guidBytes(d1 uint32, d2, d3 uint16, rest [8]byte) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], d1)
	binary.LittleEndian.PutUint16(b[4:], d2)
	binary.LittleEndian.PutUint16(b[6:], d3)
	copy(b[8:], rest[:])
	return b
}

func ace(typ, flags byte, body []byte) []byte {
	h := []byte{typ, flags, 0, 0}
	binary.LittleEndian.PutUint16(h[2:], uint16(4+len(body)))
	return append(h, body...)
}

func u32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func buildSD(control uint16, owner, group []byte, aces ...[]byte) []byte {
	acl := cat(aces...)
	aclHdr := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(aclHdr[2:], uint16(8+len(acl)))
	binary.LittleEndian.PutUint16(aclHdr[4:], uint16(len(aces)))
	hdr := make([]byte, 20)
	hdr[0] = 1
	binary.LittleEndian.PutUint16(hdr[2:], control)
	off := uint32(20)
	binary.LittleEndian.PutUint32(hdr[4:], off)
	off += uint32(len(owner))
	binary.LittleEndian.PutUint32(hdr[8:], off)
	off += uint32(len(group))
	binary.LittleEndian.PutUint32(hdr[16:], off)
	return cat(hdr, owner, group, aclHdr, acl)
}

func TestParseDescriptor(t *testing.T) {
	domain := []uint32{21, 1, 2, 3}
	da := sidBytes(5, append(domain, 512)...)
	helpdesk := sidBytes(5, append(domain, 1105)...)
	member := guidBytes(0xbf9679c0, 0x0de6, 0x11d0, [8]byte{0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2})
	userClass := guidBytes(0xbf967aba, 0x0de6, 0x11d0, [8]byte{0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2})

	sd := buildSD(ControlSelfRelative|ControlDACLPresent|ControlDACLProtected, da, da,
		ace(AceAllowed, 0, cat(u32(MappedFullControl), sidBytes(5, 18))),
		ace(AceAllowedObject, FlagInherited, cat(u32(RightWriteProp), u32(objectTypePresent|inheritedObjectTypePresent), member, userClass, helpdesk)),
		ace(AceDenied, FlagInheritOnly, cat(u32(RightDelete), sidBytes(1, 0))),
		ace(0x11, 0, cat(u32(0), sidBytes(16, 4096))), // mandatory label: not interpreted
	)
	d, err := Parse(sd)
	if err != nil {
		t.Fatal(err)
	}
	if d.Owner != "S-1-5-21-1-2-3-512" || d.Group != d.Owner {
		t.Errorf("owner/group = %s/%s", d.Owner, d.Group)
	}
	if !d.Protected() {
		t.Error("Protected() = false")
	}
	if len(d.DACL) != 3 || d.Unknown != 1 {
		t.Fatalf("DACL len %d unknown %d", len(d.DACL), d.Unknown)
	}
	a0, a1, a2 := d.DACL[0], d.DACL[1], d.DACL[2]
	if a0.Trustee != "S-1-5-18" || !a0.Allow() || !a0.Has(RightWriteDAC|RightWriteOwner) || a0.ObjectType != "" {
		t.Errorf("ace0 = %+v", a0)
	}
	if a1.Trustee != "S-1-5-21-1-2-3-1105" || a1.ObjectType != "bf9679c0-0de6-11d0-a285-00aa003049e2" ||
		a1.InheritedObjectType != "bf967aba-0de6-11d0-a285-00aa003049e2" || !a1.Inherited() || !a1.Effective() || a1.Has(RightWriteDAC) {
		t.Errorf("ace1 = %+v", a1)
	}
	if a2.Allow() || a2.Effective() || a2.Trustee != "S-1-1-0" {
		t.Errorf("ace2 = %+v", a2)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	good := buildSD(ControlSelfRelative|ControlDACLPresent, sidBytes(5, 18), nil,
		ace(AceAllowed, 0, cat(u32(1), sidBytes(5, 18))))
	if _, err := Parse(good); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	notSelfRel := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(notSelfRel[2:], ControlDACLPresent)
	for name, b := range map[string][]byte{
		"short":     good[:10],
		"revision":  append([]byte{2}, good[1:]...),
		"absolute":  notSelfRel,
		"truncated": good[:len(good)-3],
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzParse checks the parser never panics on arbitrary input (directory data is untrusted).
func FuzzParse(f *testing.F) {
	f.Add(buildSD(ControlSelfRelative|ControlDACLPresent, sidBytes(5, 18), nil,
		ace(AceAllowedObject, 0, cat(u32(1), u32(3), make([]byte, 32), sidBytes(5, 18)))))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Parse(b)
		_, _, _ = ParseSID(b)
	})
}
