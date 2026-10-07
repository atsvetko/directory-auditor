// Package secdesc parses self-relative Windows security descriptors and SIDs as
// stored in Active Directory (nTSecurityDescriptor, objectSid, sIDHistory,
// msDS-AllowedToActOnBehalfOfOtherIdentity). Read-only: there is no encoder.
//
// Layouts follow MS-DTYP: SECURITY_DESCRIPTOR 2.4.6, ACL 2.4.5, ACE_HEADER
// 2.4.4.1, ACCESS_ALLOWED_ACE 2.4.4.2, ACCESS_ALLOWED_OBJECT_ACE 2.4.4.3, SID 2.4.2.
// Access-mask values follow ADS_RIGHTS_ENUM.
package secdesc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Access-mask bits (ADS_RIGHTS_ENUM).
const (
	RightCreateChild    uint32 = 0x1
	RightDeleteChild    uint32 = 0x2
	RightList           uint32 = 0x4
	RightSelf           uint32 = 0x8
	RightReadProp       uint32 = 0x10
	RightWriteProp      uint32 = 0x20
	RightDeleteTree     uint32 = 0x40
	RightListObject     uint32 = 0x80
	RightControlAccess  uint32 = 0x100
	RightDelete         uint32 = 0x10000
	RightReadControl    uint32 = 0x20000
	RightWriteDAC       uint32 = 0x40000
	RightWriteOwner     uint32 = 0x80000
	RightGenericAll     uint32 = 0x10000000
	RightGenericExecute uint32 = 0x20000000
	RightGenericWrite   uint32 = 0x40000000
	RightGenericRead    uint32 = 0x80000000

	// What GenericAll looks like after the directory maps generic rights onto the
	// object-specific rights (all DS rights + standard rights).
	MappedFullControl = RightCreateChild | RightDeleteChild | RightList | RightSelf | RightReadProp |
		RightWriteProp | RightDeleteTree | RightListObject | RightControlAccess |
		RightDelete | RightReadControl | RightWriteDAC | RightWriteOwner
)

// ACE types (ACE_HEADER.AceType) and flags (ACE_HEADER.AceFlags).
const (
	AceAllowed       = 0x00
	AceDenied        = 0x01
	AceAllowedObject = 0x05
	AceDeniedObject  = 0x06

	FlagInheritOnly = 0x08
	FlagInherited   = 0x10

	objectTypePresent          = 0x1
	inheritedObjectTypePresent = 0x2
)

// Security-descriptor control flags.
const (
	ControlDACLPresent   uint16 = 0x0004
	ControlDACLProtected uint16 = 0x1000
	ControlSelfRelative  uint16 = 0x8000
)

// SID is a parsed security identifier.
type SID struct {
	Revision  byte
	Authority uint64
	Sub       []uint32
}

// String renders S-1-<authority>-<sub>-…
func (s SID) String() string {
	var b strings.Builder
	b.WriteString("S-")
	b.WriteString(strconv.Itoa(int(s.Revision)))
	b.WriteString("-")
	b.WriteString(strconv.FormatUint(s.Authority, 10))
	for _, x := range s.Sub {
		b.WriteString("-")
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	}
	return b.String()
}

// RID returns the last sub-authority (0 when there is none).
func (s SID) RID() uint32 {
	if len(s.Sub) == 0 {
		return 0
	}
	return s.Sub[len(s.Sub)-1]
}

// Domain returns the SID without its RID (the domain prefix for domain accounts).
func (s SID) Domain() string {
	if len(s.Sub) < 2 {
		return s.String()
	}
	d := s
	d.Sub = s.Sub[:len(s.Sub)-1]
	return d.String()
}

// ParseSID decodes a binary SID and returns it with its length in bytes.
func ParseSID(b []byte) (SID, int, error) {
	if len(b) < 8 {
		return SID{}, 0, errors.New("secdesc: SID too short")
	}
	n := int(b[1])
	size := 8 + 4*n
	if n > 15 || len(b) < size {
		return SID{}, 0, fmt.Errorf("secdesc: SID truncated (sub-authorities %d, have %d bytes)", n, len(b))
	}
	var auth uint64
	for i := 2; i < 8; i++ { // IdentifierAuthority is big-endian
		auth = auth<<8 | uint64(b[i])
	}
	s := SID{Revision: b[0], Authority: auth, Sub: make([]uint32, n)}
	for i := 0; i < n; i++ {
		s.Sub[i] = binary.LittleEndian.Uint32(b[8+4*i:])
	}
	return s, size, nil
}

// SIDString decodes a binary SID straight to its string form.
func SIDString(b []byte) (string, error) {
	s, _, err := ParseSID(b)
	if err != nil {
		return "", err
	}
	return s.String(), nil
}

// GUIDString renders a 16-byte GUID in the registry form used by Microsoft's
// schema pages (first three fields little-endian).
func GUIDString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// ACE is one access-control entry.
type ACE struct {
	Type                byte
	Flags               byte
	Mask                uint32
	ObjectType          string // GUID, empty when absent (applies to all)
	InheritedObjectType string // GUID, empty when absent
	Trustee             string // SID string
}

// Allow reports whether the ACE grants (rather than denies) access.
func (a ACE) Allow() bool { return a.Type == AceAllowed || a.Type == AceAllowedObject }

// Inherited reports whether the ACE was inherited from a parent.
func (a ACE) Inherited() bool { return a.Flags&FlagInherited != 0 }

// Effective reports whether the ACE applies to the object it is on.
func (a ACE) Effective() bool { return a.Flags&FlagInheritOnly == 0 }

// Has reports whether every bit in m is granted by the mask.
func (a ACE) Has(m uint32) bool { return a.Mask&m == m }

// Descriptor is a parsed security descriptor (SACL is skipped).
type Descriptor struct {
	Control uint16
	Owner   string
	Group   string
	DACL    []ACE
	// Unknown counts ACE types the parser does not interpret (callback,
	// conditional, audit, …). They are skipped, never guessed.
	Unknown int
}

// Protected reports whether DACL inheritance is blocked on the object.
func (d Descriptor) Protected() bool { return d.Control&ControlDACLProtected != 0 }

// Parse decodes a self-relative security descriptor.
func Parse(b []byte) (*Descriptor, error) {
	if len(b) < 20 {
		return nil, errors.New("secdesc: descriptor shorter than its 20-byte header")
	}
	if b[0] != 1 {
		return nil, fmt.Errorf("secdesc: unsupported revision %d", b[0])
	}
	d := &Descriptor{Control: binary.LittleEndian.Uint16(b[2:4])}
	if d.Control&ControlSelfRelative == 0 {
		return nil, errors.New("secdesc: not a self-relative descriptor")
	}
	offOwner := binary.LittleEndian.Uint32(b[4:8])
	offGroup := binary.LittleEndian.Uint32(b[8:12])
	offDACL := binary.LittleEndian.Uint32(b[16:20])
	sidAt := func(off uint32) (string, error) {
		if off == 0 {
			return "", nil
		}
		if int(off) >= len(b) {
			return "", fmt.Errorf("secdesc: SID offset %d beyond descriptor", off)
		}
		return SIDString(b[off:])
	}
	var err error
	if d.Owner, err = sidAt(offOwner); err != nil {
		return nil, err
	}
	if d.Group, err = sidAt(offGroup); err != nil {
		return nil, err
	}
	if d.Control&ControlDACLPresent != 0 && offDACL != 0 {
		if int(offDACL)+8 > len(b) {
			return nil, errors.New("secdesc: DACL header beyond descriptor")
		}
		if err := d.parseACL(b[offDACL:]); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (d *Descriptor) parseACL(b []byte) error {
	size := int(binary.LittleEndian.Uint16(b[2:4]))
	count := int(binary.LittleEndian.Uint16(b[4:6]))
	if size < 8 || size > len(b) {
		return fmt.Errorf("secdesc: ACL size %d invalid (have %d bytes)", size, len(b))
	}
	b = b[:size]
	pos := 8
	for i := 0; i < count; i++ {
		if pos+4 > len(b) {
			return fmt.Errorf("secdesc: ACE %d header beyond ACL", i)
		}
		typ, flags := b[pos], b[pos+1]
		asz := int(binary.LittleEndian.Uint16(b[pos+2 : pos+4]))
		if asz < 8 || pos+asz > len(b) {
			return fmt.Errorf("secdesc: ACE %d size %d invalid", i, asz)
		}
		body := b[pos+4 : pos+asz]
		switch typ {
		case AceAllowed, AceDenied:
			sid, err := SIDString(body[4:])
			if err != nil {
				return fmt.Errorf("secdesc: ACE %d: %w", i, err)
			}
			d.DACL = append(d.DACL, ACE{Type: typ, Flags: flags, Mask: binary.LittleEndian.Uint32(body[0:4]), Trustee: sid})
		case AceAllowedObject, AceDeniedObject:
			if len(body) < 8 {
				return fmt.Errorf("secdesc: object ACE %d too short", i)
			}
			a := ACE{Type: typ, Flags: flags, Mask: binary.LittleEndian.Uint32(body[0:4])}
			of := binary.LittleEndian.Uint32(body[4:8])
			p := 8
			if of&objectTypePresent != 0 {
				if p+16 > len(body) {
					return fmt.Errorf("secdesc: object ACE %d ObjectType truncated", i)
				}
				a.ObjectType = GUIDString(body[p : p+16])
				p += 16
			}
			if of&inheritedObjectTypePresent != 0 {
				if p+16 > len(body) {
					return fmt.Errorf("secdesc: object ACE %d InheritedObjectType truncated", i)
				}
				a.InheritedObjectType = GUIDString(body[p : p+16])
				p += 16
			}
			sid, err := SIDString(body[p:])
			if err != nil {
				return fmt.Errorf("secdesc: ACE %d: %w", i, err)
			}
			a.Trustee = sid
			d.DACL = append(d.DACL, a)
		default:
			d.Unknown++
		}
		pos += asz
	}
	return nil
}
