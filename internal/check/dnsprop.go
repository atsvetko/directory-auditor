package check

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// DNS zone properties as AD and Samba store them in the multi-valued binary
// attribute dNSProperty of a dnsZone object ([MS-DNSP] 2.3.2.1). Each value is
// one property, little-endian:
//
//	offset 0   DataLength uint32  length of Data in bytes
//	offset 4   NameLength uint32  not used (written as 1)
//	offset 8   Flag       uint32  0
//	offset 12  Version    uint32  1
//	offset 16  Id         uint32  property id (DSPROPERTY_ZONE_*)
//	offset 20  Data       DataLength bytes
//	           Name       1 byte, not used
//
// Only the header and Data are read; the trailing Name byte is ignored, so a
// writer that pads it differently decodes the same.
const dnsPropHeader = 20

// Property ids used by catalogue entries ([MS-DNSP] 2.3.2.1.1).
const dnsPropAllowUpdate = 0x00000002 // DSPROPERTY_ZONE_ALLOW_UPDATE: 0 off, 1 nonsecure and secure, 2 secure only

// dnsProperty is one decoded dNSProperty value.
type dnsProperty struct {
	ID   uint32
	Data []byte
}

// decodeDNSProperty parses one raw dNSProperty value. It fails on a value too
// short for its header or for the DataLength it declares.
func decodeDNSProperty(raw []byte) (dnsProperty, error) {
	if len(raw) < dnsPropHeader {
		return dnsProperty{}, fmt.Errorf("dNSProperty: %d bytes, header needs %d", len(raw), dnsPropHeader)
	}
	n := binary.LittleEndian.Uint32(raw[0:])
	if uint64(n) > uint64(len(raw)-dnsPropHeader) {
		return dnsProperty{}, fmt.Errorf("dNSProperty: DataLength %d exceeds the %d bytes present", n, len(raw)-dnsPropHeader)
	}
	return dnsProperty{ID: binary.LittleEndian.Uint32(raw[16:]), Data: raw[dnsPropHeader : dnsPropHeader+int(n)]}, nil
}

// value returns Data as a little-endian unsigned integer when it is 1, 2 or 4
// bytes long (the scalar properties: ALLOW_UPDATE is one byte, the aging
// intervals are four); ok is false for empty or longer data.
func (p dnsProperty) value() (uint32, bool) {
	switch len(p.Data) {
	case 1:
		return uint32(p.Data[0]), true
	case 2:
		return uint32(binary.LittleEndian.Uint16(p.Data)), true
	case 4:
		return binary.LittleEndian.Uint32(p.Data), true
	}
	return 0, false
}

// dnsZoneProperty returns the scalar value of property id among the snapshot
// values of dNSProperty (base64, as the collector stores binary attributes).
// It returns -1 when no value carries that id, or none that does decodes to a
// scalar — "not set", never a guessed default. Undecodable values are skipped.
func dnsZoneProperty(vals []string, id uint32) int64 {
	for _, v := range vals {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			continue
		}
		p, err := decodeDNSProperty(raw)
		if err != nil || p.ID != id {
			continue
		}
		if x, ok := p.value(); ok {
			return int64(x)
		}
	}
	return -1
}

// describeDNSProperties renders dNSProperty values for finding evidence:
// "id 0x2 = 1; id 0x1 = 0" instead of base64 blobs.
func describeDNSProperties(vals []string) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			out = append(out, "undecodable")
			continue
		}
		p, err := decodeDNSProperty(raw)
		if err != nil {
			out = append(out, "undecodable")
			continue
		}
		if x, ok := p.value(); ok {
			out = append(out, fmt.Sprintf("id 0x%x = %d", p.ID, x))
		} else {
			out = append(out, fmt.Sprintf("id 0x%x (%d bytes)", p.ID, len(p.Data)))
		}
	}
	return strings.Join(out, "; ")
}
