package check

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// dnsProp encodes one [MS-DNSP] 2.3.2.1 dnsProperty value (test data only).
func dnsProp(id uint32, data ...byte) string {
	b := make([]byte, 20, 21+len(data))
	binary.LittleEndian.PutUint32(b[0:], uint32(len(data)))
	binary.LittleEndian.PutUint32(b[4:], 1)  // NameLength
	binary.LittleEndian.PutUint32(b[12:], 1) // Version
	binary.LittleEndian.PutUint32(b[16:], id)
	b = append(append(b, data...), 0) // Name
	return base64.StdEncoding.EncodeToString(b)
}

func TestDecodeDNSProperty(t *testing.T) {
	raw, _ := base64.StdEncoding.DecodeString(dnsProp(dnsPropAllowUpdate, 1))
	p, err := decodeDNSProperty(raw)
	if v, ok := p.value(); err != nil || p.ID != 2 || !ok || v != 1 {
		t.Errorf("allow-update: %+v %v", p, err)
	}
	// Without the trailing Name byte the value still decodes.
	if p, err := decodeDNSProperty(raw[:21]); err != nil || p.ID != 2 {
		t.Errorf("no name byte: %+v %v", p, err)
	}
	// A four-byte scalar (aging intervals) and a value longer than a scalar.
	raw, _ = base64.StdEncoding.DecodeString(dnsProp(0x10, 0xa8, 0, 0, 0))
	if p, _ := decodeDNSProperty(raw); p.ID != 0x10 {
		t.Errorf("id 0x10: %+v", p)
	} else if v, ok := p.value(); !ok || v != 168 {
		t.Errorf("no-refresh interval = %d %v", v, ok)
	}
	raw, _ = base64.StdEncoding.DecodeString(dnsProp(0x80, 1, 2, 3, 4, 5, 6, 7, 8))
	if p, _ := decodeDNSProperty(raw); len(p.Data) != 8 {
		t.Errorf("8-byte data: %+v", p)
	} else if _, ok := p.value(); ok {
		t.Error("8-byte data decoded as a scalar")
	}
	// Malformed: short header, DataLength beyond the value.
	if _, err := decodeDNSProperty(make([]byte, 19)); err == nil {
		t.Error("19-byte value accepted")
	}
	bad, _ := base64.StdEncoding.DecodeString(dnsProp(2, 1))
	binary.LittleEndian.PutUint32(bad, 50)
	if _, err := decodeDNSProperty(bad); err == nil {
		t.Error("DataLength overrun accepted")
	}
}

func TestDNSZoneProperty(t *testing.T) {
	typ := dnsProp(0x01, 1, 0, 0, 0) // DSPROPERTY_ZONE_TYPE = primary
	for name, c := range map[string]struct {
		vals []string
		want int64
	}{
		"nonsecure":     {[]string{typ, dnsProp(2, 1)}, 1},
		"secure only":   {[]string{dnsProp(2, 2), typ}, 2},
		"off":           {[]string{dnsProp(2, 0)}, 0},
		"not set":       {[]string{typ}, -1},
		"none":          {nil, -1},
		"empty data":    {[]string{dnsProp(2)}, -1},
		"garbage first": {[]string{"!!", base64.StdEncoding.EncodeToString([]byte{1, 2}), dnsProp(2, 1)}, 1},
	} {
		if got := dnsZoneProperty(c.vals, dnsPropAllowUpdate); got != c.want {
			t.Errorf("%s: got %d, want %d", name, got, c.want)
		}
	}
	if got := describeDNSProperties([]string{typ, dnsProp(2, 1), "!!"}); got != "id 0x1 = 1; id 0x2 = 1; undecodable" {
		t.Errorf("describe: %q", got)
	}
}

// TestDNSHelpersInCEL runs dns_zone_property and sid_account through the engine.
func TestDNSHelpersInCEL(t *testing.T) {
	dom := "S-1-5-21-1-2-3"
	snap := &snapshot.Snapshot{Meta: snapshot.Meta{Provider: "ad", DomainSID: dom, BaseDN: "DC=x"}, Objects: []snapshot.Object{
		{DN: "DC=x", Class: []string{"domainDNS"}, Attrs: map[string][]string{"objectSid": {dom}}},
		{DN: "CN=DnsAdmins,CN=Users,DC=x", Class: []string{"group"}, Attrs: map[string][]string{"objectSid": {dom + "-1101"}, "sAMAccountName": {"DnsAdmins"}}},
		{DN: "DC=a,CN=MicrosoftDNS,CN=System,DC=x", Class: []string{"top", "dnsZone"}, Attrs: map[string][]string{"dNSProperty": {dnsProp(2, 1)}}},
		{DN: "DC=b,CN=MicrosoftDNS,CN=System,DC=x", Class: []string{"top", "dnsZone"}, Attrs: map[string][]string{"dNSProperty": {dnsProp(2, 2)}}},
	}}
	res, err := Evaluate(snap, []Pack{{ID: "T", Provider: []string{"ad"}, Severity: "high", Signed: true, Query: Query{Filter: "(objectClass=dnsZone)"},
		Evidence:  []string{"dNSProperty"},
		Condition: `dns_zone_property(obj, 2) == 1 && sid_account("` + dom + `-1101").lowerAscii() == "dnsadmins" && sid_account("S-1-5-11") == ""`}})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Checks[0].Findings
	if len(f) != 1 || f[0].DN != "DC=a,CN=MicrosoftDNS,CN=System,DC=x" || f[0].Evidence["dNSProperty"] != "id 0x2 = 1" {
		t.Errorf("findings = %+v", f)
	}
}
