package ad

import "testing"

func TestFingerprint(t *testing.T) {
	cases := []struct {
		name string
		root map[string]string
		want string
	}{
		{"windows dc", map[string]string{"forestFunctionality": "7", "domainControllerFunctionality": "7", "supportedCapabilities": "1.2.840.113556.1.4.800;1.2.840.113556.1.4.1670"}, "ad"},
		{"samba", map[string]string{"vendorName": "Samba Team (https://www.samba.org)", "vendorVersion": "4.19.0", "forestFunctionality": "7"}, "samba"},
		{"openldap", map[string]string{"supportedLDAPVersion": "3"}, ""},
	}
	for _, c := range cases {
		if got := Fingerprint(c.root); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
