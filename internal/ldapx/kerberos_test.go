package ldapx

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// samba419 is what Samba 4.19 answers a Kerberos bind over LDAPS that selects
// no SASL layer, with its default "ldap server require strong auth = yes"
// (seen in the KVM lab).
var samba419 = ldap.NewError(ldap.LDAPResultStrongAuthRequired, errors.New("SASL:[GSSAPI]: Sign or Seal are required."))

func TestNeedsSASLLayer(t *testing.T) {
	wrapped := fmt.Errorf("ldapx: Kerberos bind to ldap/dc1.lab.example as audit@LAB.EXAMPLE failed: %w", samba419)
	if !NeedsSASLLayer(wrapped) {
		t.Errorf("Samba's strong-auth refusal not recognised: %v", wrapped)
	}
	for _, err := range []error{
		ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")),
		errors.New("KDC_ERR_PREAUTH_FAILED"),
	} {
		if NeedsSASLLayer(err) {
			t.Errorf("%v classified as needing a SASL layer", err)
		}
	}
}

func TestKerberosHintSambaOverTLS(t *testing.T) {
	if h := kerberosHint(samba419, true); !strings.Contains(h, "Samba") || !strings.Contains(h, "--tls none") {
		t.Errorf("over TLS: hint %q does not explain the Samba policy", h)
	}
	// Without TLS the same code means the SASL layer was not accepted.
	if h := kerberosHint(samba419, false); !strings.Contains(h, "did not accept the SASL security layer") {
		t.Errorf("plain LDAP: hint %q", h)
	}
}

// With --server an IP and --server-name the DC's name, the name is for the SPN
// and certificate checks; the KDC must be the address that was dialled (the
// name may not resolve on the scanning machine — found in the KVM Windows lab).
func TestKDCIsDialledAddress(t *testing.T) {
	c := &Conn{opts: Options{Server: "10.55.0.10", ServerName: "dc1.da.test"}}
	if got := c.addrHost(); got != "10.55.0.10" {
		t.Errorf("addrHost = %q, want the dialled IP", got)
	}
	if got := c.host(); got != "dc1.da.test" {
		t.Errorf("host (SPN) = %q, want the server name", got)
	}
	c = &Conn{opts: Options{Server: "dc1.da.test:636"}}
	if got := c.addrHost(); got != "dc1.da.test" {
		t.Errorf("addrHost with a port = %q", got)
	}
}
