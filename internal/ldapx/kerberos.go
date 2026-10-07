package ldapx

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
)

// BindCurrentUser authenticates as the account already signed in on this
// machine (Kerberos via SASL/GSSAPI), so no password is typed or handled:
//   - Windows: SSPI with the logon session's tickets; over TLS the bind carries
//     a channel-binding token so DCs that enforce LDAP channel binding accept it.
//   - Linux/macOS: the file credential cache from `kinit` (KRB5CCNAME or
//     /tmp/krb5cc_<uid>) and krb5.conf (KRB5_CONFIG or /etc/krb5.conf).
//
// The SASL exchange selects no security layer: confidentiality comes from TLS,
// which Dial already requires. It returns the identity that was used.
func (c *Conn) BindCurrentUser() (string, error) {
	host := c.host()
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("ldapx: Kerberos needs the DC's DNS name, not an IP address (%s); pass --server dc01.example.com", host)
	}
	return bindCurrentUser(c, "ldap/"+strings.ToLower(host))
}

// peerCertificate returns the server's leaf certificate when the session uses TLS.
func (c *Conn) peerCertificate() (*x509.Certificate, error) {
	st, ok := c.c.TLSConnectionState()
	if !ok || len(st.PeerCertificates) == 0 {
		return nil, errors.New("no TLS session")
	}
	return st.PeerCertificates[0], nil
}

func (c *Conn) host() string {
	if c.opts.ServerName != "" {
		return c.opts.ServerName
	}
	h, _, err := net.SplitHostPort(c.opts.Server)
	if err != nil {
		return c.opts.Server
	}
	return h
}
