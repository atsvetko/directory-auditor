package ldapx

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
)

// BindKerberos authenticates with Kerberos (SASL/GSSAPI). With an empty
// account it uses the identity already signed in on this machine — Windows:
// SSPI and the logon session's tickets; Linux/macOS: the credential cache from
// `kinit` — so no password is handled. With an account and password it obtains
// a ticket from the DC's KDC first, so the password never crosses the network.
//
// Over TLS the bind carries a channel-binding token (tls-server-end-point) and
// selects no SASL layer. Without TLS it negotiates the SASL security layer —
// sealing where the server offers it — so the session stays encrypted and
// signed even on plain port 389. It returns the identity that was used.
func (c *Conn) BindKerberos(account, password string) (string, error) {
	host := c.host()
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("ldapx: Kerberos needs the DC's DNS name, not an IP address (%s); pass --server dc01.example.com", host)
	}
	spn := "ldap/" + strings.ToLower(host)
	var cb []byte
	if cert, err := c.peerCertificate(); err == nil {
		cb = tlsServerEndPoint(cert)
	}
	ctx, err := newGSSContext(spn, cb, account, password, c.opts.Domain, host)
	if err != nil {
		return "", fmt.Errorf("ldapx: %w", err)
	}
	cl := &saslClient{ctx: ctx, overTLS: c.transport != "ldap"}
	if err := c.c.GSSAPIBind(cl, spn, ""); err != nil {
		_ = ctx.Close()
		return "", fmt.Errorf("ldapx: Kerberos bind to %s as %s failed: %w%s", spn, ctx.Identity(), err, kerberosHint(err, c.transport != "ldap"))
	}
	c.gss = ctx
	switch {
	case cl.layer == saslLayerConf && c.sec != nil:
		c.sec.arm(ctx, true, cl.maxOut)
		c.protection = "sasl-seal"
	case cl.layer == saslLayerIntegrity && c.sec != nil:
		c.sec.arm(ctx, false, cl.maxOut)
		c.protection = "sasl-sign"
	}
	return ctx.Identity(), nil
}

// BindCurrentUser is BindKerberos with the identity already signed in.
func (c *Conn) BindCurrentUser() (string, error) { return c.BindKerberos("", "") }

func kerberosHint(err error, overTLS bool) string {
	m := err.Error()
	switch {
	case strings.Contains(m, "Stronger") || strings.Contains(m, "strongerAuthRequired") || strings.Contains(m, "Result Code 8"):
		if overTLS {
			return " (the server wants channel binding or signing on this TLS session)"
		}
		return " (the server requires LDAP signing and did not accept the SASL security layer)"
	case strings.Contains(m, "KDC_ERR_PREAUTH_FAILED") || strings.Contains(m, "Preauthentication failed"):
		return " (wrong password?)"
	case strings.Contains(m, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		return " (unknown account in this realm)"
	case strings.Contains(m, "KRB_AP_ERR_SKEW"):
		return " (clock skew between this machine and the DC exceeds 5 minutes)"
	}
	return ""
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

// splitPrincipal accepts user@REALM, user@domain, DOMAIN\user and plain user;
// the realm is upper-cased, and falls back to the domain hint.
func splitPrincipal(account, domainHint string) (name, realm string) {
	switch {
	case strings.Contains(account, "\\"):
		i := strings.IndexByte(account, '\\')
		realm, name = account[:i], account[i+1:]
		if !strings.Contains(realm, ".") && domainHint != "" {
			realm = domainHint // a NetBIOS name is not the realm
		}
	case strings.Contains(account, "@"):
		i := strings.LastIndexByte(account, '@')
		name, realm = account[:i], account[i+1:]
	default:
		name, realm = account, domainHint
	}
	return name, strings.ToUpper(realm)
}
