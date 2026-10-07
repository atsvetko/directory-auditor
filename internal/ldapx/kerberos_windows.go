//go:build windows

package ldapx

import (
	"fmt"
	"os/user"

	"github.com/go-ldap/ldap/v3/gssapi"
)

func bindCurrentUser(c *Conn, spn string) (string, error) {
	var (
		cl  *gssapi.SSPIClient
		err error
	)
	if cert, cerr := c.peerCertificate(); cerr == nil {
		cl, err = gssapi.NewSSPIClientWithChannelBinding(cert)
	} else {
		cl, err = gssapi.NewSSPIClient()
	}
	if err != nil {
		return "", fmt.Errorf("ldapx: no Kerberos credentials for the current logon: %w", err)
	}
	defer cl.Close()
	if err := c.c.GSSAPIBind(cl, spn, ""); err != nil {
		return "", fmt.Errorf("ldapx: Kerberos bind to %s as the current logon failed: %w (is this machine domain-joined and the DC name correct?)", spn, err)
	}
	who := "current logon"
	if u, err := user.Current(); err == nil {
		who = u.Username
	}
	return who, nil
}
