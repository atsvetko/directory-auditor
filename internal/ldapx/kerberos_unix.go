//go:build !windows

package ldapx

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3/gssapi"
)

func bindCurrentUser(c *Conn, spn string) (string, error) {
	ccache, err := ccachePath()
	if err != nil {
		return "", err
	}
	conf := os.Getenv("KRB5_CONFIG")
	if conf == "" {
		conf = "/etc/krb5.conf"
	}
	cl, err := gssapi.NewClientFromCCache(ccache, conf)
	if err != nil {
		return "", fmt.Errorf("ldapx: cannot use Kerberos ticket cache %s with %s: %w (run `kinit user@REALM` first)", ccache, conf, err)
	}
	defer cl.Close()
	who := cl.Credentials.CName().PrincipalNameString() + "@" + cl.Credentials.Realm()
	if err := c.c.GSSAPIBind(cl, spn, ""); err != nil {
		hint := ""
		if _, cerr := c.peerCertificate(); cerr == nil {
			hint = " If the DC enforces LDAP channel binding, Kerberos from Linux cannot satisfy it yet; use --user for this run."
		}
		return "", fmt.Errorf("ldapx: Kerberos bind to %s as %s failed: %w.%s", spn, who, err, hint)
	}
	return who, nil
}

// ccachePath resolves the file credential cache. KEYRING:, KCM: and DIR:
// caches (common with SSSD) cannot be read by a static binary; say how to fix.
func ccachePath() (string, error) {
	v := os.Getenv("KRB5CCNAME")
	switch {
	case v == "":
		return fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid()), nil
	case strings.HasPrefix(v, "FILE:"):
		return strings.TrimPrefix(v, "FILE:"), nil
	case strings.Contains(v, ":") && !strings.HasPrefix(v, "/"):
		return "", errors.New("ldapx: the Kerberos cache " + v + " is not a file; run `KRB5CCNAME=FILE:/tmp/dirauditor.cc kinit user@REALM` and start again with that KRB5CCNAME")
	}
	return v, nil
}
