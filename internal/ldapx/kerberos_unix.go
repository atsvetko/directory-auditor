//go:build !windows

package ldapx

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
)

// newGSSContext builds the Kerberos context on gokrb5: from the credential
// cache for the current logon, or from a password — then the KDC is the
// directory server itself, so no krb5.conf is needed on this machine.
func newGSSContext(spn string, channelBinding []byte, account, password, domainHint, kdc string) (gssContext, error) {
	if account == "" {
		ccache, err := ccachePath()
		if err != nil {
			return nil, err
		}
		confPath := os.Getenv("KRB5_CONFIG")
		if confPath == "" {
			confPath = "/etc/krb5.conf"
		}
		conf, err := config.Load(confPath)
		if err != nil {
			return nil, fmt.Errorf("Kerberos configuration %s: %w", confPath, err)
		}
		cc, err := credentials.LoadCCache(ccache)
		if err != nil {
			return nil, fmt.Errorf("Kerberos ticket cache %s: %w (run `kinit user@REALM` first)", ccache, err)
		}
		cl, err := client.NewFromCCache(cc, conf, client.DisablePAFXFAST(true))
		if err != nil {
			return nil, fmt.Errorf("Kerberos ticket cache %s: %w (run `kinit user@REALM` first)", ccache, err)
		}
		return newKrb5Context(cl, spn, channelBinding), nil
	}
	name, realm := splitPrincipal(account, domainHint)
	if realm == "" {
		return nil, errors.New("Kerberos with a password needs the realm: use user@domain or pass --domain")
	}
	conf, err := config.NewFromString(krb5ConfigFor(realm, kdc))
	if err != nil {
		return nil, err
	}
	cl := client.NewWithPassword(name, realm, password, conf, client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("Kerberos login as %s@%s at KDC %s: %w", name, realm, kdc, err)
	}
	return newKrb5Context(cl, spn, channelBinding), nil
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
		return "", errors.New("the Kerberos cache " + v + " is not a file; run `KRB5CCNAME=FILE:/tmp/dirauditor.cc kinit user@REALM` and start again with that KRB5CCNAME")
	}
	return v, nil
}
