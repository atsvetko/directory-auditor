//go:build windows

package ldapx

// newGSSContext builds the Kerberos context through SSPI: the logon session's
// tickets, or explicit credentials (DOMAIN\user, user@domain) that the
// Kerberos package turns into a ticket at the domain's KDC.
func newGSSContext(spn string, channelBinding []byte, account, password, domainHint, _ string) (gssContext, error) {
	if account != "" && !containsAny(account, "\\@") && domainHint != "" {
		account = account + "@" + domainHint
	}
	return newSSPIContext(spn, channelBinding, account, password)
}

func containsAny(s, chars string) bool {
	for _, c := range chars {
		for _, r := range s {
			if r == c {
				return true
			}
		}
	}
	return false
}
