//go:build windows

package ldapx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os/user"
	"strings"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
)

// sspiContext is the Kerberos security context through Windows SSPI: the
// logon session's tickets (or explicit credentials), EncryptMessage /
// DecryptMessage for the SASL security layer, and channel bindings over TLS.
type sspiContext struct {
	creds    *sspi.Credentials
	ctx      *kerberos.ClientContext
	spn      string
	cb       []byte // SEC_CHANNEL_BINDINGS structure, or nil
	identity string
	done     bool
}

// SECQOP_WRAP_NO_ENCRYPT: sign only (KERB_WRAP_NO_ENCRYPT).
const sspiWrapNoEncrypt = 0x80000001

func newSSPIContext(spn string, channelBinding []byte, account, password string) (*sspiContext, error) {
	var (
		creds *sspi.Credentials
		err   error
		who   string
	)
	if account == "" {
		creds, err = kerberos.AcquireCurrentUserCredentials()
		who = "current logon"
		if u, uerr := user.Current(); uerr == nil {
			who = u.Username
		}
	} else {
		domain, name := splitUser(account)
		creds, err = kerberos.AcquireUserCredentials(domain, name, password)
		who = account
	}
	if err != nil {
		return nil, fmt.Errorf("Kerberos credentials: %w", err)
	}
	var cb []byte
	if channelBinding != nil {
		cb = make([]byte, 32+len(channelBinding))
		binary.LittleEndian.PutUint32(cb[24:], uint32(len(channelBinding))) // cbApplicationDataLength
		binary.LittleEndian.PutUint32(cb[28:], 32)                          // dwApplicationDataOffset
		copy(cb[32:], channelBinding)
	}
	return &sspiContext{creds: creds, spn: spn, cb: cb, identity: who}, nil
}

// splitUser accepts user@domain, DOMAIN\user and plain user.
func splitUser(s string) (domain, name string) {
	if i := strings.IndexByte(s, '\\'); i >= 0 {
		return s[:i], s[i+1:]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		return s[i+1:], s[:i]
	}
	return "", s
}

func (c *sspiContext) Identity() string { return c.identity }

func (c *sspiContext) Close() error {
	var err error
	if c.ctx != nil {
		err = c.ctx.Release()
		c.ctx = nil
	}
	if c.creds != nil {
		_ = c.creds.Release()
		c.creds = nil
	}
	return err
}

func (c *sspiContext) Step(in []byte) ([]byte, bool, error) {
	const flags = uint32(sspi.ISC_REQ_INTEGRITY | sspi.ISC_REQ_CONFIDENTIALITY | sspi.ISC_REQ_MUTUAL_AUTH)
	if in == nil {
		ctx, done, out, err := kerberos.NewClientContextWithChannelBindings(c.creds, c.spn, flags, c.cb)
		if err != nil {
			return nil, false, err
		}
		c.ctx, c.done = ctx, done
		return out, done, nil
	}
	if c.ctx == nil {
		return nil, false, errors.New("context not started")
	}
	done, out, err := c.ctx.Update(in)
	if err != nil {
		return nil, false, err
	}
	if done {
		if err := c.ctx.VerifyFlags(); err != nil {
			return nil, false, err
		}
	}
	c.done = done
	return out, done, nil
}

func (c *sspiContext) Wrap(data []byte, conf bool) ([]byte, error) {
	if !c.done {
		return nil, errors.New("context not established")
	}
	qop := uint32(sspiWrapNoEncrypt)
	if conf {
		qop = 0
	}
	// EncryptMessage works in place; keep the caller's buffer intact.
	return c.ctx.EncryptMessage(append([]byte(nil), data...), qop, 0)
}

func (c *sspiContext) Unwrap(tok []byte) ([]byte, bool, error) {
	if !c.done {
		return nil, false, errors.New("context not established")
	}
	qop, data, err := c.ctx.DecryptMessage(append([]byte(nil), tok...), 0)
	if err != nil {
		return nil, false, err
	}
	return data, qop&sspiWrapNoEncrypt == 0, nil
}
