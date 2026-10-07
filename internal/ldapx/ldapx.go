// Package ldapx is the only place in the engine that talks LDAP. It exposes a
// deliberately read-only surface: Search and RootDSE. There is no Modify, Add,
// Delete or ModifyDN method here, and scripts/readonly-check.sh verifies that
// none of go-ldap's write entry points survive linking into the release binary
// (requirement N-9, review-pack artefact 11).
package ldapx

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Options controls how a connection is made. Plain LDAP without TLS is refused
// unless InsecurePlaintext is set (development only).
type Options struct {
	Server            string        // host or host:port
	UseLDAPS          bool          // 636 with TLS from the start
	StartTLS          bool          // 389 then StartTLS
	InsecurePlaintext bool          // allow no TLS at all (never the default)
	PinSHA256         string        // optional hex SHA-256 of the server certificate (self-signed CAs)
	ServerName        string        // SNI / verification name when it differs from Server
	Timeout           time.Duration // dial and per-request timeout
	MaxQPS            int           // 0 = unlimited; collectors throttle to this
}

// Conn is a read-only LDAP session.
type Conn struct {
	c       *ldap.Conn
	queries int
	opts    Options
}

// Dial opens a connection according to opts. It never binds; call BindSimple
// (or, later, BindGSSAPI) explicitly so the identity used is always visible.
func Dial(ctx context.Context, opts Options) (*Conn, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	host, port, err := net.SplitHostPort(opts.Server)
	if err != nil {
		host = opts.Server
		port = "389"
		if opts.UseLDAPS {
			port = "636"
		}
	}
	if !opts.UseLDAPS && !opts.StartTLS && !opts.InsecurePlaintext {
		return nil, errors.New("ldapx: refusing a plaintext LDAP connection; use LDAPS, StartTLS, or --insecure-plaintext for a lab")
	}
	serverName := opts.ServerName
	if serverName == "" {
		serverName = host
	}
	tlsCfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	if opts.PinSHA256 != "" {
		pin := strings.ToLower(strings.ReplaceAll(opts.PinSHA256, ":", ""))
		tlsCfg.InsecureSkipVerify = true // verification is done by the pin below, not skipped
		tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("ldapx: no server certificate presented")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != pin {
				return fmt.Errorf("ldapx: server certificate fingerprint %s does not match pin", hex.EncodeToString(sum[:]))
			}
			return nil
		}
	}

	dialer := &net.Dialer{Timeout: opts.Timeout}
	addr := net.JoinHostPort(host, port)
	var c *ldap.Conn
	switch {
	case opts.UseLDAPS:
		c, err = ldap.DialURL("ldaps://"+addr, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsCfg))
	default:
		c, err = ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(dialer))
		if err == nil && opts.StartTLS {
			if e := c.StartTLS(tlsCfg); e != nil {
				c.Close()
				return nil, fmt.Errorf("ldapx: StartTLS: %w", e)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("ldapx: dial %s: %w", addr, err)
	}
	c.SetTimeout(opts.Timeout)
	return &Conn{c: c, opts: opts}, nil
}

// BindSimple authenticates with a DN or UPN and password over the (TLS) session.
// The password is used once and not retained by this package.
func (c *Conn) BindSimple(user, password string) error {
	if password == "" {
		return errors.New("ldapx: refusing an unauthenticated (empty-password) simple bind")
	}
	return c.c.Bind(user, password)
}

// RootDSE returns selected rootDSE attributes used for dialect fingerprinting.
func (c *Conn) RootDSE(ctx context.Context) (map[string]string, error) {
	attrs := []string{
		"defaultNamingContext", "configurationNamingContext", "schemaNamingContext",
		"rootDomainNamingContext", "dnsHostName", "serverName", "forestFunctionality",
		"domainFunctionality", "domainControllerFunctionality", "supportedCapabilities",
		"supportedControl", "supportedLDAPVersion", "supportedSASLMechanisms", "vendorName",
		"vendorVersion", "isGlobalCatalogReady", "highestCommittedUSN", "ldapServiceName",
	}
	res, err := c.search(ctx, "", ldap.ScopeBaseObject, "(objectClass=*)", attrs, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if len(res.Entries) == 0 {
		return out, nil
	}
	for _, a := range res.Entries[0].Attributes {
		out[a.Name] = strings.Join(a.Values, ";")
	}
	return out, nil
}

// Entry is a minimal, library-independent search result.
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// Search runs a paged search and returns all entries. Page size 500 keeps
// per-request load modest on domain controllers.
func (c *Conn) Search(ctx context.Context, baseDN string, scope Scope, filter string, attrs []string) ([]Entry, error) {
	res, err := c.search(ctx, baseDN, int(scope), filter, attrs, 500)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(res.Entries))
	for _, e := range res.Entries {
		m := make(map[string][]string, len(e.Attributes))
		for _, a := range e.Attributes {
			m[a.Name] = a.Values
		}
		out = append(out, Entry{DN: e.DN, Attrs: m})
	}
	return out, nil
}

// Queries reports how many LDAP searches this session has issued (for the run log).
func (c *Conn) Queries() int { return c.queries }

// Close ends the session.
func (c *Conn) Close() { c.c.Close() }

// Scope mirrors LDAP search scopes without exposing go-ldap types.
type Scope int

const (
	ScopeBase Scope = iota
	ScopeOneLevel
	ScopeSubtree
)

func (c *Conn) search(ctx context.Context, base string, scope int, filter string, attrs []string, page uint32) (*ldap.SearchResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	c.queries++
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
	if page == 0 {
		return c.c.Search(req)
	}
	return c.c.SearchWithPaging(req, page)
}
