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
	"strconv"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
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
	c        *ldap.Conn
	queries  int // logical searches
	requests int // wire requests (pages, range chunks)
	last     time.Time
	opts     Options
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

// Entry is a minimal, library-independent search result. Attributes named in
// SearchOptions.Binary are returned raw in Bin (and omitted from Attrs) because
// their values are not text: SIDs, GUIDs, security descriptors.
type Entry struct {
	DN    string
	Attrs map[string][]string
	Bin   map[string][][]byte
}

// SearchOptions refines a search. The zero value is a plain paged search.
type SearchOptions struct {
	// Binary lists attributes to return as raw bytes (case-insensitive).
	Binary []string
	// SDFlags, when non-zero, attaches LDAP_SERVER_SD_FLAGS_OID so the server
	// returns only the named parts of nTSecurityDescriptor. Use SDFlagsDACL for
	// non-administrators: without the control AD also asks for the SACL and
	// omits the whole attribute when the caller may not read it.
	SDFlags uint32
}

// Parts of a security descriptor selectable with SDFlags ([MS-ADTS] 3.1.1.3.4.1.11).
const (
	SDFlagsOwner uint32 = 0x1
	SDFlagsGroup uint32 = 0x2
	SDFlagsDACL  uint32 = 0x4
	SDFlagsSACL  uint32 = 0x8
)

// OIDSDFlags is LDAP_SERVER_SD_FLAGS_OID.
const OIDSDFlags = "1.2.840.113556.1.4.801"

// Search runs a paged search and returns all entries. Page size 500 keeps
// per-request load modest on domain controllers.
func (c *Conn) Search(ctx context.Context, baseDN string, scope Scope, filter string, attrs []string) ([]Entry, error) {
	return c.SearchWith(ctx, baseDN, scope, filter, attrs, SearchOptions{})
}

// SearchWith is Search with options. Multi-valued attributes that the server
// returns in ranges (member;range=0-1499) are completed with follow-up base
// searches so callers always see the full value list under the plain name.
func (c *Conn) SearchWith(ctx context.Context, baseDN string, scope Scope, filter string, attrs []string, o SearchOptions) ([]Entry, error) {
	var controls []ldap.Control
	if o.SDFlags != 0 {
		controls = append(controls, sdFlagsControl(o.SDFlags))
	}
	res, err := c.pagedSearch(ctx, baseDN, int(scope), filter, attrs, controls, 500)
	if err != nil {
		return nil, err
	}
	binary := map[string]bool{}
	for _, b := range o.Binary {
		binary[strings.ToLower(b)] = true
	}
	out := make([]Entry, 0, len(res))
	for _, e := range res {
		en := Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attributes))}
		for _, a := range e.Attributes {
			name, lo, hi, ranged := parseRange(a.Name)
			if ranged {
				vals, err := c.completeRange(ctx, e.DN, name, a.ByteValues, lo, hi, controls)
				if err != nil {
					return nil, fmt.Errorf("ldapx: range retrieval of %s on %s: %w", name, e.DN, err)
				}
				a = &ldap.EntryAttribute{Name: name, ByteValues: vals}
			}
			if binary[strings.ToLower(a.Name)] {
				if en.Bin == nil {
					en.Bin = map[string][][]byte{}
				}
				en.Bin[a.Name] = a.ByteValues
				continue
			}
			vals := make([]string, len(a.ByteValues))
			for i, v := range a.ByteValues {
				vals[i] = string(v)
			}
			en.Attrs[a.Name] = vals
		}
		out = append(out, en)
	}
	return out, nil
}

// parseRange splits "member;range=0-1499" into ("member", 0, 1499, true);
// hi = -1 means "*" (last chunk).
func parseRange(attr string) (name string, lo, hi int, ok bool) {
	i := strings.Index(strings.ToLower(attr), ";range=")
	if i < 0 {
		return attr, 0, 0, false
	}
	name = attr[:i]
	r := attr[i+len(";range="):]
	dash := strings.IndexByte(r, '-')
	if dash < 0 {
		return attr, 0, 0, false
	}
	var err error
	if lo, err = strconv.Atoi(r[:dash]); err != nil {
		return attr, 0, 0, false
	}
	if r[dash+1:] == "*" {
		return name, lo, -1, true
	}
	if hi, err = strconv.Atoi(r[dash+1:]); err != nil {
		return attr, 0, 0, false
	}
	return name, lo, hi, true
}

func (c *Conn) completeRange(ctx context.Context, dn, name string, vals [][]byte, lo, hi int, controls []ldap.Control) ([][]byte, error) {
	for guard := 0; hi >= 0; guard++ {
		if guard > 10000 {
			return nil, errors.New("too many range chunks")
		}
		next := fmt.Sprintf("%s;range=%d-*", name, hi+1)
		res, err := c.pagedSearch(ctx, dn, ldap.ScopeBaseObject, "(objectClass=*)", []string{next}, controls, 0)
		if err != nil {
			return nil, err
		}
		if len(res) == 0 {
			break
		}
		found := false
		for _, a := range res[0].Attributes {
			n, l, h, ok := parseRange(a.Name)
			if !ok || !strings.EqualFold(n, name) {
				continue
			}
			if l != hi+1 {
				return nil, fmt.Errorf("server returned range starting at %d, expected %d", l, hi+1)
			}
			vals = append(vals, a.ByteValues...)
			hi, found = h, true
		}
		if !found {
			break
		}
	}
	_ = lo
	return vals, nil
}

// sdFlagsControl encodes LDAP_SERVER_SD_FLAGS_OID: controlValue is the BER
// encoding of SEQUENCE { Flags INTEGER }. Non-critical, so a server without
// the control still answers (with its default parts).
type sdFlags uint32

func sdFlagsControl(f uint32) ldap.Control { return sdFlags(f) }

func (sdFlags) GetControlType() string { return OIDSDFlags }

func (f sdFlags) Encode() *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDSDFlags, "Control Type (SD flags)"))
	val := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (SD flags)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlagsRequestValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(f), "Flags"))
	val.AppendChild(seq)
	p.AppendChild(val)
	return p
}

func (f sdFlags) String() string {
	return fmt.Sprintf("Control Type: SD flags (%q) Flags: %#x", OIDSDFlags, uint32(f))
}

// Queries reports how many LDAP searches this session has issued (for the run log).
func (c *Conn) Queries() int { return c.queries }

// Requests reports wire-level requests (each page and range chunk counts).
func (c *Conn) Requests() int { return c.requests }

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
	entries, err := c.pagedSearch(ctx, base, scope, filter, attrs, nil, page)
	if err != nil {
		return nil, err
	}
	return &ldap.SearchResult{Entries: entries}, nil
}

// pagedSearch issues one search, paging with the simple paged-results control
// when page > 0. Every page is one request and passes through the throttle,
// so --max-qps limits real load on the DC rather than logical searches.
func (c *Conn) pagedSearch(ctx context.Context, base string, scope int, filter string, attrs []string, controls []ldap.Control, page uint32) ([]*ldap.Entry, error) {
	c.queries++
	var paging *ldap.ControlPaging
	ctrls := append([]ldap.Control(nil), controls...)
	if page > 0 {
		paging = ldap.NewControlPaging(page)
		ctrls = append(ctrls, paging)
	}
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, ctrls)
	var out []*ldap.Entry
	for {
		if err := c.wait(ctx); err != nil {
			return out, err
		}
		c.requests++
		res, err := c.c.Search(req)
		if res != nil {
			out = append(out, res.Entries...)
		}
		if err != nil {
			return out, err
		}
		if paging == nil {
			return out, nil
		}
		pr, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(pr.Cookie) == 0 {
			return out, nil
		}
		paging.SetCookie(pr.Cookie)
	}
}

// wait enforces MaxQPS between requests and honours cancellation.
func (c *Conn) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.opts.MaxQPS <= 0 {
		return nil
	}
	gap := time.Second / time.Duration(c.opts.MaxQPS)
	if d := time.Until(c.last.Add(gap)); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	c.last = time.Now()
	return nil
}
