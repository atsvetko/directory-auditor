// Package ldapx is the only place in the engine that talks LDAP. It exposes a
// deliberately read-only surface: Search and RootDSE. There is no Modify, Add,
// Delete or ModifyDN method here, and scripts/readonly-check.sh verifies that
// none of go-ldap's write entry points survive linking into the release binary
// (requirement N-9, review-pack artefact 11).
//
// Never convert *Conn (or anything holding it) to an interface: the linker then
// keeps every method of the embedded *ldap.Conn, write methods included, and the
// gate fails. Pass method values instead (see provider/ad.searcher).
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

// TLSMode says how the connection is protected.
type TLSMode string

const (
	// TLSAuto tries LDAPS, then StartTLS, then plain LDAP — where a Kerberos
	// bind negotiates a SASL security layer (sealing) so the session is still
	// encrypted, and a password is refused unless InsecurePlaintext is set.
	TLSAuto     TLSMode = "auto"
	TLSLDAPS    TLSMode = "ldaps"
	TLSStartTLS TLSMode = "starttls"
	TLSNone     TLSMode = "none"
)

// Options controls how a connection is made.
type Options struct {
	Server            string        // host or host:port
	TLS               TLSMode       // "" = TLSAuto
	InsecurePlaintext bool          // allow a password (simple bind) on an unencrypted connection (labs only)
	PinSHA256         string        // optional hex SHA-256 of the server certificate (self-signed CAs)
	ServerName        string        // SNI / verification name when it differs from Server
	Timeout           time.Duration // dial and per-request timeout
	MaxQPS            int           // 0 = unlimited; collectors throttle to this
	Domain            string        // DNS domain; the Kerberos realm for --user with a password
}

// ErrCertificate marks a TLS failure caused by the server certificate (not
// trusted, name mismatch, pin mismatch): the fix is trust or --pin, never a
// fallback to an unencrypted connection.
var ErrCertificate = errors.New("server certificate not accepted")

// Conn is a read-only LDAP session.
type Conn struct {
	c        *ldap.Conn
	sec      *secConn   // the plaintext connection, when there is no TLS
	gss      gssContext // the Kerberos context after a Kerberos bind
	queries  int        // logical searches
	requests int        // wire requests (pages, range chunks)
	last     time.Time
	opts     Options

	transport  string // ldaps | starttls | ldap
	protection string // tls | sasl-seal | sasl-sign | none
	noTLS      string // why TLS is not in use (auto mode)
}

// Transport describes how the session is protected, for reports and logs.
func (c *Conn) Transport() string {
	switch c.transport {
	case "ldaps":
		return "LDAPS"
	case "starttls":
		return "StartTLS"
	}
	switch c.protection {
	case "sasl-seal":
		return "LDAP, Kerberos-sealed (no TLS)"
	case "sasl-sign":
		return "LDAP, Kerberos-signed (no TLS)"
	}
	return "LDAP, unencrypted"
}

// Encrypted reports whether the session is confidential (TLS or SASL sealing).
func (c *Conn) Encrypted() bool { return c.transport != "ldap" || c.protection == "sasl-seal" }

// NoTLSReason says why the connection has no TLS ("" when it has).
func (c *Conn) NoTLSReason() string { return c.noTLS }

func (o Options) tlsConfig(host string) *tls.Config {
	serverName := o.ServerName
	if serverName == "" {
		serverName = host
	}
	cfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	if o.PinSHA256 != "" {
		pin := strings.ToLower(strings.ReplaceAll(o.PinSHA256, ":", ""))
		cfg.InsecureSkipVerify = true // verification is done by the pin below, not skipped
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
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
	return cfg
}

// certError reports whether a TLS failure is about the certificate (trust,
// name, pin) rather than the server not speaking TLS at all.
func certError(err error) bool {
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ce x509.CertificateInvalidError
	var ve *tls.CertificateVerificationError
	if errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ce) || errors.As(err, &ve) {
		return true
	}
	m := err.Error()
	return strings.Contains(m, "does not match pin") || strings.Contains(m, "x509:") || strings.Contains(m, "certificate")
}

// Dial opens a connection according to opts. It never binds; call
// BindKerberos or BindSimple explicitly so the identity used is always visible.
//
// In TLSAuto mode a server that offers no TLS at all (a Windows DC without a
// certificate is the common case) is reached over plain LDAP; the bind then
// decides what is acceptable there. A certificate the client does not trust
// is never a reason to fall back.
func Dial(ctx context.Context, opts Options) (*Conn, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.TLS == "" {
		opts.TLS = TLSAuto
	}
	host, port, err := net.SplitHostPort(opts.Server)
	if err != nil {
		host, port = opts.Server, ""
	}
	dialer := &net.Dialer{Timeout: opts.Timeout}
	tlsCfg := opts.tlsConfig(host)
	var reasons []string

	if opts.TLS == TLSAuto || opts.TLS == TLSLDAPS {
		p := port
		if p == "" {
			p = "636"
		}
		addr := net.JoinHostPort(host, p)
		c, err := ldap.DialURL("ldaps://"+addr, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsCfg))
		if err == nil {
			c.SetTimeout(opts.Timeout)
			return &Conn{c: c, opts: opts, transport: "ldaps", protection: "tls"}, nil
		}
		// A certificate problem hard-fails only when LDAPS was asked for
		// explicitly. In auto mode it is a reason to try the next transport:
		// Kerberos sealing there gives mutual authentication and
		// confidentiality without depending on the certificate.
		if certError(err) && opts.TLS == TLSLDAPS {
			return nil, fmt.Errorf("ldapx: LDAPS %s: %w: %v", addr, ErrCertificate, err)
		}
		if opts.TLS == TLSLDAPS {
			return nil, fmt.Errorf("ldapx: dial %s: %w", addr, err)
		}
		reasons = append(reasons, "LDAPS "+addr+": "+shortErr(err))
	}

	p := port
	if p == "" {
		p = "389"
	}
	addr := net.JoinHostPort(host, p)
	if opts.TLS == TLSAuto || opts.TLS == TLSStartTLS {
		c, err := ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(dialer))
		if err != nil {
			return nil, fmt.Errorf("ldapx: dial %s: %w%s", addr, err, after(reasons))
		}
		c.SetTimeout(opts.Timeout)
		err = c.StartTLS(tlsCfg)
		if err == nil {
			return &Conn{c: c, opts: opts, transport: "starttls", protection: "tls"}, nil
		}
		c.Close()
		if certError(err) && opts.TLS == TLSStartTLS {
			return nil, fmt.Errorf("ldapx: StartTLS %s: %w: %v", addr, ErrCertificate, err)
		}
		if opts.TLS == TLSStartTLS {
			return nil, fmt.Errorf("ldapx: StartTLS %s: %w", addr, err)
		}
		reasons = append(reasons, "StartTLS: "+shortErr(err))
	}

	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ldapx: dial %s: %w%s", addr, err, after(reasons))
	}
	sec := &secConn{Conn: raw}
	c := ldap.NewConn(sec, false)
	c.SetTimeout(opts.Timeout)
	c.Start()
	return &Conn{c: c, sec: sec, opts: opts, transport: "ldap", protection: "none", noTLS: strings.Join(reasons, "; ")}, nil
}

func shortErr(err error) string {
	m := err.Error()
	for _, cut := range []string{"LDAP Result Code 200 \"Network Error\": ", "ldap: "} {
		m = strings.ReplaceAll(m, cut, "")
	}
	return m
}

func after(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return " (after " + strings.Join(reasons, "; ") + ")"
}

// BindSimple authenticates with a DN or UPN and password. The password is
// used once and not retained by this package. On an unencrypted connection it
// is refused unless Options.InsecurePlaintext is set: a password must not
// cross the network in the clear.
func (c *Conn) BindSimple(user, password string) error {
	if password == "" {
		return errors.New("ldapx: refusing an unauthenticated (empty-password) simple bind")
	}
	if c.transport == "ldap" && !c.opts.InsecurePlaintext {
		return fmt.Errorf("ldapx: refusing to send a password over an unencrypted connection (%s); use Kerberos (the current logon, or --user with the domain as Kerberos realm), or --insecure-plaintext in a lab", c.noTLS)
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
		"vendorVersion", "isGlobalCatalogReady", "highestCommittedUSN", "ldapServiceName", "currentTime",
		"namingContexts", "supportedExtension",
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
	// SizeLimit caps the number of entries the server returns (0 = no cap);
	// used by probes that only need to know whether anything is readable.
	SizeLimit int
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
	page := uint32(500)
	if o.SizeLimit > 0 {
		page = 0 // a capped probe is a single request
	}
	res, err := c.pagedSearchLimited(ctx, baseDN, int(scope), filter, attrs, controls, page, o.SizeLimit)
	if err != nil && !(o.SizeLimit > 0 && ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)) {
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

// Close ends the session and releases the Kerberos context, if any.
func (c *Conn) Close() {
	c.c.Close()
	if c.gss != nil {
		_ = c.gss.Close()
		c.gss = nil
	}
}

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
	return c.pagedSearchLimited(ctx, base, scope, filter, attrs, controls, page, 0)
}

func (c *Conn) pagedSearchLimited(ctx context.Context, base string, scope int, filter string, attrs []string, controls []ldap.Control, page uint32, sizeLimit int) ([]*ldap.Entry, error) {
	c.queries++
	var paging *ldap.ControlPaging
	ctrls := append([]ldap.Control(nil), controls...)
	if page > 0 {
		paging = ldap.NewControlPaging(page)
		ctrls = append(ctrls, paging)
	}
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, sizeLimit, 0, false, filter, attrs, ctrls)
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
