// Package doctor diagnoses why a connection to a directory fails and prints the
// cause and a one-line fix (requirement AR-3): DNS SRV, TCP reachability, the
// TLS certificate, an anonymous rootDSE read (server type) and clock skew
// against the DC, which breaks Kerberos beyond five minutes.
package doctor

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/atsvetko/directory-auditor/internal/ldapx"
)

// Step is one diagnostic with a verdict and, on failure, a cause and a fix.
type Step struct {
	Name  string
	OK    bool
	Info  string
	Cause string
	Fix   string
}

// Run executes the diagnostics for a domain (and optionally a specific server).
func Run(ctx context.Context, domain, server string) []Step {
	var steps []Step
	timeout := 5 * time.Second
	resolver := &net.Resolver{}

	// 1. DNS SRV for LDAP and Kerberos.
	if domain != "" {
		for _, svc := range []string{"_ldap._tcp.", "_kerberos._tcp."} {
			cctx, cancel := context.WithTimeout(ctx, timeout)
			_, addrs, err := resolver.LookupSRV(cctx, "", "", svc+domain)
			cancel()
			s := Step{Name: "DNS SRV " + svc + domain}
			if err != nil || len(addrs) == 0 {
				s.Cause = "no SRV records for " + svc + domain
				s.Fix = "this host does not use the domain's DNS; point it at a domain DNS server or pass --server <dc-fqdn>"
			} else {
				s.OK = true
				names := make([]string, 0, len(addrs))
				for _, a := range addrs {
					names = append(names, strings.TrimSuffix(a.Target, "."))
				}
				sort.Strings(names)
				s.Info = strings.Join(names, ", ")
				if server == "" && svc == "_ldap._tcp." {
					server = names[0]
				}
			}
			steps = append(steps, s)
		}
	}
	if server == "" {
		steps = append(steps, Step{Name: "server", Cause: "no server to test", Fix: "pass --server <dc-fqdn> or --domain with working SRV records"})
		return steps
	}

	// 2. TCP 389 / 636.
	for _, port := range []string{"389", "636"} {
		s := Step{Name: "TCP " + net.JoinHostPort(server, port)}
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server, port))
		if err != nil {
			s.Cause = err.Error()
			s.Fix = "a firewall blocks the port, the name does not resolve, or the DC is down; try from a host in the same site or use the other port"
		} else {
			conn.Close()
			s.OK = true
		}
		steps = append(steps, s)
	}

	// 3. TLS on 636: certificate chain and fingerprint.
	s := Step{Name: "LDAPS certificate " + server}
	d := &net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server, "636"))
	if err != nil {
		s.Cause = "port 636 unreachable"
		s.Fix = "LDAPS is not enabled on the DC (or a firewall blocks 636); the default mode falls back to StartTLS, then to plain LDAP with Kerberos signing and sealing"
		steps = append(steps, s)
		steps = append(steps, rootDSESteps(ctx, server, "", timeout, time.Now)...)
		return steps
	}
	var fingerprint string // of the leaf certificate, for the anonymous rootDSE read below
	tc := tls.Client(raw, &tls.Config{ServerName: server, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		// Retry without verification to show the fingerprint for pinning.
		raw.Close()
		raw2, err2 := d.DialContext(ctx, "tcp", net.JoinHostPort(server, "636"))
		if err2 == nil {
			tc2 := tls.Client(raw2, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // diagnostic only: shows the fingerprint, never used for a session
			if tc2.HandshakeContext(ctx) == nil && len(tc2.ConnectionState().PeerCertificates) > 0 {
				c := tc2.ConnectionState().PeerCertificates[0]
				sum := sha256.Sum256(c.Raw)
				fingerprint = hex.EncodeToString(sum[:])
				s.Info = fmt.Sprintf("subject %s, issuer %s, SHA-256 %s", c.Subject.CommonName, c.Issuer.CommonName, fingerprint)
			}
			tc2.Close()
		}
		if fingerprint == "" {
			// The port accepted the TCP connection but no TLS handshake
			// completed even without verification: there is no LDAPS listener
			// with a certificate behind it (a DC without a server certificate).
			s.Cause = "the DC accepts TCP on 636 but does not complete a TLS handshake: no server certificate is installed, so LDAPS is not offered (" + err.Error() + ")"
			s.Fix = "nothing to trust or pin; the default mode falls back to StartTLS, then to plain LDAP with Kerberos signing and sealing (the password path needs --insecure-plaintext, which sends it in clear). To enable LDAPS, install a server-authentication certificate on the DC"
			steps = append(steps, s)
			steps = append(steps, rootDSESteps(ctx, server, "", timeout, time.Now)...)
			return steps
		}
		s.Cause = "certificate not trusted by this host: " + err.Error()
		s.Fix = "import the domain CA into this host's trust store, or pin the fingerprint shown above with --pin <sha256>"
	} else {
		st := tc.ConnectionState()
		if len(st.PeerCertificates) > 0 {
			c := st.PeerCertificates[0]
			sum := sha256.Sum256(c.Raw)
			fingerprint = hex.EncodeToString(sum[:])
			s.Info = fmt.Sprintf("subject %s, issuer %s, expires %s, SHA-256 %s", c.Subject.CommonName, c.Issuer.CommonName, c.NotAfter.Format("2006-01-02"), fingerprint)
		}
		s.OK = true
		tc.Close()
	}
	steps = append(steps, s)
	if fingerprint != "" {
		steps = append(steps, rootDSESteps(ctx, server, fingerprint, timeout, time.Now)...)
	}
	return steps
}

// rootDSESteps reads the rootDSE anonymously — over LDAPS pinned to the
// certificate just inspected when there is one, otherwise over StartTLS or
// plain LDAP as the scan would — no bind, no credentials — to identify the
// server and compare its clock with ours.
func rootDSESteps(ctx context.Context, server, pin string, timeout time.Duration, now func() time.Time) []Step {
	s := Step{Name: "LDAP rootDSE " + server}
	mode := ldapx.TLSLDAPS
	if pin == "" {
		mode = ldapx.TLSAuto
	}
	c, err := ldapx.Dial(ctx, ldapx.Options{Server: server, TLS: mode, PinSHA256: pin, Timeout: timeout})
	if err != nil {
		s.Cause, s.Fix = err.Error(), "the port answered but not as LDAP; check that the host is a directory server"
		return []Step{s}
	}
	defer c.Close()
	root, err := c.RootDSE(ctx)
	if err != nil {
		s.Cause, s.Fix = err.Error(), "the server refused an anonymous rootDSE read; collection still works after bind"
		return []Step{s}
	}
	s.OK = true
	s.Info = describeRoot(root) + " · via " + c.Transport()
	return []Step{s, skewStep(root["currentTime"], now())}
}

func describeRoot(root map[string]string) string {
	kind := "directory"
	switch {
	case strings.Contains(strings.ToLower(root["vendorName"]), "samba"):
		kind = "Samba AD DC " + root["vendorVersion"]
	case root["domainControllerFunctionality"] != "":
		kind = "Active Directory DC (functional level " + root["domainControllerFunctionality"] + ")"
	}
	if nc := root["defaultNamingContext"]; nc != "" {
		kind += ", " + nc
	}
	return kind
}

// skewStep compares the DC's currentTime with local time. Kerberos rejects
// requests when clocks differ by more than the realm's tolerance (5 minutes by
// default), which shows up as a confusing bind failure.
func skewStep(current string, local time.Time) Step {
	s := Step{Name: "clock skew vs DC"}
	dc, err := parseGeneralized(current)
	if err != nil {
		s.OK = true
		s.Info = "DC did not report currentTime; skipped"
		return s
	}
	d := local.Sub(dc)
	if d < 0 {
		d = -d
	}
	s.Info = fmt.Sprintf("DC %s, local %s, difference %s", dc.Format(time.RFC3339), local.UTC().Format(time.RFC3339), d.Round(time.Second))
	if d > 5*time.Minute {
		s.Cause = "clocks differ by more than 5 minutes; Kerberos sign-in (current logon) will fail"
		s.Fix = "sync this host's time with the domain (Windows: w32tm /resync; Linux: chronyc makestep) or use --user"
		return s
	}
	s.OK = true
	return s
}

func parseGeneralized(v string) (time.Time, error) {
	for _, layout := range []string{"20060102150405.0Z", "20060102150405Z", "20060102150405.0Z0700", "20060102150405Z0700"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unparsable time %q", v)
}

// Print writes the steps in a console-friendly form.
func Print(w io.Writer, steps []Step) (ok bool) {
	ok = true
	for _, s := range steps {
		if s.OK {
			fmt.Fprintf(w, "  OK   %s", s.Name)
			if s.Info != "" {
				fmt.Fprintf(w, " — %s", s.Info)
			}
			fmt.Fprintln(w)
			continue
		}
		ok = false
		fmt.Fprintf(w, "  FAIL %s\n       cause: %s\n       fix:   %s\n", s.Name, s.Cause, s.Fix)
		if s.Info != "" {
			fmt.Fprintf(w, "       info:  %s\n", s.Info)
		}
	}
	return ok
}
