// Package doctor diagnoses why a connection to a directory fails and prints the
// cause and a one-line fix (requirement AR-3). The skeleton covers DNS SRV,
// TCP reachability and the TLS certificate; Kerberos and LDAP-signing checks
// arrive with the AD provider at K3.
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

	// 2. Time skew (Kerberos tolerates 5 minutes) — only a hint until Kerberos arrives.
	// 3. TCP 389 / 636.
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

	// 4. TLS on 636: certificate chain and fingerprint.
	s := Step{Name: "LDAPS certificate " + server}
	d := &net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server, "636"))
	if err != nil {
		s.Cause = "port 636 unreachable"
		s.Fix = "use StartTLS on 389 (--starttls) if LDAPS is not enabled on the DC"
		steps = append(steps, s)
		return steps
	}
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
				s.Info = fmt.Sprintf("subject %s, issuer %s, SHA-256 %s", c.Subject.CommonName, c.Issuer.CommonName, hex.EncodeToString(sum[:]))
			}
			tc2.Close()
		}
		s.Cause = "certificate not trusted by this host: " + err.Error()
		s.Fix = "import the domain CA into this host's trust store, or pin the fingerprint shown above with --pin <sha256>"
	} else {
		st := tc.ConnectionState()
		if len(st.PeerCertificates) > 0 {
			c := st.PeerCertificates[0]
			sum := sha256.Sum256(c.Raw)
			s.Info = fmt.Sprintf("subject %s, issuer %s, expires %s, SHA-256 %s", c.Subject.CommonName, c.Issuer.CommonName, c.NotAfter.Format("2006-01-02"), hex.EncodeToString(sum[:]))
		}
		s.OK = true
		tc.Close()
	}
	steps = append(steps, s)
	return steps
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
