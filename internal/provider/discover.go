package provider

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// DC discovery from DNS SRV records, shared by `scan` and the web UI so a
// domain name alone is enough to start a scan on a domain-joined machine (or
// any machine that uses the domain's DNS).
//
// Active Directory and Samba AD DC publish the DC-specific locator record
// _ldap._tcp.dc._msdcs.<domain>; FreeIPA and plain LDAP directories publish
// only _ldap._tcp.<domain>. The DC-specific record is preferred so a generic
// LDAP server in the same DNS zone is never picked over a domain controller.

// Hooks, replaced in tests.
var (
	lookupSRV = func(ctx context.Context, name string) ([]*net.SRV, error) {
		_, addrs, err := net.DefaultResolver.LookupSRV(ctx, "", "", name)
		return addrs, err
	}
	reachable = func(ctx context.Context, host string) bool {
		d := net.Dialer{Timeout: 3 * time.Second}
		for _, port := range []string{"636", "389"} {
			if c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port)); err == nil {
				c.Close() // TCP connect only: nothing is sent to the server
				return true
			}
		}
		return false
	}
)

// srvRecords lists the locator records tried, most specific first.
func srvRecords(domain string) []string {
	return []string{"_ldap._tcp.dc._msdcs." + domain, "_ldap._tcp." + domain}
}

// DiscoverDCs returns the domain controllers DNS advertises for a domain, in
// SRV order (lowest priority first, then highest weight, then name for a
// stable result), de-duplicated. It reports which record answered.
func DiscoverDCs(ctx context.Context, domain string) (hosts []string, record string, err error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return nil, "", fmt.Errorf("no domain given")
	}
	for _, name := range srvRecords(domain) {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, lerr := lookupSRV(c, name)
		cancel()
		if lerr != nil || len(addrs) == 0 {
			continue
		}
		sort.SliceStable(addrs, func(i, j int) bool {
			if addrs[i].Priority != addrs[j].Priority {
				return addrs[i].Priority < addrs[j].Priority
			}
			if addrs[i].Weight != addrs[j].Weight {
				return addrs[i].Weight > addrs[j].Weight
			}
			return addrs[i].Target < addrs[j].Target
		})
		seen := map[string]bool{}
		for _, a := range addrs {
			h := strings.TrimSuffix(strings.ToLower(a.Target), ".")
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			hosts = append(hosts, h)
		}
		if len(hosts) > 0 {
			return hosts, name, nil
		}
	}
	return nil, "", fmt.Errorf("DNS has no domain controller records for %s (looked up %s): this computer does not use the domain's DNS servers — point it at them, or pass --server with the DC's name or IP address",
		domain, strings.Join(srvRecords(domain), " and "))
}

// DiscoverDC returns the first advertised DC that accepts a TCP connection on
// 636 or 389, so a DC that is down or firewalled is skipped. When none
// answers, the first in SRV order is returned and the caller's connection
// attempt reports the real error.
func DiscoverDC(ctx context.Context, domain string) (host, record string, err error) {
	hosts, record, err := DiscoverDCs(ctx, domain)
	if err != nil {
		return "", "", err
	}
	const maxProbe = 5
	for i, h := range hosts {
		if i == maxProbe {
			break
		}
		if reachable(ctx, h) {
			return h, record, nil
		}
	}
	return hosts[0], record, nil
}

// ResolveServer fills t.Server from DNS when only the domain is known. It is a
// no-op when a server is already given, and returns a note naming the DC that
// was chosen (empty when nothing changed).
func ResolveServer(ctx context.Context, t *Target) (string, error) {
	if strings.TrimSpace(t.Server) != "" {
		return "", nil
	}
	if strings.TrimSpace(t.Domain) == "" {
		return "", fmt.Errorf("no target: pass --domain (the DC is then found through DNS) or --server")
	}
	host, record, err := DiscoverDC(ctx, t.Domain)
	if err != nil {
		return "", err
	}
	t.Server = host
	return fmt.Sprintf("domain controller %s found through DNS (%s)", host, record), nil
}
