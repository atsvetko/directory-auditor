# ADR-0014: The domain controller is found through DNS SRV records when only the domain is given

**Status:** accepted (2026-10-15) · `internal/provider/discover.go`

## Context
Admins know their domain name, not necessarily which DC to point at. Hard-coding a server makes
the first run fail when that DC is down or firewalled.

## Decision
- With `--domain` and no `--server`, look up `_ldap._tcp.dc._msdcs.<domain>` (AD, Samba),
  then `_ldap._tcp.<domain>` (FreeIPA, plain LDAP). The DC-specific record wins so a generic
  LDAP server in the same zone is never chosen over a DC.
- Order by SRV priority, then weight, then name; de-duplicate.
- Probe at most five hosts with a TCP connect to 636, then 389 (nothing is sent); take the
  first that answers. If none answers, use the first and let the bind report the real error.
- An explicit `--server` is always kept. The chosen DC and the record that answered are
  reported. The same code serves CLI and web UI.
- With no records, the error explains the cause (wrong DNS servers) and the fix (`--server`).

## Alternatives
- **DsGetDcName / CLDAP ping (site-aware)** — better DC choice on Windows; rejected for now:
  platform-specific or adds a UDP protocol; may be added later behind the same function.
- **Require `--server`** — rejected: worse first run.

## Consequences
- The selected DC may be in a remote site; the scan still works, just slower.
- The probe opens TCP connections to several DCs; this is listed in the network sheet.
