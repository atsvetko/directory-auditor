# ADR-0012: Three privilege tiers; each check declares its tier; admin config is local and opt-in

**Status:** accepted (2026-10-15) · approach §5, open question 11/12 (defaults adopted)

## Context
The first-run user has an ordinary domain account. Many important facts are readable by any
user over LDAP; some need SYSVOL or network probes; some (Samba `smb.conf`, DC host settings)
need administrator or local access. Asking for admin rights up front blocks adoption in
regulated companies.

## Decision
- Tier 0: ordinary user, LDAP only (default, quick scan). Tier 1: adds SYSVOL reads and
  read-only network probes. Tier 2: administrator or local configuration.
- Every catalogue entry declares `tier`; the run reports which tiers were collected and which
  checks were skipped for lack of a tier.
- Samba: the default is a remote LDAP scan like AD. Tier-2 configuration is read only when
  explicitly asked — `--smbconf PATH` or `--local` on the DC itself; nothing is fetched
  remotely with admin credentials.

## Alternatives
- **Two modes (user / admin)** — rejected: hides the large middle ground of tier 1.
- **Remote admin collection (RPC/WinRM/SSH) in v1** — deferred: credentials in flight and
  write-capable protocol libraries conflict with ADR-0004 until designed separately.

## Consequences
- Reports must state coverage honestly (see ADR-0019).
- Tier-1 work (SYSVOL, SMB/LDAP signing probes) is planned but paused; it needs its own
  review of what is read and how results are presented.
