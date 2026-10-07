# Tier-0 definition used by the catalogue

Several entries (DSA-0002, 0007, 0009, 0014, 0015, 0016) need a single, shared answer to
"is this principal or object Tier 0?". This file is that answer. RIDs are from Microsoft's
well-known SIDs table; the protected-group list follows Microsoft's Appendix C.

## Tier-0 groups (members resolved transitively, including primaryGroupID)

| Group | Kind | RID / SID |
|---|---|---|
| Administrators | built-in alias | S-1-5-32-544 (0x220) |
| Account Operators | built-in alias | S-1-5-32-548 (0x224) |
| Server Operators | built-in alias | S-1-5-32-549 (0x225) |
| Print Operators | built-in alias | S-1-5-32-550 (0x226) |
| Backup Operators | built-in alias | S-1-5-32-551 (0x227) |
| Replicator | built-in alias | S-1-5-32-552 (0x228) |
| Domain Admins | domain group | RID 512 (0x200) |
| Schema Admins | domain group (forest root) | RID 518 (0x206) |
| Enterprise Admins | domain group (forest root) | RID 519 (0x207) |
| Domain Controllers | domain group | RID 516 (0x204) |
| Read-only Domain Controllers | domain group | RID 521 (0x209) — Tier 0 for exposure, not for trust |
| Key Admins | domain group | RID 526 (0x20E) |
| Enterprise Key Admins | domain group (forest root) | RID 527 (0x20F) |

Not Tier 0 by itself, but referenced: **Protected Users**, RID 525 (0x20D).

## Tier-0 principals that are not group members

- SYSTEM (S-1-5-18), Enterprise Domain Controllers (S-1-5-9), the built-in Administrator
  account (RID 500, 0x1F4), the krbtgt account and RODC krbtgt_<n> accounts.
- Any principal holding DS-Replication-Get-Changes-All on the domain head (DSA-0014)
  is *treated as* Tier 0 for path analysis, and is also reported as a finding.

## Tier-0 objects (whose ACLs are checked by DSA-0015)

Domain naming-context head · CN=AdminSDHolder,CN=System · every group above and its
members · OU=Domain Controllers and DC computer objects · krbtgt · GPOs linked to the
domain head or to OU=Domain Controllers (Group Policy batch).

## Open points for verification

- The group list now matches Appendix C for Server 2016–2025 (Account Operators,
  Administrator, Administrators, Backup Operators, Domain Admins, Domain Controllers,
  Enterprise Admins, Enterprise Key Admins, Key Admins, Krbtgt, Print Operators,
  Read-only Domain Controllers, Replicator, Schema Admins, Server Operators).
  Confirm the Samba AD DC equivalent in the lab.
- krbtgt RID (502) is not in Microsoft's well-known SIDs table; the catalogue matches
  krbtgt by sAMAccountName until a primary source for the RID is found.
- Exchange, AD CS and sync products add privileged groups (e.g. Exchange Windows
  Permissions); report them as findings rather than adding them to Tier 0 silently.

## Sources

- Microsoft Learn — Well-known SIDs: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
- Microsoft Learn — Appendix C: Protected accounts and groups in Active Directory:
  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
