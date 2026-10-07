# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for a security problem in Directory Auditor.

Until a dedicated address exists, report privately through GitHub's
"Report a vulnerability" (Security → Advisories → New draft) on this repository. You will get
an acknowledgement within 72 hours and a fix or a mitigation plan within 30 days for issues
that affect users' directories or the read-only guarantee.

## Scope

In scope: anything that breaks the safety contract in the README — a write path to a
directory, SYSVOL, DNS or registry; credential leakage; data leaving the machine; a check pack
loading without a valid signature; XSS in the report or wizard from directory-sourced data;
denial of service against a domain controller caused by the collector.

Out of scope: findings about the *target* directory (that is what the tool reports),
and issues in third-party dependencies already tracked upstream (report them there; tell us so
we can pin).

## Supported versions

Pre-release. Every release is signed; verify before running
(see the review pack shipped with each release once releases exist).
