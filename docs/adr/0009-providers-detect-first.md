# ADR-0009: One provider per directory type, chosen by fingerprint before anything else

**Status:** accepted (2026-10-15, recording a decision taken this month) · approach §4

## Context
Active Directory and Samba AD DC both answer LDAP with AD-shaped data, and FreeIPA/ALD Pro
answers with a different schema. Valid credentials say nothing about the server type. Running
AD checks against Samba produces false findings (Samba lacks some objects and attributes and
has its own defaults), and running nothing because the user picked the wrong `--provider`
wastes the run.

## Decision
- Separate providers: `ad`, `samba`, `freeipa`, each with its own collection logic and check list.
- `provider.Pick` always fingerprints the server first (rootDSE vendor/version and
  capability attributes → `Detect`), whatever the user asked for.
- `--provider auto` (default) uses the detected type. An explicit `--provider` that conflicts
  with the detection is overridden, and the run says so ("requested --provider ad, but the
  server is samba — using samba so the right checks apply"). An explicit provider is used as
  given only when the type cannot be confirmed, again with a note.
- The detected type is shown to the user (web wizard and console) and recorded in the snapshot.

## Alternatives
- **Trust `--provider` as given** — rejected: one wrong flag yields a wrong report that looks right.
- **One generic LDAP provider with per-check guards** — rejected: every check would carry
  vendor branches; check lists could not be audited per directory type.
- **Fail on mismatch** — rejected: the tool knows the right answer, so stopping only costs the
  user another run.

## Consequences
- Fingerprinting must be maintained as vendors change rootDSE output; a detection miss falls
  back to the explicit choice with a visible warning.
- Adding a directory type (Entra ID later) means a new provider plus a detector.
