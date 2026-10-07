# ADR-0002: Collection and analysis are separated by a versioned snapshot

**Status:** accepted (2026-10-07) · requirement AR-13

## Context
Most adoption features — `--demo`, offline collector, re-analysis with new packs, diff and
trend, redacted snapshots for support, test fixtures, consultant mode — need the same thing:
analysis that does not touch the live directory.

## Decision
`collect` writes a zstd-compressed JSON snapshot with a semver schema (`internal/snapshot`).
`analyse` runs every check against the snapshot only. The report embeds the snapshot hash.
Readers accept the same major version and migrate older minors.

## Consequences
- Re-analysis costs seconds and causes no DC load and no SOC alerts.
- Snapshots are as sensitive as reports: they inherit encryption, redaction and
  classification requirements.
- Snapshots of very large forests need attribute allow-lists and compression; target ≤ 50 MB
  for a 50 k-object domain.
- The collector needs an LDAP filter re-implementation to apply pack queries to snapshots
  (`internal/check/filter.go`); it is small and fully tested.
