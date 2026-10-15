# ADR-0011: Check IDs are stable and allocated in blocks per domain

**Status:** accepted (2026-10-15) · requirement AR-8 (stable check IDs)

## Context
Exceptions, diffs between runs, SIEM rules and compliance mappings all key on check IDs.
An ID that changes or is reused breaks every one of them. The catalogue grows in parallel
across domains, often from several sessions at once.

## Decision
- IDs are `DSA-NNNN`, never reused, never renumbered.
- Blocks: directory-core `00xx`; FreeIPA `01xx`; Samba `02xx`; DNS `0301+`;
  Group Policy `0401–0499` (reserved); PKI / AD CS `0501–0599`, where the last two digits
  equal the ESC number (ESC12 is a deliberate gap).
- A retired check keeps its ID with a retired status.

## Alternatives
- **Single sequence** — rejected: parallel work collides and the ID says nothing about the domain.
- **Semantic slugs (e.g. `ad-krbtgt-age`)** — rejected: slugs invite renames; numbers do not.
- **Reuse incumbent numbering** — rejected by ADR-0007.

## Consequences
- Blocks can run out (directory-core already uses most of `00xx`); a domain that overflows
  gets a new block recorded in `catalogue/README.md`, not a renumbering.
