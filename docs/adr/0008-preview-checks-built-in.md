# ADR-0008: Unverified catalogue entries ship inside the binary as "preview" checks

**Status:** accepted (2026-10-15, recording a decision taken during the first check batches) · supplements ADR-0003, ADR-0006

## Context
ADR-0003 and ADR-0006 make signed packs the trust unit, and catalogue entries carry
`verified_by` / `verified_on` for a human reviewer. No signing key and no verified entries
exist yet, yet the tool must produce useful results now — in the lab, for early users, and to
validate the catalogue itself. Hiding every check behind signing would make the first run empty.

## Decision
- Catalogue entries that have a `condition_cel` are compiled into the binary and evaluated as
  **preview** checks: unsigned, `status: draft`, `verified_by: ''`.
- Every surface labels them: the console prints "preview checks: N (unverified catalogue
  entries — confirm findings before acting)", the report and web UI mark each finding, and
  `dirauditor manifest` lists them separately.
- `--no-preview` turns them off so only signed packs run. `--allow-unsigned` remains a
  development-only switch for external unsigned packs.
- Each entry's `expect:` list is a regression fixture against the synthetic snapshot.
- An entry leaves preview only when a human fills `verified_by` and the check is shipped in a
  signed pack.

## Alternatives
- **Only signed packs, no preview** — rejected: zero checks until the signing pipeline and
  reviews exist; the product cannot be tried (G0).
- **Ship unverified checks as normal findings** — rejected: an unreviewed false positive in a
  bank's report costs more trust than a missing check.
- **Separate "experimental" download** — rejected: a second artefact to sign and explain.

## Consequences
- Findings from preview checks can be wrong; the labelling is the mitigation and must never
  be dropped from any output format.
- The read-only gate (ADR-0004) still covers preview checks: CEL cannot write.
- A backlog of human verification builds up; it is visible in `dirauditor manifest`.
