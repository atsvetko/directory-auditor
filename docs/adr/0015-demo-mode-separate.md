# ADR-0015: Demo data is an explicit mode; a failed connection never falls back to it

**Status:** accepted (2026-10-15) · refines open question 25 / AR-9

## Context
`--demo` and the web UI's "Try with demo data" run the full pipeline on a bundled synthetic
snapshot (`lab.example`). In the lab the wizard showed a detected domain, the connection
failed, and the scan quietly ran on demo data — the screen looked like a real result. A
silent substitution of synthetic data is the worst possible failure for an auditor.

## Decision
- Demo is a separate connection mode (`mode: demo`) chosen on purpose, labelled "synthetic
  data" everywhere, and its run log stays in memory.
- Every connect attempt resets the previous target, so an earlier demo session cannot carry
  over into a real one.
- If a domain is detected or entered and is unreachable, the connect step fails with the
  reason; it never offers results from another source. A regression test covers this.

## Alternatives
- **Fallback to demo with a banner** — rejected: banners get missed, screenshots get shared.
- **Remove demo from the web UI** — rejected: the demo is the zero-risk first look (AR-9).

## Consequences
- The user sees an error sooner; error texts must teach the fix (DNS, firewall, `--server`).
