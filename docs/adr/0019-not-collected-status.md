# ADR-0019: A check whose input could not be read reports "not collected", never "passed"

**Status:** proposed (2026-10-15) · requirement AR-12 (honest states)

## Context
A tier-0 account often cannot read some attributes or security descriptors (confidential
attributes, restricted ACLs, missing schema). Today a CEL condition over an absent attribute
evaluates to false and the check counts as passed. That is a silent false negative — the
report claims something is fine that was never seen.

## Decision (proposed)
- The collector records, per object and attribute, whether it was readable.
- A check result has four states: finding, passed, **not collected** (input unreadable or
  tier not run), error.
- Helpers such as `sd_readable(obj)` become mandatory guards, and the engine marks a check
  "not collected" when any required attribute is unreadable for all matched objects.
- The score excludes "not collected" checks and the report lists them with the tier needed.

## Alternatives
- **Status quo (absent = pass)** — rejected: dishonest results.
- **Absent = finding** — rejected: floods ordinary-user runs with false positives.

## Consequences
- Snapshot schema change (minor version) to carry readability.
- Lower-looking coverage on first runs, but every "passed" becomes trustworthy.
