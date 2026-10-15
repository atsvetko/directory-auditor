# ADR-0010: Which provider runs a check is decided by the catalogue, with an explicit override

**Status:** accepted (2026-10-15) · follows ADR-0009

## Context
With separate providers (ADR-0009) each check must be bound to the directory types it applies
to. Most directory-core checks hold for both AD and Samba AD DC; some (dMSA, DSA-0073/0074)
exist only in the Windows Server 2025 schema; FreeIPA has its own schema.

## Decision
- The catalogue domain gives the default (`Entry.providerList` in `internal/catalogue`):
  `samba` → `[samba]`; `freeipa` → `[freeipa]`; every other domain (`directory-core`, `dns`,
  `pki`, …) → `[ad, samba]`.
- An entry may narrow or widen this with `providers: [...]`; the loader rejects unknown names.
  The override carries a comment explaining why (e.g. "dMSA exists only in the Windows Server
  2025 schema; Samba AD DC does not implement it").
- The compiled check carries its provider list; the engine runs only checks whose list
  contains the active provider.

## Alternatives
- **Provider list on every entry** — rejected: noise on the 80 % of entries that follow the domain.
- **Runtime feature probing inside conditions only** — kept as a second line (e.g.
  `schema_guid(...) != ""`) but not sufficient: a check that is irrelevant to a directory type
  should not even be listed for it.

## Consequences
- The checks list per provider is reviewable from YAML alone.
- A wrong domain default silently hides or exposes a check for a whole provider; the table
  has no dedicated unit test yet (follow-up).
