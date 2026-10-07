# ADR-0004: Read-only is a build-time property, not a promise

**Status:** accepted (2026-10-07) · requirements N-8, N-9; review-pack artefact 11

## Context
Every auditor says it is read-only. Approvers in banks and telecoms have heard it before.

## Decision
- All LDAP traffic goes through `internal/ldapx`, whose public surface has no write method.
- `scripts/readonly-check.sh` lists the symbols of the built binary with `go tool nm` and
  fails if any of go-ldap's write entry points (Modify, Add, Del, ModifyDN, PasswordModify and
  their request constructors) — or, later, SMB write, DNS update or registry write symbols —
  are present. Go's linker eliminates unreachable methods, so a clean engine produces a clean
  symbol table. The script is part of CI and of the per-release review pack, and any reviewer
  can run it on the downloaded binary.
- No exploit code, no coercion, no relay, no authentication attempts against user accounts.
  "Verify this finding" buttons are rejected by design.

## Consequences
- A future feature that needs a write (there is none planned) requires a new ADR and a new
  binary name; it will not be added to `dirauditor`.
- The denylist must be extended whenever a new protocol library is added.
