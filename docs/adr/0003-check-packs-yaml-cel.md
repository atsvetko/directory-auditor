# ADR-0003: Checks are signed YAML packs with CEL conditions

**Status:** accepted (2026-10-07) · requirement AR-8, approach §3

## Context
"Signed to prevent modification" is only meaningful if the signed thing is small, readable
and separate from the engine. Admins will not review a 20 000-line engine, but they will read
a 40-line YAML file.

## Decision
One check per YAML file (`internal/check.Pack`): metadata, an LDAP query (base, scope,
filter, attributes), a CEL condition over the matched object, evidence attributes, ATT&CK and
БДУ mappings, bilingual remediation (why / abuse / fix / verify) and primary references.
Packs are Ed25519-signed; the engine refuses unsigned packs unless `--allow-unsigned` is given,
and then shows a banner in the report.

Complex checks (GPO parsing, trust graph, PKI analysis, attack paths) are named engine
implementations that packs reference by name with parameters — still declarative at the pack
level.

## Alternatives rejected
- Packs with embedded scripting (Lua/Starlark): Turing-complete, unreviewable, a sandbox to
  maintain.
- All checks in Go: contributors must write Go; the signed, readable unit disappears.
- `expr-lang/expr` instead of CEL: lighter, but CEL has a type checker, cost limits and a
  broader audit history. Can be revisited if binary size becomes a problem.

## Consequences
- The query manifest and permissions matrix of the review pack are generated from packs.
- A schema validator for attribute names (against Microsoft's published schema) is required
  at the catalogue stage to stop invented attributes.
