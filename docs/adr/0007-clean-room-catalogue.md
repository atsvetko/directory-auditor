# ADR-0007: The check catalogue is built clean-room, from primary sources only

**Status:** accepted (2026-10-15, recording a decision taken 2026-10-07) · approach §9, [clean-room.md](../clean-room.md)

## Context
PingCastle (Netwrix, OSL 3.0, reciprocal) and Purple Knight (Semperis, closed source, EULA
forbids reverse engineering) define what admins expect from an AD auditor. The project must
reach comparable coverage while its Apache 2.0 licence stays beyond dispute. Facts and methods
are not protected by copyright (17 U.S.C. §102(b); ГК РФ ст. 1259 п. 5); expression is. Most
of the code is written by AI agents, so the protocol must hold for them as well as for people.

## Decision
- Every check starts as a catalogue entry (`catalogue/<domain>/DSA-NNNN.yaml`) written in our
  own words: object, attributes, condition, threshold, tier, rationale, primary references.
  The entry is committed before the condition that implements it.
- References are primary only (Microsoft Learn and protocol specs, MITRE ATT&CK, ANSSI, DISA,
  SpecterOps, БДУ ФСТЭК, vendor advisories). The loader rejects references to
  `pingcastle`, `purple-knight`, `purpleknight`, `semperis.com`, `netwrix.com`
  (`forbiddenRef` in `internal/catalogue`).
- Incumbents are consulted only to produce a **gap list** (which topics are missing). Their
  indicator lists and rule texts are never committed, never placed in an agent's context
  while implementing, and never cited.
- Specification and implementation are separated: the agent or person implementing a
  condition works from the catalogue entry and primary references only.
- Permissive sources (Apache/MIT/BSD) may be used with attribution after a licence check;
  GPL/OSL tools are knowledge only. Nominative use ("comparable to PingCastle") is allowed in
  prose, never in names, IDs or pack text.

## Alternatives
- **Port or paraphrase PingCastle rules** — fastest coverage; rejected: OSL 3.0 makes any
  translation a derivative work, which would force the core under OSL.
- **Black-box Purple Knight outputs into rules** — rejected: EULA risk and the rule set's
  selection and arrangement is itself expression.
- **Ignore the incumbents entirely** — legally cleanest; rejected: admins compare against
  them, and a gap list made from public indicator names is a fact-level comparison.

## Consequences
- Slower catalogue growth: every check needs research and two primary sources.
- The git history (catalogue before code), `SOURCES.md`, DCO sign-off and a pre-1.0 similarity
  scan form the evidence trail a reviewer or court can follow.
- Some incumbent checks will be missing until a primary source is found for them.
