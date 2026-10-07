# Clean-room protocol

Directory Auditor is built with full knowledge that PingCastle (Netwrix, Non-Profit OSL 3.0)
and Purple Knight (Semperis, closed source) exist and are good. This document records how we
learn from them without ever copying them, so that the Apache 2.0 licence of this project is
beyond dispute.

## Legal basis, in one paragraph

Ideas, methods and facts are not protected by copyright (17 U.S.C. §102(b); ГК РФ ст. 1259
п. 5). *Which* attribute to read, *what* threshold is dangerous and *which* ATT&CK technique a
misconfiguration enables are facts. The protected part is expression: source code, rule texts,
the selection and arrangement of a rule set, report layout, scoring formulas. OSL 3.0 is
reciprocal: translating or adapting PingCastle's code — into Go, into YAML, into "rewritten
text" — creates a derivative work that must itself be OSL-licensed. Decompiling Purple Knight
violates its EULA. So: knowledge in, expression never.

## Rules

1. **Spec first, never code.** Whatever is learned from any source — primary documentation,
   research papers, the incumbents' public documentation and reports — is recorded in the
   catalogue as *facts in our own words*: object, attribute, condition in plain language,
   threshold, privilege tier, primary reference. No code snippets. No copied filter strings.
   No rule texts, however paraphrased.
2. **Primary references only.** Each catalogue entry cites the source the fact rests on:
   Microsoft Learn, MS-ADTS / MS-GPOL / MS-DNSP / MS-CRTD, MITRE ATT&CK, ANSSI AD
   recommendations, DISA STIGs, SpecterOps AD CS research, ADSecurity, Powermad/ADIDNS
   research, БДУ ФСТЭК. The incumbents are consulted only to produce a *gap list* and are
   never cited as the source of a check.
3. **Separate reading from writing.** Implementation happens from the catalogue with no
   incumbent source open. Standard LDAP filters reconstructed from Microsoft's documentation
   are facts; function decomposition, data structures, report layout and scoring are ours.
4. **Own taxonomy and scoring.** Checks are organised by ATT&CK tactic and БДУ threat IDs,
   with our own check domains and IDs (`DSA-NNNN`). The scoring model is designed and
   documented before the incumbents' models are looked at again.
5. **Catalogue before code.** The catalogue entry for a check is committed before the pack
   that implements it. The git history is the evidence.
6. **AI agents are inside the clean room.** No restrictively licensed source is ever placed
   in an AI agent's context; agents work from the catalogue and primary references. All
   generated code is scanned for similarity to known open-source code in CI
   (see [ai-policy.md](ai-policy.md)).
7. **Permissive sources may be used with attribution** after their `LICENSE` is checked:
   BloodHound CE (Apache 2.0), Certify / PSPKIAudit (BSD-3), Locksmith (MIT), Powermad
   (BSD-3). GPL/OSL tools (ADRecon, PingCastle forks): knowledge only.
8. **Nominative use is fine.** "Comparable to PingCastle and Purple Knight" may appear in the
   README and talks. Neither name appears in a product name, check ID or pack text.

## Evidence trail (what a reviewer will find)

- This file, and `CONTRIBUTING.md` which binds contributors to it.
- `catalogue/` committed before `packs/` for every check ID (git log).
- `references:` on every pack; `SOURCES.md` at the repository root listing all primary sources.
- DCO sign-off on every commit; licence scanner and similarity scanner in CI.
- A one-off similarity scan of this repository against the PingCastle repository before
  v1.0, with the report kept in `docs/review-pack/`.
