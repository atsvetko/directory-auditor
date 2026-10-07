# Check catalogue (milestone K1)

The catalogue is the clean-room spec from which packs are implemented. It is committed before
any pack and is the evidence that implementation followed primary sources, not incumbents.

Each entry (one YAML file per check, `catalogue/<domain>/DSA-NNNN.yaml`) records:

- `id`, `title` (en/ru), `domain`, `tier`, `severity`, `quick`
- `object` and `attributes` examined (names validated against the published schema)
- `condition` in plain language — what makes it a finding, with thresholds
- `rationale` — why it matters and how it is abused, in our own words
- `references` — primary sources only (Microsoft Learn, MS-ADTS/MS-GPOL/MS-DNSP/MS-CRTD,
  MITRE ATT&CK, ANSSI, DISA STIG, SpecterOps, БДУ ФСТЭК)
- `attack`, `bdu`, `compliance` mappings
- `verified_by` — the human who confirmed the entry against its source, and the date

ID blocks: `DSA-0001…0099` directory-core (AD / Samba), `DSA-0101…0199` FreeIPA / IdM (verified
against the FreeIPA source tree, commit `13a1df3`, and Red Hat IdM documentation), DNS and Group
Policy blocks to follow.

Implemented entries carry `condition_cel` (the pack condition, evaluated by the engine) and `expect`
(the objects in the matching synthetic snapshot under `testdata/` that must fire). `go test
./internal/catalogue` runs every implemented entry against its snapshot, so a check is proven before
the pack is written. Packs are still written only from entries with `verified_by` filled.

Status: 19 directory-core and 23 FreeIPA entries, all `draft` (awaiting human verification).
