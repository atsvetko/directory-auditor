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

Status: not started. Target for v1: ~50 entries across directory-core, dns, gpo, pki, kerberos.
