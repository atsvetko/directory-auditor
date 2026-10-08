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

ID blocks: `DSA-0001…0099` directory-core (AD and Samba AD DC, read over LDAP), `DSA-0101…0199`
FreeIPA / IdM (verified against the FreeIPA source tree, commit `13a1df3`, and Red Hat IdM
documentation), `DSA-0201…0299` Samba AD DC configuration (smb.conf on the DC, tier 2; verified
against the Samba source tree — docs-xml/smbdotconf, loadparm, provision LDIFs — and the release
notes of the versions that changed each default). DNS and Group Policy blocks to follow.

Implemented entries carry `condition_cel` (the pack condition, evaluated by the engine) and `expect`
(the objects in the matching synthetic snapshot under `testdata/` that must fire). `go test
./internal/catalogue` runs every implemented entry against its snapshot, so a check is proven before
the pack is written. Packs are still written only from entries with `verified_by` filled.

Status: 29 directory-core, 23 FreeIPA and 20 Samba entries, all `draft` (awaiting human
verification). All 72 carry `condition_cel` and are exercised by `go test ./internal/catalogue`
against `testdata/synthetic-*.json.zst` (`synthetic-samba-hardened` is the negative control on
which no entry may fire) and, in CI, against a live Samba AD DC on every push and a live FreeIPA
server nightly (`testdata/lab/*-expect.yaml`, `tools/lab/`).

Every entry with `condition_cel` is also built into the binary (`embed.go` in this directory,
`go:embed */*.yaml`) and evaluated as a **preview check** — unsigned, labelled in every report,
switched off with `--no-preview`. `TestEmbeddedMatchesWorkingTree` fails the build when the
embedded copy and the working tree diverge. Verifying an entry (`status: verified`, `verified_by`)
and signing its pack is what turns a preview into a real check; nothing else changes.
