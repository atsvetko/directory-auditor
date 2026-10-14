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
notes of the versions that changed each default), `DSA-0301…0399` DNS (AD-integrated zones, read over
LDAP from the DNS application partitions), `DSA-0401…0499` Group Policy (reserved, to follow),
`DSA-0501…0599` PKI / AD CS (certificate templates, CAs and the Public Key Services containers in the
configuration partition, with the CA-side and DC-side settings their abuse depends on). The Group Policy
block is still to follow.

Implemented entries carry `condition_cel` (the pack condition, evaluated by the engine) and `expect`
(the objects in the matching synthetic snapshot under `testdata/` that must fire). `go test
./internal/catalogue` runs every implemented entry against its snapshot, so a check is proven before
the pack is written. Packs are still written only from entries with `verified_by` filled.

Status: 89 directory-core, 2 DNS, 23 FreeIPA, 21 Samba and 16 PKI / AD CS entries, all `draft`
(awaiting human verification). The PKI block (`DSA-0501…0520`) is spec-only — no `condition_cel` yet —
and covers AD CS escalation ESC1–ESC16 (ESC12, shell access to the CA with a YubiHSM, is not detectable
from the directory or over the network and is deliberately left as a reserved gap at `DSA-0512`) plus weak
CA / NTAuth certificates (`DSA-0520`). The SID-security-extension entries, the CA-side flags (ESC6, ESC7,
ESC11, ESC16) and the DC mapping mode (ESC10) are tier 1–2 reads flagged as such; the rest are tier-0 LDAP
reads of the configuration partition. 135 of the other entries carry `condition_cel` and are exercised by `go test ./internal/catalogue`
against `testdata/synthetic-*.json.zst` (`synthetic-samba-hardened` is the negative control on
which no entry may fire) and, in CI, against a live Samba AD DC on every push and a live FreeIPA
server nightly (`testdata/lab/*-expect.yaml`, `tools/lab/`). Group A (DSA-0075…0089, DSA-0301,
DSA-0302) was committed as specs before any implementation, as clean-room rule 5 requires; all 17 of its
entries are now implemented. The two DNS entries run against both the AD and the Samba synthetic labs.

Every entry with `condition_cel` is also built into the binary (`embed.go` in this directory,
`go:embed */*.yaml`) and evaluated as a **preview check** — unsigned, labelled in every report,
switched off with `--no-preview`. `TestEmbeddedMatchesWorkingTree` fails the build when the
embedded copy and the working tree diverge. Verifying an entry (`status: verified`, `verified_by`)
and signing its pack is what turns a preview into a real check; nothing else changes.

## ANSSI mapping

Each entry declares the ANSSI / CERT-FR *Points de contrôle Active Directory* it implements in its
`anssi:` field. `frameworks/anssi.yaml` is the official index (CERTFR-2020-DUR-001, 76 points, levels
1–4); `frameworks/anssi-plan.yaml` schedules the points not yet covered. `ANSSI-COVERAGE.md` is
generated from both by `go run ./tools/anssimatrix`; CI fails if it is stale, if a tag names a point
that does not exist, or if a point is neither implemented nor planned. Only identifiers and titles are
taken from ANSSI — every check is written in our own words from primary sources.
