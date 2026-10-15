# ADR-0016: Apache 2.0 open core, personal ownership with employer consent, name "Directory Auditor"

**Status:** accepted (2026-10-07) · approach §11, open questions 3, 4, 20

## Context
The author works for a DCAP vendor (InfoWatch, product DD+DAT). The tool must be freely usable
by admins in banks and telecoms, keep a path to revenue, and have an IP boundary no employer
or customer can question. The working name "Directory Protector" collided with DD+DAT naming.

## Decision
- Core under Apache 2.0; a Pro tier is possible later (open core) and only after measurable
  adoption.
- Personal repository and copyright, with written employer consent on the IP boundary obtained
  **before** the first public commit. Public commits carry a DCO `Signed-off-by`.
- Name: **Directory Auditor**, CLI `dirauditor` (`diraudit` collides with a PyPI package).
  Trademark, domain and package collision checks remain to be completed before release.

## Alternatives
- **AGPL / OSL core** — rejected: legal departments in the target market block copyleft tools.
- **Employer-owned project** — rejected: ties the tool to one vendor's roadmap and market.
- **Keep "Directory Protector"** — rejected: collision with DD+DAT, and "protector" overstates
  a read-only auditor.

## Consequences
- Nothing goes public until the consent letter exists.
- Contributions need DCO; a CLA is not required under Apache 2.0.
