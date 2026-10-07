# Contributing

Thank you for considering a contribution. Three rules protect this project's licence, its
users' directories and its reviewability; they are not negotiable.

## 1. Clean room — no code or text from restrictively licensed tools

Directory Auditor is Apache 2.0. PingCastle is under the Non-Profit OSL 3.0 (a reciprocal
licence); Purple Knight is closed source. Their *knowledge* (what to check) is free; their
*expression* (code, texts, structure) is not.

- Never copy, port, translate or paraphrase code, rule texts, filter strings, comments or
  report layouts from PingCastle, Purple Knight, or any other tool whose licence is not
  Apache/MIT/BSD-compatible. This includes code produced by an AI assistant that was shown
  such sources.
- Every check cites primary sources: Microsoft Learn and protocol specifications (MS-ADTS,
  MS-GPOL, MS-DNSP, MS-CRTD), MITRE ATT&CK, ANSSI, DISA STIGs, SpecterOps research,
  БДУ ФСТЭК. "PingCastle has this check" is not a reference.
- The catalogue entry for a check is committed **before** its implementation. A pull request
  that adds a pack without a prior catalogue entry is closed.
- Full protocol: [docs/clean-room.md](docs/clean-room.md).

## 2. Read-only, always

No pull request may add a code path that writes to a directory, SYSVOL, DNS or a registry.
`scripts/readonly-check.sh` runs in CI on every build and blocks the merge if a forbidden
symbol is linked. "Verify this finding by exploiting it" features are rejected by design.

## 3. AI-assisted contributions are welcome — and disclosed

Most of this engine is written with an AI coding agent under the rules in
[docs/ai-policy.md](docs/ai-policy.md). Contributors may do the same, provided that:

- the agent was never shown restrictively licensed sources (rule 1);
- the pull request says so in one line (`AI-assisted: yes — <tool>`), so reviewers calibrate
  their reading;
- you, a human, read what you submit and sign it off (DCO below).

Pull requests are kept small; first contributions are read in full.

## Developer Certificate of Origin

Every commit carries a `Signed-off-by:` line (`git commit -s`), certifying the
[DCO 1.1](https://developercertificate.org/): you wrote the change or have the right to submit
it under the project licence.

## Check packs

- One check per YAML file under `packs/<domain>/`; ID `DSA-NNNN`, never reused.
- Required fields are enforced by `Pack.Validate()` — including remediation `why / abuse /
  fix / verify` in **both** English and Russian, at least one primary reference, and a CEL
  condition that compiles to `bool`.
- Add a fixture snapshot under `testdata/` and a golden expectation; `go test ./...` must pass.
- Packs are signed by maintainers at release; your PR submits them unsigned and CI loads them
  with `--allow-unsigned`.

## Engine code

- `gofmt`, `go vet`, `go test ./...` and `govulncheck` must be clean.
- No new runtime dependencies without an ADR in `docs/adr/`. Compile-time dependencies must be
  Apache/MIT/BSD-licensed and are listed in the SBOM.
- Protocol code lives only in `internal/ldapx` (and later `smbx`, `dnsx`, `httpx`); checks and
  providers never import a protocol library directly.
- Terminal and report strings exist in English and Russian.

## Reporting a security issue

See [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability.
