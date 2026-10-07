# ADR-0006: Signing with immediate reputation; packs signed separately

**Status:** accepted (2026-10-07) · requirement AR-1, approach §6

## Decision
- Windows: Authenticode with a certificate that carries SmartScreen reputation from the first
  public release — EV, or Azure Trusted Signing if an individual outside the US is eligible.
  No public release before it exists.
- Linux/macOS: Sigstore `cosign` (keyless, CI OIDC) and a minisign/Ed25519 detached
  signature for air-gapped verification. Astra Linux SE: ЗПС-compatible ELF signature when
  question 10 is decided.
- Reproducible builds (pinned toolchain, `-trimpath`, no build IDs), SLSA provenance,
  SBOM (CycloneDX + SPDX), checksums; `dirauditor verify` prints its own hash.
- Check packs: Ed25519 sidecar signatures; the maintainers' public key is compiled in; the
  private key is offline.
- No auto-update; `--check-update` is opt-in and off by default. Packs can be updated as
  signed bundles without a new binary.

## Consequences
- Certificate lead time is weeks: ordering it is the first action of milestone K0.
- A key-rotation procedure for the pack key is required before v1.0.
