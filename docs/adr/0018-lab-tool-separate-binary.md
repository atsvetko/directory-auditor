# ADR-0018: The lab builder is a separate binary (`labctl`) in the same repository

**Status:** accepted (2026-10-15) · `cmd/labctl`, `internal/labctl`

## Context
Checks are validated against real DCs (Windows Server 2025, Samba, FreeIPA/ALD Pro) built in
Hyper-V and on Linux hosts. The lab builder must create VMs, run provisioning over SSH or
PowerShell Direct and take snapshots — all writes, which ADR-0004 forbids in `dirauditor`.

## Decision
- `labctl` (init / build / up / create / provision / snapshot / scan) is its own command and
  binary. The read-only symbol gate runs on `dirauditor` only, and `dirauditor` never imports
  `internal/labctl`.
- Lab safety rules learned in practice are built in: provisioning as a non-root user with
  sudo, a subnet guard that refuses to act outside the lab network, throwaway lab credentials only.

## Alternatives
- **Separate repository** — rejected for now: lab and checks evolve together; split later if
  it gains outside users.
- **Lab commands inside `dirauditor`** — rejected: would break the read-only contract.
- **Hand-written scripts per lab** — rejected: not repeatable, kept failing on parse and setup steps.

## Consequences
- Two release artefacts; only `dirauditor` goes through the full security review pack.
