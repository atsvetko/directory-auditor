# ADR-0001: Engine language is Go

**Status:** accepted (2026-10-07) · **Supersedes:** the earlier PowerShell-module form factor

## Context
Hard constraints: one file, no runtime dependencies, Windows and Linux (macOS as a bonus),
signed and reproducible, reviewable. Four runtimes were compared in detail
(`docs/requirements/approach.md` §17): Go static binary, PowerShell 7 module, Python stdlib,
.NET 8 Native AOT.

## Decision
Go, `CGO_ENABLED=0`, `-trimpath`, cross-compiled from one Linux CI host for linux/amd64,
linux/arm64, windows/amd64 and darwin/arm64. Protocol libraries are pure Go
(`go-ldap`, a pure-Go Kerberos implementation to be selected at K3, `go-smb2` later).

## Consequences
- No libc, no OpenSSL, no ICU on the target: the "zero dependencies" claim holds on every OS.
- Reproducible builds and `go tool nm`-based read-only proof are first-class.
- Kerberos depends on a small third-party library that must be pinned, vendored and watched.
- Go binaries attract more AV false positives than .NET ones until signing reputation accrues;
  mitigated by immediate-reputation signing (ADR-0006) and AV allow-list enrolment.
- The AD research community writes C#; contributors to the engine will need Go. Checks are
  YAML, so most contributions never touch Go.
