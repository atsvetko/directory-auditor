# ADR-0013: Kerberos first, encrypted transport by default, plaintext passwords only in labs

**Status:** accepted (2026-10-07; flags recorded 2026-10-15) · approach §5, open question 8

## Context
Approvers reject tools that ask for passwords on the command line or send them in clear.
Admins run the tool from domain-joined Windows, from Linux, and from non-joined lab machines
where the DC is reachable only by IP and certificates are self-signed.

## Decision
- Default: Kerberos with the current logon (SSPI on Windows, ccache on Linux/macOS).
- Explicit user: Kerberos with the prompted password, then simple bind as fallback. Passwords
  are prompted, never accepted from argv or environment, never written to disk.
- `--tls auto` (default): LDAPS → StartTLS → plain LDAP with Kerberos signing and sealing.
  Simple bind over an unencrypted channel is refused unless `--insecure-plaintext` (lab only).
- `--pin SHA256` pins a self-signed certificate instead of disabling verification.
- `--server IP` + `--server-name FQDN` keeps TLS name checks and the Kerberos SPN correct when
  DNS cannot resolve the DC.
- NTLM and certificate authentication are not in v1.

## Alternatives
- **Password in a flag or env var** — rejected: shell history, process lists, CI logs.
- **`--insecure-skip-verify`** — rejected in favour of pinning.
- **NTLM support** — rejected for v1: weak, and its presence undermines the "secure by default" story.

## Consequences
- Non-joined machines without Kerberos configuration need LDAPS/StartTLS for a password logon.
- The lab path (`--insecure-plaintext`) must stay visibly labelled in output.
