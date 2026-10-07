#!/usr/bin/env bash
# readonly-check.sh — proves a built dirauditor binary links no directory-write code.
#
# Review-pack artefact 11 (docs/requirements/approach.md §6.1) and requirement N-9.
# Usage: scripts/readonly-check.sh <path-to-binary>
# Exit 0 = clean, 1 = a forbidden symbol is present, 2 = usage/tooling error.
#
# How it works: `go tool nm` lists every linked symbol. go-ldap's write entry points
# have stable names; if our code never calls them the Go linker's dead-code
# elimination removes them. Any reviewer can reproduce this on the downloaded binary
# with the same command. The denylist is deliberately broad (SMB/DNS/registry
# writers are listed before those protocols exist in the engine).
set -euo pipefail

bin="${1:-}"
if [[ -z "$bin" || ! -f "$bin" ]]; then
  echo "usage: $0 <binary>" >&2
  exit 2
fi

# Forbidden symbols: package/receiver.method patterns as printed by `go tool nm`.
deny=(
  'ldap/v3.(*Conn).Modify'
  'ldap/v3.(*Conn).ModifyWithResult'
  'ldap/v3.(*Conn).ModifyDN'
  'ldap/v3.(*Conn).Add'
  'ldap/v3.(*Conn).Del'
  'ldap/v3.(*Conn).PasswordModify'
  'ldap/v3.NewModifyRequest'
  'ldap/v3.NewAddRequest'
  'ldap/v3.NewDelRequest'
  'ldap/v3.NewModifyDNRequest'
  'ldap/v3.NewPasswordModifyRequest'
  'smb2.(*File).Write'
  'smb2.(*Share).Create'
  'smb2.(*Share).Remove'
  'smb2.(*Share).Mkdir'
  'dns.(*Client).Exchange.*UPDATE'
  'registry.Key).SetStringValue'
  'registry.Key).SetDWordValue'
  'registry.CreateKey'
  'registry.DeleteKey'
)

symbols="$(go tool nm "$bin" 2>/dev/null || true)"
if [[ -z "$symbols" ]]; then
  echo "readonly-check: go tool nm produced no output (stripped binary? run on the unstripped build or use the release's symbol list)" >&2
  exit 2
fi

status=0
for pat in "${deny[@]}"; do
  if grep -F -q -- "$pat" <<<"$symbols"; then
    echo "FORBIDDEN symbol linked: $pat"
    status=1
  fi
done

if [[ $status -ne 0 ]]; then
  exit $status
fi

# Sanity: the read-only entry points must be present, otherwise nm did not see the engine.
if ! grep -F -q -- 'ldap/v3.(*Conn).Search' <<<"$symbols"; then
  echo "readonly-check: expected read symbols are missing — wrong binary?" >&2
  exit 2
fi

if [[ $status -eq 0 ]]; then
  echo "readonly-check: OK — no directory-write symbols linked into $(basename "$bin")"
fi
exit $status
