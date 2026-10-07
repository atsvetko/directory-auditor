## What

<!-- one paragraph -->

## Clean room

- [ ] No code, text, filter string or layout from PingCastle, Purple Knight or any restrictively licensed tool (by me or by an AI agent I used)
- [ ] New checks have a catalogue entry committed before the pack, with primary references
- [ ] No new write path to a directory, SYSVOL, DNS or registry (`scripts/readonly-check.sh` passes)

## AI-assisted

AI-assisted: yes — <tool> / no

## Checks

- [ ] `gofmt`, `go vet`, `go test ./...` pass locally
- [ ] Strings exist in English and Russian where user-visible
- [ ] Commits are signed off (DCO)
