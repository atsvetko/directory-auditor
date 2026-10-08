# Directory Auditor

**Find what an attacker would find in your directory — one file, read-only, five minutes.**

Directory Auditor is a free, open-source security auditor for directory services and the
services around them: Active Directory, Samba AD DC (and therefore РЕД АДМ and Альт Домен),
FreeIPA / ALD Pro, OpenLDAP and Microsoft Entra ID — plus DNS, Group Policy, PKI, Kerberos,
credential management and integrated applications.

> **Status: engine skeleton (pre-alpha).** Nothing here audits anything yet. The catalogue of
> checks is written *before* any check code, on purpose — see [docs/clean-room.md](docs/clean-room.md).
> The requirements, plan and design decisions are complete and live in `docs/`.

## Why is it free?

Because the trust problem is the product. A tool that reads your whole directory with your
credentials has to be reviewable, reproducible and silent — no account, no licence key, no
telemetry, no cloud. The core is Apache 2.0 and will stay that way. If the project earns
adoption, paid support and enterprise features (continuous monitoring, multi-forest consoles)
may follow as an *addition*, never as a gate on the first run. There is no hidden agenda; this
paragraph is here because unexplained free security tools read as telemetry traps, and they
should.

## What it will do (v1 scope)

| | |
|---|---|
| **One file** | Static binary for Windows, Linux and macOS. No installer, no runtime, no dependencies. |
| **Read-only, provably** | No LDAP modify/add/delete code is linked into the binary. [`scripts/readonly-check.sh`](scripts/readonly-check.sh) proves it on every release and any reviewer can reproduce it. |
| **Runs as you** | Kerberos with your current logon; ~80 % of findings need only a normal user's read access. Admin credentials are opt-in for the few checks that need them. |
| **Express path** | Launch → detected domain and identity → **Scan now** → report in under five minutes. |
| **Snapshot architecture** | Collect once into a versioned snapshot, analyse as often as you like — re-run new checks without touching a domain controller again. |
| **Readable checks** | Every check is a signed YAML pack with a CEL condition, primary references, and remediation in English and Russian. |
| **Honest report** | Score 0–100, what was checked, what passed, what was skipped and why. |

## Try it

**Double-click** `dirauditor` (or run it with no arguments). A local page opens in your browser:
**1 Connect** (detected domain with your current logon, or domain + account) → **2 Scan** (fast or
full) → **3 Results** (score, findings, Tier-0 inventory, PDF/HTML/JSON). No domain at hand?
Click **Try with demo data**. The page is served on `127.0.0.1` only, behind a one-time token.

Command line, for scripts and servers without a browser:

```sh
dirauditor scan --server dc01.corp.example.com          # current logon (Kerberos), LDAPS, read-only
dirauditor scan --server dc01.corp.example.com --user audit@corp.example.com   # password prompted once
dirauditor analyse --snapshot dirauditor-out/snapshot-*.json.zst               # re-analyse, no DC traffic
dirauditor doctor --domain corp.example.com             # DNS SRV, ports, certificate, clock skew
dirauditor manifest --queries                           # every behaviour and every LDAP search
```

Build from source: `go build ./cmd/dirauditor` (Go 1.25+, no CGO).

Kerberos with the current logon works from Windows (SSPI, with channel binding) against any DC,
and from Linux against Windows DCs at the default channel-binding setting. Samba DCs require
channel binding by default (`ldap server require strong auth = yes`), which the Linux Kerberos
client cannot provide yet — use `--user` there (simple bind over LDAPS, password prompted once).

## Labs in CI

Every push runs the engine against a **real Samba AD DC** provisioned on the runner with
deliberately weak settings (`tools/lab/samba`, ~3 min); nightly and on demand it runs against a
**real FreeIPA server** in a container (`tools/lab/freeipa`, ~6 min), as an ordinary user and as
admin. `tools/lab/verify` compares `report.json` with `testdata/lab/*-expect.yaml`: every expected
finding must fire on the expected object, nothing else may, and containers the account cannot
read must show as "not collected". The lab scripts refuse to run without `DIRAUDITOR_LAB=1`.

To try an implemented catalogue entry against your own directory before it becomes a signed pack:
`dirauditor scan … --catalogue catalogue` (clearly marked as an unsigned dry run in the report).

Checks are written only from catalogue entries a human has verified, so today the only pack is a
format fixture (`TEST-0001`); the Tier-0 inventory ("who controls the domain, and why") is
already complete. The engine detects Active Directory, Samba AD DC and FreeIPA / Red Hat IdM
(`--provider auto`). The FreeIPA (23 entries) and Samba (19 entries, plus 6 domain-policy entries
shared with AD) catalogues ship with their conditions implemented and tested against synthetic
labs. On a Samba DC, `dirauditor scan --local` (or the wizard, automatically) also audits
`smb.conf` through Samba's own `testparm`: NetLogon secure channel, NTLMv1, SMB signing, LDAP
strong auth, DNS updates, RC4, audit logging and more.

## Documents

- [Requirements and approach](docs/requirements/approach.md) — goal, first-run contract, hard
  constraints, adoption requirements AR-1…AR-14, negative requirements N-1…N-10, architecture,
  trust chain, enterprise review pack, open questions.
- [One-page brief](docs/requirements/brief-en.pdf) (EN) · [Implementation plan](docs/ru/plan-v1.pdf) and
  [plan with AI-assisted development](docs/ru/plan-v2-ai.pdf) (RU).
- [Clean-room protocol](docs/clean-room.md) · [AI usage policy](docs/ai-policy.md) ·
  [Architecture decisions](docs/adr/) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md).

## Safety contract

- Strictly read-only. No writes to the directory, SYSVOL, DNS or any registry — ever.
- No exploit code: vulnerabilities are inferred from versions, flags and ACLs, never demonstrated.
- No checks that can lock an account.
- Nothing leaves the machine: no telemetry, no update checks by default, no cloud.
- Credentials are prompted on the terminal, used once and never written anywhere.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE). Check packs are data and carry the same licence.
