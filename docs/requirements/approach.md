# Directory Auditor — High-Level Approach

**Version:** v9 — 2026-10-07  
**Name:** Directory Auditor (CLI `dirauditor`); full collision checks — action A2.  
**Status words used in tables:** Decided · Default (applies unless changed) · Open

---

## 1. Goal and strategic rationale

**Goal.** A free, open-source tool that finds misconfigurations and vulnerabilities inside a directory service **and the services around it — DNS, Group Policy, PKI, Kerberos, credential management, integrated applications** — that an administrator can copy to a Windows or Linux machine and run with one action, with read-only domain access by default, and that covers a wide range of directory services.

**Reading of "vulnerabilities".** Known-exploitable *conditions* inferred from configuration and version data (DC build numbers, protocol capability flags, ACLs, template settings) — never demonstrated by running exploit code. See §7.

**Why it can win.** Both incumbents are Windows-only .NET executables focused on on-prem Active Directory. Neither covers Samba AD DC, FreeIPA, or the Russian directory stack (ALD Pro, РЕД АДМ, Альт Домен). PingCastle's free edition now carries a built-in licence expiry and is owned by Netwrix; Purple Knight's commercial-use terms require vendor verification. A cross-platform, zero-dependency, verifiably signed tool with Russian-stack coverage occupies a space nobody holds.

**Market.** Both markets from day one; RU-stack coverage (Samba AD DC / ALD Pro / РЕД АДМ / Альт Домен, БДУ ФСТЭК mapping, RU report language, RU distribution mirror) is the differentiator in global messaging as well — "the only auditor that covers the directories you actually run".

### 1.1 Primary goal — the admin wants to try it

**G0.** An administrator who hears about the tool downloads **one file**, runs it on Windows or Linux, and has a **useful report on screen within five minutes** — without installing anything, configuring anything, asking anyone for approval, creating an account, or entering a licence key. Every other requirement in this document exists to make G0 true and safe, or bends to it.

**First-run contract (measurable).**

| Metric | Target | How it is met |
|---|---|---|
| Steps from download to report | **3** — download, run, read | One asset per OS with an obvious name; no archive on Windows; interactive mode on launch; report opens by itself |
| Time to first report (TTFR) | **≤ 5 min** on a 50 k-object domain | Default is a **quick scan** (tier 0, the ~40 highest-value checks); the full scan is one click more |
| Configuration before the first run | **zero** on a domain-joined machine | Domain, DC and identity auto-detected from the logon / `krb5.conf` / DNS SRV; the express path (§2.1) is a single "Scan now" button |
| Questions asked when auto-detect fails | **one** — "which domain, and as whom?" | Everything else has a default |
| Prompts, nags, accounts, keys, e-mail, telemetry | **none** | Stated on the first screen |
| What the admin must trust before pressing Run | "Read-only, nothing leaves this machine, signed, source public" — shown on the first screen in one sentence | §7 safety contract, §6 trust chain |
| First report value | At least one finding the admin did not know, with a fix that takes ≤ 10 minutes | "Quick wins" block at the top of the report |

**Hard constraints — the five things that make G0 true and safe.**

| # | Constraint | Why it serves G0 | Design answer |
|---|---|---|---|
| C1 | One file, no install, no runtime — Windows and Linux (macOS as a bonus) | "Download, run" is impossible otherwise | Single static binary per OS/arch; compile-time deps vendored, pinned, in the SBOM (§2, §17) |
| C2 | Works with the admin's current logon, read-only, tier 0 by default | Nothing to request, nothing to approve for a trial | Kerberos SSO; three tiers; admin credentials only when the admin opts in (§5) |
| C3 | Safe to run on production at any time | The admin must not fear the first run | No write paths, no exploit code, no lockouts, throttled, no telemetry (§7) |
| C4 | Signed and reproducible | The admin can defend having run it | Authenticode with immediate reputation, cosign/minisign, Astra signature, Ed25519 packs (§6) |
| C5 | Open source | The admin can read what it did | Apache 2.0 core; small engine + readable check packs (§3, §9) |

**Enablers — important, but they never add friction to the first run.**

| # | Enabler | Rule |
|---|---|---|
| E1 | Wide range of directories and the services around them (§4, §4.1) | Delivered in phases; the AD/Samba express path must not get slower because FreeIPA or Entra exist |
| E2 | Enterprise approvability — review pack, packaging, audit-account script, SOC runbook, pre-flight manifest, report protection (§6.1, §8.1, §18) | Lives beside the binary (review-pack folder, MSI, flags), never in front of it; the trial path stays "download, run, read" |
| E3 | Compliance mappings, exceptions, SIEM export, management summary (§8.1) | Visible in the report, not in the wizard's express path |
| E4 | Pro / monetisation | No feature gating in the first-run experience; no "upgrade" prompts |

**Design rule derived from G0.** When a requirement from E1–E4 and the first-run contract conflict, the first-run contract wins and the enabler becomes opt-in.

### 1.2 Adoption requirements AR-1…AR-14 (rationale in §19)

Each requirement has an acceptance criterion that CI or a release checklist can verify. "First" = alpha, "Then" = the step after (§13).

| ID | Requirement | Acceptance criterion | Step |
|---|---|---|---|
| AR-1 | **Signed binary with immediate reputation.** Windows binaries signed with a certificate that carries SmartScreen reputation from the first release (EV, or Trusted Signing if eligible — see §12, question 15); Linux/macOS artefacts carry cosign and minisign signatures; Astra build carries a ЗПС-compatible signature; no packers; allow-list submissions filed with Microsoft, Kaspersky, ESET, Dr.Web | Release checklist: a clean Windows 11 VM runs the downloaded binary with no "Unknown publisher" dialog; `cosign verify` and `minisign -V` pass; VirusTotal shows zero detections or an open vendor ticket per detection; allow-list ticket IDs recorded | First |
| AR-2 | **Express path and quick scan.** Launch without arguments on a domain-joined host shows detected domain, identity and the trust statement with one **Scan now** button; the quick scan runs ≤ 40 tier-0 checks marked `quick: true` in their packs; "Run full scan" is one click | CI timing test on the reference lab domain (50 k objects): launch → rendered report ≤ 5 min with zero input; step count = 3 (download, run, read); on a non-joined host exactly one question is asked | First |
| AR-3 | **`doctor` and teaching errors.** `doctor` checks DNS SRV, time skew, Kerberos ticket and realm, LDAP reachability, signing and channel-binding requirements, TLS certificate, SMB/SYSVOL; every failure anywhere in the tool prints cause and one-line fix in EN and RU | Test suite with ≥ 15 induced failures (skew, no ticket, wrong realm, signing required, CBT required, untrusted cert, no SRV, port blocked, SYSVOL denied, …) each producing its expected message; no raw library error reaches the user | First |
| AR-4 | **Modern-DC compatibility.** Kerberos with signing and sealing, channel binding tokens, LDAPS with fingerprint pinning; works against DCs with LDAP signing = Required and channel binding = Always | CI lab includes a hardened DC profile; tier-0 scan completes against it over Kerberos and over LDAPS with a pinned fingerprint | First |
| AR-5 | **Report as the shareable artefact.** Score 0–100 overall and per domain; "quick wins ≤ 10 min" block; "top 5 paths to Tier 0" from ACL edges (GenericAll / WriteDACL / WriteOwner / DCSync / RBCD) on Tier-0 objects; checked/passed/skipped counts; EN/RU toggle; `--redact` pseudonymises DNs, SIDs, hostnames, IPs and free-text attributes deterministically within a run | Golden reports for score, quick wins, counts; redaction test: a redacted report contains no string from a deny-list built from the snapshot (names, SIDs, hosts, IPs); paths block has golden tests on a synthetic ACL graph | First (score, quick wins, counts, redact) · Then (paths) |
| AR-6 | **Copy-paste remediation and `fix --plan`.** Every check pack carries `remediation` with: why it matters, how it is abused, exact command per provider (PowerShell, `ldapmodify`, `samba-tool`, `ipa`), how to verify; `fix --plan` writes a script for the findings the admin selected, `-WhatIf`/dry-run by default, header listing finding and check IDs; the tool never executes it | Pack schema validation fails without all remediation fields; generated scripts pass PSScriptAnalyzer / shellcheck in CI; CI asserts the binary contains no code path that executes generated scripts (same symbol test family as §6.1 #11) | Then |
| AR-7 | **Diff/trend and `schedule`.** `--diff` compares two snapshots and reports fixed / new / unchanged per check; `schedule` creates a Task Scheduler or cron entry (least privilege, `-WhatIf` default, idempotent) writing the summary to file, syslog or a chat webhook | Diff golden test on two fixture snapshots; `schedule` run twice leaves exactly one entry; webhook payload schema documented and tested | Then |
| AR-8 | **Community checks without touching the engine.** Documented pack schema; `new-check` scaffolds a pack with a fixture and test; `check test <snapshot>` runs one pack; `--allow-unsigned` prints a persistent banner; public check IDs `XXX-NNNN` are stable and never reused; maintainers sign accepted community packs | A contributor can add a check with no engine change (CI job proves it on a sample pack); ID uniqueness and never-reuse enforced by a CI test against the ID registry | Then |
| AR-9 | **`--demo` and the online sample report.** `--demo` renders the full report from a bundled synthetic snapshot with no network access; the same snapshot's report is published as the sample | CI runs `--demo` with networking disabled; synthetic snapshot contains no real names, domains, SIDs or IPs (deny-list test); sample report regenerated on every release | First |
| AR-10 | **Consultant / MSP mode.** `--targets <file>` scans many directories with a consolidated report and per-target sections; `--portable` keeps profile, snapshots and output beside the binary; per-target redaction | Multi-target golden test on three fixture snapshots; `--portable` run writes nothing outside the binary's folder (filesystem watch test on Windows and Linux) | Then |
| AR-11 | **Console output.** Coloured, UTF-8-safe terminal output with live counters; enables VT and UTF-8 on Windows consoles; honours `NO_COLOR`; usable over SSH | Snapshot tests of console output in cmd, Windows Terminal, bash over SSH; Cyrillic renders correctly in all three | First |
| AR-12 | **Honest states.** The report lists every skipped check with its reason (tier, permission, provider, error) and shows passed counts; a zero-finding report still shows what was checked | Golden test on a clean fixture: report shows "0 findings, N checks passed, M skipped (reasons)" | First |
| AR-13 | **Snapshot architecture.** Collection and analysis are separate stages joined by a versioned (semver), zstd-compressed JSON snapshot with an attribute allow-list; checks run only against snapshots; `analyse <snapshot>` reproduces the report; snapshot hash is embedded in the report; migrations for older schema versions; snapshots inherit report protection (encryption, redaction, classification) | Schema version check and migration tests; `collect` then `analyse` twice yields byte-identical reports except timestamps; snapshot of the 50 k-object lab ≤ 50 MB compressed; encryption round-trip test | First |
| AR-14 | **First-run contract measured in CI.** TTFR, step count and zero-configuration are measured on every release against the reference lab | Release gate: TTFR ≤ 5 min and zero input on the Samba lab domain; AD lab run recorded manually per release until an AD lab exists in CI | First |

### 1.3 Negative requirements N-1…N-10

| ID | The tool never… | Verified by |
|---|---|---|
| N-1 | …requires an installer, account, licence key or e-mail to produce the first report | AR-2 test runs from a bare download |
| N-2 | …sends anything off the machine except directory traffic to the targets the admin named (no telemetry, not even opt-in in v1; no auto-update; `--check-update` is opt-in and off by default) | Network-capture test in CI: only LDAP/SMB/DNS/HTTP(S) to lab targets |
| N-3 | …has a runtime dependency (interpreter, framework, shared library beyond the OS itself; Linux .NET OpenSSL exception only if .NET is chosen, documented) | Static-link check in the release pipeline |
| N-4 | …loads Turing-complete plugins; packs are data evaluated by a bounded expression language | Pack schema; no `exec`/`eval` paths in the engine |
| N-5 | …embeds a browser engine (Electron, WebView2, GTK/Qt) | Build graph / SBOM check |
| N-6 | …gates a feature or shows an upgrade prompt in the first-run path | UI review per release; no Pro strings in the express path templates |
| N-7 | …is installed via `curl \| sh` or any unsigned installer | README and docs lint |
| N-8 | …executes exploit code, coerces authentication, relays, sprays passwords or authenticates as any user other than the one the admin supplied | §7; CI symbol and dependency tests; code review rule |
| N-9 | …writes to the directory, SYSVOL, DNS or the registry of a target | §6.1 #11 read-only proof |
| N-10 | …writes outside the chosen output folder (or the binary's folder in `--portable`), except the profile file in the user's config directory when the admin saves one | Filesystem watch test (AR-10) |

**Premise correction.** "No libraries" is read as **no runtime dependencies**. A statically compiled binary with vendored, pinned, reproducibly built libraries is more reviewable than a 20 000-line script: reviewers audit the diff, the SBOM and the signature, not every line.

---

## 2. Form factor

**Single static binary (Go — proposed; the runtime comparison is in §17).** Windows x64, Linux x64/arm64 (musl static), macOS arm64. ~15–25 MB. No installer, no runtime.

**Run modes (one binary, one `Config` struct behind all three; the web UI is the primary mode):**

1. **No arguments → local web UI with a connection wizard (default).** The binary starts an HTTP server on `127.0.0.1` (random port, one-time token), opens the default browser, and walks the admin through connection → credentials → scope → run → report (§2.1). The admin's browser is the GUI; no WebView2, GTK or cgo; all assets embedded in the binary, nothing fetched from the network. This is the "single click" UX.
2. **`--console` → text mode.** Same wizard as numbered prompts for headless hosts (SSH to a jump host, Server Core). Progress display, "press Enter to close".
3. **Flags → automation.** `--server`, `--tier`, `--json`, `--diff previous.json`, `--no-pause`, `--targets file`, `--profile name`. For CI, scheduled runs, MSPs. A wizard run can be exported as the equivalent command line.

### 2.1 Web UX and connection wizard

**Express path (the G0 path).** On a domain-joined machine the first screen already shows the detected domain, directory type and identity, the one-sentence trust statement ("Read-only · nothing leaves this machine · signed · source public") and a single **Scan now** button that runs the quick scan as the current user. The seven guided steps below are reached by "Change settings"; they are the same screens with the detected values pre-filled. On a non-domain-joined machine the express path asks one question — domain and identity — and continues.

**Wizard steps (guided path).**

| Step | What the admin sees | What the engine does |
|---|---|---|
| 1 Welcome | Detected domain / identity, the trust statement, **Scan now** (express) or Change settings; what will be read, what will never be written (the safety contract, §7); language EN/RU | Auto-detection as in step 2 |
| 2 Directory | Auto-detected directory type and domain, with override | DNS SRV lookup (`_ldap._tcp`, `_kerberos._tcp`), Kerberos realm from logon/`krb5.conf`, rootDSE fingerprint → AD / Samba AD DC / FreeIPA / OpenLDAP |
| 3 Target | Domain or specific DC, port, TLS mode (LDAPS / StartTLS), certificate check with fingerprint pinning for self-signed CAs | Connectivity probe; shows the server certificate |
| 4 Identity | "Use my current logon" (Kerberos SSO, default) · "Other account" · "Add an admin account for tier-2 checks" (optional, separate field) · **Test connection** | Binds, shows *who you are* (DN, groups) and which tiers are available with this identity; nothing is stored |
| 5 Scope | Domain / forest / list of targets; check domains to run (§4.1); exclusions (OUs, accounts); output folder | Estimates object count and run time from rootDSE / `highestCommittedUSN` |
| 6 Run | Live progress per check, ETA, cancel | Streams progress over SSE; throttled collection |
| 7 Report | Rendered report in the browser; download HTML / JSON / CSV; diff against a previous JSON; save a **profile** (everything except secrets) for next time | Writes the self-contained report to the output folder |

**Security model of the local UI (defaults).**
- Binds to loopback only; random high port; a one-time token in the launch URL; `Host` and `Origin` checked on every request (defeats DNS rebinding and other local users on a shared host).
- Strict CSP, no inline scripts without nonce, no external resources; all directory-sourced strings (DNs, descriptions, GPO names, DNS records) are context-escaped — they are attacker-controllable data.
- Credentials travel only over loopback and live only in process memory; profiles never contain secrets; no cookies persisted.
- Loopback HTTP rather than self-signed HTTPS (which would produce browser warnings and teach admins to click through them). Remote use (jump host) is documented as SSH port forwarding to the loopback port.

**Design.** One design system shared by the wizard and the report: same typography, colours, severity scale, EN/RU strings; works offline; readable at 1280 px and on a 4K monitor; keyboard-navigable. The report is rendered by the same templates whether viewed in the wizard or opened later as a file.

**Frontend stack (open — question 21).** All options are compile-time embedded assets, so none adds a runtime dependency; the choice is about reviewability vs richness: (a) server-rendered templates + a small vendored HTML-over-the-wire library + SSE, a few hundred lines of own JS — smallest surface to review; (b) a vendored small component framework (Preact/Svelte) built into a single bundle — richer interactions, larger vendored tree in the SBOM; (c) hand-written vanilla JS web components — no vendored frontend code at all, more own code to maintain.

**Launchers.** `run.sh` / `run.cmd` may be shipped as pure pass-through (`exec "$(dirname "$0")/tool" "$@"` / `"%~dp0tool.exe" %*`). They carry **no logic** and are not a trust boundary.

**Rejected: compiled library + shell-script UX.** Reasons:
- A shell script cannot load a `.so`/`.dll`; it needs a host (Python, PowerShell, an exe) — reintroducing a runtime dependency.
- Script layer is unsignable in practice: no execution policy on Linux; `.bat`/`.cmd` cannot carry Authenticode; `.ps1` double-click opens an editor.
- Astra Linux SE ЗПС blocks interpreters and unsigned ELF.
- Two UX codebases (bash + PowerShell/batch), duplicated i18n, argument/encoding/quoting bugs, credential leakage through argv/env, worse AV/EDR heuristics.
- Reviewability does not improve: the engine must be trusted either way.

**Later, for integrators only:** a C-callable library build (`-buildmode=c-shared` in Go, `NativeLibrary` in .NET AOT) for a PowerShell module or Python bindings. Secondary artifact, not the end-user path.

---

## 3. Architecture — small engine, readable rules

```
┌──────────────────────────────────────────────────────────────┐
│ Engine (compiled, reviewed once, reproducibly built, signed)  │
│  connectors · auth · LDAP/SMB/DNS/HTTPS clients · evaluator  │
│  scorer · reporter (HTML/JSON/CSV) · pack signature verifier │
│  named complex checks (GPO/SYSVOL, trust graph, PKI/ESC,     │
│  DNS zone ACLs, DC build-number → known-vulnerability map)   │
└──────────────┬───────────────────────────────────────────────┘
               │ loads only signed packs (Ed25519 key compiled in)
┌──────────────▼───────────────────────────────────────────────┐
│ Check packs (YAML, one check per file, reviewed by everyone)  │
│  id · provider · domain · tier · query · condition           │
│  severity · attack (ATT&CK) · bdu (БДУ ФСТЭК)                │
│  remediation EN/RU · references (primary sources only)       │
└──────────────────────────────────────────────────────────────┘
```

- **Packs are data, not code.** `condition` uses a non-Turing-complete expression language. Default: CEL (Common Expression Language) — no loops, no I/O, bounded evaluation cost, widely audited.
- **Complex checks** (SYSVOL/GPO parsing, trust graph, PKI template analysis, DNS zone ACL analysis) live in the engine as named check implementations; packs reference them by name and supply parameters (thresholds, exclusions, severity).
- `domain:` (§4.1) groups packs by the service examined; the report is organised by ATT&CK tactic, with a per-domain view.
- **Snapshot architecture** (AR-13, §19.2): collection and analysis are separate stages joined by a versioned snapshot file; checks run against the snapshot, never against the live directory.
- Unsigned packs load only with an explicit `--allow-unsigned` (development mode), clearly flagged in the report.

---

## 4. Providers — LDAP-first, then REST

| Phase | Provider | Covers | Transport | Notes |
|---|---|---|---|---|
| 1 | Active Directory | AD DS 2016+ | LDAP/LDAPS, SMB (SYSVOL), DNS, HTTP (AD CS web enrollment probe), optional RPC/WinRM (tier 2) | Reference implementation |
| 1 | Samba AD DC | Samba 4.x, **РЕД АДМ**, **Альт Домен** | same as AD; SSH for tier 2 | Same LDAP schema; dialect via rootDSE fingerprint; Samba-specific quirks isolated; internal DNS or BIND9_DLZ |
| 2 | FreeIPA / 389-ds | FreeIPA, **ALD Pro** | LDAP/LDAPS, FreeIPA JSON-RPC over HTTPS, SSH for tier 2 | Different schema: HBAC, sudo, permissions/privileges/roles, Kerberos policy, integrated DNS, Dogtag PKI |
| 2 | OpenLDAP | generic LDAP | LDAP/LDAPS | Anonymous bind, ACL leaks, cleartext/weak hashes, TLS posture |
| 3 | Entra ID | Microsoft Entra | Graph API over HTTPS | Roles, CA policies, legacy auth, PIM, app consent |

**Coverage:** full coverage over time in the phase order above — AD + Samba AD DC in v1, FreeIPA/ALD Pro in v2, Entra ID in v3. The v1 scope (AD + Samba AD DC) is the default and is still to be confirmed.

A provider "dialect" layer handles rootDSE fingerprinting, schema differences and per-provider check gating so an AD-only check is never run against 389-ds.

### 4.1 Check domains — directory and related services

Each domain is a set of packs with a `domain:` field, run by the same engine against the same session — not separate tools. Tier numbers refer to §5.

| Domain | What is examined (examples) | Data source | Tier | Providers |
|---|---|---|---|---|
| **Directory core** | Object ACLs and delegation, privileged groups and AdminSDHolder, DCSync rights, delegation (unconstrained / constrained / RBCD), SPNs on privileged accounts, AS-REP-roastable accounts, SID history, reversible encryption, `ms-DS-MachineAccountQuota`, stale and disabled objects, trusts and SID filtering, schema and configuration-partition hygiene | LDAP | 0 | all |
| **DNS (directory-integrated)** | Zone ACLs — who may create records; non-secure dynamic updates; wildcard, WPAD and ISATAP records; dangling records pointing to decommissioned hosts; DnsAdmins membership; zone transfer and recursion exposure | LDAP (`DomainDnsZones` / `ForestDnsZones`, `dnsZone` / `dnsNode` objects) + DNS protocol probes (AXFR, recursion) | 0 / 1 | AD, Samba AD DC, FreeIPA (BIND via LDAP) |
| **Group Policy** | GPO link and edit ACLs, SYSVOL ACLs, GPP `cpassword`, scripts and MSI packages from writable paths, unlinked / orphaned / empty GPOs, security-settings baselines (password and lockout policy, audit policy, user-rights assignments, LM/NTLM level) | LDAP (`groupPolicyContainer`) + SMB (SYSVOL) | 0 / 1 | AD, Samba AD DC |
| **PKI (AD CS / Dogtag)** | ESC1–ESC13 as far as readable without admin: template enrollment flags and ACLs, CA ACLs, enrollment agents; `EDITF_ATTRIBUTESUBJECTALTNAME2` (registry — tier 2); web enrollment / NTLM relay exposure (ESC8 — HTTP probe) | LDAP (Configuration partition) + HTTP probe + registry (tier 2) | 0 / 1 / 2 | AD; FreeIPA (Dogtag — separate checks) |
| **Kerberos and authentication protocols** | RC4/DES allowed, pre-authentication disabled, KRBTGT password age, duplicate SPNs, LDAP signing and channel binding, SMB signing, NTLM policy, anonymous bind | LDAP + network probes + registry (tier 2) | 0 / 1 / 2 | all |
| **Credential management** | LAPS (legacy and Windows LAPS) coverage and read ACLs, gMSA usage and `PrincipalsAllowedToRetrieve`, Protected Users, PSOs, built-in Administrator hygiene | LDAP | 0 | AD, Samba AD DC |
| **Replication, topology, lifecycle** | Sites and subnets, FSMO placement, replication metadata and failures, backup freshness (DIT backup markers), tombstone lifetime, DCs on unsupported OS or missing security updates (build-number inference) | LDAP | 0 | AD, Samba AD DC |
| **Integrated applications (when present)** | Exchange (`Exchange Trusted Subsystem` / `Exchange Windows Permissions` rights on the domain), SCCM/MECM (`System Management` container ACLs, NAA accounts), Entra Connect / ADFS service accounts with DCSync rights, SQL and other service SPN hygiene | LDAP | 0 | AD |
| **Host-level DC state** | Print Spooler on DCs, SMBv1, audit policy as applied, event-log sizes, local administrators on DCs, Samba `smb.conf` hardening, FreeIPA server settings | RPC/WinRM (AD), SSH (Samba, FreeIPA) | 2 | all |
| **FreeIPA / ALD Pro specific** | HBAC `allow_all`, sudo rules with `!authenticate` or `ALL`, permissions/privileges/roles sprawl, Kerberos ticket policy, integrated DNS, Dogtag certificates, trusts to AD | LDAP + JSON-RPC | 0 | FreeIPA / ALD Pro |

---

## 5. Privilege tiers and authentication

| Tier | Identity | Access used | Share of value | Example checks |
|---|---|---|---|---|
| **0** | Any authenticated domain user | LDAP read only | ~80 % | Directory core, DNS zone ACLs, GPO ACLs, PKI templates, Kerberos settings, credential management, replication, integrated applications (§4.1) |
| **1** | Any authenticated domain user | + SYSVOL via SMB, + unauthenticated network probes to DCs (LDAP, SMB, DNS, HTTP) | ~15 % | GPO content, GPP passwords, logon scripts, LDAP signing / channel binding, SMB signing, anonymous bind, LDAP TLS versions, zone transfer, AD CS web enrollment |
| **2** | Admin credentials supplied interactively | + DC-side state (registry, services, NTLM policy, LAPS state, event log settings) via RPC/WinRM/SSH | ~5 % | NTLM level, SMBv1, audit policy, print spooler on DCs, local admin membership on DCs, `EDITF_ATTRIBUTESUBJECTALTNAME2`, `smb.conf` |

Rules: every check declares its tier; the report lists checks skipped for lack of privilege; admin credentials are prompted, used in memory, never persisted. Default: remote-only collection — the tool is never installed on a DC.

**Authentication.**
- **Kerberos via the current logon**: SSPI on Windows (logon token, no password handling), credential cache (`KRB5CCNAME`) on Linux/macOS. Works unchanged for AD, Samba AD DC and FreeIPA/ALD Pro (all Kerberos realms).
- **Simple bind over LDAPS or StartTLS** with interactively prompted credentials — the always-works fallback and the path for tier-2 admin accounts. Simple bind without TLS is refused.
- Deferred: NTLM (only if real demand appears), certificate auth, Entra device-code OAuth (comes with the Entra provider in phase 3).
- Implementation note: Kerberos implemented in the binary's own language (no MIT/Heimdal libraries at runtime); SMB for SYSVOL reuses the same ticket.

---

## 6. Trust chain and distribution

**Binary.**
- Windows: Authenticode with an immediate-reputation certificate — EV, or Trusted Signing if eligible (AR-1).
- Linux/macOS: Sigstore `cosign` (keyless, CI OIDC) **and** minisign/Ed25519 detached signature for air-gapped verification.
- Reproducible builds (pinned toolchain), SLSA provenance from CI, SHA-256 checksums on the release page, `tool verify` subcommand that prints its own hash and verifies pack signatures.
- **Astra Linux SE ЗПС:** all ELF binaries and libraries must be signed (embedded, xattr, or detached signature, checked in that order); unsigned ELF launched by an unprivileged user is blocked; interpreters are blocked. Open (question 10): whether an Astra-registered signing key ("Ready for Astra") is a v1 release step; with both markets in scope, the default is yes.

**Check packs.** Ed25519 signature, public key compiled into the engine, offline signing key. Packs can be updated as signed bundles independently of the binary (air-gap friendly).

**Channels (default, question 16).** GitHub Releases + winget + Homebrew + an RU mirror (GitVerse/GitFlic) because GitHub access from Russia is unreliable.

**Updates (default, question 17).** No auto-update; `--check-update` opt-in; zero network calls except to the directory under test.

### 6.1 Security review pack — per release, generated by CI

Every release ships a `review-pack/` folder next to the binaries. It is produced by the CI pipeline from the build itself, never hand-written, and **a release is blocked if any artefact is missing**. Approvers get a folder, not a conversation.

| # | Artefact | Produced from | Format |
|---|---|---|---|
| 1 | Threat model and data-flow diagram | Maintained in repo (`docs/threat-model.md`), rendered per release | MD + SVG |
| 2 | Network-interactions sheet — ports, protocols, directions, per tier (RU: «Описание сетевых взаимодействий») | Generated from the connector registry in the engine | MD / CSV, EN + RU |
| 3 | **Query manifest** — every LDAP base/scope/filter/attribute set, SMB path, DNS and HTTP probe the release can issue | Generated from the signed check packs and engine check registry | JSON + MD |
| 4 | Permissions matrix per tier and per check domain | Generated from pack metadata (`tier`, `domain`) | MD |
| 5 | SBOM and licence inventory | Build graph | CycloneDX + SPDX |
| 6 | SLSA provenance and step-by-step reproducible-build verification | CI attestation + `docs/reproduce.md` | in-toto / MD |
| 7 | Static-analysis and dependency-scan results, fuzzing summary | CodeQL, gosec, govulncheck (or the .NET equivalents if .NET is chosen), fuzz corpus run | SARIF + MD |
| 8 | VirusTotal link and AV allow-list status per vendor (Microsoft, Kaspersky Allowlist Program, ESET, Dr.Web) | Release job + maintained status table | MD |
| 9 | SOC runbook — expected alerts per EDR/NDR vendor (Defender for Identity, Kaspersky, PT, MaxPatrol) and allow-list recipes | Maintained in repo, versioned with the query manifest | MD, EN + RU |
| 10 | Personal-data inventory (152-ФЗ / GDPR): categories read, purpose, retention guidance | Generated from attribute sets in the query manifest + maintained purpose text | MD, EN + RU |
| 11 | **Read-only proof** — a CI test that the release binary's symbol table contains no LDAP modify/add/delete, SMB-write or DNS-update symbols, with the exact command for a reviewer to reproduce on the downloaded binary | Symbol-table scan of the signed artefact | Test log + MD |
| 12 | Support, release and vulnerability-disclosure policies | `SECURITY.md`, `SUPPORT.md`, `security.txt` | MD |
| 13 | RU: content for «Паспорт ПО» / «Формуляр»; EN: security whitepaper | Assembled from 1–12 | PDF + MD |

---

## 7. Safety contract ("safe to run in production")

- Strictly read-only: no LDAP modify paths compiled in, ever; no DNS updates, no SMB writes, no registry writes.
- No checks that can lock accounts (no password spraying, no authentication attempts against user accounts).
- **No exploit code.** Vulnerability checks are inference-based: DC OS build numbers from LDAP, protocol capability flags from harmless probes, ACLs and template flags. The tool never runs a proof-of-concept (no Zerologon/PetitPotam/noPac attempts, no coercion, no relay).
- Connection throttling and concurrency caps; traffic only to domain controllers / directory servers.
- No telemetry, no outbound calls except to the directory.
- Credentials: masked prompt or OS credential store; never argv, never env, never logs.

---

## 8. Output

- **Self-contained HTML** (no CDN assets, works offline, EN/RU toggle in the report), score 0–100 overall, per ATT&CK tactic and per check domain (§4.1), severity, ATT&CK and БДУ mapping, remediation text, evidence (object DNs/attributes).
- **JSON** (machine-readable, stable schema, for SIEM/CI) and **CSV**.
- `--diff previous.json` for trend between runs.
- Own taxonomy: organised by ATT&CK tactic and БДУ threat IDs, not by the incumbents' categories (also neutralises any "selection and arrangement" claim).
- Own scoring model, designed and documented before looking at the incumbents' again.

### 8.1 Approver-facing product features

| Feature | What it does | Who it is for | When |
|---|---|---|---|
| `--dry-run` | Pre-flight manifest for the planned run: target DCs, queries and attributes, estimated object count, load and duration, tiers used — formatted as text for a change ticket (RFC) or SOC notice, EN/RU | Change management, SOC | First |
| `--manifest` | Prints every behaviour of the binary: listeners, files written, network targets, update checks (off), telemetry (none), signature status of loaded packs | ИБ approvers, inventory | First |
| Compliance mappings | Per-check fields: CIS Benchmarks, NIST SP 800-53, ISO/IEC 27001:2022 Annex A, PCI DSS 4.0, DORA; ГОСТ Р 57580.1, приказы ФСТЭК №17/21/239, БДУ ФСТЭК; filterable in the report | GRC, auditors | Then |
| Exceptions | Risk acceptance per finding with justification, owner and expiry, stored in the profile; expired exceptions resurface automatically | AD team | Then |
| Management summary | One-page view: score, trend, top risks, owners, effort — printable | CISO, management | Then |
| SIEM export | Syslog/CEF and SARIF; run log (account, DCs, queries, timestamps) as JSON | SOC, internal audit | Then |
| Encrypted / redacted reports | Passphrase-encrypted export; pseudonymisation mode for sharing with vendors or consultants; classification banner; report hash in the footer | ИБ, DPO | Then |
| README "why is it free?" | The open-core model stated on the first screen of the README and the wizard welcome page — unexplained free tools read as telemetry traps to approvers | Everyone | First |

---

## 9. Check catalogue — sourcing and clean-room protocol

**Decision:** build the catalogue from public research — MITRE ATT&CK, Microsoft security baselines and protocol docs (MS-ADTS, MS-GPOL, MS-DNSP, MS-CRTD), ANSSI AD hardening recommendations, DISA STIGs, SpecterOps AD CS (ESC) research, ADSecurity, Kevin Robertson's ADIDNS research, БДУ ФСТЭК. PingCastle source and Purple Knight (black-box only) are studied for **knowledge**, never for code or text.

**Legal basis.** Ideas, methods and facts are unprotected (17 U.S.C. §102(b); ГК РФ ст. 1259 п. 5). PingCastle's source is under the Non-Profit OSL 3.0 — a reciprocal licence under which translating, adapting or transforming the work creates a derivative work that must be distributed under the OSL. Porting rule logic C# → Go/YAML with rewritten texts is still a derivative work and would make Apache 2.0 and a Pro tier impossible. Purple Knight is closed-source; decompiling violates its EULA — study its reports and public indicator documentation only.

**Protocol.**
1. **Extract into a spec, never into code.** From the sources above (and the incumbents, used only to build a *gap list*), the catalogue records per check: object/attribute, condition in plain language, threshold, tier, primary reference. No code snippets, no copied LDAP filter strings, no comments, no rule texts even paraphrased.
2. **Separate reading from writing.** Implementation is done from the catalogue with the PingCastle repository closed. Standard LDAP filters reconstructed from Microsoft docs are facts; function decomposition, data structures, report layout and scoring are expression and are original.
3. **Own taxonomy and scoring** (see §8).
4. **Evidence trail.** `docs/clean-room.md` describing this method; the catalogue commit precedes any implementation commit; `references:` per check; `SOURCES.md`; DCO sign-off; licence scanner in CI; a one-off similarity scan against the PingCastle repository before v1.0, report kept.
5. **Contributors** follow the same rules via `CONTRIBUTING.md`; first PRs squash-reviewed.

**Permissively licensed tools that may be borrowed from with attribution — verify each `LICENSE` before use:** BloodHound CE (Apache 2.0, attack-path edges), SpecterOps Certify / PSPKIAudit (BSD-3, AD CS), Locksmith (MIT, AD CS), Powermad (BSD-3, ADIDNS). GPL/OSL tools (ADRecon, PingCastle forks): knowledge only.

**Nominative use.** "Comparable to PingCastle and Purple Knight" is acceptable in README and talks; never in the product name.

---

## 10. Development and QA

- Containerised lab in CI: Samba AD DC (with internal DNS), FreeIPA; real AD forest with AD CS and Exchange schema in the owner's lab for AD-specific validation.
- Golden-report regression test per check; both interactive and CLI paths tested against the same `Config`.
- **Acceptance tests for AR-1…AR-14 and N-1…N-10 (§1.2, §1.3)** run in CI: first-run timing on the reference lab (TTFR ≤ 5 min, zero input), induced-failure suite for `doctor`, hardened-DC profile, redaction deny-list test, `--demo` with networking disabled, filesystem-watch test for `--portable`, network-capture test for N-2, static-link and symbol tests for N-3/N-8/N-9. The release is blocked when a "First"-step acceptance test fails.
- Release pipeline: reproducible build → sign → SBOM → SLSA provenance → static analysis and dependency scan → read-only symbol test → **review pack assembled (§6.1) — release blocked if any artefact is missing** → checksums → VirusTotal result published per release.

---

## 11. Decisions settled

| Topic | Decision | Status |
|---|---|---|
| Goal and scope | Directory **and related services** (DNS, GPO, PKI, Kerberos, credential management, integrated applications, host-level DC state); vulnerabilities by inference only | Decided |
| Licence model | Apache 2.0 core + Pro option (open-core) | Decided |
| Languages | Engine neutral; report strings EN/RU | Decided |
| Provider phases | AD → Samba AD DC → FreeIPA/ALD Pro → Entra ID | Decided |
| Coverage over time | All four directory families, in the phase order above; v1 = AD + Samba AD DC | Default — v1 scope to confirm |
| Market | Both global and RU; RU-stack coverage as the differentiator | Decided |
| Ownership | Personal repo and copyright, with written employer consent on the IP boundary — obtained **before** the first public commit | Decided |
| Name | **Directory Auditor** ("Directory Protector" dropped because of the DD+DAT collision); CLI `dirauditor`; trademark/domain/package collision checks still to run (§16) | Decided; collision checks pending |
| Catalogue sourcing | Public research + clean-room study of incumbents | Decided |
| Check logic | Declarative packs + engine-coded complex checks | Decided |
| Authentication | Kerberos via current logon + simple bind over LDAPS/StartTLS with prompted credentials | Decided |
| Privilege model | Two modes (user / admin), refined to three tiers | Default |
| Form factor | Single static binary with UX inside; shell-wrapper UX rejected; runtime language open (§17) | Open — see §17 |
| Primary UX | Local web UI with connection wizard (§2.1); console mode for headless hosts; CLI for automation | Decided |
| Enterprise approvability (R7) | Security review pack per release from CI, release blocked if incomplete (§6.1); approver-facing features — `--dry-run`, `--manifest`, compliance mappings, exceptions, management summary, SIEM export, encrypted/redacted reports, "why free" README (§8.1) | Decided |
| Adoption requirements | AR-1…AR-14 with acceptance criteria (§1.2): immediate-reputation signing, express path + quick scan, `doctor`, modern-DC compatibility, shareable report with `--redact` and top-5 paths, remediation + `fix --plan`, diff + `schedule`, community packs with stable IDs, `--demo`, consultant mode, console output, honest states, snapshot architecture, first-run contract measured in CI | Decided |
| Negative requirements | N-1…N-10 (§1.3): no installer/account/key, nothing leaves the machine, no runtime deps, no Turing-complete plugins, no browser engine, no gating in the first run, no `curl \| sh`, no exploit code, no writes to targets, no writes outside the output folder | Decided |
| Signing | Immediate-reputation certificate from the first public release — EV, or Trusted Signing if an individual outside the US is eligible; no public release before it exists | Decided |

---

## 12. Open questions (recommended default in bold)

| # | Question | Options | Status / answer |
|---|---|---|---|
| 1 | v1 directory coverage | (a) AD only · **(b) AD + Samba AD DC** · (c) + FreeIPA/ALD Pro · (d) + Entra | Default — full coverage over time in phase order; v1 = (b) |
| 2 | Primary market for v1 messaging | (a) global · (b) RU import-substitution · **(c) both, RU-stack coverage as differentiator** | Decided: (c) |
| 3 | Ownership / IP boundary | (a) personal repo, personal copyright · (b) InfoWatch-owned · **(c) personal with written employer consent** | Decided: (c) — consent letter is action A1 |
| 4 | Name | (a) keep "Directory Protector" · **(b) rename; run trademark/GitHub/winget/PyPI collision checks** | Decided: (b) — Directory Auditor; collision checks pending (A2) |
| 5 | Check catalogue source | **(a) public research + clean-room study of PingCastle/PK for knowledge only** | Decided: (a) — see §9 |
| 6 | Runtime | **(a) Go static binary** · (b) PowerShell 7 module · (c) Python stdlib · (d) .NET self-contained / Native AOT | Open — comparison in §17; recommendation (a), credible alternative (d) |
| 7 | Where check logic lives | **(a) declarative packs + engine-coded complex checks** · (b) packs with embedded scripting · (c) all in Go | Decided: (a) |
| 8 | Auth methods v1 | **(a) Kerberos via current logon (SSPI / ccache) + simple bind over LDAPS/StartTLS with prompted credentials** · (b) + NTLM · (c) + certificate auth | Decided: (a) |
| 9 | OS/arch matrix v1 | **(a) Windows x64, Linux x64 + arm64 static, macOS arm64** · (b) Windows + Linux x64 only · (c) + Windows arm64 / Linux x86 | Default |
| 10 | Astra Linux SE ЗПС | (a) out of scope for v1 · **(b) v1 ships an Astra-signed ELF via "Ready for Astra"** · (c) v2 | Open |
| 11 | Privilege model | (a) two tiers · **(b) three tiers, each check self-declares** | Default |
| 12 | Admin-tier collection | **(a) remote only, credentials prompted, never persisted** · (b) also "run on DC" local mode | Default |
| 13 | Read-only guarantee | **(a) hard — no write paths compiled in, documented as a contract** · (b) soft `--safe` flag | Default |
| 14 | Run scope | (a) single domain · **(b) domain by default, `--forest` opt-in, `--targets file` for multi-directory** | Default |
| 15 | Windows code signing | (a) OV · **(b) EV from day one — immediate SmartScreen reputation; "Unknown publisher" on the first run breaks G0** · (c) OV now, EV later · (d) Azure Trusted Signing (Microsoft-managed, immediate reputation; eligibility for an individual outside the US to be verified) | Decided: immediate reputation required (AR-1) — (b), or (d) if eligible; eligibility check is action A6 |
| 16 | Channels | (a) GitHub Releases only · **(b) + winget + Homebrew + RU mirror (GitVerse/GitFlic)** · (c) + PowerShell Gallery thin wrapper | Default |
| 17 | Updates | **(a) none automatic; `--check-update` opt-in; packs as signed bundles** · (b) auto-updater | Default |
| 18 | Report formats v1 | **(a) HTML + JSON + CSV + diff** · (b) + PDF · (c) + SARIF/Syslog | Default |
| 19 | Telemetry | **(a) none, stated loudly** · (b) opt-in anonymous counts | Default |
| 20 | Monetisation timing | (a) Pro designed in from day one · **(b) Apache 2.0 core first; Pro only after measurable adoption** · (c) sponsorship only | Default |
| 21 | Web UI frontend stack (§2.1) | **(a) server-rendered templates + small vendored HTML-over-the-wire library + SSE** · (b) vendored component framework (Preact/Svelte) single bundle · (c) hand-written vanilla web components | Default |
| 22 | Governance / accountable party (§18.1 #1) | (a) personal GitHub account, single maintainer · **(b) project organisation, ≥2 maintainers, signed releases, SECURITY.md, support and release policy; legal entity only when Pro/support contracts exist** · (c) legal entity from day one | Open |
| 23 | Russian software registry route (§18.1 #2) | **(a) not in the registry; target non-КИИ scope, MSPs and integrators in RU** · (b) Russian legal entity (ИП/ООО) as rights holder of the RU build, registry application · (c) a Russian partner vendor bundles and registers it | Open — interacts with the ownership decision (question 3) |
| 24 | Snapshot architecture (§19.2) | **(a) collect → versioned snapshot → analyse → report; every feature in §19 builds on it** · (b) live analysis against the directory, no snapshot | Decided: (a) — AR-13 |
| 25 | Demo mode (§19.1 #9) | **(a) `--demo` runs the full report on a bundled synthetic snapshot; same snapshot published online as the sample report** · (b) online sample report only | Decided: (a) — AR-9 |
| 26 | Fix-plan generation (§19.1 #6) | **(a) `fix --plan` writes a PowerShell / shell script with `-WhatIf` for selected findings; the tool itself never executes it** · (b) remediation text only | Decided: (a) — AR-6 |

---

## 13. Roadmap and rough effort

| Step | Scope | Effort | Cash |
|---|---|---|---|
| **First** (6–8 weeks) | Employer consent (A1) and name (A2); runtime decision (§17); signing pipeline + reproducible build in CI; engine skeleton; AD LDAP provider; check catalogue v1 (~50 checks across directory core, DNS, GPO, PKI, Kerberos — clean-room); 25 tier-0 checks implemented; HTML/JSON report; **web wizard steps 1–7 with shared design system and the express path**; console mode; **snapshot architecture, quick scan default, `doctor`, teaching error messages, LDAP signing/sealing + channel binding + LDAPS, stable check IDs, redaction, `--demo`**; **security review pack v1 generated in CI (SBOM, provenance, query manifest, network sheet, read-only symbol test), `--manifest`/`--dry-run`, run log, audit-account script, MSI + .deb/.rpm + portable zip**. Shippable alpha. | ~290 h (wizard ~60 h, enterprise pack ~40 h, adoption items ~40 h) | Immediate-reputation code-signing certificate (EV ~$300–700/yr or Trusted Signing subscription) |
| **Then** | Samba AD DC validation; SYSVOL/SMB tier 1; DNS and HTTP probes; 50+ checks; **top-5 paths to Tier 0, `fix --plan`, diff/trend, `schedule` helper, `new-check` scaffolding, consultant mode**; profiles and diff view in the UI; **exceptions with justification and expiry, compliance mappings per check, SOC runbook per EDR vendor, AV allow-list enrolment, encrypted/redacted report export, syslog/CEF and SARIF, chat webhook**; winget/brew/scoop; RU mirror | ~180 h | — |
| **Later** | FreeIPA/ALD Pro provider (+~120 h); Entra Graph provider (+~120 h); tier-2 collectors (RPC/WinRM/SSH) and the offline collector-script path; Astra signing; PowerShell wrapper module; C-callable library for integrators; **independent third-party security audit; registry route if chosen (question 23)** | per item | Astra programme fees; audit: five-figure USD when revenue exists |

Per-check effort after the engine exists: 1–2 h per declarative tier-0 check; 0.5–1 day per engine-coded complex check. Clean-room protocol overhead: ~1 day over the whole project.

---

## 14. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Employer IP / naming collision with DD+DAT | Written consent (A1) and rename (A2) before the first public commit |
| Astra SE ЗПС blocks unsigned ELF and interpreters | Astra-registered signing key in v1 or explicit exclusion of Astra SE max level (question 10) |
| Kerberos without system libraries (pure-Go and pure-managed Kerberos libraries are small projects; one has a CVE history) | Pin, vendor, fuzz; simple bind over TLS as the always-works fallback |
| SMB client with Kerberos is the least mature piece in both Go and .NET ecosystems | On Windows use the OS (UNC path with logon token); on Linux NTLM-over-SMB or a maintained fork; SYSVOL checks are tier 1 and degrade gracefully |
| False positives on Samba/FreeIPA dialects | rootDSE fingerprinting; provider-specific test suites; AD-only checks gated off for 389-ds |
| AV / SmartScreen flagging a new binary (higher reported false-positive rate for Go binaries) | OV certificate + reputation time; no packers (no UPX); VirusTotal results per release; EV later |
| "Vulnerability" checks accused of being exploit tooling | No exploit code (§7), stated in README; inference only |
| Resemblance claim despite clean room | Evidence trail in §9; functional similarity between two tools auditing the same directory is expected, not infringement |
| Contributor pastes copyleft code | CONTRIBUTING rule, DCO, licence scanner in CI, squash-review of first PRs |
| Coverage gap vs incumbents at launch | Gap list becomes the public roadmap; honest check counts |
| Scoring looks like PingCastle's | Own model designed and documented before reviewing theirs again |
| Console window closes instantly on double-click | Web mode keeps the process alive while the browser session is open; "Press Enter to exit" in console mode; `--no-pause` for automation |
| XSS in the wizard or report from attacker-controlled directory data (object names, descriptions, DNS records, GPO names) | Context-aware auto-escaping templates, strict CSP, no `innerHTML` of directory data; fuzz the renderer with hostile LDAP values in CI |
| Local web server reachable by other users on a shared host, or via DNS rebinding | Loopback bind, random port, one-time token, `Host`/`Origin` checks; documented SSH port-forwarding for jump hosts |
| No browser on the host (Server Core, jump box) | `--console` mode with the same wizard; report still written to disk |
| Web UI scope creep delays the alpha | Wizard steps fixed at seven; profiles, diff view and dashboards are "Then" items |
| Enterprise enablers (E2–E4) creep into the first run and break G0 | Design rule in §1.1: first-run contract wins; TTFR and step count measured in CI against the lab domain on every release |
| "Unknown publisher" SmartScreen warning on the very first run | Immediate-reputation signing (EV or Trusted Signing); until the certificate exists, no public release |
| Linux download loses the executable bit, forcing `chmod +x` | Ship `.tar.gz` (mode preserved) and `.deb`/`.rpm`; README shows the one-line run; never a `curl \| sh` installer (unsignable) |
| Quick scan finds nothing in a well-run lab → "it does nothing" | Report always shows what was checked and passed, with counts; "Run full scan" as the obvious next step |
| Acceptance tests (§1.2) need a reference lab in CI; AD cannot run in a container | Samba AD DC container is the CI reference for timing and functional gates; AD-specific gates run on the owner's lab and are recorded per release until an AD lab is automated |
| Fourteen adoption requirements inflate the alpha | "First"-step items are the cheap ones (AR-1–5, 9, 11–14); AR-6–8, 10 are "Then"; acceptance criteria stop gold-plating by defining "done" |
| Immediate-reputation signing not obtainable in time (EV identity checks, Trusted Signing eligibility) | Action A6 starts now; the alpha can be tested privately without it, but no public release happens unsigned |
| Timing — PingCastle free edition's licence expiry opens a window that closes if v1 slips past 2027 | Alpha within the "First" step; AD + Samba first, everything else later |
| Scope creep from "all four directories" and "related services" | Hard v1 boundary = AD + Samba, tiers 0–1, five check domains; everything else is a roadmap issue |
| Enterprise approval blocked by "no accountable party" (§18.1 #1) | Governance default (question 22): project organisation, two maintainers, signed releases, SECURITY.md, published support/release policy |
| RU КИИ subjects cannot adopt without registry status (§18.1 #2) | Decide the registry route (question 23) explicitly; until then, RU messaging targets non-КИИ scope, MSPs and integrators |
| SOC stops the first run as reconnaissance (§18.1 #3) | SOC runbook with expected alerts and allow-list recipes shipped with the tool; pre-flight manifest as ticket text; throttling and single-DC targeting |
| Security review pack goes stale between releases | Generated by CI from the build, not hand-written; release blocked if any artefact is missing |
| Audit-account script itself needs privileges to run | Script requires only the rights to create a user and set ACLs on it; `-WhatIf` by default; documented alternative via existing JML process |

---

## 15. Sources

- Netwrix — PingCastle vs Purple Knight: https://netwrix.com/zh/resources/blog/pingcastle-vs-purple-knight/
- Netwrix docs — PingCastle 3.5 licensing and usage: https://docs.netwrix.com/docs/pingcastle/3_5
- Netwrix — Compare PingCastle editions: https://netwrix.com/en/products/pingcastle/pingcastle-comparison/
- Interoperable Europe — Open Software License 3.0 text: https://interoperable-europe.ec.europa.eu/licence/open-software-license-v-30-osl-30
- choosealicense.com — OSL 3.0 summary: https://choosealicense.com/licenses/osl-3.0
- Semperis — Purple Knight third-party legal notices: https://www.semperis.com/docs/PurpleKnight-Third-Party-Contributions.pdf
- OS Day — Замкнутая программная среда в Astra Linux SE (Аксенова): https://osday.ru/downloads/Aksenova.pdf
- Habr — Astra Linux SE bug bounty, ЗПС mechanics: https://habr.com/en/articles/782112
- Microsoft Learn — Native AOT cross-compilation (no cross-OS compilation): https://learn.microsoft.com/dotnet/core/deploying/native-aot/cross-compile
- dotnet/corefx #24843 — System.DirectoryServices.Protocols on Linux/macOS (P/Invoke to libldap): https://github.com/dotnet/corefx/issues/24843
- NuGet — ToolUp.AuthProviders.LdapActiveDirectory (S.DS.P links wldap32 on Windows, OpenLDAP libldap on Linux/macOS): https://www.nuget.org/packages/ToolUp.AuthProviders.LdapActiveDirectory/
- Microsoft Learn — Defender for Identity security alerts overview (reconnaissance alerts): https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview
- Контур — Указ Президента №166: что изменится с 1 января 2025 года (запрет иностранного ПО на значимых объектах КИИ): https://kontur.ru/talk/spravka/54411-ukaz_prezidenta_ob_importozameshchenii
- vc.ru — Закон о КИИ 2025: импортозамещение ПО: https://vc.ru/dev/2632413-zakon-o-kii-2025-importozameshchenie-po
- Kaspersky — Allowlist Program for software developers: https://www.kaspersky.com/partners/allowlist-program

---

## 16. Next actions and name

**Next actions (in order).**

| # | Action | Owner | Output |
|---|---|---|---|
| A1 | Employer consent on the IP boundary: a short written agreement stating that the tool is the author's personal project, developed on personal time and equipment, outside InfoWatch's product scope, with InfoWatch waiving claims to it; names, scope and non-compete-style boundaries explicit; wording must leave room for the governance and registry options (questions 22 and 23) | Draft (RU) → sign with InfoWatch | Consent letter |
| A2 | Name collision checks for "Directory Auditor" / `dirauditor`: trademark (WIPO, USPTO, Роспатент — including "Auditor"-family marks held by Netwrix and Lepide), GitHub organisation and repository, winget, Homebrew, scoop, PyPI/npm/crates, domains (`.io`, `.dev`, `.ru`), InfoWatch's own naming | Owner | Collision report; go / adjust |
| A3 | Decide runtime after reading §17 | Owner | One line |
| A4 | Check catalogue v1 (~50 checks across the five v1 domains, clean-room, primary references) | Draft → owner review | `catalogue-v1.yaml` |
| A5 | Repo skeleton: licence, `CONTRIBUTING.md` with clean-room rule, DCO, `docs/clean-room.md`, CI with reproducible build + signing + SBOM + acceptance-test scaffolding (§1.2) | — | Repo scaffold |
| A6 | Immediate-reputation signing (AR-1): check Azure Trusted Signing eligibility for an individual outside the US; otherwise start an EV certificate order (identity validation takes weeks) | Owner | Certificate or subscription |
| A7 | Governance and registry decisions (questions 22 and 23) — they change the wording of A1 | Owner | Two lines |

**Name decision.** *Directory Auditor* — descriptive, pronounceable in Russian («Директори Аудитор»), reads correctly for AD, Samba, FreeIPA and LDAP alike, and makes no claim beyond what the tool does. CLI command `dirauditor` (not `diraudit`: an unrelated `dir-audit` file-system package already exists on PyPI).

**Quick check (not a clearance).** A web search found no existing security product named "Directory Auditor"; the nearest marks are product families with "Auditor" in the name (Netwrix Auditor, LepideAuditor). A descriptive two-word name is weak as a trademark — hard for others to block, equally hard to protect — which fits an open-source project. Full checks are A2.

**Naming constraints (kept for the record).** Not "Knight", "Castle", "Purple", "Protector", "Watch" (employer name), "Sentinel", "Lighthouse", "Sonar", "Beacon"; pronounceable and non-comic in Russian; works as a CLI command; no existing security product of the same name.

---

## 17. Runtime options compared

**Note on reputation.** SmartScreen reputation accrues per signing certificate and per file hash, not per runtime; no evidence was found that .NET binaries build it slower than Go binaries. The measurable difference between runtimes on the AV side is the widely reported higher false-positive rate for Go binaries (a consequence of Go's popularity with malware authors), which signing, no packing and per-release VirusTotal publication mitigate.

### 17.1 Scorecard against the four hard requirements and secondary criteria

| Criterion | (a) Go static binary | (b) PowerShell 7 module | (c) Python stdlib | (d) .NET self-contained / Native AOT |
|---|---|---|---|---|
| **R1 reviewable** | ✅ Source + reproducible build + SBOM; reviewer verifies the hash matches the source | ✅ Plain-text scripts — but 15–20 k lines of PowerShell is not reviewed in practice either | ✅ Plain-text scripts | ✅ Source; deterministic builds supported, byte-for-byte reproducibility of AOT output across toolchains weaker than Go's |
| **R2 signing enforced** | ✅ Authenticode (PE), cosign/minisign and Astra ELF signature; packs Ed25519 | ⚠️ Enforced on Windows only (`AllSigned`); on Linux/macOS the execution policy is `Unrestricted` and cannot be changed; the `.cmd` launcher needed for double-click cannot be signed | ❌ No signing mechanism for scripts; a PyInstaller "one-file" exe is signable but unpacks unsigned payload to a temp directory at every run | ✅ Native AOT: one signable PE/ELF. ⚠️ Single-file (non-AOT): native runtime pieces may be extracted to temp — same unsigned-payload problem, weaker than AOT |
| **R3 zero runtime dependencies** | ✅ Fully static with cgo off; own TLS stack in the standard library; pure-Go LDAP, Kerberos, SMB, SSPI via syscalls | ❌ `pwsh` 7 is not preinstalled anywhere (Windows ships 5.1, which differs); on Linux it is a ~170 MB install from Microsoft's repo; LDAP on Linux needs `libldap` or a bundled .NET DLL inside the "script" module | ❌ Python is not preinstalled on Windows; the standard library has **no LDAP, Kerberos or SMB client** — all three would be written from scratch or vendored (`ldap3` is LGPL-3.0); distro Python drift 3.6 → 3.12 | ⚠️ Windows: zero extra (wldap32, SSPI, UNC paths are in the OS). Linux/macOS: `System.DirectoryServices.Protocols` P/Invokes **OpenLDAP libldap**; Negotiate auth needs **libgssapi_krb5**; TLS always uses **system OpenSSL**; globalization needs ICU unless `InvariantGlobalization`. Pure-managed LDAP and Kerberos libraries remove two of the four; OpenSSL remains a true runtime dependency on Linux |
| **R4 one action on Windows and Linux** | ✅ Double-click / `./tool`; interactive mode inside | ⚠️ Windows: needs a launcher; Linux: install pwsh first, then terminal | ❌ Windows: install Python first, or ship a 30–50 MB PyInstaller bundle | ✅ Native AOT behaves like (a) |
| **Astra Linux SE ЗПС** | ✅ One static ELF, signable with Astra's tooling; no shared libraries to sign | ❌ Interpreter blocked | ❌ Interpreter blocked; PyInstaller temp payload unsigned | ⚠️ AOT ELF signable; its system-library dependencies are Astra-signed already; single-file non-AOT not viable |
| **Cross-compilation from one CI host** | ✅ All OS/arch targets from one Linux runner (`GOOS`/`GOARCH`) | n/a | n/a | ❌ Native AOT does not support cross-OS compilation (needs the target OS SDK); solved with a 3-OS CI matrix; a third-party Zig-linker workaround exists but adds supply-chain surface |
| **Binary size (approx.)** | 15–25 MB | Module 1–2 MB + 170 MB runtime | 30–50 MB (PyInstaller) | AOT 12–25 MB; single-file trimmed 30–40 MB; untrimmed ~70 MB |
| **Protocol libraries** | `go-ldap` (MIT), `gokrb5` (Apache 2.0; lightly maintained, CVE history — pin and fuzz), `go-smb2` (MIT; Kerberos via fork), SSPI without cgo | Windows: ADSI / S.DS.P built in; RSAT `ActiveDirectory` module is itself a dependency — avoid. Linux: see R3 | None in stdlib; `minikerberos` (MIT), `smbprotocol` (MIT) are dependencies | S.DS.P (wldap32 / libldap); `Novell.Directory.Ldap.NETStandard` (MIT, pure managed); `Kerberos.NET` (MIT, pure managed, reads ccache); SMB on Linux: `SMBLibrary` is **LGPL-3.0** — a licence problem when statically linked into an Apache 2.0 AOT binary; on Windows UNC paths via OS |
| **AV / SmartScreen** | ⚠️ Higher reported false-positive rate; mitigated by signing, no packer, VirusTotal per release | ⚠️ AMSI scans scripts; "script spawns LDAP/SMB to a DC" heuristics | ⚠️ PyInstaller one-file is a classic false-positive trigger | ✅ Looks like every other Windows application |
| **Performance (500 k objects, ACL parsing)** | ✅ Parallel paged searches, low memory | ❌ 10–100× slower object pipeline; large forests take hours | ⚠️ Adequate with care | ✅ Comparable to Go |
| **Author's ramp-up** | ⚠️ New language; 2–3 weeks part-time to fluency; LLM assistance is strong for Go | ✅ Native skill | ✅ Familiar | ✅ C# is close to PowerShell; same BCL and idioms |
| **Contributor pool** | Large Go security-tool community (offensive tooling, cloud-native) | Windows admins and the PowerShell AD community | Python security community (Impacket) | **AD security research community is C#-heavy** (SharpHound, Certify, Rubeus, PingCastle); strongest pool for this exact domain |
| **Future PowerShell module / C library** | ✅ `-buildmode=c-shared` (needs cgo); PS module wraps the exe and parses JSON | — | — | ✅ Same language: a PS module can reference the engine assembly directly, no wrapper plumbing |
| **Verdict** | **Recommended** — the only option that meets R1–R4 without exceptions | **Rejected as core**; natural *wrapper* and Windows-admin front door later | **Rejected** — fails R3 and R4 on Windows; nothing usable in stdlib | **Credible alternative** — meets R1, R2, R4; R3 holds on Windows, with one documented exception on Linux (system OpenSSL) once pure-managed LDAP/Kerberos are used |

### 17.2 Option narratives

**(a) Go static binary.** `CGO_ENABLED=0` produces a binary with no libc dependency on Linux (musl-free static), its own TLS and crypto in the standard library, and cross-compiles to every target from one runner — the shortest path to "copy the file, run it" on Windows, any Linux distro including Astra SE, and macOS. Reproducible builds are first-class, which is what makes "the hash matches the source" a verifiable claim. Costs: the author learns a new language; `gokrb5` is the one library that needs active supervision (pin, vendor, fuzz, watch advisories); SMB-with-Kerberos on Linux is the least mature piece (fallback: NTLM over SMB for SYSVOL, or a maintained fork); Go binaries attract more AV false positives until signing reputation accrues.

**(b) PowerShell 7 module.** The fastest prototype for the author and the most readable for Windows admins. It fails the Linux half of the brief on three counts: `pwsh` must be installed first (no "copy and run"), script signing cannot be enforced there, and Astra SE ЗПС blocks interpreters outright. Even on Windows, the preinstalled 5.1 differs from 7 enough to force dual support, and the double-click path needs an unsignable `.cmd`. Performance on large forests is the other hard limit. Keep it as the later wrapper module (signed, PowerShell Gallery) over the compiled engine.

**(c) Python stdlib.** Python is absent on Windows by default and the standard library contains no LDAP, Kerberos or SMB client, so "stdlib only" means writing BER/ASN.1 LDAP, Kerberos and SMB2 from scratch — months of work that nobody will review. Vendoring libraries brings in `ldap3` (LGPL-3.0, incompatible with a clean Apache 2.0 core) and C extensions. Packaging into a single exe via PyInstaller produces a large, slow-starting, AV-flagged bundle that unpacks unsigned code at runtime and is blocked under ЗПС. No path to the requirements.

**(d) .NET self-contained / Native AOT.** Two sub-variants. *Single-file self-contained* bundles the runtime (~70 MB, or 30–40 MB trimmed) and still extracts native pieces — weaker than AOT on R2 and ЗПС. *Native AOT* (.NET 8+) yields a real native binary comparable to Go in size and startup; on Windows it is the most "native" option of all (SSPI, wldap32, UNC paths are the OS). On Linux the picture is different: the standard LDAP class P/Invokes OpenLDAP's `libldap`, Negotiate auth uses `libgssapi_krb5`, TLS always goes through system OpenSSL, and globalization wants ICU. Pure-managed `Novell.Directory.Ldap` and `Kerberos.NET` (both MIT) remove the first two; `InvariantGlobalization` removes ICU; OpenSSL remains — present on every mainstream distro, but a dependency and a version-drift risk (OpenSSL 1.1 vs 3) that must be documented as the one exception to R3. SMB on Linux has no permissively licensed pure-managed client (`SMBLibrary` is LGPL-3.0). AOT cannot cross-compile across OSes, so CI runs a Windows/Linux/macOS matrix. The decisive advantages: the author's existing fluency, and the fact that the AD security research community — the people most likely to contribute checks — writes C#.

**Web UX and the runtime choice.** Neutral: Go (`embed`) and .NET (embedded resources) both compile the wizard's HTML/CSS/JS into the single binary; both have an HTTP server and SSE in the standard library. PowerShell and Python would need a web framework or a long hand-rolled server — one more reason they are out.

### 17.3 Decision rule

- Choose **(a)** if the priority is the cleanest possible claim — one static file, no exceptions, every OS from one build — and the author accepts a 2–3-week ramp-up.
- Choose **(d) Native AOT** if the author intends to write most of the engine personally and values the C# contributor pool more than a documented OpenSSL dependency on Linux and a three-OS build matrix.
- In both cases **(b)** returns later as the signed PowerShell wrapper; **(c)** is closed.

Effort delta: (a) adds ~2–3 weeks of language ramp-up at the start; (d) adds ~1 week of AOT trimming work (reflection-free YAML/JSON via source generators) and a slightly heavier CI. Over the 150-hour "First" step the two are within ~15 % of each other.

---

## 18. Enterprise adoption review — bank / telecom operator

Reviewer stance: AD platform lead plus the ИБ approver in a large bank or telecom operator, deciding whether the tool passes software intake («допуск ПО к эксплуатации» / OSS intake) and whether a first run would be allowed on production. Two findings do not depend on any technical design: there is **no accountable party** behind the tool, and the tool's network behaviour is **indistinguishable from attacker reconnaissance** to the SOC. Everything else is fixable with a security review pack and packaging work (~40 h in "First", ~60 h in "Then").

### 18.1 Showstoppers, ranked (who blocks → fix → effort)

| # | Showstopper | Who blocks | Fix | Effort |
|---|---|---|---|---|
| 1 | **No accountable party**: individual author, personal GitHub account, no support policy, no vulnerability-disclosure process, bus factor 1 | Procurement, ИБ, legal | Project organisation on GitHub (not a personal account), ≥2 maintainers, signed commits and releases, `SECURITY.md` + `security.txt`, published support and release policy (LTS branch), public roadmap; a legal entity only when Pro/support contracts exist (question 22) | 1 week + ongoing |
| 2 | **RU КИИ subjects**: not in the Реестр российского ПО. Decree 166 bans foreign software on significant КИИ objects for state-linked organisations from 1 January 2025; banks and telecoms with such objects are in scope. Open source by an individual is neither "registered Russian" nor clearly "foreign", so approvers default to "no" | ИБ, legal (RU) | Decide the registry route (question 23): (a) stay outside the registry and target non-КИИ scope, MSPs and integrators; (b) Russian legal entity as rights holder of the RU build and a registry application; (c) a Russian partner vendor bundles and registers it. (b) and (c) conflict with the personal-project ownership decision and need the employer-consent letter to allow them | decision memo |
| 3 | **Looks like attacker reconnaissance**: Defender for Identity documents alerts for exactly this behaviour ("Security principal reconnaissance (LDAP)", "Account enumeration reconnaissance", "Active Directory attributes reconnaissance (LDAP)", "Network mapping reconnaissance (DNS)"); Kaspersky, PT and MaxPatrol rule sets are equivalent. PingCastle and Purple Knight trigger them too — the difference is whether the SOC was warned | SOC | Ship a **SOC runbook**: expected alerts per EDR/NDR vendor, allow-list recipe for the audit account, run-window advice; **pre-flight manifest** (`--dry-run`) exportable as RFC/SOC-ticket text (DCs, queries, estimated load, duration); `--max-qps`, `--dc` single-DC targeting, a fixed and documented LDAP client fingerprint so the SOC can allow-list the tool rather than the account | 1 week |
| 4 | **"Copy and run" violates deployment policy**: software arrives as MSI/.deb/.rpm with publisher metadata, deployed by SCCM/Ansible, inventoried, allowed by AppLocker/WDAC publisher rule | Desktop / server engineering | MSI (WiX) + signed .deb/.rpm + portable zip built from the same signed binary; stable certificate subject for WDAC publisher rules; `--version --manifest` for inventory; uninstall leaves nothing behind | 1 week |
| 5 | **Admin credentials typed into a third-party tool** (tier 2) | ИБ, PAM team | Tier 2 is a separate opt-in with explicit scope; PAM-friendly paths: run on a PAW under the admin session (no password typing), credential from Windows Credential Manager; alternative **offline collector**: a signed, readable PowerShell/Bash script the admin runs on the DC, output fed to the tool for analysis | 2 weeks ("Later") |
| 6 | **Attribution**: activity must be traceable to a dedicated read-only audit identity, not the admin's personal account | ИБ, internal audit | Ship `New-AuditAccount.ps1` (and the FreeIPA equivalent) creating a least-privilege account: Domain Users plus explicit read rights, explicit deny on LAPS password attributes, Protected Users, no interactive logon, `-WhatIf` default; wizard step 4 recommends it and detects when it is used | 2 days |
| 7 | **The report is a treasure map** (privileged accounts, ACL paths, vulnerable DCs) and **contains personal data** (152-ФЗ / GDPR) | ИБ, DPO | Classification banner; encrypted export (passphrase); redaction / pseudonymisation mode for sharing with vendors; data-inventory sheet (what personal data is read, why, retention); `Cache-Control: no-store` in the local UI; report hash in the footer | 1 week |
| 8 | **Local listening port and auto-launched browser** on a PAW or server: host-firewall policy, EDR "new listener" alerts, proxy PAC routing `localhost`, IE ESC / Edge policies | Endpoint security | `--console` is first-class; `--no-browser` prints the URL; loopback-only listener declared in the manifest; Unix-socket / named-pipe transport later | small |
| 9 | **Unverified supply chain**: lightly maintained Kerberos library, no SBOM, no scan evidence, Go false positives | AppSec, AV team | Security review pack (§18.2); AV allow-list enrolment (Microsoft, Kaspersky Allowlist Program, ESET, Dr.Web); CodeQL + gosec + govulncheck + fuzzing in CI; OpenSSF Scorecard and Best Practices badge; SLSA L3 provenance | 1 week + ongoing |
| 10 | **Load on DCs** in 1 M-object forests with 100+ DCs | AD platform team | Paged, throttled reads; `--dc` single DC (never the PDC emulator by default); estimated load in pre-flight; resumable runs; incremental (USN-based) collection later | in engine |
| 11 | **No audit trail** of what the tool did | Internal audit | Run log as JSON (account, DCs, queries, attributes read, timestamps) with syslog/CEF option; run-manifest hash embedded in the report | 2 days |
| 12 | **Provenance screening both ways**: Western compliance screens the author's residence and employer (sanctions and "software from Russia" policies); RU compliance distrusts a Western CA signature and GitHub hosting | Compliance | Neutral project identity; InfoWatch association kept out of the project; provenance through reproducible builds ("trust the hash, not the author"); RU mirror and a ГОСТ-signed Astra build | — |
| 13 | **Findings fatigue**: the same 300 findings every run, no risk acceptance, no owner | AD team | Exceptions with justification and expiry stored in the profile; baseline diff; owner and effort per finding; management summary page; Jira/SARIF export | "Then" |
| 14 | **No control mapping**: approvers and auditors ask "which requirement does this evidence?" | GRC | Per-check mapping fields: CIS Benchmarks, NIST SP 800-53, ISO/IEC 27001:2022 Annex A, PCI DSS 4.0, DORA; ГОСТ Р 57580.1, приказы ФСТЭК №17/21/239, БДУ | catalogue field |

### 18.2 Security review pack

Adopted as a requirement — see **§6.1** (artefact list, sources, formats, release gate).

### 18.3 What makes approval easy and the tool appealing

Adopted as requirements — see **§8.1** (approver-facing product features). Items that live elsewhere: dedicated audit-account script with `-WhatIf` default (§18.1 #6, "First"); enterprise packaging — MSI, .deb/.rpm beside the portable file, WDAC/AppLocker publisher rules (§18.1 #4, "First"); everything works offline, documentation bundled in the binary (§6, §7).

---

## 19. Adoption-driven technical design — rationale for AR-1…AR-14 and N-1…N-10

Adopted as requirements in §1.2 and §1.3; this section keeps the reasoning. The question answered here: which *technical* decisions make an administrator try the tool, succeed on the first run, come back, and tell a colleague. Free security tools that spread (PingCastle, Sysinternals, BloodHound, Nmap, ripgrep-class CLI tools) share the same pattern: one file, instant value, output people screenshot, errors that teach, and a way for users to extend it. Each decision below names the adoption effect it buys, its cost, and where it lands in the roadmap.

### 19.1 Twelve decisions, ranked by adoption effect per hour of work

| # | Decision | Adoption effect | Cost | When |
|---|---|---|---|---|
| 1 | **Signed single binary with immediate reputation** (EV or Trusted Signing, no packers, AV allow-lists) | Removes the "Unknown publisher — Don't run" wall and AV quarantine on the very first run — the largest single drop-off point for new tools | cert + 1 day | First |
| 2 | **Express path + quick scan default**: "Scan now" as current user, ~40 highest-value tier-0 checks, report in ≤ 5 min; full scan one click more | TTFR is what people remember; a 40-minute first scan is abandoned | 3 days | First |
| 3 | **`doctor` + teaching error messages**: one command checks DNS SRV, Kerberos (clock skew, no ticket, wrong realm), LDAP (signing required, channel binding, LDAPS cert), SMB; every failure prints the cause and the one-line fix | First-run failures are the #1 reason admins give up and never return; "it just told me my clock was 6 minutes off" is a story they retell | 1 week | First |
| 4 | **Modern-DC compatibility out of the box**: Kerberos signing and sealing, channel binding tokens, LDAPS with cert pinning, works when DCs enforce signing (the 2020+ default) | A tool that fails against hardened DCs fails exactly in the organisations that care about security | in engine | First |
| 5 | **The report as the viral artefact**: 0–100 score card, "top 5 ways to Tier 0" (attacker-path lite from ACL edges on Tier-0 objects: GenericAll / WriteDACL / WriteOwner / DCSync / RBCD), "quick wins ≤ 10 min", what was checked and passed, EN/RU, `--redact` so it can be posted on Reddit/Habr/forums | The report is the marketing; a score people want to improve and a screenshot people want to share. Redaction turns private results into public conversations | 2 weeks | First (score, quick wins, redact) · Then (paths) |
| 6 | **Copy-paste remediation + `fix --plan`**: every finding has why it matters, how it is abused, the exact command to fix it (PowerShell / `ldapmodify` / `samba-tool` / `ipa`) with `-WhatIf`, and how to verify; `fix --plan` writes a script for the findings the admin ticked — the tool never executes it (§7 stays intact) | "It wrote the fix for me" — findings get closed, scores improve, the admin returns to re-scan | 1–2 h per check + 1 week | Then |
| 7 | **Diff / trend + one-command `schedule`**: `--diff` ("fixed 12, new 2"), and `schedule` that creates a weekly scheduled task / cron entry with least privilege and `-WhatIf`, posting the summary to a file, syslog or chat webhook | Habit formation: a tool that runs weekly and reports deltas is never uninstalled | 1 week | Then |
| 8 | **Community checks without touching the engine**: YAML packs, `new-check` scaffolding, `check test` against a snapshot, `--allow-unsigned` for development, maintainers sign accepted community packs, stable public check IDs (`DSA-0042`) that blog posts and KBs can cite | Contributors multiply coverage; stable IDs make the tool citeable, which is how it enters internal wikis and vendor KBs | 1 week | Then |
| 9 | **`--demo` mode + online sample report**: a bundled synthetic snapshot renders the full report without any domain | Evaluators, students, conference audiences and people without a lab see the output before committing; the sample report is the landing page | 2 days (after §19.2) | First |
| 10 | **Consultant / MSP mode**: `--targets` with many domains, consolidated report, `--portable` keeping profile and output beside the binary (USB-stick use), per-customer redaction | Auditors and MSPs carry tools into dozens of organisations — PingCastle's growth channel | 1 week | Then |
| 11 | **Pretty console, not only web**: coloured, UTF-8-safe terminal output with live counters, works in cmd / Windows Terminal / SSH | Half the audience lives in a terminal; terminal screenshots are the ones that end up in chats | 2 days | First |
| 12 | **Honest "could not check" and "nothing found" states**: the report always shows what was skipped and why (tier, permission, provider), and what passed, with counts | Trust; a well-run lab that returns "0 findings, 212 checks passed" still looks like value instead of "it does nothing" | 1 day | First |

### 19.2 The one structural decision: snapshot architecture (AR-13)

```
 collect ──▶ snapshot.json.zst ──▶ analyse ──▶ report / diff / fix-plan
 (live LDAP/SMB/DNS/HTTP)   (versioned schema,   (signed packs,
                             redactable)          engine checks)
```

Collection and analysis are separate stages joined by a versioned, compressed snapshot. Checks run against the snapshot, never against the live directory. This single decision is what makes most of §19.1 cheap:

- **Re-analyse without re-collecting** — new packs, new engine version, different thresholds: seconds, no DC load, no SOC alerts.
- **`--demo`** is a bundled snapshot; the online sample report is the same file rendered.
- **Offline collector** (§18.1 #5): a readable PowerShell/Bash script that produces the same snapshot format for admins who will not run a binary on a DC or hand it admin credentials.
- **Support and community help**: a redacted snapshot can be shared when a check misfires; maintainers reproduce the exact report.
- **Tests**: every regression test is a snapshot fixture plus a golden report; community checks are tested with `check test snapshot.json`.
- **Diff and trend** compare snapshots, not reports — robust to report-template changes.
- **Consultant mode** collects once per customer, analyses many times.
- **Reproducibility for audits**: the snapshot hash goes into the report; a reviewer can re-run the analysis and get the same result.

Cost: a schema to version and migrate; snapshots of large forests can be hundreds of MB (compression and attribute allow-lists keep them under control); snapshots are sensitive data and inherit the report's protection (§8.1: encryption, redaction, classification).

### 19.3 Deliberately not — things that would raise short-term polish and lower adoption

- No installer-only distribution, no account, no licence key, no e-mail gate, no "free tier" nag — the first run asks for nothing.
- No cloud component, no telemetry (not even opt-in in v1), no auto-update — "nothing leaves your machine" must be literally true.
- No Turing-complete plugin language, no Electron/WebView shell, no runtime dependencies — the binary stays one file that a reviewer can reason about.
- No feature gating or "Pro" prompts in the first-run path (E4).
- No `curl | sh` installers — unsignable and the wrong lesson for a security tool.
- No exploit execution, ever, however much a "verify this finding" button would impress (§7).

### 19.4 First-run funnel and where it leaks

| Stage | Leak | Decision that plugs it |
|---|---|---|
| Hears about it | "What does the output look like?" | Online sample report, `--demo` (#9) |
| Downloads | Wrong asset, archive confusion, lost executable bit | One obvious asset per OS; `.tar.gz` for Linux; winget/brew/scoop |
| Runs | SmartScreen / AV wall | Immediate-reputation signing, allow-lists (#1) |
| Connects | Kerberos, DNS, signing failures | `doctor`, teaching errors, modern-DC support (#3, #4) |
| Waits | Scan takes too long | Quick scan default, live counters (#2, #11) |
| Reads | "So what?" | Score, top-5 paths, quick wins, honest states (#5, #12) |
| Acts | "How do I fix it?" | Copy-paste commands, `fix --plan` (#6) |
| Returns | No reason to re-run | Diff/trend, `schedule` (#7) |
| Tells others | Can't share without exposing the domain | `--redact`, stable check IDs, EN/RU (#5, #8) |
| Extends | Engine too hard to touch | YAML packs, `new-check`, `check test` (#8, §19.2) |
