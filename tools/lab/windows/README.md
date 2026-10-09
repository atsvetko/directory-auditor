# Windows AD DC lab (self-hosted, Hyper-V)

Automated live testing of the AD checks against **real Windows Server domain
controllers**, the counterpart to the Samba lab (`tools/lab/samba`). A
self-hosted GitHub Actions runner on your Hyper-V host restores a disposable DC
to a known-vulnerable checkpoint, scans it, and checks the findings against
[`testdata/lab/windows-expect.yaml`](../../../testdata/lab/windows-expect.yaml).
After the one-time setup below it runs nightly with no human intervention.

Matrix: **Windows Server 2022** (`DA-DC-2022`, 10.55.0.10) and **2025**
(`DA-DC-2025`, 10.55.0.11), both in the `da.test` forest.

> **Lab only.** Every script refuses unless `DIRAUDITOR_LAB=1`. Run them only on
> disposable VMs on an **isolated** Hyper-V switch with no route to your home or
> corporate network. The forest, accounts and passwords here are throw-away.

## One-time host setup

Run on the Hyper-V host as Administrator. `pwsh`/Windows PowerShell both work.

```powershell
$env:DIRAUDITOR_LAB = "1"

# 1. Isolated lab network (internal switch — host-only, no uplink).
New-VMSwitch -Name "da-lab" -SwitchType Internal
# give the host a presence on it so the runner can reach the DCs
New-NetIPAddress -InterfaceAlias "vEthernet (da-lab)" -IPAddress 10.55.0.1 -PrefixLength 24

# 2. Create two VMs from a Windows Server *evaluation* ISO (2022 and 2025),
#    4 GB RAM / 2 vCPU / 60 GB each, attached to "da-lab". Install the OS,
#    set a local admin password, leave them in a workgroup.
#    (Create them in Hyper-V Manager or with New-VM; nothing lab-specific here.)

# 3. Build each DC's vulnerable baseline. For 2022 (repeat for 2025 with
#    -DCAddress 10.55.0.11 -ForestMode Win2025 and VM name DA-DC-2025):
./tools/lab/windows/rebuild-baseline.ps1 `
    -VMName "DA-DC-2022" -DomainName "da.test" -DCAddress "10.55.0.10" -ForestMode Win2016
# rebuild-baseline drives provision.ps1 (promote, reboot) + populate.ps1
# (seed the weak objects) inside the VM, then takes the "vuln-baseline" checkpoint.
```

If you prefer to do it by hand, inside each VM:

```powershell
$env:DIRAUDITOR_LAB = "1"
./provision.ps1 -DomainName da.test -IPAddress 10.55.0.10   # promotes, reboots
# after reboot:
./populate.ps1  -DomainName da.test
```

Then on the host: `Checkpoint-VM -Name DA-DC-2022 -SnapshotName vuln-baseline`.

## Register the runner

Install the GitHub Actions runner on the **host** with the labels the workflow
expects, and store the audit password as a repo secret:

```powershell
# from the repo's Settings > Actions > Runners > New self-hosted runner (Windows)
./config.cmd --url https://github.com/atsvetko/directory-auditor `
             --token <RUNNER_TOKEN> --labels self-hosted,windows,hyperv-lab
./svc.sh install ; ./svc.sh start      # run as a service so nightly works unattended
```

- In the repo: **Settings > Secrets and variables > Actions**, add
  `LAB_AUDIT_PASSWORD` = the value `populate.ps1` used for the `audit` account
  (default `Lab-Audit-Pass-2026!`, or whatever you set via `-AuditPassword`).
- The runner needs the Go toolchain from `go.mod`; `actions/setup-go` installs it.

That is all. `lab-windows.yml` then runs nightly, on demand, and on pushes that
touch the catalogue or the AD provider.

## What it proves (and what it doesn't)

- The check **logic** against real Windows AD data, as an **ordinary user** — so
  it also shows which checks fall to `not-collected` without admin rights (the
  "~80% from a normal user" claim).
- The native **Windows SSPI** Kerberos sealing path (the sealed scan), which the
  Linux/Samba lab cannot exercise.
- It does **not** replace the synthetic fixtures (`go test ./internal/catalogue`),
  which stay the fast, deterministic gate on every push.

## Maintenance

- **Re-baseline** after changing the fixtures, or when the evaluation licence
  nears expiry: rerun `rebuild-baseline.ps1`. The evaluation is time-limited;
  rebuilding from a fresh eval VM resets the clock.
- **Tighten the expectations**: the committed `windows-expect.yaml` pins only the
  deterministic fixtures and allows everything else. After the first green run,
  download the `report.json` artifact and promote more checks from `allow` to
  `must` with their exact DNs.
- The host must be powered on for the nightly run; a miss is a skipped run, not a
  failure.
