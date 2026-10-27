# Hyper-V lab (Windows host)

Live testing against real directory servers in VMs on a Windows host with Hyper-V: a
**Samba AD DC** and a **Windows Server 2025 AD DC**, each restored to a checkpoint, scanned
as the ordinary `audit` user, verified against `testdata/lab/*-expect.yaml`, and checked
from the DC side for writes. This is the lab `.github/workflows/lab-hyperv.yml` runs nightly,
on pushes to `main` and on same-repository pull requests (never forks). It is the Hyper-V
counterpart of [`tools/lab/kvm`](../kvm/README.md), with the same VM names, addresses and
checks.

> **Lab only.** The DCs are deliberately weak. They live on `DA-Lab`, an internal Hyper-V
> switch with no NAT and no forwarding on the host. The Samba VM has internet access only
> while packages are installed, through a temporary card on `Default Switch` that is removed
> before anything is weakened; the Windows DC never has a route out (AD DS and AD CS install
> from the ISO). The scripts refuse to run unless `DIRAUDITOR_LAB=1`.

| File | What it does |
|---|---|
| `setup-host.ps1` | once per host, as administrator: `DA-Lab` (internal, host 10.55.0.1/24, no NAT, forwarding off) and the lab SSH key |
| `samba-lab.ps1` | `create` · `provision` · `snapshot` · `reset` · `scan` · `stop` · `destroy` for VM `da-samba-dc1` (10.55.0.20), Ubuntu 24.04 with cloud-init, reached over SSH |
| `windows-lab.ps1` | the same for a **Windows Server 2025** DC, VM `da-win2025-dc1` (10.55.0.10, forest `da.test`), plus `populate`, `adcs` and named snapshots; reached over PowerShell Direct. `scanner` builds `da-scan1` (Ubuntu, 10.55.0.30, no packages, never a route out), the VM the scans run from |
| `windows/autounattend.xml` | unattended install: Generation 2 (UEFI, GPT), static IP, a ready marker at first logon |
| `common.ps1` | shared helpers: answer/seed ISOs (IMAPI2), Ubuntu VMs over SSH, waits, binaries |
| `setup-runner.ps1` | once: a GitHub Actions runner (`self-hosted, windows, hyperv-lab`) as the local user `labrunner` |

## One-time setup

In an elevated PowerShell, with `DIRAUDITOR_LAB=1`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\lab\hyperv\setup-host.ps1
```

`-ExecutionPolicy Bypass` applies to that one process; the host keeps its own policy.
Lab state lives in `DA_LAB_HOME` (default `C:\DirAuditorLab`):

- `iso\Win2025.iso`: your Windows Server 2025 ISO (`WIN_ISO` to override; `IMAGE_INDEX`,
  default 2 = Standard, Desktop Experience);
- `vhd\noble-base.vhdx`: the Ubuntu 24.04 cloud image, checked against Ubuntu's published
  sums and converted with `qemu-img convert -O vhdx -o subformat=dynamic`;
- `state\id_ed25519`: the lab SSH key; `out\`: reports.

No lab binary runs on the host: `dirauditor` and `tools/lab/verify` are built for Linux and run
inside the Samba VM or the scanner VM, so a host with Smart App Control (which refuses unsigned
executables) needs no exception. Go (the version in `go.mod`) on `PATH` cross-compiles them;
without it, set `DA_BIN` to a folder holding the Linux `dirauditor` and `verify`.

## Build and run

```powershell
$env:DIRAUDITOR_LAB = '1'
$lab = 'powershell -NoProfile -ExecutionPolicy Bypass -File'
# Windows DC: ~30 min install, ~15 min forest, ~10 min AD CS
iex "$lab tools\lab\hyperv\windows-lab.ps1 create"
iex "$lab tools\lab\hyperv\windows-lab.ps1 provision"
iex "$lab tools\lab\hyperv\windows-lab.ps1 snapshot baseline"
iex "$lab tools\lab\hyperv\windows-lab.ps1 adcs"
iex "$lab tools\lab\hyperv\windows-lab.ps1 snapshot adcs"
iex "$lab tools\lab\hyperv\windows-lab.ps1 scanner"       # once: the Linux VM the scans run from
iex "$lab tools\lab\hyperv\windows-lab.ps1 reset baseline"; iex "$lab tools\lab\hyperv\windows-lab.ps1 scan"
# Samba DC
iex "$lab tools\lab\hyperv\samba-lab.ps1 create"
iex "$lab tools\lab\hyperv\samba-lab.ps1 provision"
iex "$lab tools\lab\hyperv\samba-lab.ps1 snapshot"
iex "$lab tools\lab\hyperv\samba-lab.ps1 scan"
```

`scan` prints `LAB PASS` or `LAB FAIL` and exits non-zero on failure. It fails on any
expectation mismatch, on any directory object whose `uSNChanged` moved during the scan
(beyond the `audit` user's own logon bookkeeping), and on a password in the report or logs.
`stop` powers a VM off; the next `reset` brings it back from its checkpoint.

Windows PE has no dynamic-memory driver, so `create` installs with 4 GB of static memory and
switches the VM to dynamic memory (1-4 GB) once Windows is up. Run one lab VM at a time on a
host with little free memory; the workflow's jobs already do.

## CI runner

Download the Windows runner zip from the repository's **Settings > Actions > Runners > New
self-hosted runner** page, save a registration token to a file, and run in an elevated
console:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\lab\hyperv\setup-runner.ps1 `
    -RunnerZip actions-runner-win-x64-<version>.zip -Sha256 <published sha> -TokenFile token.txt
```

It creates `labrunner` (member of **Hyper-V Administrators** only, asking you for its
password), gives it its own copy of the lab key and write access to `out\`, and registers
the runner as a service running as `labrunner`. Hyper-V Administrators may control every VM
on the host, not only the lab's.
