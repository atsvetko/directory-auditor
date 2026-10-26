# KVM lab (Linux host, libvirt)

Live testing against real directory servers in VMs on a Linux host with KVM — the
counterpart of the Hyper-V lab (`tools/lab/windows`, `cmd/labctl`). Today it builds the
**Samba AD DC** lab that `lab-samba.yml` builds on the GitHub runner, but in a VM with a
baseline snapshot, and adds a DC-side check that the scan wrote nothing.

> **Lab only.** The DC is deliberately weak. It lives on `da-lab`, an isolated libvirt
> network with no route out; the VM has internet access only while packages are
> installed, through a temporary NAT card that is removed before anything is weakened.
> `samba-lab.sh` refuses to run unless `DIRAUDITOR_LAB=1`.

| File | What it does |
|---|---|
| `setup-libvirt.sh` | once per host: installs libvirt, adds you to `libvirt`/`kvm`, defines `da-lab` (10.55.0.0/24, host 10.55.0.1, no forwarding, no DHCP, no libvirt DNS) |
| `da-lab.xml` | the network definition |
| `verify-da-lab.sh` | independent isolation check: a throwaway namespace on the bridge must reach 10.55.0.1 and must not reach the LAN gateway or the internet |
| `samba-lab.sh` | `create` · `provision` · `snapshot` · `reset` · `scan` · `ssh` · `destroy` for VM `da-samba-dc1` (10.55.0.20) |
| `windows-lab.sh` | the same for a **Windows Server 2025** DC, VM `da-win2025-dc1` (10.55.0.10, forest `da.test`), plus `populate`, `adcs` and named snapshots |
| `windows/` | `autounattend.xml` and `firstlogon.ps1`: unattended install, static IP, OpenSSH with the lab key |
| `setup-runner.sh` | once: a GitHub Actions runner (`self-hosted, linux, kvm-lab`) as the unprivileged user `labrunner` |

## One-time setup

```bash
tools/lab/kvm/setup-libvirt.sh      # asks for sudo; log out and in afterwards
tools/lab/kvm/verify-da-lab.sh      # expect "VERIFIED: da-lab is isolated."
```

Lab state lives in `DA_LAB_HOME` (default `~/.local/share/da-lab`): the base image, the
lab SSH key, snapshots' seed media and reports. Put the Ubuntu 24.04 cloud image there,
checked against Ubuntu's published sums:

```bash
mkdir -p ~/.local/share/da-lab/cache/img && cd ~/.local/share/da-lab/cache/img
curl -fLO https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
curl -fL https://cloud-images.ubuntu.com/noble/current/SHA256SUMS | grep ' \*\?noble-server-cloudimg-amd64.img$' | sha256sum -c
```

Go (the version in `go.mod`) on `PATH`, or unpacked at `$DA_LAB_HOME/cache/go/go/bin/go`.

## Build the lab, then test any commit

```bash
export DIRAUDITOR_LAB=1
tools/lab/kvm/samba-lab.sh create      # VM + packages (~5 min), NAT card removed at the end
tools/lab/kvm/samba-lab.sh provision   # tools/lab/samba/provision.sh + populate.sh inside the VM
tools/lab/kvm/samba-lab.sh snapshot    # "baseline"

tools/lab/kvm/samba-lab.sh reset       # back to baseline (~30 s, includes boot)
tools/lab/kvm/samba-lab.sh scan        # build this checkout, scan, verify, read-only check
```

`scan` mirrors `lab-samba.yml`: it builds `dirauditor` and `tools/lab/verify` from the
checkout, scans inside the VM as the ordinary `audit` user (`--tls auto` with `--pin`, then
`--tls none`), both with `--local`, and checks:

- both reports against `testdata/lab/samba-expect.yaml` (findings, Tier-0, `expect_auth`);
- the sealed scan's transport;
- **DC side:** `highestCommittedUSN` and the `audit` account's `badPwdCount`/`lockoutTime`
  are the same before and after both scans (a warm-up Kerberos logon runs first, so a
  first-logon timestamp update is not counted);
- the lab password appears nowhere in the output directory.

It ends with `LAB PASS` or `LAB FAIL`. Samba listens on 127.0.0.1 only (as in CI), so the
scan runs inside the VM; the host reaches the VM over SSH on `da-lab`.

## Windows Server 2025 DC

You supply the ISO (an evaluation ISO from Microsoft works); `virtio-win` is optional
(guest tools). The VM never has a route out: AD DS and AD CS install from the ISO.

```bash
export DIRAUDITOR_LAB=1 WIN_ISO=~/iso/Win2025.iso
tools/lab/kvm/windows-lab.sh create             # unattended install + first logon (~30 min)
tools/lab/kvm/windows-lab.sh provision          # tools/lab/windows: new forest, reboot, weak objects
tools/lab/kvm/windows-lab.sh snapshot baseline
tools/lab/kvm/windows-lab.sh adcs               # Enterprise CA + weak templates (when provision-adcs.ps1 exists)
tools/lab/kvm/windows-lab.sh snapshot adcs

tools/lab/kvm/windows-lab.sh reset baseline
tools/lab/kvm/windows-lab.sh scan               # EXPECT=… to choose the expectation file
```

`scan` runs from the host as `audit@da.test` with `--server 10.55.0.10 --server-name dc1.da.test`
(the host does not resolve `da.test`), logs on once first so the account's
`lastLogonTimestamp` update is not counted, and checks `highestCommittedUSN` like the Samba lane.
Shutdown for a snapshot goes through SSH (`Stop-Computer`): Windows Server ignores the ACPI
button when nobody is logged on.

## CI runner

`setup-runner.sh <actions-runner tarball> <token file>` creates `labrunner` (member of `libvirt`
only; no sudo, no access to your home), gives it the lab SSH key, registers the runner and
installs it as a service. Ubuntu 26.10 ships OpenSSL 4, which the runner's .NET cannot load;
the script installs the side-by-side `libssl3t64`. `.github/workflows/lab-kvm.yml` runs the
Samba lane, then the Windows lane (both snapshots, `baseline` and `adcs`), nightly, on pushes to `main`
and on same-repository pull requests (never forks). Each job starts by resetting its VM to a
snapshot and ends with `stop`, so the VMs use memory only while a job runs.
Note that membership in `libvirt` gives `labrunner` control of every system VM on the host.

## Resources

2 vCPU, 2 GB RAM, ~3 GB disk for the Samba VM (copy-on-write over the base image);
2 vCPU, 4 GB RAM, ~20 GB disk for the Windows DC.
