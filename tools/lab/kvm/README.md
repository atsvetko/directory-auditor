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

## Resources

2 vCPU, 2 GB RAM, ~3 GB disk for the Samba VM (copy-on-write over the base image).
