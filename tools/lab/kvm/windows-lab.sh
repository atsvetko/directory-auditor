#!/usr/bin/env bash
# Windows Server 2025 AD DC lab on KVM (libvirt qemu:///system, network da-lab).
# The KVM counterpart of tools/lab/windows (Hyper-V) and lab-windows.yml:
#
#   create        VM from your Windows Server ISO, unattended (SeaBIOS, SATA, e1000e — no
#                 drivers needed), static IP, OpenSSH with the lab key. Never has a route out:
#                 AD DS and AD CS install from the ISO.
#   provision     tools/lab/windows/provision.ps1 (new forest da.test, reboots) + populate.ps1
#   populate      populate.ps1 again (idempotent)
#   adcs          tools/lab/windows/provision-adcs.ps1 (Enterprise CA + weak templates), when present
#   snapshot NAME shut down, snapshot NAME, start again   (baseline, adcs, …)
#   reset NAME    revert to snapshot NAME and wait for AD
#   scan          build this checkout, scan from the host as the ordinary 'audit' user
#                 (auto transport, then --tls none), verify, and check from the DC side that
#                 the scan wrote nothing. EXPECT selects the expectation file.
#   ssh [CMD]     PowerShell on the DC as Administrator
#   destroy       remove the VM and its disk (keeps the uploaded ISOs)
#
# Usage: DIRAUDITOR_LAB=1 WIN_ISO=/path/to/Win2025.iso windows-lab.sh <command>
# Env:   DA_LAB_HOME (~/.local/share/da-lab), GO, REPO, EXPECT, IMAGE_INDEX (2 = Standard,
#        Desktop Experience), VIRTIO_ISO ($DA_LAB_HOME/cache/virtio/virtio-win-*.iso)
set -euo pipefail

[[ "${DIRAUDITOR_LAB:-}" == "1" ]] || { echo "refusing: set DIRAUDITOR_LAB=1 (this builds and scans a deliberately weak forest)"; exit 2; }

here="$(cd "$(dirname "$0")" && pwd)"
REPO=${REPO:-$(cd "$here/../../.." && pwd)}
LAB=${DA_LAB_HOME:-$HOME/.local/share/da-lab}
GO=${GO:-$(command -v go || echo "$LAB/cache/go/go/bin/go")}
WIN_ISO=${WIN_ISO:-$LAB/cache/iso/Win2025.iso}
VIRTIO_ISO=${VIRTIO_ISO:-$(ls "$LAB"/cache/virtio/virtio-win-*.iso 2>/dev/null | tail -1)}
IMAGE_INDEX=${IMAGE_INDEX:-2}
EXPECT=${EXPECT:-$REPO/testdata/lab/windows-expect.yaml}
export LIBVIRT_DEFAULT_URI=qemu:///system

VM=da-win2025-dc1
POOL=da-lab
POOL_DIR=/var/lib/libvirt/images/da-lab
IP=10.55.0.10
MAC=52:54:00:55:00:10
DOMAIN=da.test
DCNAME=dc1.da.test
ADMIN_PW='Lab-Admin-Pass-2026!'   # throwaway lab values
AUDIT_PW='Lab-Reader-Pass-2026!'  # populate.ps1 default
KEY=$LAB/state/id_ed25519
OUT=$LAB/state/out-windows
SSH=(ssh -i "$KEY" -o UserKnownHostsFile="$LAB/state/known_hosts_windows" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o BatchMode=yes administrator@$IP)
SCP=(scp -q -i "$KEY" -o UserKnownHostsFile="$LAB/state/known_hosts_windows" -o StrictHostKeyChecking=accept-new -o BatchMode=yes)

# grep that reads all its input: with pipefail, grep -q exits at the first match and
# the writer dies on SIGPIPE, which would fail a pipeline whose condition held
has() { grep "$@" >/dev/null; }
log() { printf '\n== %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }
vssh() { "${SSH[@]}" "$@"; }

wait_ssh() { # minutes
  for i in $(seq 1 $(( ${1:-15} * 6 ))); do vssh 'exit 0' 2>/dev/null && return 0; sleep 10; done
  die "no SSH to $IP after ${1:-15} min"
}
wait_down() { for i in $(seq 1 60); do vssh 'exit 0' 2>/dev/null || return 0; sleep 5; done; die "$VM did not go down"; }
wait_ad() {
  for i in $(seq 1 60); do
    vssh '(Get-ADDomain -ErrorAction Stop).DNSRoot' 2>/dev/null | has "$DOMAIN" && return 0; sleep 10
  done
  die "AD on $VM not answering after 10 min"
}

ensure_pool() {
  virsh pool-info "$POOL" >/dev/null 2>&1 && return
  virsh pool-define-as "$POOL" dir --target "$POOL_DIR" >/dev/null
  virsh pool-build "$POOL" >/dev/null; virsh pool-start "$POOL" >/dev/null; virsh pool-autostart "$POOL" >/dev/null
}
vol_upload() { # name file format
  virsh vol-info --pool "$POOL" "$1" >/dev/null 2>&1 && return
  echo "uploading $(basename "$2") ($(du -h "$2" | cut -f1)) to pool $POOL"
  virsh vol-create-as "$POOL" "$1" "$(stat -c %s "$2")" --format "$3" >/dev/null
  virsh vol-upload --pool "$POOL" "$1" "$2"
}

cmd_create() {
  [[ -f $WIN_ISO ]] || die "missing Windows ISO: set WIN_ISO (now $WIN_ISO)"
  virsh dominfo "$VM" >/dev/null 2>&1 && die "$VM already exists (destroy it first)"
  [[ -f $KEY ]] || { mkdir -p "$LAB/state"; ssh-keygen -q -t ed25519 -N '' -C da-lab -f "$KEY"; }
  mkdir -p "$OUT"

  log "storage"
  ensure_pool
  vol_upload win-install.iso "$WIN_ISO" raw
  local virtio_disk=()
  if [[ -n $VIRTIO_ISO ]]; then
    vol_upload virtio-win.iso "$VIRTIO_ISO" raw
    virtio_disk=(--disk vol="$POOL/virtio-win.iso",device=cdrom,bus=sata)
  fi
  virsh vol-create-as "$POOL" "$VM.qcow2" 60G --format qcow2 >/dev/null

  log "answer media"
  local a; a=$(mktemp -d); mkdir -p "$a/lab"
  sed -e "s|@ADMIN_PASSWORD@|$ADMIN_PW|g" -e "s|@IMAGE_INDEX@|$IMAGE_INDEX|g" \
      -e "s|@MAC@|${MAC//:/-}|g" -e "s|@IP@|$IP|g" "$here/windows/autounattend.xml" >"$a/autounattend.xml"
  cp "$here/windows/firstlogon.ps1" "$a/lab/"
  cp "$KEY.pub" "$a/lab/authorized_keys"
  xorriso -as mkisofs -quiet -V ANSWER -J -r -o "$LAB/state/$VM-answer.iso" "$a"
  rm -rf "$a"
  virsh vol-delete --pool "$POOL" "$VM-answer.iso" >/dev/null 2>&1 || true
  vol_upload "$VM-answer.iso" "$LAB/state/$VM-answer.iso" raw

  log "VM $VM (2 vCPU, 4 GB) on da-lab $IP — no other network"
  virt-install --name "$VM" --memory 4096 --vcpus 2 --osinfo win2k25 --import \
    --clock offset=utc --tpm none \
    --disk vol="$POOL/$VM.qcow2",bus=sata,boot.order=2 \
    --disk vol="$POOL/win-install.iso",device=cdrom,bus=sata,boot.order=1 \
    --disk vol="$POOL/$VM-answer.iso",device=cdrom,bus=sata \
    "${virtio_disk[@]}" \
    --network network=da-lab,mac="$MAC",model=e1000e \
    --graphics vnc,listen=127.0.0.1 --noautoconsole >/dev/null
  virsh domiflist "$VM"

  log "waiting for unattended install and first logon (20–40 min)"
  wait_ssh 60
  for i in $(seq 1 60); do vssh 'Test-Path C:\lab-ready.txt' 2>/dev/null | has True && break; sleep 10; done
  vssh '"{0} {1} build {2}" -f (Get-CimInstance Win32_OperatingSystem).Caption, $env:COMPUTERNAME, [Environment]::OSVersion.Version'
}

copy_lab_scripts() {
  vssh 'New-Item -ItemType Directory -Force C:\lab\windows | Out-Null'
  "${SCP[@]}" "$REPO"/tools/lab/windows/*.ps1 administrator@$IP:C:/lab/windows/
}

cmd_provision() {
  log "copying tools/lab/windows"
  copy_lab_scripts
  log "provision.ps1 (new forest $DOMAIN; the DC reboots)"
  vssh "\$env:DIRAUDITOR_LAB='1'; & C:\\lab\\windows\\provision.ps1 -DomainName $DOMAIN -IPAddress $IP -ForestMode Win2025 -Confirm:\$false" || true
  wait_down; wait_ssh 20; wait_ad
  cmd_populate
}

cmd_populate() {
  copy_lab_scripts
  log "populate.ps1 (weak objects)"
  vssh "\$env:DIRAUDITOR_LAB='1'; & C:\\lab\\windows\\populate.ps1 -DomainName $DOMAIN -Confirm:\$false"
}

cmd_adcs() {
  [[ -f $REPO/tools/lab/windows/provision-adcs.ps1 ]] || die "no tools/lab/windows/provision-adcs.ps1 in $REPO (it comes with the AD CS collectors)"
  copy_lab_scripts
  log "provision-adcs.ps1 (Enterprise CA + weak templates)"
  vssh "\$env:DIRAUDITOR_LAB='1'; Set-Location C:\\lab\\windows; & C:\\lab\\windows\\provision-adcs.ps1 -DomainName $DOMAIN -Confirm:\$false"
}

cmd_snapshot() {
  local name=${1:?snapshot name}
  log "shutting down for snapshot $name"
  if ! virsh domstate "$VM" | has 'shut off'; then
    # Windows Server ignores the ACPI button when nobody is logged on; ask it over SSH
    vssh 'Stop-Computer -Force' 2>/dev/null || virsh shutdown "$VM" >/dev/null
  fi
  for i in $(seq 1 300); do virsh domstate "$VM" | has 'shut off' && break; sleep 2; done
  virsh domstate "$VM" | has 'shut off' || die "$VM did not shut down"
  virsh snapshot-delete "$VM" "$name" >/dev/null 2>&1 || true
  virsh snapshot-create-as "$VM" "$name" >/dev/null
  virsh snapshot-list "$VM"
  virsh start "$VM" >/dev/null; wait_ssh 15; wait_ad
}

cmd_reset() {
  local name=${1:?snapshot name}
  log "reverting $VM to $name"
  virsh snapshot-revert "$VM" "$name" >/dev/null
  virsh start "$VM" >/dev/null 2>&1 || true
  wait_ssh 15; wait_ad; echo "AD up"
}

usn() { vssh '(Get-ADRootDSE).highestCommittedUSN' | tr -d '\r'; }
audit_state() { vssh '$u = Get-ADUser audit -Properties badPwdCount,lockoutTime; "badPwdCount=$($u.badPwdCount) lockoutTime=$($u.lockoutTime)"' | tr -d '\r'; }

scan_one() { # label outdir extra-args...
  local label=$1 out=$2; shift 2
  log "scan: $label"
  echo "$AUDIT_PW" | "$OUT/dirauditor" scan --server "$IP" --server-name "$DCNAME" --domain "$DOMAIN" \
    --user "audit@$DOMAIN" --password-stdin --catalogue "$REPO/catalogue" --packs '' --out "$out" --lang en "$@" 2>&1 \
    | grep -v -E '^\s+· ' | tail -12
}

cmd_scan() {
  [[ -x $GO ]] || die "missing Go at $GO"
  mkdir -p "$OUT"
  log "build dirauditor + verify from $(git -C "$REPO" rev-parse --abbrev-ref HEAD)@$(git -C "$REPO" rev-parse --short HEAD)"
  (cd "$REPO" && CGO_ENABLED=0 GOTOOLCHAIN=local "$GO" build -trimpath -o "$OUT/dirauditor" ./cmd/dirauditor \
     && GOTOOLCHAIN=local "$GO" build -o "$OUT/verify" ./tools/lab/verify)

  # The baseline predates the audit account's first logon, so the first Kerberos
  # logon after a reset updates its lastLogonTimestamp; log on once (a scan whose
  # output is discarded) so that only the measured scans are measured.
  scan_one "warm-up logon (not measured)" "$OUT/warm-up" >/dev/null || true
  rm -rf "$OUT/warm-up"
  usn0=$(usn); acct0=$(audit_state)
  echo "before: highestCommittedUSN=$usn0 audit: $acct0"
  rm -rf "$OUT/lab-out" "$OUT/lab-seal"
  scan_one "audit user, --tls auto" "$OUT/lab-out" || true
  scan_one "audit user, --tls none (Kerberos sealing)" "$OUT/lab-seal" --tls none || true
  usn1=$(usn); acct1=$(audit_state)
  echo "after:  highestCommittedUSN=$usn1 audit: $acct1"

  rc=0
  for r in lab-out lab-seal; do
    log "verify $r against $(basename "$EXPECT")"
    [[ -f $OUT/$r/report.json ]] || { echo "FAIL: no report"; rc=1; continue; }
    python3 -c "import json; i=json.load(open('$OUT/$r/report.json'))['inventory']; print('transport:', i.get('transport'), '| identity:', i.get('identity'))"
    "$OUT/verify" -report "$OUT/$r/report.json" -expect "$EXPECT" || rc=1
  done

  log "read-only check (DC side)"
  if [[ $usn0 == "$usn1" ]]; then echo "ok: highestCommittedUSN unchanged ($usn0)"
  else
    echo "CHANGED: highestCommittedUSN $usn0 -> $usn1; objects changed during the scans:"
    vssh "Get-ADObject -IncludeDeletedObjects -Filter 'uSNChanged -gt $usn0' -Properties uSNChanged,whenChanged | Select-Object uSNChanged,whenChanged,DistinguishedName | Format-Table -AutoSize | Out-String -Width 220"
    rc=1
  fi
  if [[ $acct0 == "$acct1" ]]; then echo "ok: audit account unchanged ($acct0)"
  else echo "FAIL: audit account changed: '$acct0' -> '$acct1'"; rc=1; fi
  if grep -rlF "$AUDIT_PW" "$OUT/lab-out" "$OUT/lab-seal" 2>/dev/null; then echo "FAIL: password found in output"; rc=1
  else echo "ok: password not present in any report or run log"; fi

  echo; [[ $rc -eq 0 ]] && echo "LAB PASS" || echo "LAB FAIL"
  echo "reports: $OUT/lab-out/report.html $OUT/lab-seal/report.html"
  return $rc
}

cmd_destroy() {
  virsh destroy "$VM" >/dev/null 2>&1 || true
  for s in $(virsh snapshot-list "$VM" --name 2>/dev/null); do virsh snapshot-delete "$VM" "$s" >/dev/null; done
  virsh undefine "$VM" >/dev/null 2>&1 || true
  virsh vol-delete --pool "$POOL" "$VM.qcow2" >/dev/null 2>&1 || true
  virsh vol-delete --pool "$POOL" "$VM-answer.iso" >/dev/null 2>&1 || true
  rm -f "$LAB/state/known_hosts_windows"
  echo "destroyed $VM (install ISOs kept in pool $POOL)"
}

case "${1:-}" in
  create|provision|populate|adcs|scan|destroy) "cmd_$1" ;;
  snapshot|reset) c=$1; shift; "cmd_$c" "$@" ;;
  ssh) shift; vssh "$@" ;;
  *) sed -n '2,24p' "$0"; exit 2 ;;
esac
