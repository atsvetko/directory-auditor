#!/usr/bin/env bash
# Samba AD DC lab on KVM (libvirt qemu:///system, network da-lab).
# Mirrors .github/workflows/lab-samba.yml, but in a VM on this host:
#
#   create     VM from the Ubuntu 24.04 cloud image; packages via a temporary NAT NIC,
#              which is removed before anything is weakened
#   provision  tools/lab/samba/provision.sh + populate.sh inside the VM
#   snapshot   shut down, take the "baseline" snapshot, start again
#   reset      revert to "baseline" and start Samba (seconds)
#   scan       build dirauditor + verify on the host, scan inside the VM as the
#              'audit' user (pinned LDAPS, then sealed LDAP), verify both reports,
#              and check from the DC side that the scan wrote nothing
#   ssh        shell in the VM
#   destroy    remove the VM, its disks and the seed (keeps the base image)
#
# Usage: DIRAUDITOR_LAB=1 samba-lab.sh <command>
# Env:   DA_LAB_HOME  lab state: base image, SSH key, reports (~/.local/share/da-lab)
#        GO           go binary (default: go on PATH, else $DA_LAB_HOME/cache/go/go/bin/go)
#        REPO         directory-auditor checkout to build and scan (default: this one)
# Host prerequisites: setup-libvirt.sh (once), and the cloud image in
# $DA_LAB_HOME/cache/img (see README.md).
set -euo pipefail

[[ "${DIRAUDITOR_LAB:-}" == "1" ]] || { echo "refusing: set DIRAUDITOR_LAB=1 (this builds and scans a deliberately weak domain)"; exit 2; }

here="$(cd "$(dirname "$0")" && pwd)"
REPO=${REPO:-$(cd "$here/../../.." && pwd)}
LAB=${DA_LAB_HOME:-$HOME/.local/share/da-lab}
GO=${GO:-$(command -v go || echo "$LAB/cache/go/go/bin/go")}
IMG=$LAB/cache/img/noble-server-cloudimg-amd64.img
export LIBVIRT_DEFAULT_URI=qemu:///system

VM=da-samba-dc1
POOL=da-lab
POOL_DIR=/var/lib/libvirt/images/da-lab
IP=10.55.0.20
MAC_LAB=52:54:00:55:00:20
MAC_NAT=52:54:00:55:01:20
KEY=$LAB/state/id_ed25519
OUT=$LAB/state/out
USER_PW='Lab-User-Pass-2026!'   # populate.sh default; throwaway lab value
SSH=(ssh -i "$KEY" -o UserKnownHostsFile="$LAB/state/known_hosts" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o BatchMode=yes lab@$IP)
SCP=(scp -q -i "$KEY" -o UserKnownHostsFile="$LAB/state/known_hosts" -o StrictHostKeyChecking=accept-new -o BatchMode=yes)

log() { printf '\n== %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }
vssh() { "${SSH[@]}" "$@"; }

wait_ssh() {
  for i in $(seq 1 120); do vssh true 2>/dev/null && return 0; sleep 5; done
  die "no SSH to $IP after 10 min"
}

ensure_pool() {
  virsh pool-info "$POOL" >/dev/null 2>&1 && return
  virsh pool-define-as "$POOL" dir --target "$POOL_DIR" >/dev/null
  virsh pool-build "$POOL" >/dev/null
  virsh pool-start "$POOL" >/dev/null
  virsh pool-autostart "$POOL" >/dev/null
}

vol_upload() { # name file format
  virsh vol-info --pool "$POOL" "$1" >/dev/null 2>&1 && return
  virsh vol-create-as "$POOL" "$1" "$(stat -c %s "$2")" --format "$3" >/dev/null
  virsh vol-upload --pool "$POOL" "$1" "$2"
}

cmd_create() {
  [[ -f $IMG ]] || die "missing $IMG"
  virsh dominfo "$VM" >/dev/null 2>&1 && die "$VM already exists (destroy it first)"
  mkdir -p "$LAB/state" "$OUT"
  [[ -f $KEY ]] || ssh-keygen -q -t ed25519 -N '' -C da-lab -f "$KEY"

  log "storage"
  ensure_pool
  vol_upload noble-base.qcow2 "$IMG" qcow2
  virsh vol-create-as "$POOL" "$VM.qcow2" 20G --format qcow2 \
    --backing-vol noble-base.qcow2 --backing-vol-format qcow2 >/dev/null

  log "cloud-init seed"
  seed=$(mktemp -d)
  cat >"$seed/meta-data" <<EOF
instance-id: $VM
local-hostname: dc1
EOF
  cat >"$seed/network-config" <<EOF
version: 2
ethernets:
  lab:
    match: {macaddress: "$MAC_LAB"}
    addresses: [$IP/24]
  nat:
    match: {macaddress: "$MAC_NAT"}
    dhcp4: true
    optional: true
EOF
  cat >"$seed/user-data" <<EOF
#cloud-config
hostname: dc1
users:
  - name: lab
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: ["$(cat "$KEY.pub")"]
ssh_pwauth: false
package_update: true
packages: [samba, samba-dsdb-modules, samba-vfs-modules, winbind, krb5-user, ldb-tools, ldap-utils, qemu-guest-agent]
runcmd:
  - [systemctl, enable, --now, qemu-guest-agent]
EOF
  xorriso -as mkisofs -quiet -V cidata -J -r -o "$LAB/state/$VM-seed.iso" \
    "$seed/user-data" "$seed/meta-data" "$seed/network-config"
  rm -rf "$seed"
  virsh vol-delete --pool "$POOL" "$VM-seed.iso" >/dev/null 2>&1 || true
  vol_upload "$VM-seed.iso" "$LAB/state/$VM-seed.iso" raw

  log "VM $VM (2 vCPU, 2 GB) on da-lab $IP + temporary NAT"
  virt-install --name "$VM" --memory 2048 --vcpus 2 --osinfo ubuntu24.04 --import \
    --disk vol="$POOL/$VM.qcow2",bus=virtio \
    --disk vol="$POOL/$VM-seed.iso",device=cdrom \
    --network network=da-lab,mac="$MAC_LAB",model=virtio \
    --network network=default,mac="$MAC_NAT",model=virtio \
    --graphics none --noautoconsole >/dev/null

  log "waiting for SSH and cloud-init (package install)"
  wait_ssh
  vssh 'cloud-init status --wait >/dev/null; cloud-init status --long | head -3; samba -V'

  log "removing the NAT NIC (no route out from here on)"
  virsh detach-interface "$VM" network --mac "$MAC_NAT" --live --config >/dev/null
  virsh domiflist "$VM"
  if vssh 'timeout 5 bash -c "echo > /dev/tcp/1.1.1.1/443"' 2>/dev/null; then
    die "VM still reaches the internet"
  fi
  echo "ok: VM has no route out"
}

cmd_provision() {
  virsh domiflist "$VM" | grep -q "$MAC_NAT" && die "NAT NIC still attached; refusing to weaken a VM with internet access"
  log "copying lab scripts"
  vssh 'rm -rf ~/lab && mkdir -p ~/lab'
  "${SCP[@]}" "$REPO"/tools/lab/samba/{provision.sh,populate.sh} lab@$IP:lab/
  log "provision (weak Samba AD DC)"
  vssh 'sudo DIRAUDITOR_LAB=1 bash ~/lab/provision.sh'
  log "populate (weak objects)"
  vssh 'sudo DIRAUDITOR_LAB=1 bash ~/lab/populate.sh'
}

start_samba() {
  # provision.sh is idempotent: on an existing domain it only starts samba
  vssh 'sudo DIRAUDITOR_LAB=1 bash ~/lab/provision.sh' | grep -E '^lab:' || true
}

cmd_snapshot() {
  log "shutting down for the baseline snapshot"
  virsh shutdown "$VM" >/dev/null
  for i in $(seq 1 60); do virsh domstate "$VM" | grep -q 'shut off' && break; sleep 2; done
  virsh domstate "$VM" | grep -q 'shut off' || die "$VM did not shut down"
  virsh snapshot-delete "$VM" baseline >/dev/null 2>&1 || true
  virsh snapshot-create-as "$VM" baseline "provisioned + populated weak Samba DC" >/dev/null
  virsh snapshot-list "$VM"
  virsh start "$VM" >/dev/null
  wait_ssh
  start_samba
}

cmd_reset() {
  log "reverting $VM to baseline"
  virsh snapshot-revert "$VM" baseline >/dev/null
  virsh start "$VM" >/dev/null 2>&1 || true
  wait_ssh
  start_samba
}

usn() { vssh "sudo ldbsearch -H /var/lib/samba/private/sam.ldb -s base -b '' highestCommittedUSN" | awk '/^highestCommittedUSN/{print $2}'; }
audit_state() { vssh "sudo ldbsearch -H /var/lib/samba/private/sam.ldb -b DC=lab,DC=example '(sAMAccountName=audit)' badPwdCount lockoutTime" | grep -E '^(badPwdCount|lockoutTime)' | sort | tr '\n' ' '; }

cmd_scan() {
  mkdir -p "$OUT"
  [[ -x $GO ]] || die "missing Go at $GO"
  log "build dirauditor + verify from $(git -C "$REPO" rev-parse --abbrev-ref HEAD)@$(git -C "$REPO" rev-parse --short HEAD)"
  (cd "$REPO" && CGO_ENABLED=0 GOTOOLCHAIN=local "$GO" build -trimpath -o "$OUT/dirauditor" ./cmd/dirauditor \
     && GOTOOLCHAIN=local "$GO" build -o "$OUT/verify" ./tools/lab/verify)
  "$OUT/dirauditor" version

  log "deploy binary + catalogue"
  vssh 'rm -rf ~/scan && mkdir -p ~/scan'
  "${SCP[@]}" "$OUT/dirauditor" lab@$IP:scan/
  tar -C "$REPO" -czf - catalogue | vssh 'tar -C ~/scan -xzf -'

  # Kerberos logon by 'audit' can itself update the account (lastLogonTimestamp)
  # on first use; log on once before measuring so only the scan is measured.
  # (own krb5.conf: the VM's resolver is systemd-resolved, so the DNS KDC lookup
  # in Samba's krb5.conf finds nothing; dirauditor itself goes to --server)
  vssh "printf '[libdefaults]\n default_realm = LAB.EXAMPLE\n[realms]\n LAB.EXAMPLE = {\n  kdc = 127.0.0.1\n }\n' > ~/scan/krb5.conf && \
    echo '$USER_PW' | KRB5_CONFIG=~/scan/krb5.conf kinit audit@LAB.EXAMPLE >/dev/null && kdestroy" || die "kinit as audit failed"
  usn0=$(usn); acct0=$(audit_state)
  echo "before: highestCommittedUSN=$usn0 audit: $acct0"

  log "scan 1: audit user, pinned LDAPS, local smb.conf"
  vssh "cd ~/scan && PIN=\$(sudo openssl x509 -in /var/lib/samba/private/tls/cert.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':') && \
    echo '$USER_PW' | sudo -E ./dirauditor scan --server dc1.lab.example --domain lab.example \
      --user audit@lab.example --password-stdin --pin \"\$PIN\" --local --catalogue catalogue --packs '' --out lab-out --lang en 2>&1 | tail -15"

  log "scan 2: audit user, plain LDAP with Kerberos SASL sealing"
  vssh "cd ~/scan && echo '$USER_PW' | sudo -E ./dirauditor scan --server dc1.lab.example --domain lab.example \
      --user audit@lab.example --password-stdin --tls none --local --catalogue catalogue --packs '' --out lab-seal --lang en 2>&1 | tail -5"

  usn1=$(usn); acct1=$(audit_state)
  echo "after:  highestCommittedUSN=$usn1 audit: $acct1"

  log "fetch reports"
  vssh 'sudo chown -R lab ~/scan/lab-out ~/scan/lab-seal'
  rm -rf "$OUT/lab-out" "$OUT/lab-seal"
  "${SCP[@]}" -r lab@$IP:scan/lab-out lab@$IP:scan/lab-seal "$OUT/"

  rc=0
  log "verify scan 1 against testdata/lab/samba-expect.yaml"
  "$OUT/verify" -report "$OUT/lab-out/report.json" -expect "$REPO/testdata/lab/samba-expect.yaml" || rc=1
  log "verify scan 2 (sealed)"
  t=$(python3 -c "import json; print(json.load(open('$OUT/lab-seal/report.json'))['inventory'].get('transport',''))")
  echo "transport: $t"
  [[ $t == 'LDAP, Kerberos-sealed (no TLS)' ]] || { echo "FAIL: transport"; rc=1; }
  "$OUT/verify" -report "$OUT/lab-seal/report.json" -expect "$REPO/testdata/lab/samba-expect.yaml" || rc=1

  log "read-only check (DC side)"
  if [[ $usn0 == "$usn1" ]]; then echo "ok: highestCommittedUSN unchanged ($usn0)"
  else
    echo "FAIL: highestCommittedUSN $usn0 -> $usn1; objects changed during the scan:"
    vssh "sudo ldbsearch -H /var/lib/samba/private/sam.ldb -b DC=lab,DC=example '(uSNChanged>=$((usn0+1)))' dn uSNChanged" | grep -E '^(dn|uSNChanged):'
    rc=1
  fi
  if [[ $acct0 == "$acct1" ]]; then echo "ok: audit account badPwdCount/lockoutTime unchanged ($acct0)"
  else echo "FAIL: audit account changed: '$acct0' -> '$acct1'"; rc=1; fi

  log "secrets in output"
  if grep -rlF "$USER_PW" "$OUT/lab-out" "$OUT/lab-seal"; then echo "FAIL: password found in output"; rc=1
  else echo "ok: password not present in any report or run log"; fi

  echo; [[ $rc -eq 0 ]] && echo "LAB PASS" || echo "LAB FAIL"
  echo "reports: $OUT/lab-out/report.html, $OUT/lab-seal/report.html"
  return $rc
}

cmd_destroy() {
  virsh destroy "$VM" >/dev/null 2>&1 || true
  virsh snapshot-delete "$VM" baseline >/dev/null 2>&1 || true
  virsh undefine "$VM" >/dev/null 2>&1 || true
  virsh vol-delete --pool "$POOL" "$VM.qcow2" >/dev/null 2>&1 || true
  virsh vol-delete --pool "$POOL" "$VM-seed.iso" >/dev/null 2>&1 || true
  rm -f "$LAB/state/known_hosts"
  echo "destroyed $VM (base image kept)"
}

case "${1:-}" in
  create|provision|snapshot|reset|scan|destroy) "cmd_$1" ;;
  ssh) shift; vssh "$@" ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
