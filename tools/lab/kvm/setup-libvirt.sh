#!/usr/bin/env bash
# One-time host setup for the Directory Auditor KVM lab: installs libvirt,
# grants the current user access, and defines the isolated da-lab network.
# Idempotent: safe to run again. Run as your normal user; it asks for sudo.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
user="${SUDO_USER:-$USER}"
virsh="sudo virsh -c qemu:///system"

echo "== packages"
sudo apt-get update -q
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
  qemu-system-x86 qemu-utils libvirt-daemon-system libvirt-clients virtinst ovmf swtpm swtpm-tools
sudo systemctl enable --now libvirtd.service

echo "== groups for $user"
sudo usermod -aG libvirt,kvm "$user"

echo "== network da-lab (isolated, 10.55.0.0/24)"
# refuse if 10.55.0.0/24 is already routed somewhere other than our bridge
if ip -4 route show 10.55.0.0/24 | grep -v -q 'da-lab0'; then
  echo "10.55.0.0/24 is already in use on this host:"; ip -4 route show 10.55.0.0/24; exit 1
fi
if ! $virsh net-info da-lab >/dev/null 2>&1; then
  $virsh net-define "$here/da-lab.xml"
fi
$virsh net-autostart da-lab
$virsh net-info da-lab | grep -q 'Active:.*yes' || $virsh net-start da-lab

echo "== checks"
fail=0
$virsh net-dumpxml da-lab | grep -q '<forward' && { echo "FAIL: da-lab has a <forward> element"; fail=1; }
ip -4 -br addr show da-lab0 | grep -q '10.55.0.1/24' || { echo "FAIL: da-lab0 has no 10.55.0.1/24"; fail=1; }
ip -4 route show default | grep -q da-lab0 && { echo "FAIL: default route via da-lab0"; fail=1; }
sudo nft list ruleset 2>/dev/null | grep -q da-lab0 || sudo iptables -S 2>/dev/null | grep -q da-lab0 \
  || { echo "FAIL: no libvirt firewall rules for da-lab0"; fail=1; }
$virsh net-list --all
ip -4 -br addr show da-lab0
[ "$fail" -eq 0 ] && echo "OK: da-lab is isolated." || exit 1

echo
echo "Log out and back in (or run 'newgrp libvirt') so '$user' can use qemu:///system without sudo."
