#!/usr/bin/env bash
# One-time: a GitHub Actions runner for the KVM lab, as the unprivileged user
# 'labrunner' (member of libvirt only: it can drive the lab VMs on
# qemu:///system, it has no sudo and no access to your home directory).
#
# Usage: setup-runner.sh <actions-runner-linux-x64-*.tar.gz> <token-file> [repo-url]
#   token-file: a registration token from
#     gh api -X POST repos/<owner>/<repo>/actions/runners/registration-token --jq .token
#   (valid one hour; the file is deleted after use).
# Run as your normal user; it asks for sudo. Labels: self-hosted, linux, kvm-lab.
set -euo pipefail

tarball=${1:?runner tarball}; tokfile=${2:-}
url=${3:-https://github.com/atsvetko/directory-auditor}
lab=${DA_LAB_HOME:-$HOME/.local/share/da-lab}
u=labrunner
rhome=/home/$u
name="kvm-lab-$(hostname -s)"

[[ -f $tarball ]] || { echo "need the runner tarball"; exit 2; }
[[ -f $lab/state/id_ed25519 ]] || { echo "no lab SSH key in $lab/state (build a lab first)"; exit 2; }

# The runner's bundled .NET loads OpenSSL 3 or 1.1 only; Ubuntu 26.10 ships
# OpenSSL 4 and keeps OpenSSL 3 as the side-by-side package libssl3t64.
# (grep without -q: with pipefail, -q exits early and ldconfig dies on SIGPIPE)
if ! ldconfig -p | grep 'libssl\.so\.3 ' >/dev/null; then
  echo "== OpenSSL 3 compatibility library for the runner"
  sudo apt-get install -y -q libssl3t64
fi

echo "== user $u"
id "$u" >/dev/null 2>&1 || sudo useradd -m -s /bin/bash -G libvirt "$u"
sudo usermod -aG libvirt "$u"

echo "== lab state for $u (SSH key and known hosts only)"
sudo install -d -o "$u" -g "$u" -m 700 "$rhome/.local/share/da-lab/state"
for f in id_ed25519 id_ed25519.pub known_hosts known_hosts_windows; do
  [[ -f $lab/state/$f ]] && sudo install -o "$u" -g "$u" -m 600 "$lab/state/$f" "$rhome/.local/share/da-lab/state/$f"
done

echo "== libvirt access as $u"
sudo -u "$u" virsh -c qemu:///system list --all

echo "== runner $name"
sudo install -d -o "$u" -g "$u" "$rhome/actions-runner"
# fed on stdin: $u cannot read your home directory, which is the point
sudo -u "$u" tar -xzf - -C "$rhome/actions-runner" <"$tarball"
if ! sudo test -f "$rhome/actions-runner/.runner"; then
  [[ -s $tokfile ]] || { echo "not registered yet: pass a fresh registration token file"; exit 2; }
  tok=$(cat "$tokfile")
  sudo -u "$u" -H bash -c "cd ~/actions-runner && ./config.sh --unattended --url '$url' --token '$tok' \
      --name '$name' --labels kvm-lab --work _work --replace"
fi
[[ -n $tokfile ]] && rm -f "$tokfile"
# svc.sh must run from the runner directory, which only $u (and root) can enter
sudo bash -c "cd '$rhome/actions-runner' && { [ -f .service ] || ./svc.sh install '$u' >/dev/null; } && ./svc.sh start && ./svc.sh status | head -5"
echo
echo "OK: runner '$name' (self-hosted, linux, kvm-lab) runs as $u."
