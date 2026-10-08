#!/usr/bin/env bash
# Start a throw-away FreeIPA server in a container and wait until it is ready.
# LAB ONLY (DIRAUDITOR_LAB=1). Needs Docker with user-namespace remapping
# (FreeIPA runs systemd; the image refuses --privileged). Idempotent: an
# existing container is reused.
#
# Usage: DIRAUDITOR_LAB=1 run.sh
# Env:   IPA_IMAGE (quay.io/freeipa/freeipa-server:almalinux-9) IPA_HOST (ipa.ipa.example)
#        IPA_REALM (IPA.EXAMPLE) IPA_DOMAIN (ipa.example) IPA_PASSWORD (admin + Directory Manager)
set -euo pipefail
[[ "${DIRAUDITOR_LAB:-}" == "1" ]] || { echo "refusing: set DIRAUDITOR_LAB=1"; exit 2; }

IMAGE=${IPA_IMAGE:-quay.io/freeipa/freeipa-server:almalinux-9}
HOST=${IPA_HOST:-ipa.ipa.example}
REALM=${IPA_REALM:-IPA.EXAMPLE}
DOMAIN=${IPA_DOMAIN:-ipa.example}
PASSWORD=${IPA_PASSWORD:-'Lab-Admin-Pass-2026!'}
NAME=${IPA_CONTAINER:-dirauditor-ipa}
DATA=${IPA_DATA:-$PWD/ipa-data}

if ! grep -q "$HOST" /etc/hosts; then
  echo "127.0.0.1 $HOST" | sudo tee -a /etc/hosts >/dev/null
fi

# Docker needs user-namespace remapping for systemd in the container (the
# freeipa-container project's own CI does this); --privileged is explicitly
# unsupported by the image. The workflow configures the daemon; here we only check.
if docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q userns; then
  echo "lab: docker userns remapping active"
else
  echo "lab: WARNING: docker userns-remap is not enabled; systemd in the container may fail (see .github/workflows/lab-freeipa.yml)"
fi

if ! docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  (umask 0; mkdir -p "$DATA"; chmod 777 "$DATA")
  docker run -d --name "$NAME" -h "$HOST" \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    -v "$DATA:/data:Z" \
    -e PASSWORD="$PASSWORD" \
    -p 127.0.0.1:389:389 -p 127.0.0.1:636:636 -p 127.0.0.1:88:88 -p 127.0.0.1:88:88/udp -p 127.0.0.1:464:464 \
    "$IMAGE" ipa-server-install -U -r "$REALM" -n "$DOMAIN" --no-ntp --no-host-dns >/dev/null
  echo "lab: container $NAME started from $IMAGE"
fi

echo "lab: waiting for FreeIPA (up to 25 min)…"
for i in $(seq 1 150); do
  state=$(docker inspect "$NAME" --format '{{.State.Status}}' 2>/dev/null || echo missing)
  if [[ "$state" == "exited" || "$state" == "dead" ]]; then
    echo "lab: container exited with $(docker inspect "$NAME" --format '{{.State.ExitCode}}')"
    docker logs --tail 40 "$NAME" 2>&1 | sed 's/^/  log: /'
    sudo tail -60 "$DATA/var/log/ipaserver-install.log" 2>/dev/null || true
    exit 1
  fi
  sysd=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
  if [[ "$sysd" == "running" ]] && docker exec "$NAME" bash -c "echo '$PASSWORD' | kinit admin >/dev/null 2>&1 && ipa ping >/dev/null 2>&1"; then
    echo "lab: ready after $((i*10))s"
    docker exec "$NAME" ipa ping
    exit 0
  fi
  if [[ "$sysd" == "degraded" ]]; then
    echo "lab: systemd degraded inside the container:"; docker exec "$NAME" systemctl --failed || true
    sudo tail -60 "$DATA/var/log/ipaserver-install.log" 2>/dev/null || true
    exit 1
  fi
  if (( i % 6 == 0 )); then
    echo "  …${i}0s: container $state, systemd ${sysd:-starting}; $(sudo tail -1 "$DATA/var/log/ipaserver-install.log" 2>/dev/null | cut -c1-120)"
  fi
  sleep 10
done
echo "lab: FreeIPA did not become ready"; docker logs --tail 60 "$NAME"; sudo tail -80 "$DATA/var/log/ipaserver-install.log" 2>/dev/null || true; exit 1
