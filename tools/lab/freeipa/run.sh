#!/usr/bin/env bash
# Start a throw-away FreeIPA server in a container and wait until it is ready.
# LAB ONLY (DIRAUDITOR_LAB=1). Needs Docker with a privileged container allowed
# (FreeIPA runs systemd). Idempotent: an existing container is reused.
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

if ! docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  mkdir -p "$DATA"
  docker run -d --name "$NAME" -h "$HOST" --privileged --cgroupns=host \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v "$DATA:/data:Z" \
    -e PASSWORD="$PASSWORD" \
    -p 127.0.0.1:389:389 -p 127.0.0.1:636:636 -p 127.0.0.1:88:88 -p 127.0.0.1:88:88/udp -p 127.0.0.1:464:464 \
    "$IMAGE" ipa-server-install -U -r "$REALM" -n "$DOMAIN" --no-ntp --no-host-dns >/dev/null
  echo "lab: container $NAME started from $IMAGE"
fi

echo "lab: waiting for FreeIPA (up to 20 min)…"
for i in $(seq 1 120); do
  if docker exec "$NAME" systemctl is-active ipa >/dev/null 2>&1 && \
     docker exec "$NAME" bash -c "echo '$PASSWORD' | kinit admin >/dev/null 2>&1 && ipa ping >/dev/null 2>&1"; then
    echo "lab: ready after $((i*10))s"
    docker exec "$NAME" ipa ping
    exit 0
  fi
  if (( i % 6 == 0 )); then
    docker logs --tail 3 "$NAME" 2>&1 | sed 's/^/  log: /' || true
  fi
  sleep 10
done
echo "lab: FreeIPA did not become ready"; docker logs --tail 60 "$NAME"; exit 1
