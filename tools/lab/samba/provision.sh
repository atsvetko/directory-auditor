#!/usr/bin/env bash
# Provision a throw-away Samba AD DC with deliberately weak settings on this
# machine (a CI runner or a disposable VM) and start it in the foreground.
#
# LAB ONLY: it overwrites /etc/samba/smb.conf and /var/lib/samba. Refuses to
# run unless DIRAUDITOR_LAB=1. Idempotent: an existing lab domain is reused.
#
# Usage: sudo DIRAUDITOR_LAB=1 provision.sh [--dry-run]
# Env:   LAB_REALM (LAB.EXAMPLE) LAB_DOMAIN (LAB) LAB_HOST (dc1) LAB_ADMIN_PASSWORD
#        SAMBA_PYTHON (python3)  — the interpreter that has the samba modules
set -euo pipefail

[[ "${DIRAUDITOR_LAB:-}" == "1" ]] || { echo "refusing: set DIRAUDITOR_LAB=1 (this script replaces the Samba configuration on this machine)"; exit 2; }
DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1
[[ $EUID -eq 0 || $DRY -eq 1 ]] || { echo "run as root"; exit 2; }

REALM=${LAB_REALM:-LAB.EXAMPLE}
DOMAIN=${LAB_DOMAIN:-LAB}
HOST=${LAB_HOST:-dc1}
FQDN="$HOST.$(echo "$REALM" | tr 'A-Z' 'a-z')"
ADMINPW=${LAB_ADMIN_PASSWORD:-'Lab-Admin-Pass-2026!'}
PY=${SAMBA_PYTHON:-python3}
ST="$PY /usr/bin/samba-tool"
LOG=${LAB_LOG:-/var/log/samba-lab.log}

run() { if (( DRY )); then echo "+ $*"; else "$@"; fi; }

echo "lab: $FQDN ($DOMAIN / $REALM), python: $($PY --version 2>&1)"

# 1. Name resolution for the DC itself (Kerberos needs the FQDN).
if ! grep -q "$FQDN" /etc/hosts; then
  run sh -c "echo '127.0.0.1 $FQDN $HOST' >> /etc/hosts"
fi

# 1b. The distribution package may have started the classic file server; an AD
#     DC runs its own smbd, so stop and disable those units when systemd is present.
if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; then
  for u in smbd nmbd winbind samba-ad-dc; do
    run systemctl stop "$u" 2>/dev/null || true
    run systemctl disable "$u" 2>/dev/null || true
    run systemctl mask "$u" 2>/dev/null || true
  done
fi
if (( ! DRY )); then
  pkill -x smbd 2>/dev/null || true; pkill -x nmbd 2>/dev/null || true; pkill -x winbindd 2>/dev/null || true
  sleep 1
  if command -v ss >/dev/null && ss -ltn 2>/dev/null | grep -qE ':(445|389|636|88) '; then
    echo "lab: a service already listens on a DC port:"; ss -ltnp | grep -E ':(445|389|636|88) ' || true
  fi
fi

# 2. Provision once.
if [[ -f /var/lib/samba/private/sam.ldb ]] && (( ! DRY )); then
  echo "lab: existing domain found, keeping it"
else
  run rm -f /etc/samba/smb.conf
  run rm -rf /var/lib/samba/private /var/lib/samba/sysvol
  run $ST domain provision --realm="$REALM" --domain="$DOMAIN" --server-role=dc --dns-backend=SAMBA_INTERNAL \
      --adminpass="$ADMINPW" --host-name="$HOST" --host-ip=127.0.0.1 --use-rfc2307 --option="dns forwarder = 127.0.0.53"
fi

# 3. Weak settings, all in [global]. Each one is a catalogue entry.
if (( ! DRY )) && ! grep -q "lab weaknesses" /etc/samba/smb.conf; then
  python3 - "$FQDN" <<'EOF'
import sys
p = '/etc/samba/smb.conf'
s = open(p).read()
weak = """\t# --- lab weaknesses (deliberate; see catalogue/samba) ---
\tinterfaces = 127.0.0.1
\tbind interfaces only = yes
\tserver schannel = auto
\treject md5 clients = no
\tntlm auth = ntlmv1-permitted
\tallow dns updates = nonsecure
\tserver min protocol = NT1
\tdsdb:schema update allowed = yes
\told password allowed period = 1440
\tmap to guest = Bad User
\tlog level = 0
\tkdc:user ticket lifetime = 24
\tkerberos encryption types = legacy
"""
head, sep, rest = s.partition('\n[sysvol]')
s = head.rstrip('\n') + '\n' + weak + sep + rest
s += """
[public]
\tpath = /srv/public
\tread only = No
\tguest ok = Yes
"""
open(p, 'w').write(s)
EOF
  run mkdir -p /srv/public
fi
run sh -c "testparm -s --suppress-prompt /etc/samba/smb.conf >/dev/null"

# 4. Kerberos client config for the lab realm.
run cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

# 4b. Register the standard service principal names (ldap/<dc>, …). A fresh
#     provision may not have them until the periodic task runs; the Kerberos
#     SASL bind over plain LDAP needs ldap/<dc> to resolve.
if (( ! DRY )); then
  run $PY /usr/sbin/samba_spnupdate 2>/dev/null || true
fi

# 5. Start samba in the foreground (no systemd needed) unless it is running.
if (( ! DRY )); then
  if ! pgrep -x samba >/dev/null; then
    nohup samba -i -s /etc/samba/smb.conf >"$LOG" 2>&1 &
    disown
  fi
  for i in $(seq 1 30); do
    if ldapsearch -x -H ldap://127.0.0.1 -s base -b "" vendorVersion 2>/dev/null | grep -q vendorVersion; then
      echo "lab: LDAP up after ${i}s"; break
    fi
    sleep 1
    [[ $i -eq 30 ]] && { echo "lab: samba did not come up; log:"; tail -20 "$LOG"; echo "--- log.smbd:"; tail -20 /var/log/samba/log.smbd 2>/dev/null || true; echo "--- listeners:"; ss -ltnp 2>/dev/null || true; exit 1; }
  done
  # Self-check
  ldapsearch -x -H ldap://127.0.0.1 -s base -b "" vendorVersion defaultNamingContext domainFunctionality 2>/dev/null | grep -E "^(vendorVersion|defaultNamingContext|domainFunctionality)"
  echo "lab: LDAPS pin $(openssl x509 -in /var/lib/samba/private/tls/cert.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
fi
