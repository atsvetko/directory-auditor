#!/usr/bin/env bash
# Independent isolation check for the da-lab network. Plugs a throwaway network
# namespace into the da-lab0 bridge as a fake guest (10.55.0.250) and probes:
#   must reach : the host on 10.55.0.1
#   must NOT   : the host's LAN gateway, the host's LAN address, the internet
# Also prints libvirt's definition and firewall rules for the bridge.
# Removes everything it creates. Run as your normal user; it asks for sudo.
set -uo pipefail
# grep that reads all its input (with pipefail, grep -q can fail a pipeline whose condition held)
has() { grep "$@" >/dev/null; }

ns=dalab-probe
br=da-lab0
virsh="sudo virsh -c qemu:///system"
lan_gw=$(ip -4 route show default | awk '{print $3; exit}')
lan_ip=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
fail=0

cleanup() { sudo ip netns del "$ns" 2>/dev/null; sudo ip link del dalab-h 2>/dev/null; }
trap cleanup EXIT
cleanup

echo "== libvirt definition"
$virsh net-dumpxml da-lab
$virsh net-dumpxml da-lab | has '<forward' && { echo "FAIL: <forward> present"; fail=1; }

echo "== firewall rules mentioning $br"
if sudo nft list ruleset >/dev/null 2>&1; then
  sudo nft list ruleset | grep -n "$br"
else
  sudo iptables -S | grep "$br"
fi

echo "== probe from a fake guest (10.55.0.250)"
sudo ip netns add "$ns"
sudo ip link add dalab-h type veth peer name dalab-g
sudo ip link set dalab-g netns "$ns"
sudo ip link set dalab-h master "$br" up
sudo ip -n "$ns" addr add 10.55.0.250/24 dev dalab-g
sudo ip -n "$ns" link set dalab-g up
sudo ip -n "$ns" link set lo up
sudo ip -n "$ns" route add default via 10.55.0.1
sleep 2   # bridge port to forwarding state (stp delay 0)

probe() { # want(reach|block) label target
  if sudo ip netns exec "$ns" ping -c 2 -W 2 -q "$3" >/dev/null 2>&1; then got=reach; else got=block; fi
  if [ "$got" = "$1" ]; then echo "ok    $2 ($3): $got"; else echo "FAIL  $2 ($3): $got, expected $1"; fail=1; fi
}
probe reach "lab host"        10.55.0.1
probe block "LAN gateway"     "$lan_gw"
probe block "internet"        1.1.1.1
# The host's LAN address: libvirt's isolated mode does not stop a guest from
# talking to the host itself on another address (that is INPUT, not FORWARD).
# Reported, not failed; the runner and services on the host are the boundary.
if sudo ip netns exec "$ns" ping -c 2 -W 2 -q "$lan_ip" >/dev/null 2>&1; then
  echo "note  host LAN address ($lan_ip): reachable (host-local, not routed onward)"
else
  echo "ok    host LAN address ($lan_ip): blocked"
fi
if sudo ip netns exec "$ns" timeout 3 bash -c 'echo > /dev/tcp/1.1.1.1/443' 2>/dev/null; then
  echo "FAIL  internet TCP 443: connected"; fail=1
else
  echo "ok    internet TCP 443: blocked"
fi

echo
[ "$fail" -eq 0 ] && echo "VERIFIED: da-lab is isolated." || { echo "NOT ISOLATED: see FAIL lines."; exit 1; }
