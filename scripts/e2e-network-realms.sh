#!/usr/bin/env bash
# Real Linux network-isolation evidence for orbit recovery.
#
# This is intentionally not the same-host/loopback mesh lane.  It creates two
# device namespaces, two independent router namespaces (each doing its own
# stateful NAT), a simulated WAN, and a separate Ethernet broadcast domain.
# The daemons are ordinary production binaries in discovery mode.  The lane
# proves a relay-only enrollment, two-NAT reachability, an actual Wi-Fi to
# Ethernet address change, direct operation with relay/directory egress gone,
# sleep/wake, provider/daemon disappearance, stale-address discovery recovery,
# and pre-mutation remote-volume SLO refusal.
#
# Run on Linux as a user with passwordless sudo.  `e2e-lima-recovery.sh` is the
# macOS entry point and supplies a nested-KVM Lima guest for this script.
set -euo pipefail

[ "$(uname -s)" = Linux ] || {
  echo "NETWORK REALMS E2E FAIL: Linux network namespaces are required" >&2
  exit 2
}
sudo -n true 2>/dev/null || {
  echo "NETWORK REALMS E2E FAIL: passwordless sudo is required for network namespaces" >&2
  exit 2
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AST="${AST_BIN:-$ROOT/target/debug/ast}"
ASTD="${ASTD_BIN:-$ROOT/target/debug/astd}"
for binary in "$AST" "$ASTD"; do
  [ -x "$binary" ] || {
    echo "NETWORK REALMS E2E FAIL: missing executable $binary" >&2
    exit 2
  }
done

RUN="$(mktemp -d /tmp/asterism-network-realms.XXXXXX)"
TAG="ar$(( $$ % 10000 ))"
DEV_A="${TAG}a"
DEV_B="${TAG}b"
NAT_A="${TAG}na"
NAT_B="${TAG}nb"
WAN="${TAG}wan"
LAN="${TAG}lan"
UPLINK="$(ip route show default | awk 'NR == 1 { print $5 }')"
UID_NOW="$(id -u)"
GID_NOW="$(id -g)"
HOME_NOW="$HOME"
A="$RUN/a"
B="$RUN/b"
A_NAME="realm-a-$TAG"
B_NAME="realm-b-$TAG"
INST="realm-volume-$TAG"
VOL="tank"
ROOT_FORWARD="$(sysctl -n net.ipv4.ip_forward)"
DAEMONS=()
WAN_RULE=0

fail() { echo "NETWORK REALMS E2E FAIL: $*" >&2; exit 1; }

kill_daemon() {
  local home="$1" pid
  pid="$(cat "$home/astd.pid" 2>/dev/null || true)"
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  sudo kill -CONT "$pid" 2>/dev/null || true
  sudo kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    sudo kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  sudo kill -KILL "$pid" 2>/dev/null || true
}

cleanup() {
  set +e
  if [ -n "${ASTERISM_TEST_ARTIFACTS:-}" ]; then
    evidence="$ASTERISM_TEST_ARTIFACTS/network-realms"
    mkdir -p "$evidence/a" "$evidence/b"
    for file in astd.log orbit.json volumes.json state.json invite.out; do
      [ ! -f "$A/$file" ] || cp "$A/$file" "$evidence/a/$file"
    done
    for file in astd.log orbit.json volumes.json state.json add.out; do
      [ ! -f "$B/$file" ] || cp "$B/$file" "$evidence/b/$file"
    done
    for ns in "$DEV_A" "$DEV_B" "$NAT_A" "$NAT_B"; do
      # The evidence directory is owned by the invoking user; only reading the
      # namespace requires sudo, so both redirects intentionally happen here.
      # shellcheck disable=SC2024
      sudo ip -n "$ns" address show >"$evidence/$ns-addresses.txt" 2>&1 || true
      # shellcheck disable=SC2024
      sudo ip -n "$ns" route show >"$evidence/$ns-routes.txt" 2>&1 || true
    done
  fi
  kill_daemon "$A"
  kill_daemon "$B"
  if [ "$WAN_RULE" = 1 ]; then
    sudo iptables -D FORWARD -s 198.18.77.0/24 -o "$UPLINK" \
      -m comment --comment "$TAG-outage" -j REJECT
  fi
  sudo iptables -t nat -D POSTROUTING -s 198.18.77.0/24 -o "$UPLINK" \
    -m comment --comment "$TAG" -j MASQUERADE
  for ns in "$DEV_A" "$DEV_B" "$NAT_A" "$NAT_B"; do
    sudo ip netns del "$ns" 2>/dev/null || true
    sudo rm -f "/etc/netns/$ns/resolv.conf"
    sudo rmdir "/etc/netns/$ns" 2>/dev/null || true
  done
  sudo ip link del "$WAN" 2>/dev/null || true
  sudo ip link del "$LAN" 2>/dev/null || true
  sudo sysctl -w "net.ipv4.ip_forward=$ROOT_FORWARD" >/dev/null
  rm -rf "$RUN"
}
trap cleanup EXIT

ns_user() {
  local ns="$1" home="$2"; shift 2
  sudo ip netns exec "$ns" setpriv --reuid="$UID_NOW" --regid="$GID_NOW" --init-groups \
    env HOME="$HOME_NOW" ASTERISM_HOME="$home" "$@"
}

ast_a() { ns_user "$DEV_A" "$A" "$AST" "$@"; }
ast_b() { ns_user "$DEV_B" "$B" "$AST" "$@"; }

start_daemon() {
  local ns="$1" home="$2" no_direct="${3:-0}" old="" now=""
  mkdir -p "$home"
  old="$(cat "$home/astd.pid" 2>/dev/null || true)"
  # The home is owned by the invoking user, so this redirect is intentionally
  # outside sudo and cannot write anywhere that user could not already write.
  # shellcheck disable=SC2024
  sudo ip netns exec "$ns" setpriv --reuid="$UID_NOW" --regid="$GID_NOW" --init-groups \
    env HOME="$HOME_NOW" ASTERISM_HOME="$home" ASTERISM_MESH_NO_DIRECT="$no_direct" \
    "$ASTD" >>"$home/astd.log" 2>&1 &
  DAEMONS+=("$!")
  for _ in $(seq 1 300); do
    now="$(cat "$home/astd.pid" 2>/dev/null || true)"
    if [ -n "$now" ] && [ "$now" != "$old" ] && sudo kill -0 "$now" 2>/dev/null \
      && grep -q "discovery: published" "$home/astd.log" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  fail "daemon in $ns did not publish:"$'\n'"$(tail -40 "$home/astd.log" 2>/dev/null)"
}

wait_ping() {
  local side="$1" peer="$2" wanted="$3" out=""
  for _ in $(seq 1 150); do
    if [ "$side" = a ]; then out="$(ast_a ping "$peer" 2>&1 || true)";
    else out="$(ast_b ping "$peer" 2>&1 || true)"; fi
    grep -q "via $wanted" <<<"$out" && { printf '%s\n' "$out"; return 0; }
    sleep 0.2
  done
  fail "$side could not ping $peer via $wanted (last answer: $out)"
}

no_lease() {
  python3 - "$A/volumes.json" "$VOL" <<'PY'
import json, sys
volume = json.load(open(sys.argv[1]))["volumes"][sys.argv[2]]
raise SystemExit(0 if volume.get("lease") is None else 1)
PY
}

mkdir -p "$A" "$B"

# Network namespaces use a real resolver rather than the host namespace's
# 127.0.0.53 stub.  Each path is namespace-scoped and removed exactly by the
# cleanup trap.
for ns in "$DEV_A" "$DEV_B" "$NAT_A" "$NAT_B"; do
  sudo mkdir -p "/etc/netns/$ns"
  printf 'nameserver 1.1.1.1\n' | sudo tee "/etc/netns/$ns/resolv.conf" >/dev/null
  sudo ip netns add "$ns"
  sudo ip -n "$ns" link set lo up
done

# Simulated WAN shared only by the two independent NAT routers.
sudo ip link add "$WAN" type bridge
sudo ip addr add 198.18.77.1/24 dev "$WAN"
sudo ip link set "$WAN" up

make_router() {
  local router="$1" device="$2" number="$3"
  local root_wan="${TAG}w${number}" router_wan="wan${number}"
  local router_lan="lan${number}" device_wifi="wifi${number}"
  sudo ip link add "$root_wan" type veth peer name "$router_wan"
  sudo ip link set "$root_wan" master "$WAN"
  sudo ip link set "$root_wan" up
  sudo ip link set "$router_wan" netns "$router"
  sudo ip -n "$router" addr add "198.18.77.$((number + 1))/24" dev "$router_wan"
  sudo ip -n "$router" link set "$router_wan" up
  sudo ip -n "$router" route add default via 198.18.77.1

  sudo ip link add "$router_lan" type veth peer name "$device_wifi"
  sudo ip link set "$router_lan" netns "$router"
  sudo ip link set "$device_wifi" netns "$device"
  sudo ip -n "$router" addr add "10.${number}.0.1/24" dev "$router_lan"
  sudo ip -n "$router" link set "$router_lan" up
  sudo ip -n "$device" addr add "10.${number}.0.2/24" dev "$device_wifi"
  sudo ip -n "$device" link set "$device_wifi" up
  sudo ip -n "$device" route add default via "10.${number}.0.1"
  sudo ip netns exec "$router" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sudo ip netns exec "$router" iptables -t nat -A POSTROUTING -s "10.${number}.0.0/24" \
    -o "$router_wan" -j MASQUERADE
  sudo ip netns exec "$router" iptables -A FORWARD -i "$router_lan" -o "$router_wan" -j ACCEPT
  sudo ip netns exec "$router" iptables -A FORWARD -i "$router_wan" -o "$router_lan" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}
make_router "$NAT_A" "$DEV_A" 101
make_router "$NAT_B" "$DEV_B" 102

# A distinct common Ethernet broadcast domain.  Both device-side interfaces
# start down; bringing them up later is the real roam event.
sudo ip link add "$LAN" type bridge
sudo ip link set "$LAN" up
for side in a b; do
  if [ "$side" = a ]; then ns="$DEV_A"; octet=2; else ns="$DEV_B"; octet=3; fi
  host_if="${TAG}e$side"; dev_if="eth$side"
  sudo ip link add "$host_if" type veth peer name "$dev_if"
  sudo ip link set "$host_if" master "$LAN"
  sudo ip link set "$host_if" up
  sudo ip link set "$dev_if" netns "$ns"
  sudo ip -n "$ns" addr add "172.30.77.$octet/24" dev "$dev_if"
done

sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
sudo iptables -t nat -A POSTROUTING -s 198.18.77.0/24 -o "$UPLINK" \
  -m comment --comment "$TAG" -j MASQUERADE

start_daemon "$DEV_A" "$A" 1
start_daemon "$DEV_B" "$B"
echo "ok: two daemons published from independent NAT realms"

# The relay-only ticket proves the first connection has no direct hint to use.
ast_a device invite --name "$A_NAME" --yes >"$A/invite.out" 2>&1 &
INVITE_PID=$!
TICKET=""
for _ in $(seq 1 150); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$A/invite.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.2
done
[ -n "$TICKET" ] || fail "A printed no pairing ticket"
ast_b device add "$TICKET" --name "$B_NAME" --yes >"$B/add.out" 2>&1 \
  || fail "pairing across two NATs failed:"$'\n'"$(cat "$B/add.out")"
wait "$INVITE_PID" || fail "inviter failed:"$'\n'"$(cat "$A/invite.out")"

read -r ADDRS RELAYS < <(python3 - "$B/orbit.json" "$A_NAME" <<'PY'
import json, sys
for d in json.load(open(sys.argv[1]))["devices"]:
    if d["name"] == sys.argv[2]:
        print(len(d["addrs"]), len(d["relays"]))
        break
PY
)
[ "$ADDRS" = 0 ] && [ "$RELAYS" -gt 0 ] \
  || fail "the forced-relay enrollment carried direct addresses ($ADDRS/$RELAYS)"
echo "ok: pairing crossed two NATs from a relay-only ticket (0 direct hints, $RELAYS relay hint)"

TWO_NAT_PING="$(wait_ping b "$A_NAME" relay)"
echo "ok: selected relay path crossed the two independent NATs — $TWO_NAT_PING"

# SLO refusal is measured on that real selected relay path.  A remote volume
# requires a measured direct path no slower than 5ms, so prove both the
# provider lease and consumer instance record remain unchanged.
qemu-img create -f raw "$B/tiny.raw" 1M >/dev/null
ast_b create "$INST" --backend qemu --image "$B/tiny.raw" --mem 512M --disk 1G >/dev/null
ast_a volume create "$VOL" --size 5G >/dev/null
REFUSAL="$(ast_b attach "$INST" --volume "$A_NAME:$VOL" 2>&1 || true)"
grep -q "refused before mutation" <<<"$REFUSAL" \
  || fail "slow/relay remote-volume placement was not refused:"$'\n'"$REFUSAL"
no_lease || fail "a refused placement moved the provider lease"
if ast_b status "$INST" | grep -q " $VOL ("; then
  fail "a refused placement wrote a consumer volume record"
fi
echo "ok: roadmap direct/<=5ms SLO refused the relay before either device mutated"

# Wi-Fi to Ethernet: publish the common-LAN interfaces, then remove the routed
# Wi-Fi links and their defaults.  There is no route to a relay or directory
# afterwards, so a successful ping is simultaneously same-LAN proof and proof
# that direct data survives infrastructure outage without coordination.
sudo ip -n "$DEV_A" link set etha up
sudo ip -n "$DEV_B" link set ethb up
sleep 2
sudo ip -n "$DEV_A" route del default
sudo ip -n "$DEV_B" route del default
sudo ip -n "$DEV_A" link set wifi101 down
sudo ip -n "$DEV_B" link set wifi102 down
sudo iptables -I FORWARD 1 -s 198.18.77.0/24 -o "$UPLINK" \
  -m comment --comment "$TAG-outage" -j REJECT
WAN_RULE=1
ROAM_PING="$(wait_ping b "$A_NAME" direct)"
echo "ok: Wi-Fi-to-Ethernet roam selected same-LAN direct with relay/coordinator unreachable — $ROAM_PING"

# SIGSTOP/SIGCONT is the software-observable half of sleep/wake: the process,
# endpoint identity and address survive while no mesh request is answered.
A_PID="$(cat "$A/astd.pid")"
sudo kill -STOP "$A_PID"
if timeout 8 ast_b ping "$A_NAME" >/dev/null 2>&1; then
  fail "a sleeping provider still answered"
fi
sudo kill -CONT "$A_PID"
WAKE_PING="$(wait_ping b "$A_NAME" direct)"
echo "ok: sleep/wake recovered the same endpoint — $WAKE_PING"

# The direct link is now admissible; this also proves the earlier refusal did
# not leave a hidden lease behind.
ast_b attach "$INST" --volume "$A_NAME:$VOL" >/dev/null \
  || fail "the same remote volume was not admissible after direct roam"
python3 - "$A/volumes.json" "$VOL" "$INST" <<'PY'
import json, sys
lease = json.load(open(sys.argv[1]))["volumes"][sys.argv[2]].get("lease")
assert lease and lease["holder"] == sys.argv[3] and lease["epoch"] == 1, lease
PY
echo "ok: suitable placement committed exactly one epoch after the refusal"

# Restore Wi-Fi/WAN, disappear the provider daemon, forge a stale address, and
# restart both sides.  Discovery by public key must find the provider's new
# ephemeral port and repair the durable store.
sudo ip -n "$DEV_A" link set wifi101 up
sudo ip -n "$DEV_B" link set wifi102 up
sudo ip -n "$DEV_A" route add default via 10.101.0.1
sudo ip -n "$DEV_B" route add default via 10.102.0.1
sudo iptables -D FORWARD -s 198.18.77.0/24 -o "$UPLINK" \
  -m comment --comment "$TAG-outage" -j REJECT
WAN_RULE=0

kill_daemon "$A"
if timeout 8 ast_b --device "$A_NAME" volume ls >/dev/null 2>&1; then
  fail "a disappeared provider still answered"
fi
echo "ok: provider disappearance is observable from the consumer"

kill_daemon "$B"
python3 - "$B/orbit.json" "$A_NAME" <<'PY'
import json, sys
path, name = sys.argv[1:]
store = json.load(open(path))
for d in store["devices"]:
    if d["name"] == name:
        d["addrs"] = ["127.0.0.1:1"]
        d["relays"] = []
        d["addrs_seen_at"] = 1
json.dump(store, open(path, "w"), indent=2)
PY
start_daemon "$DEV_A" "$A" 0
start_daemon "$DEV_B" "$B" 0
RECOVERED="$(wait_ping b "$A_NAME" direct)"
TELEMETRY="$(ast_b devices)"
grep -q "stale_address_recovered_by_discovery" <<<"$TELEMETRY" \
  || fail "stale-address recovery was not surfaced:"$'\n'"$TELEMETRY"
if grep -q '127.0.0.1:1' "$B/orbit.json"; then
  fail "the stale address survived discovery recovery"
fi
echo "ok: provider/consumer daemon restart repaired a stale address by key — $RECOVERED"

echo "NETWORK REALMS E2E GREEN"
