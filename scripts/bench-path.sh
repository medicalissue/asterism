#!/usr/bin/env bash
# Measure one network path between this device and one peer, and print the
# result as JSON — one object per line, one line per measurement.
#
# The reason this exists: the only latency number this project had for
# Mac-to-dev5 was a warm `ast ping` of 68-78ms with nothing attached to it. A
# number with no path beside it cannot be attributed, and so that one never
# was. Every line this prints carries the device ids, what kind of path the
# sample crossed, which relay was configured, and the git SHA of the build
# that produced it, because those are the four things that turn a latency
# figure into evidence.
#
# It measures four things, and deliberately none of them touch a disk:
#
#   icmp   plain ping to an address, for a floor that owes nothing to Asterism
#   tcp    TCP connect time to an address, one round trip through the kernel
#   ping   `ast ping`, a mesh round trip, with the path kind it crossed
#   bench  `ast mesh bench`, N bytes down one mesh stream, for throughput
#
# The first two are the controls. Without them a slow `ast ping` reads as
# Asterism being slow, when it may be the wire underneath being slow — which
# is exactly what happened the first time this number was looked at.
#
# Usage:
#   scripts/bench-path.sh --peer <device> --label <path-kind> [options]
#
#   --peer <name>       the device to measure against, as `ast devices` names it
#   --label <kind>      what path this run is exercising, free text, e.g.
#                       "relay-forced" or "upgradeable". Recorded, not checked:
#                       the script does not get to decide what path it got, it
#                       reports what `ast ping` says it got.
#   --samples <n>       how many `ast ping` samples to take (default 20)
#   --bytes <list>      comma-separated benchmark sizes (default 1048576,67108864)
#   --icmp-target <ip>  address for the icmp/tcp controls; repeatable
#   --tcp-port <port>   port for the tcp control (default 22)
#   --idle-secs <n>     seconds to watch an idle paired pair, for the relayed
#                       bytes/minute figure AST-94 needs (default 0, skipped)
#   --out <file>        append JSON lines here as well as stdout
#   --ast <path>        the `ast` binary (default: ast on PATH)
#
# Everything is optional except --peer and --label.
set -euo pipefail

PEER=""
LABEL=""
SAMPLES=20
BYTES_LIST="1048576,67108864"
ICMP_TARGETS=()
TCP_PORT=22
IDLE_SECS=0
OUT=""
AST="${AST:-ast}"

die() {
  echo "bench-path: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --peer) PEER="${2:-}"; shift 2 ;;
    --label) LABEL="${2:-}"; shift 2 ;;
    --samples) SAMPLES="${2:-}"; shift 2 ;;
    --bytes) BYTES_LIST="${2:-}"; shift 2 ;;
    --icmp-target) ICMP_TARGETS+=("${2:-}"); shift 2 ;;
    --tcp-port) TCP_PORT="${2:-}"; shift 2 ;;
    --idle-secs) IDLE_SECS="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --ast) AST="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$PEER" ] || die "--peer is required"
[ -n "$LABEL" ] || die "--label is required"
command -v "$AST" >/dev/null 2>&1 || die "no ast binary at ${AST}"
command -v python3 >/dev/null 2>&1 || die "python3 is required for percentiles"

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"

# Everything is emitted through python3 rather than assembled with printf,
# so a relay URL with a slash in it cannot produce a line that is not JSON.
emit() {
  python3 -c '
import json, sys
obj = json.loads(sys.argv[1])
obj.update(json.loads(sys.argv[2]))
print(json.dumps(obj, sort_keys=True))
' "$(base_fields)" "$1" | tee_out
}

base_fields() {
  python3 -c '
import json, sys
print(json.dumps({
    "run_id": sys.argv[1],
    "git_sha": sys.argv[2],
    "label": sys.argv[3],
    "peer": sys.argv[4],
}))
' "$RUN_ID" "$GIT_SHA" "$LABEL" "$PEER"
}

tee_out() {
  if [ -n "$OUT" ]; then
    tee -a "$OUT"
  else
    cat
  fi
}

# ---- controls ---------------------------------------------------------------

# ICMP, via whatever `ping` this platform ships. Both the BSD and iproute2
# summary lines end in a slash-separated list of min/avg/max, so the parse is
# the same on the Mac and on Linux.
measure_icmp() {
  local target="$1" out line
  if ! out="$(ping -c "$SAMPLES" -i 0.3 "$target" 2>&1)"; then
    emit "$(python3 -c '
import json, sys
print(json.dumps({"kind": "icmp", "target": sys.argv[1], "ok": False,
                  "error": "no reply"}))' "$target")"
    return 0
  fi
  line="$(printf '%s\n' "$out" | grep -E 'min/avg/max' | tail -1)"
  emit "$(python3 -c '
import json, sys
target, line, samples = sys.argv[1], sys.argv[2], int(sys.argv[3])
nums = line.rsplit("=", 1)[-1].strip().split()[0].split("/")
out = {"kind": "icmp", "target": target, "ok": True, "samples": samples}
for name, value in zip(("min_ms", "avg_ms", "max_ms"), nums):
    out[name] = float(value)
print(json.dumps(out))' "$target" "$line" "$SAMPLES")"
}

# TCP connect time: one round trip, measured in the kernel rather than by
# anything Asterism ships. The control that says whether a slow mesh round
# trip is the mesh or the wire.
measure_tcp() {
  local target="$1" i ms
  for i in $(seq 1 5); do
    ms="$(python3 -c '
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
start = time.monotonic()
try:
    s = socket.create_connection((host, port), timeout=5)
    s.close()
except OSError:
    print("")
else:
    print((time.monotonic() - start) * 1000.0)
' "$target" "$TCP_PORT")"
    if [ -n "$ms" ]; then
      emit "$(python3 -c '
import json, sys
print(json.dumps({"kind": "tcp_connect", "target": sys.argv[1],
                  "port": int(sys.argv[2]), "sample": int(sys.argv[3]),
                  "ok": True, "millis": float(sys.argv[4])}))' \
        "$target" "$TCP_PORT" "$i" "$ms")"
    else
      emit "$(python3 -c '
import json, sys
print(json.dumps({"kind": "tcp_connect", "target": sys.argv[1],
                  "port": int(sys.argv[2]), "sample": int(sys.argv[3]),
                  "ok": False}))' "$target" "$TCP_PORT" "$i")"
    fi
  done
}

# ---- the mesh itself --------------------------------------------------------

# `ast ping`, N times. The first sample is reported on its own and left out of
# the percentiles: a cold pool pays a dial and a liveness probe that no later
# sample pays, so folding it in would describe a path nobody is on by the
# second command they type.
measure_ping() {
  local i json cold="" samples_json="[]"
  for i in $(seq 1 "$SAMPLES"); do
    if ! json="$("$AST" ping "$PEER" --json 2>/dev/null)"; then
      emit "$(python3 -c '
import json, sys
print(json.dumps({"kind": "ast_ping", "sample": int(sys.argv[1]),
                  "ok": False}))' "$i")"
      continue
    fi
    if [ "$i" = "1" ]; then
      cold="$json"
    fi
    samples_json="$(python3 -c '
import json, sys
acc = json.loads(sys.argv[1])
acc.append(json.loads(sys.argv[2]))
print(json.dumps(acc))' "$samples_json" "$json")"
    emit "$(python3 -c '
import json, sys
one = json.loads(sys.argv[2])
one.update({"kind": "ast_ping", "sample": int(sys.argv[1]), "ok": True,
            "cold": sys.argv[1] == "1"})
print(json.dumps(one))' "$i" "$json")"
  done
  [ -n "$cold" ] || return 0
  emit "$(python3 -c '
import json, sys
rows = json.loads(sys.argv[1])
warm = [r["millis"] for r in rows[1:]]
out = {"kind": "ast_ping_summary", "samples": len(rows),
       "cold_millis": rows[0]["millis"],
       "path": rows[-1].get("path"),
       "connection_type": rows[-1].get("connection_type"),
       "relay_url": rows[-1].get("relay_url"),
       "upgrade_millis": rows[-1].get("upgrade_millis"),
       "device_id": rows[-1].get("device_id")}
if warm:
    warm.sort()
    def pct(p):
        if len(warm) == 1:
            return warm[0]
        idx = min(len(warm) - 1, int(round((p / 100.0) * (len(warm) - 1))))
        return warm[idx]
    out.update({"warm_samples": len(warm), "warm_p50_ms": pct(50),
                "warm_p95_ms": pct(95), "warm_min_ms": warm[0],
                "warm_max_ms": warm[-1]})
print(json.dumps(out))' "$samples_json")"
}

# `ast mesh bench` at each requested size. Throughput on the same path the
# round trip above crossed, so the two numbers can be read together.
measure_bench() {
  local size json
  for size in $(printf '%s' "$BYTES_LIST" | tr ',' ' '); do
    if ! json="$("$AST" mesh bench --to "$PEER" --bytes "$size" --json 2>/dev/null)"; then
      emit "$(python3 -c '
import json, sys
print(json.dumps({"kind": "ast_bench", "requested_bytes": int(sys.argv[1]),
                  "ok": False}))' "$size")"
      continue
    fi
    emit "$(python3 -c '
import json, sys
one = json.loads(sys.argv[2])
one.update({"kind": "ast_bench", "requested_bytes": int(sys.argv[1]),
            "ok": True})
print(json.dumps(one))' "$size" "$json")"
  done
}

# What a paired pair costs when nobody is using it. Two reads of the relay
# meter with a measured gap, reported per minute, because the question AST-94
# asks is a monthly bill and the honest way to reach one is a rate.
measure_idle() {
  local before after
  [ "$IDLE_SECS" -gt 0 ] || return 0
  before="$("$AST" ping "$PEER" --json 2>/dev/null)" || return 0
  sleep "$IDLE_SECS"
  after="$("$AST" ping "$PEER" --json 2>/dev/null)" || return 0
  emit "$(python3 -c '
import json, sys
before, after, secs = json.loads(sys.argv[1]), json.loads(sys.argv[2]), float(sys.argv[3])
keys = ("relayed_bytes_sent", "relayed_bytes_recv",
        "direct_bytes_sent", "direct_bytes_recv")
delta = {k: after.get(k, 0) - before.get(k, 0) for k in keys}
relayed = delta["relayed_bytes_sent"] + delta["relayed_bytes_recv"]
direct = delta["direct_bytes_sent"] + delta["direct_bytes_recv"]
out = {"kind": "idle_meter", "seconds": secs,
       "relayed_bytes": relayed, "direct_bytes": direct,
       "relayed_bytes_per_min": relayed * 60.0 / secs,
       "direct_bytes_per_min": direct * 60.0 / secs,
       "path": after.get("path"), "relay_url": after.get("relay_url")}
out.update({k + "_delta": v for k, v in delta.items()})
print(json.dumps(out))' "$before" "$after" "$IDLE_SECS")"
}

# ---- run --------------------------------------------------------------------

for target in ${ICMP_TARGETS+"${ICMP_TARGETS[@]}"}; do
  measure_icmp "$target"
  measure_tcp "$target"
done

measure_ping
measure_bench
measure_idle
