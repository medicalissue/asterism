#!/usr/bin/env bash
# End-to-end for OCI images as an instance source (MODEL.md: container
# images are an image SOURCE, booted as microVMs).
#
# Two shapes of image, because they fail differently:
#
#   1. A service — nginx. Pull, unpack, build ext4, boot with a direct
#      kernel, and prove it is a real machine serving real bytes: curl the
#      published port and get the welcome page, read its stdout with
#      `ast logs`, take it down and up again.
#   2. A one-shot with no shell in it at all — hello-world, which is a
#      single static binary on an empty filesystem. It prints and exits,
#      and the machine powers itself off.
#
# Both boots are real. Nothing here is mocked, and every assertion is on
# output content (see e2e.sh for why this is a bash script).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
cargo build -q
AST="$ROOT/target/debug/ast"

# Fresh, SHORT home: unix socket paths are capped near 104 bytes.
export ASTERISM_HOME="/private/tmp/ast-oci-$$"
PORT="${E2E_PORT:-8080}"
WEB=oci-web
ONESHOT=oci-once

cleanup() {
  "$AST" down "$WEB" >/dev/null 2>&1 || true
  "$AST" down "$ONESHOT" >/dev/null 2>&1 || true
  "$AST" rm "$WEB" >/dev/null 2>&1 || true
  "$AST" rm "$ONESHOT" >/dev/null 2>&1 || true
  pkill -f "$ROOT/target/debug/astd" 2>/dev/null || true
  rm -rf "$ASTERISM_HOME"
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images"
# Reuse an already-built store instead of re-pulling half of Docker Hub. The
# guest kernel and the blob cache are the expensive parts; the ext4 images
# rebuild in under a second from cached blobs.
CACHE="${E2E_IMAGE_CACHE:-$HOME/.asterism/images}"
if [ -d "$CACHE" ]; then
  cp -R "$CACHE/kernel" "$ASTERISM_HOME/images/" 2>/dev/null || true
  cp -R "$CACHE/oci" "$ASTERISM_HOME/images/" 2>/dev/null || true
  cp "$CACHE/"oci-*.raw "$ASTERISM_HOME/images/" 2>/dev/null || true
  cp "$CACHE/"oci-*.json "$ASTERISM_HOME/images/" 2>/dev/null || true
fi

fail() { echo "E2E FAIL: $*" >&2; exit 1; }

# expect <desc> <needle> <cmd...>: run cmd, require success AND the needle
# in its combined output.
expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  echo "ok: $desc"
}

# refuse <desc> <needle> <cmd...>: the command must FAIL, and say why.
refuse() {
  local desc="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then
    fail "$desc: expected a refusal, got:"$'\n'"$out"
  fi
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  echo "ok: $desc"
}

# ---- 1. a service ----------------------------------------------------------

# `nginx` with no registry and no tag: docker.io/library/nginx:latest.
expect "create from a bare docker hub name" "$WEB  defined" \
  "$AST" create "$WEB" --image nginx -p "$PORT:80" --mem 1G --disk 10G

expect "status names the source" "oci rootfs, direct kernel boot" \
  "$AST" status "$WEB"
expect "status names the published port" "127.0.0.1:$PORT -> :80" \
  "$AST" status "$WEB"
expect "the image is recorded fully qualified" "docker.io/library/nginx:latest" \
  "$AST" status "$WEB"

# The store knows what it built, and says so next to the catalog.
expect "images lists what this device built" "docker.io/library/nginx:latest" \
  "$AST" images
expect "ls shortens the hub prefix" "nginx:latest" "$AST" ls

started=$(date +%s)
expect "up" "$WEB  running" "$AST" up "$WEB"

# The claim is a microVM that serves in seconds, so it is timed.
served=
for _ in $(seq 1 40); do
  if body="$(curl -sS --max-time 2 "http://127.0.0.1:$PORT/" 2>/dev/null)" \
     && grep -qF "Welcome to nginx!" <<<"$body"; then
    served=$(( $(date +%s) - started ))
    break
  fi
  sleep 0.5
done
[ -n "$served" ] || fail "nginx did not serve on 127.0.0.1:$PORT — see: ast logs $WEB"
echo "ok: curl 127.0.0.1:$PORT returned the nginx welcome page (${served}s after up)"
[ "$served" -le 20 ] || fail "boot to first byte took ${served}s"

# The console is the whole of an OCI instance's output, so it has to carry
# the image's own startup as well as the kernel's.
expect "logs show the entrypoint" "/docker-entrypoint.sh" "$AST" logs "$WEB" -n 400
expect "logs show nginx itself" "start worker process" "$AST" logs "$WEB" -n 400

# ssh is the one thing an OCI instance cannot offer, and it says so at once
# rather than waiting three minutes for a banner.
refuse "ssh says why it cannot" "has no ssh server" "$AST" ssh "$WEB" -- true
refuse "ssh says where to look instead" "ast logs" "$AST" ssh "$WEB" -- true

# A volume needs an init system in the guest to mount it; there is none.
refuse "volumes are refused with a reason" "no init system" \
  "$AST" attach "$WEB" --volume "$ASTERISM_HOME"

# Down is a real ACPI powerdown: the generated init hears the power button
# and stops nginx. Up again on the same disk.
expect "down" "$WEB  stopped" "$AST" down "$WEB"
expect "logs show a clean shutdown" "exited with status" "$AST" logs "$WEB" -n 400
expect "snapshot a stopped oci disk" "$WEB  snapshot clean" "$AST" snapshot "$WEB" clean
expect "up again" "$WEB  running" "$AST" up "$WEB"

again=
for _ in $(seq 1 40); do
  body="$(curl -sS --max-time 2 "http://127.0.0.1:$PORT/" 2>/dev/null || true)"
  if grep -qF "Welcome to nginx!" <<<"$body"; then
    again=1
    break
  fi
  sleep 0.5
done
[ -n "$again" ] || fail "nginx did not come back after down/up"
echo "ok: serving again after down/up"

expect "down 2" "$WEB  stopped" "$AST" down "$WEB"
expect "rm" "$WEB  removed" "$AST" rm "$WEB"
[ -d "$ASTERISM_HOME/instances/$WEB" ] && fail "rm left the instance directory behind"
echo "ok: rm cleaned up"

# ---- 2. a one-shot with no shell -------------------------------------------

# hello-world is FROM scratch: one static binary, no /bin/sh, no /proc.
# It runs because the init and the shell it runs under are ours.
expect "create a one-shot" "$ONESHOT  defined" \
  "$AST" create "$ONESHOT" --image hello-world --mem 1G --disk 10G
expect "up the one-shot" "$ONESHOT  running" "$AST" up "$ONESHOT"

greeted=
for _ in $(seq 1 40); do
  # Captured rather than piped: `grep -q` exits on the first match, and
  # under `pipefail` the SIGPIPE that gives `ast` would fail the test.
  out="$("$AST" logs "$ONESHOT" -n 400 2>/dev/null || true)"
  if grep -qF "Hello from Docker!" <<<"$out"; then
    greeted=1
    break
  fi
  sleep 0.5
done
[ -n "$greeted" ] || fail "the one-shot never printed — see: ast logs $ONESHOT"
echo "ok: the image's Cmd ran with no shell in the image"

expect "it powers itself off" "exited with status 0" "$AST" logs "$ONESHOT" -n 400
expect "and the kernel obeyed" "Power down" "$AST" logs "$ONESHOT" -n 400

# Honest status: the machine is off, and it stays off — a container that
# finished is not a crash to be restarted.
stopped=
for _ in $(seq 1 20); do
  out="$("$AST" status "$ONESHOT" 2>/dev/null || true)"
  if grep -qF "status:  stopped" <<<"$out"; then
    stopped=1
    break
  fi
  sleep 1
done
[ -n "$stopped" ] || fail "status still claims the one-shot is running"
echo "ok: status says stopped once the entrypoint returned"
sleep 8
expect "and it is left alone" "status:  stopped" "$AST" status "$ONESHOT"
expect "rm the one-shot" "$ONESHOT  removed" "$AST" rm "$ONESHOT"

# ---- 3. what is refused ----------------------------------------------------

# On a device with a signed vz helper this is the capability check; on one
# without, vz refuses to be selected at all, one step earlier. Either way
# `--backend vz --image nginx` must not produce an instance. (The capability
# itself is asserted in `backend::check_can_boot`'s unit test, which does not
# need a signed helper to run.)
out="$("$AST" create refused --image nginx --backend vz 2>&1)" \
  && fail "vz accepted an oci image:"$'\n'"$out"
grep -qF "vz" <<<"$out" || fail "the refusal does not name vz:"$'\n'"$out"
echo "ok: vz refuses an oci image"

echo "E2E-OCI GREEN (nginx served on 127.0.0.1:$PORT in ${served}s)"
