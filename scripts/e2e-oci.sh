#!/usr/bin/env bash
# End-to-end for OCI images as an instance source (MODEL.md: OCI is an image
# source, and every resulting Instance boots as a VM/microVM).
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
# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin oci
harness_binaries "$ROOT"

# Fresh, SHORT home: unix socket paths are capped near 104 bytes.
export ASTERISM_HOME="/private/tmp/ast-oci-$$"
harness_own_home "$ASTERISM_HOME"
PORT="${E2E_PORT:-8080}"
WEB=oci-web
ONESHOT=oci-once
VOL="$ASTERISM_HOME/oci-volume"
VOL_MARKER="oci-volume-$$"
VOL_GUEST_MARKER="oci-guest-volume-$$"
PROFILE_TIMEOUT="${E2E_PROFILE_TIMEOUT:-180}"

mkdir -p "$ASTERISM_HOME/images"
# Reuse an already-built store instead of re-pulling half of Docker Hub. The
# guest kernel and the blob cache are the expensive parts; the ext4 images
# rebuild in under a second from cached blobs.
# The harness's own cache, never ~/.asterism: that one belongs to the user's
# daemon and may be written to while this is reading it.
CACHE="${E2E_IMAGE_CACHE:-$(harness_cache_dir)/images}"
if [ -d "$CACHE" ]; then
  cp -R "$CACHE/kernel" "$ASTERISM_HOME/images/" 2>/dev/null || true
  cp -R "$CACHE/oci" "$ASTERISM_HOME/images/" 2>/dev/null || true
  cp "$CACHE/"oci-*.raw "$ASTERISM_HOME/images/" 2>/dev/null || true
  cp "$CACHE/"oci-*.json "$ASTERISM_HOME/images/" 2>/dev/null || true
fi

cleanup() {
  harness_keep_home "$ASTERISM_HOME" home
  # Fill the cache on the way out, so that the next run starts from the store
  # this one built. The read at the top is the other half; without this the
  # cache is a directory that is only ever copied *from*, and every run
  # re-pulls half of Docker Hub.
  if [ -d "$ASTERISM_HOME/images" ]; then
    mkdir -p "$CACHE"
    cp -R "$ASTERISM_HOME/images/." "$CACHE/" 2>/dev/null || true
  fi
  "$AST" down "$WEB" >/dev/null 2>&1 || true
  "$AST" down "$ONESHOT" >/dev/null 2>&1 || true
  "$AST" rm "$WEB" >/dev/null 2>&1 || true
  "$AST" rm "$ONESHOT" >/dev/null 2>&1 || true
  # Only what this run started. The `pkill -f` that used to be here matched
  # every astd built at this path, including a second checkout's.
  harness_reap
  rm -rf "$ASTERISM_HOME"
  harness_artifacts_note
}
trap cleanup EXIT

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
  "$AST" create "$WEB" --image nginx -p "$PORT:80" --mem 1G --disk 10G --profile base

expect "the OCI instance records its profile" "base" "$AST" profile "$WEB"

expect "status names the source" "oci rootfs, direct kernel boot" \
  "$AST" status "$WEB"
expect "status names the published port" "127.0.0.1:$PORT -> :80" \
  "$AST" status "$WEB"
expect "the image is recorded fully qualified" "docker.io/library/nginx:latest" \
  "$AST" status "$WEB"

mkdir -p "$VOL"
printf '%s\n' "$VOL_MARKER" >"$VOL/marker.txt"
expect "attach a directory to the OCI guest" "/usr/share/nginx/html/volume" \
  "$AST" attach "$WEB" --volume "$VOL" --at /usr/share/nginx/html/volume

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

expect "the generated init mounted the directory" "$VOL_MARKER" \
  curl -sS --max-time 2 "http://127.0.0.1:$PORT/volume/marker.txt"

expect "guest control writes through the mounted directory" "$VOL_GUEST_MARKER" \
  "$AST" exec "$WEB" -- /bin/sh -c \
    "printf '%s\\n' '$VOL_GUEST_MARKER' >/usr/share/nginx/html/volume/guest.txt && cat /usr/share/nginx/html/volume/guest.txt"
grep -qF "$VOL_GUEST_MARKER" "$VOL/guest.txt" \
  || fail "the guest write did not reach the host directory"
echo "ok: the host sees the guest's directory-volume write"

# OCI rootfs guests have no SSH server. Their verifier must therefore travel
# over authenticated guest control, while the profile itself treats sshd's
# keepalive as inapplicable rather than as a missing feature of the machine.
echo "waiting up to ${PROFILE_TIMEOUT}s for the OCI base profile ..."
deadline=$(( $(date +%s) + PROFILE_TIMEOUT ))
profile_report=
while :; do
  if profile_report="$("$AST" profile "$WEB" --check 2>&1)"; then break; fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "$profile_report"
    fail "the OCI base profile did not become ready"
  fi
  sleep 5
done
for needle in "ok    git" "ok    tmux" "not applicable (guest control)" \
              "this guest is ready"; do
  grep -qF "$needle" <<<"$profile_report" \
    || fail "the OCI profile verifier did not report '$needle':"$'\n'"$profile_report"
done
echo "ok: the OCI profile applies and verifies over guest control"

# The console is the whole of an OCI instance's output, so it has to carry
# the image's own startup as well as the kernel's.
expect "logs show the entrypoint" "/docker-entrypoint.sh" "$AST" logs "$WEB" -n 400
expect "logs show nginx itself" "start worker process" "$AST" logs "$WEB" -n 400

# ssh is the one thing an OCI instance cannot offer, and it says so at once
# rather than waiting three minutes for a banner.
refuse "ssh says why it cannot" "has no ssh server" "$AST" ssh "$WEB" -- true
refuse "ssh says where to look instead" "ast logs" "$AST" ssh "$WEB" -- true

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
expect "the OCI profile still verifies after restart" "this guest is ready" \
  "$AST" profile "$WEB" --check

expect "down 2" "$WEB  stopped" "$AST" down "$WEB"
expect "detach the directory" "oci-volume detached" \
  "$AST" detach "$WEB" --volume "$VOL"
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

# Honest status: the machine is off, and it stays off — a one-shot workload
# that finished is not a crash to be restarted.
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

echo "E2E-OCI GREEN (nginx served on 127.0.0.1:$PORT in ${served}s)"
