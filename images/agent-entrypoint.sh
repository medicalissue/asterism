#!/bin/sh
# Pid 1's child in an Asterism agent image.
#
# Asterism's generated init (crates/asterism-core/src/oci.rs) has already
# mounted /proc, /sys and /dev, brought the network up, installed the egress
# CA, and exported this instance's secret handles. Everything left is the
# part that is about *this* image being an agent workspace:
#
#   1. put the data volume on /work, formatting it the first time;
#   2. make the box reachable, so `ast attach` has an ssh server to talk to;
#   3. publish the instance environment to login shells, so a session started
#      by `ast attach` sees the same handles the agent does;
#   4. restart the recorded tmux session, which is what makes an agent survive
#      a reboot without anyone typing anything;
#   5. stay alive, because pid 1's child exiting powers the machine off.
#
# Nothing here holds a credential. The values that reach this guest are opaque
# handles the egress door swaps out on the way to one authority, and the raw
# key is never on this disk.
set -eu

WORK="${AST_AGENT_WORKDIR:-/work}"
STATE="$WORK/.asterism"

say() { echo "asterism-agent: $*"; }

# ---- 1. the workspace ------------------------------------------------------
#
# Two shapes, and this image takes either.
#
# A DIRECTORY share (`ast attach <name> --volume /path --at /work`, which is
# what `ast create --agent` makes) is mounted by Asterism's generated init
# before this script runs, so there is nothing to do but notice it. That is the
# common case and the one worth checking first: formatting a disk over a
# workspace that is already there would be the worst bug this file could have.
#
# A BLOCK volume arrives as a plain virtio disk with nothing on it, and the
# guest is the one that decides what it is. /dev/vda is the root Asterism built
# from this image, so the first extra disk is the workspace.
#
# Neither is not an error: the agent then works on the root disk and says so,
# which is a real thing to know before you start a week of work in it.
mount_work() {
  mkdir -p "$WORK"
  if grep -q " $WORK " /proc/mounts 2>/dev/null; then
    say "$WORK is a shared directory from the host"
    return 0
  fi
  for disk in /dev/vdb /dev/vdc /dev/vdd; do
    [ -b "$disk" ] || continue
    if ! blkid "$disk" >/dev/null 2>&1; then
      say "formatting $disk for $WORK"
      mkfs.ext4 -q -F "$disk"
    fi
    if mount "$disk" "$WORK" 2>/dev/null; then
      say "$WORK is $disk"
      return 0
    fi
  done
  say "no workspace part — $WORK is on the root disk, which a restore rewinds"
}

# ---- 2. the way in ---------------------------------------------------------
#
# `ast attach` is ssh with a tty running tmux, so this image ships an ssh
# server. It authorizes exactly one key: the host's guest key, written into
# the volume by `ast create --agent` through the authenticated guest-control
# channel. Password authentication is off and the account has no password, so
# the key is the only door.
start_sshd() {
  mkdir -p /run/sshd /root/.ssh
  chmod 0700 /root/.ssh
  if [ -f "$STATE/authorized_keys" ]; then
    cp "$STATE/authorized_keys" /root/.ssh/authorized_keys
    chmod 0600 /root/.ssh/authorized_keys
  fi
  ssh-keygen -A >/dev/null 2>&1 || true
  if /usr/sbin/sshd; then
    say "sshd is up"
  else
    say "sshd did not start — ast attach will not reach this guest"
  fi
}

# ---- 4. the session --------------------------------------------------------
#
# Started here rather than only at create time, because "the agent keeps
# running" has to mean across a reboot too. The script is the same one
# `ast create --agent` ran, and it is idempotent by construction.
restart_session() {
  if [ ! -f "$STATE/start.sh" ]; then
    say "no agent session recorded yet"
    return 0
  fi
  if sh "$STATE/start.sh"; then
    return 0
  fi
  say "the recorded agent session did not start; ast logs will say why"
}

mount_work
mkdir -p "$STATE"
start_sshd
/usr/local/sbin/asterism-agent-env
restart_session

# The one file `ast create --agent` waits for. It means more than "the machine
# booted": it means the workspace volume is mounted, so anything written under
# it lands on the volume and not on the root disk, where a restore would drop
# it without a word.
: > /run/asterism-agent.ready
say "ready"

# ---- 5. stay ---------------------------------------------------------------
#
# exec, so `ast down`'s SIGTERM reaches this process directly and the machine
# powers off promptly instead of at the end of a sleep interval.
exec sleep infinity
