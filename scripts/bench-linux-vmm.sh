#!/usr/bin/env bash
# Linux VMM bench: Cloud Hypervisor vs Firecracker, same pinned kernel, same
# pinned cloud image, same seed, on one KVM host. The evidence behind
# docs/adr/0001-linux-vmm.md (as-lvf.4).
#
# What it measures, per VMM, from the same inputs:
#   boot-to-vsock-ready   spawn of the VMM process -> a guest-initiated
#                         AF_VSOCK connection reaches the host ("ready")
#   idle RSS              VmRSS of the VMM process (plus virtiofsd where one
#                         runs) 10 s after ready
#   launch burst          wall time until every member of a concurrent OCI
#                         burst is ready, plus their summed steady-state RSS
#   artifact footprint    bytes of the binaries the product would have to ship
#   failure recovery      SIGKILL and restart with a marker on an attached
#                         writable block device surviving the failed VMM
# and then proves, or records the refusal for, each row of the matrix the
# product needs: vsock both ways, local directory sharing, local block,
# remote block (an NBD export consumed as a host block device), snapshot /
# restore, hotplug, and recovery (VMM outlives its spawner; SIGKILL leaves a
# bootable disk).
#
# Same house style as scripts/e2e*.sh: bash -euo pipefail, and every step
# asserts on the CONTENT of what came back. A refusal is a result — it is
# recorded with the exact error, never papered over.
#
# Inputs (all in $BENCH, default ~/bench):
#   base.raw        the pinned cloud image, converted to raw
#   oci.raw         the pinned workload from build-linux-vmm-oci-rootfs.sh
#   oci.manifest    its image/platform/config/module provenance
#   Image           the matching kernel, *uncompressed* arm64 Image or x86 bzImage
#   initrd          the matching initrd
#   cloud-hypervisor, ch-remote, firecracker, jailer   pinned release binaries
# Host needs: /dev/kvm rw, virtiofsd, qemu-nbd (qemu-utils), nbd-client,
# cloud-localds (cloud-image-utils), python3, sudo for nbd-client/loop.
#
# Results land in $BENCH/out/<vmm>/ and a summary in $BENCH/out/summary.txt.
set -euo pipefail

BENCH="${BENCH:-$HOME/bench}"
OUT="$BENCH/out"
ARCH="$(uname -m)"
MEM_MIB="${MEM_MIB:-1024}"
VCPUS="${VCPUS:-2}"
ROUNDS="${ROUNDS:-3}"
BURST="${BURST:-4}"
READY_TIMEOUT="${READY_TIMEOUT:-240}"
CHV="$BENCH/cloud-hypervisor"
CHR="$BENCH/ch-remote"
FC="$BENCH/firecracker"
KERNEL="$BENCH/Image"
INITRD="$BENCH/initrd"
BASE="$BENCH/base.raw"
OCI="$BENCH/oci.raw"
MODE="${1:-all}"

case "$ARCH" in
  aarch64) CHV_CONSOLE=ttyAMA0; FC_CONSOLE=ttyS0 ;;
  x86_64)  CHV_CONSOLE=ttyS0;   FC_CONSOLE=ttyS0 ;;
  *) echo "unsupported arch $ARCH" >&2; exit 1 ;;
esac

cd "$BENCH"
mkdir -p "$OUT"
: > "$OUT/summary.txt"
say() { echo "$*" | tee -a "$OUT/summary.txt"; }
now() { date +%s.%N; }
ms() { python3 -c "import sys; print(int((float(sys.argv[1])-float(sys.argv[2]))*1000))" "$1" "$2"; }

for f in "$CHV" "$CHR" "$FC" "$KERNEL" "$INITRD" "$BASE"; do
  [ -e "$f" ] || { echo "missing $f" >&2; exit 1; }
done
if [ "$MODE" = all ] || [ "$MODE" = oci ]; then
  [ -e "$OCI" ] || {
    echo "missing $OCI (build it with scripts/build-linux-vmm-oci-rootfs.sh)" >&2
    exit 1
  }
fi
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "/dev/kvm not rw" >&2
  exit 1
fi

# ---- guest side: one seed for both VMMs --------------------------------------
# cloud-init (NoCloud) drops an "agent": a python process that (1) connects
# out to the host on vsock port 5000 and says "ready", then (2) listens on
# vsock port 5001 and runs one shell line per connection. That is the whole
# control channel this bench uses, and it is the shape of the product's own
# guest control channel (as-94f.5): vsock, guest-side listener, host connects.
mkdir -p seed
make_seed() { # make_seed <instance-id>  -> $BENCH/seed.img
  printf 'instance-id: %s\nlocal-hostname: bench\n' "$1" > seed/meta-data
  rm -f seed.img; cloud-localds seed.img seed/user-data seed/meta-data
}
cat > seed/user-data <<'EOF'
#cloud-config
hostname: bench
write_files:
  - path: /usr/local/bin/bench-agent
    permissions: "0755"
    content: |
      #!/usr/bin/env python3
      import socket, subprocess, sys, time
      # 1. tell the host we are up
      for _ in range(600):
          try:
              s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
              s.connect((2, 5000)); s.sendall(b"ready\n"); s.close(); break
          except OSError:
              time.sleep(0.1)
      # 2. serve one shell line per connection
      l = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
      l.bind((socket.VMADDR_CID_ANY, 5001)); l.listen(8)
      while True:
          c, _ = l.accept()
          f = c.makefile("rwb", buffering=0)
          line = f.readline().decode().rstrip("\n")
          p = subprocess.run(line, shell=True, capture_output=True, text=True)
          out = p.stdout + p.stderr + f"\n[rc={p.returncode}]\n"
          try:
              f.write(out.encode())
          finally:
              # the makefile holds a reference: close it, then shut the
              # socket down, or the host never sees EOF
              f.close()
              try: c.shutdown(socket.SHUT_RDWR)
              except OSError: pass
              c.close()
runcmd:
  - [ sh, -c, "modprobe vmw_vsock_virtio_transport || true; nohup /usr/local/bin/bench-agent >/var/log/bench-agent.log 2>&1 &" ]
EOF
SEED_N=0

# Host side of the vsock protocol. Both VMMs speak the same one (Cloud
# Hypervisor's is derived from Firecracker's): a unix socket per VM; to
# reach guest port P the host connects and writes "CONNECT P\n" and reads
# "OK <port>\n"; a guest connect to host port P arrives on "<socket>_P".
vs_cmd() { # vs_cmd <vsock-uds> <shell line>   -> stdout
  python3 - "$1" "$2" <<'PY'
import socket, sys
uds, line = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(60)
s.connect(uds)
s.sendall(b"CONNECT 5001\n")
buf = b""
while not buf.endswith(b"\n"):
    ch = s.recv(1)
    if not ch: sys.exit("vsock: closed during CONNECT")
    buf += ch
if not buf.startswith(b"OK "): sys.exit(f"vsock: {buf!r}")
s.sendall(line.encode() + b"\n")
out = b""
while b"[rc=" not in out:          # the agent's trailer; EOF also ends it
    d = s.recv(65536)
    if not d: break
    out += d
sys.stdout.write(out.decode(errors="replace"))
PY
}

persist_agent_service() { # persist_agent_service <vsock-uds>
  vs_cmd "$1" 'printf "%s\n" "[Unit]" "After=local-fs.target" "[Service]" "ExecStartPre=-/sbin/modprobe vmw_vsock_virtio_transport" "ExecStart=/usr/local/bin/bench-agent" "Restart=always" "[Install]" "WantedBy=multi-user.target" > /etc/systemd/system/bench-agent.service; systemctl enable bench-agent.service >/dev/null; echo enabled' | head -1
}

# Listener for the guest's "ready": prints the receive time to $2 and exits.
ready_listener() { # ready_listener <vsock-uds>_5000 <stamp-file>
  # stdout must not be the caller's $(...) pipe, or the caller blocks here.
  python3 - "$1" "$2" > "$2.log" 2>&1 <<'PY' &
import os, socket, sys, time
path, stamp = sys.argv[1], sys.argv[2]
try: os.unlink(path)
except FileNotFoundError: pass
l = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); l.bind(path); l.listen(1)
c, _ = l.accept()
t = time.time()
data = c.recv(64)
open(stamp, "w").write(f"{t:.6f} {data.decode().strip()}\n")
PY
  echo $!
}

wait_ready() { # wait_ready <stamp-file> -> prints stamp time
  local i=0
  while [ ! -s "$1" ]; do
    sleep 0.05; i=$((i+1))
    [ $i -lt $((READY_TIMEOUT*20)) ] || return 1
  done
  awk '{print $1}' "$1"
}

rss_kib() { awk '/^VmRSS/{print $2}' "/proc/$1/status"; }

# One root disk for the whole run, cloned sparsely from the base once. Every
# boot gets a new cloud-init instance-id instead of a new disk, which reruns
# runcmd (the agent) without another 3.5 GB write on a host short of space.
ROOT="$BENCH/root.raw"
[ -e "$ROOT" ] || cp --reflink=auto --sparse=always "$BASE" "$ROOT"
fresh_root() { # fresh_root <ignored>  (kept for call-site readability)
  SEED_N=$((SEED_N+1)); make_seed "bench-$(date +%s%N)-$SEED_N"
}
trim() { sync; sudo fstrim / >/dev/null 2>&1 || true; }

# ---- Cloud Hypervisor --------------------------------------------------------
chv_spawn() { # chv_spawn <dir> <root.raw> [extra args...]
  local d="$1" root="$2"; shift 2
  rm -f "$d/api.sock" "$d/vsock.sock"
  # setsid: the VMM must not belong to this shell; the product's daemon will
  # restart underneath running guests.
  setsid "$CHV" --api-socket "$d/api.sock" \
    --kernel "$KERNEL" --initramfs "$INITRD" \
    --cmdline "console=$CHV_CONSOLE root=/dev/vda1 rw systemd.mask=systemd-networkd-wait-online.service" \
    --cpus "boot=$VCPUS,max=4" --memory "${CHV_MEMORY:-size=${MEM_MIB}M}" \
    --disk "path=$root,image_type=raw" --disk "path=$BENCH/seed.img,readonly=on,image_type=raw" \
    --vsock "cid=3,socket=$d/vsock.sock" \
    --serial "file=$d/serial.log" --console off \
    "$@" > "$d/${CHV_LOG:-chv.log}" 2>&1 &
  echo $!
}

bench_chv() {
  local d="$OUT/chv"; mkdir -p "$d"
  say "== Cloud Hypervisor $("$CHV" --version | head -1)"
  local r t0 t1 pid lpid
  for r in $(seq 1 "$ROUNDS"); do
    fresh_root "$ROOT"
    rm -f "$d/ready"
    lpid=$(ready_listener "$d/vsock.sock_5000" "$d/ready")
    sleep 0.2
    t0=$(now)
    pid=$(chv_spawn "$d" "$ROOT")
    t1=$(wait_ready "$d/ready") || { say "chv round $r: NO READY in ${READY_TIMEOUT}s"; tail -20 "$d/chv.log"; kill -9 "$pid" "$lpid" 2>/dev/null || true; continue; }
    local boot_ms; boot_ms=$(ms "$t1" "$t0")
    sleep 10
    local rss; rss=$(rss_kib "$pid")
    say "chv round $r: boot-to-vsock-ready ${boot_ms} ms; idle RSS ${rss} KiB (guest ${MEM_MIB} MiB, ${VCPUS} vcpu)"
    if [ "$r" -eq "$ROUNDS" ]; then CHV_PID=$pid; else "$CHR" --api-socket "$d/api.sock" shutdown-vmm; wait "$pid" 2>/dev/null || true; fi
  done
  local pid=$CHV_PID
  local api="$d/api.sock" vs="$d/vsock.sock"

  say "-- chv matrix"
  # vsock host->guest (the agent answering at all is the proof)
  say "vsock h->g: $(vs_cmd "$vs" 'uname -r; cat /etc/os-release | grep -m1 PRETTY' | head -2 | tr '\n' ' ')"
  say "persistent recovery agent: $(persist_agent_service "$vs")"
  # recovery: VMM outlives the shell that spawned it (this shell is alive, so
  # prove it the other way: the parent of the VMM is init, not us)
  say "recovery: VMM ppid=$(awk '/^PPid/{print $2}' "/proc/$pid/status") (1 = reparented, survives spawner)"

  # local directory sharing: virtiofs via virtiofsd (vhost-user) -> needs
  # shared memory, which is a *boot-time* property, so hot-add the fs onto a
  # guest that was booted with shared=on. This guest was not; record the
  # refusal, then prove the feature on a second guest booted for it.
  local fsd_out; fsd_out=$("$CHR" --api-socket "$api" add-fs "tag=share,socket=/nonexistent" 2>&1 || true)
  say "virtiofs hot-add on non-shared memory: $(echo "$fsd_out" | tail -1)"

  # local block hotplug
  rm -f "$d/extra.raw"; truncate -s 256M "$d/extra.raw"; mkfs.ext4 -q "$d/extra.raw"
  local add; add=$("$CHR" --api-socket "$api" add-disk "path=$d/extra.raw,image_type=raw,serial=localhot" 2>&1)
  say "disk hot-add: $add"
  sleep 2
  local seen; seen=$(vs_cmd "$vs" 'lsblk -dn -o NAME,SIZE | tr "\n" " "')
  say "guest lsblk after hot-add: $seen"
  if ! echo "$seen" | grep -q '256M'; then
    say "guest pci rescan + dmesg: $(vs_cmd "$vs" 'echo 1 > /sys/bus/pci/rescan; sleep 2; lsblk -dn -o NAME,SIZE | tr "\n" " "; dmesg | tail -4 | tr "\n" "|"; ls /sys/bus/pci/devices | tr "\n" " "; cat /sys/firmware/acpi/tables/APIC >/dev/null 2>&1 && echo acpi-tables-present || echo no-acpi-tables' | tr '\n' ' ')"
    seen=$(vs_cmd "$vs" 'lsblk -dn -o NAME,SIZE | tr "\n" " "')
  fi
  if echo "$seen" | grep -q '256M'; then
    say "disk hot-add: PROVEN (guest sees 256M disk)"
  else
    say "disk hot-add: NOT SEEN"
  fi
  # This command is intentionally single-quoted: it expands inside the guest.
  # shellcheck disable=SC2016
  vs_cmd "$vs" 'dev=$(readlink -f /dev/disk/by-id/virtio-localhot); mount "$dev" /mnt && echo hello-from-guest > /mnt/proof && sync && umount /mnt' | tail -1
  local dev_id; dev_id=$(echo "$add" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
  say "disk hot-remove: $("$CHR" --api-socket "$api" remove-device "$dev_id" 2>&1 || true) (removed $dev_id)"
  sleep 1
  mkdir -p "$d/m"; if sudo mount -o loop,ro "$d/extra.raw" "$d/m"; then say "host reads guest write on hot-added disk: $(cat "$d/m/proof")"; sudo umount "$d/m"; else say "host mount of hot-added disk FAILED"; fi

  # remote block: an NBD export on a unix socket, consumed by the host kernel
  # (nbd-client) and handed to the VMM as a plain block device. This is the
  # DiskSpec::NbdUnix shape: the VMM never sees NBD.
  rm -f "$d/remote.raw"; truncate -s 256M "$d/remote.raw"; mkfs.ext4 -q "$d/remote.raw"
  sudo modprobe nbd max_part=8
  qemu-nbd --socket="$d/nbd.sock" --format=raw --export-name=vol "$d/remote.raw" &
  local nbd_pid=$!; sleep 0.5
  sudo nbd-client -unix "$d/nbd.sock" -name vol /dev/nbd0 >/dev/null
  sudo chmod 666 /dev/nbd0
  add=$("$CHR" --api-socket "$api" add-disk "path=/dev/nbd0,image_type=raw,serial=remotevol" 2>&1)
  say "remote(NBD-over-unix) block hot-add as /dev/nbd0: $add"
  sleep 2
  say "guest remote block discovery: $(vs_cmd "$vs" 'echo 1 > /sys/bus/pci/rescan; sleep 2; readlink -f /dev/disk/by-id/virtio-remotevol' | tr '\n' ' ')"
  # shellcheck disable=SC2016 # expands inside the guest
  say "guest writes to remote block: $(vs_cmd "$vs" 'dev=$(readlink -f /dev/disk/by-id/virtio-remotevol); mount "$dev" /mnt && echo via-nbd > /mnt/proof && sync && umount /mnt && echo ok' | tr '\n' ' ')"
  dev_id=$(echo "$add" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
  "$CHR" --api-socket "$api" remove-device "$dev_id" >/dev/null 2>&1 || true
  sleep 1; sudo nbd-client -d /dev/nbd0 >/dev/null; kill "$nbd_pid" 2>/dev/null || true; wait "$nbd_pid" 2>/dev/null || true
  if sudo mount -o loop,ro "$d/remote.raw" "$d/m"; then say "provider side sees guest write through NBD: $(cat "$d/m/proof")"; sudo umount "$d/m"; else say "provider-side mount of NBD-backed disk FAILED"; fi

  # cpu / memory resize on a guest booted without hotplug_size: record the
  # refusal — the real test is on the second guest.
  say "cpu resize (no max headroom case is boot=$VCPUS,max=4): $("$CHR" --api-socket "$api" resize --cpus 3 2>&1 || true)"
  sleep 2
  say "guest nproc after cpu resize: $(vs_cmd "$vs" 'nproc' | head -1)"
  say "memory resize without hotplug_size: $("$CHR" --api-socket "$api" resize --memory 2048M 2>&1 || true)"

  # snapshot / restore: pause, snapshot, kill the VMM, restore in a new one,
  # prove the guest continued (a counter written before the snapshot).
  vs_cmd "$vs" 'echo 41 > /root/counter; sync' >/dev/null
  rm -rf "$d/snap"; mkdir -p "$d/snap"
  "$CHR" --api-socket "$api" pause
  local ts0; ts0=$(now)
  "$CHR" --api-socket "$api" snapshot "file://$d/snap"
  say "snapshot took $(ms "$(now)" "$ts0") ms; files: $(find "$d/snap" -maxdepth 1 -type f -printf '%f=%s\n' | sort | tr '\n' ' ')"
  "$CHR" --api-socket "$api" shutdown-vmm; wait "$pid" 2>/dev/null || true
  rm -f "$api" "$vs"
  ts0=$(now)
  setsid "$CHV" --api-socket "$api" --restore "source_url=file://$d/snap" > "$d/chv-restore.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 200); do [ -S "$api" ] && break; sleep 0.05; done
  "$CHR" --api-socket "$api" resume
  local tr; tr=$(ms "$(now)" "$ts0")
  local after; after=$(vs_cmd "$vs" 'cat /root/counter; uptime -p' | head -2 | tr '\n' ' ')
  say "restore+resume ${tr} ms; guest after restore: $after"
  if echo "$after" | grep -q '^41'; then
    say "snapshot/restore: PROVEN"
  else
    say "snapshot/restore: FAILED"
  fi
  rm -rf "$d/snap"; trim

  # recovery from SIGKILL: the disk must boot again.
  kill -9 "$pid"; wait "$pid" 2>/dev/null || true
  sleep 1
  fresh_root "$ROOT"
  rm -f "$d/ready"; lpid=$(ready_listener "$d/vsock.sock_5000" "$d/ready"); sleep 0.2
  rm -f "$api" "$vs"
  t0=$(now); pid=$(CHV_LOG=chv-reboot.log chv_spawn "$d" "$ROOT")
  if t1=$(wait_ready "$d/ready"); then say "reboot after SIGKILL: PROVEN, ready in $(ms "$t1" "$t0") ms; counter=$(vs_cmd "$vs" 'cat /root/counter' | head -1)"; else say "reboot after SIGKILL: FAILED: $(tail -3 "$d/chv-reboot.log" | tr '\n' ' ') serial: $(tail -c 300 "$d/serial.log" | tr '\n' ' ')"; fi
  "$CHR" --api-socket "$api" shutdown-vmm; wait "$pid" 2>/dev/null || true

  # second guest: shared memory + virtiofs + hotplug headroom + landlock
  say "-- chv guest 2: shared memory, virtiofs, memory hotplug, landlock"
  mkdir -p "$d/share"; echo host-wrote-this > "$d/share/from-host"
  rm -f "$d/fs.sock"
  /usr/libexec/virtiofsd --socket-path="$d/fs.sock" --shared-dir="$d/share" --cache=never --sandbox=none > "$d/virtiofsd.log" 2>&1 &
  local fsd=$!; sleep 0.5
  fresh_root "$ROOT"; rm -f "$d/ready"; rm -f "$api" "$vs"
  lpid=$(ready_listener "$d/vsock.sock_5000" "$d/ready"); sleep 0.2
  t0=$(now)
  pid=$(CHV_MEMORY="size=${MEM_MIB}M,shared=on,hotplug_size=2048M" CHV_LOG=chv-guest2.log chv_spawn "$d" "$ROOT" --fs "tag=share,socket=$d/fs.sock" --landlock --landlock-rules "path=$d,access=rw" "path=$BENCH,access=rw")
  if t1=$(wait_ready "$d/ready"); then
    say "guest2 (shared=on, virtiofs, landlock) ready in $(ms "$t1" "$t0") ms; RSS VMM $(rss_kib "$pid") KiB + virtiofsd $(rss_kib "$fsd") KiB"
    say "virtiofs mount: $(vs_cmd "$vs" 'mkdir -p /mnt/s && mount -t virtiofs share /mnt/s && cat /mnt/s/from-host && echo guest-wrote-this > /mnt/s/from-guest && echo mounted' | tr '\n' ' ')"
    say "host sees guest write via virtiofs: $(cat "$d/share/from-guest" 2>&1)"
    say "memory hot-add: $("$CHR" --api-socket "$api" resize --memory 2048M 2>&1 || true)"
    sleep 3
    # shellcheck disable=SC2016 # expands inside the guest
    say "guest MemTotal after hot-add (was ~${MEM_MIB} MiB): $(vs_cmd "$vs" 'modprobe virtio_mem || true; for state in /sys/devices/system/memory/memory*/state; do [ "$(cat "$state")" = offline ] && echo online > "$state" || true; done; grep MemTotal /proc/meminfo' | grep MemTotal | tail -1)"
    say "cpu hot-add on $ARCH: $("$CHR" --api-socket "$api" resize --cpus 4 2>&1 || true)"; sleep 2
    say "guest nproc: $(vs_cmd "$vs" 'nproc' | head -1)"
    say "vm.info hotplugged: $(curl -s --unix-socket "$api" http://localhost/api/v1/vm.info | python3 -c 'import sys,json; c=json.load(sys.stdin); print("cpus",c["config"]["cpus"],"mem",c["config"]["memory"]["size"],"hotplug_size",c["config"]["memory"]["hotplug_size"])')"
  else
    say "guest2: NO READY: $(tail -5 "$d/chv-guest2.log" | tr '\n' ' ')"
  fi
  "$CHR" --api-socket "$api" shutdown-vmm 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  kill "$fsd" 2>/dev/null || true
  say "seccomp: on by default ($("$CHV" --help | grep -A1 -- '--seccomp' | tr -s ' \n' ' ' | cut -c1-120))"
}

# ---- Firecracker -------------------------------------------------------------
fc_config() { # fc_config <dir> <root.raw> <out.json> [memhotplug:0/1]
  local d="$1" root="$2" out="$3" mh="${4:-0}"
  python3 - "$d" "$root" "$out" "$BENCH" "$KERNEL" "$INITRD" "$FC_CONSOLE" "$VCPUS" "$MEM_MIB" "$mh" <<'PY'
import json, sys
d, root, out, bench, kernel, initrd, con, vcpus, mem, mh = sys.argv[1:]
cfg = {
  "boot-source": {"kernel_image_path": kernel, "initrd_path": initrd,
                  "boot_args": f"console={con} root=/dev/vda1 rw systemd.mask=systemd-networkd-wait-online.service"},
  "drives": [
    # False is deliberate: when true Firecracker appends root=/dev/vda to the
    # cmdline, overriding the partitioned cloud image's root=/dev/vda1.
    {"drive_id": "rootfs", "path_on_host": root, "is_root_device": False, "is_read_only": False},
    {"drive_id": "seed", "path_on_host": f"{bench}/seed.img", "is_root_device": False, "is_read_only": True}],
  "machine-config": {"vcpu_count": int(vcpus), "mem_size_mib": int(mem)},
  "vsock": {"guest_cid": 3, "uds_path": f"{d}/vsock.sock"},
}
if mh == "1":
    cfg["memory-hotplug"] = {"total_size_mib": 2048}
json.dump(cfg, open(out, "w"), indent=1)
PY
}

fc_api() { # fc_api <api.sock> <METHOD> <path> [json]
  local s="$1" m="$2" p="$3" body="${4:-}"
  if [ -n "$body" ]; then
    curl -s -X "$m" --unix-socket "$s" -H 'Content-Type: application/json' -d "$body" "http://localhost$p" -w ' [http %{http_code}]'
  else
    curl -s -X "$m" --unix-socket "$s" "http://localhost$p" -w ' [http %{http_code}]'
  fi
  echo
}

fc_spawn() { # fc_spawn <dir> <config.json> [extra fc args]
  local d="$1" cfg="$2"; shift 2
  rm -f "$d/api.sock" "$d/vsock.sock"
  setsid "$FC" --api-sock "$d/api.sock" --config-file "$cfg" "$@" > "$d/serial.log" 2>&1 &
  echo $!
}

bench_fc() {
  local d="$OUT/fc"; mkdir -p "$d"
  say "== Firecracker $("$FC" --version | head -1)"
  local r t0 t1 pid lpid
  for r in $(seq 1 "$ROUNDS"); do
    fresh_root "$ROOT"; rm -f "$d/ready"
    fc_config "$d" "$ROOT" "$d/cfg.json"
    lpid=$(ready_listener "$d/vsock.sock_5000" "$d/ready"); sleep 0.2
    t0=$(now)
    pid=$(fc_spawn "$d" "$d/cfg.json")
    t1=$(wait_ready "$d/ready") || { say "fc round $r: NO READY in ${READY_TIMEOUT}s"; tail -20 "$d/serial.log"; kill -9 "$pid" "$lpid" 2>/dev/null || true; continue; }
    local boot_ms; boot_ms=$(ms "$t1" "$t0")
    sleep 10
    say "fc round $r: boot-to-vsock-ready ${boot_ms} ms; idle RSS $(rss_kib "$pid") KiB (guest ${MEM_MIB} MiB, ${VCPUS} vcpu)"
    if [ "$r" -eq "$ROUNDS" ]; then FC_PID=$pid; else fc_api "$d/api.sock" PUT /actions '{"action_type":"SendCtrlAltDel"}' >/dev/null; sleep 3; kill -9 "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  local pid=$FC_PID api="$d/api.sock" vs="$d/vsock.sock"

  say "-- fc matrix"
  say "vsock h->g: $(vs_cmd "$vs" 'uname -r; grep -m1 PRETTY /etc/os-release' | head -2 | tr '\n' ' ')"
  say "persistent recovery agent: $(persist_agent_service "$vs")"
  say "recovery: VMM ppid=$(awk '/^PPid/{print $2}' "/proc/$pid/status") (1 = reparented, survives spawner)"
  say "virtiofs / directory sharing: no such device in the Firecracker device model (docs/device-api.md; #1180 'not on our roadmap')"

  # block hot-add WITHOUT --enable-pci (the default transport, MMIO)
  rm -f "$d/extra.raw"; truncate -s 256M "$d/extra.raw"; mkfs.ext4 -q "$d/extra.raw"
  say "disk hot-add on MMIO transport (default): $(fc_api "$api" PUT /drives/extra "{\"drive_id\":\"extra\",\"path_on_host\":\"$d/extra.raw\",\"is_root_device\":false,\"is_read_only\":false}")"
  # PATCH of an existing drive's backing file is what FC offers post-boot
  say "drive PATCH (path swap of existing 'seed'): $(fc_api "$api" PATCH /drives/seed "{\"drive_id\":\"seed\",\"path_on_host\":\"$BENCH/seed.img\"}")"
  say "memory hot-add without pre-boot hotplug config: $(fc_api "$api" PATCH /hotplug/memory '{"requested_size_mib":1024}')"
  say "cpu hot-add: no API (machine-config is pre-boot only): $(fc_api "$api" PATCH /machine-config '{"vcpu_count":3}')"

  # remote block via the same NBD-over-unix -> /dev/nbd0 path, pre-boot, on
  # guest 2 below. Snapshot first on this guest.
  vs_cmd "$vs" 'echo 41 > /root/counter; sync' >/dev/null
  rm -rf "$d/snap"; mkdir -p "$d/snap"
  fc_api "$api" PATCH /vm '{"state":"Paused"}' >/dev/null
  local ts0; ts0=$(now)
  say "snapshot: $(fc_api "$api" PUT /snapshot/create "{\"snapshot_type\":\"Full\",\"snapshot_path\":\"$d/snap/state\",\"mem_file_path\":\"$d/snap/mem\"}") in $(ms "$(now)" "$ts0") ms; files: $(find "$d/snap" -maxdepth 1 -type f -printf '%f=%s\n' | sort | tr '\n' ' ')"
  kill -9 "$pid"; wait "$pid" 2>/dev/null || true
  rm -f "$api" "$vs"
  ts0=$(now)
  setsid "$FC" --api-sock "$api" > "$d/serial-restore.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 200); do [ -S "$api" ] && break; sleep 0.05; done
  say "restore: $(fc_api "$api" PUT /snapshot/load "{\"snapshot_path\":\"$d/snap/state\",\"mem_backend\":{\"backend_type\":\"File\",\"backend_path\":\"$d/snap/mem\"},\"resume_vm\":true}") in $(ms "$(now)" "$ts0") ms"
  sleep 1
  local after; after=$(vs_cmd "$vs" 'cat /root/counter; uptime -p' | head -2 | tr '\n' ' ')
  say "guest after restore: $after"
  if echo "$after" | grep -q '^41'; then
    say "snapshot/restore: PROVEN"
  else
    say "snapshot/restore: FAILED"
  fi
  rm -rf "$d/snap"; trim

  kill -9 "$pid"; wait "$pid" 2>/dev/null || true; sleep 1
  fresh_root "$ROOT"
  rm -f "$d/ready" "$api" "$vs"
  lpid=$(ready_listener "$d/vsock.sock_5000" "$d/ready"); sleep 0.2
  fc_config "$d" "$ROOT" "$d/cfg.json"
  t0=$(now); pid=$(fc_spawn "$d" "$d/cfg.json")
  if t1=$(wait_ready "$d/ready"); then say "reboot after SIGKILL: PROVEN, ready in $(ms "$t1" "$t0") ms; counter=$(vs_cmd "$vs" 'cat /root/counter' | head -1)"; else say "reboot after SIGKILL: FAILED"; fi
  kill -9 "$pid"; wait "$pid" 2>/dev/null || true

  # guest 2: --enable-pci (hotplug developer preview) + memory hotplug + NBD
  say "-- fc guest 2: --enable-pci, virtio-mem, remote block"
  rm -f "$d/remote.raw"; truncate -s 256M "$d/remote.raw"; mkfs.ext4 -q "$d/remote.raw"
  sudo modprobe nbd max_part=8
  qemu-nbd --socket="$d/nbd.sock" --format=raw --export-name=vol "$d/remote.raw" &
  local nbd_pid=$!; sleep 0.5
  sudo nbd-client -unix "$d/nbd.sock" -name vol /dev/nbd0 >/dev/null; sudo chmod 666 /dev/nbd0
  fresh_root "$ROOT"; rm -f "$d/ready" "$api" "$vs"
  fc_config "$d" "$ROOT" "$d/cfg2.json" 1
  python3 - "$d/cfg2.json" <<'PY'
import json, sys
p = sys.argv[1]; c = json.load(open(p))
c["drives"].append({"drive_id": "remote", "path_on_host": "/dev/nbd0", "is_root_device": False, "is_read_only": False})
json.dump(c, open(p, "w"), indent=1)
PY
  lpid=$(ready_listener "$d/vsock.sock_5000" "$d/ready"); sleep 0.2
  t0=$(now); pid=$(fc_spawn "$d" "$d/cfg2.json" --enable-pci)
  if t1=$(wait_ready "$d/ready"); then
    say "guest2 (pci, virtio-mem headroom 2048M, /dev/nbd0 drive) ready in $(ms "$t1" "$t0") ms; RSS $(rss_kib "$pid") KiB"
    say "guest lsblk: $(vs_cmd "$vs" 'lsblk -dn -o NAME,SIZE | tr "\n" " "' | head -1)"
    say "guest writes to remote(NBD) block: $(vs_cmd "$vs" 'mount /dev/vdc /mnt && echo via-nbd > /mnt/proof && sync && umount /mnt && echo ok' | tr '\n' ' ')"
    say "disk hot-add on PCI (dev preview): $(fc_api "$api" PUT /drives/extra "{\"drive_id\":\"extra\",\"path_on_host\":\"$d/extra.raw\",\"is_root_device\":false,\"is_read_only\":false}")"
    sleep 1
    say "guest after pci rescan: $(vs_cmd "$vs" 'echo 1 > /sys/bus/pci/rescan; sleep 1; lsblk -dn -o NAME,SIZE | tr "\n" " "' | head -1)"
    say "memory hot-add (virtio-mem) to 2048: $(fc_api "$api" PATCH /hotplug/memory '{"requested_size_mib":1024}')"
    sleep 3
    # shellcheck disable=SC2016 # expands inside the guest
    say "guest MemTotal after hot-add (was ~${MEM_MIB} MiB): $(vs_cmd "$vs" 'modprobe virtio_mem || true; for state in /sys/devices/system/memory/memory*/state; do [ "$(cat "$state")" = offline ] && echo online > "$state" || true; done; grep MemTotal /proc/meminfo' | grep MemTotal | tail -1)"
    say "hotplug/memory status: $(fc_api "$api" GET /hotplug/memory)"
  else
    say "guest2: NO READY"; tail -20 "$d/serial.log"
  fi
  kill -9 "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  sleep 1; sudo nbd-client -d /dev/nbd0 >/dev/null; kill "$nbd_pid" 2>/dev/null || true; wait "$nbd_pid" 2>/dev/null || true
  mkdir -p "$d/m"; if sudo mount -o loop,ro "$d/remote.raw" "$d/m"; then say "provider side sees guest write through NBD: $(cat "$d/m/proof" 2>&1)"; sudo umount "$d/m"; else say "provider-side mount of NBD-backed disk FAILED"; fi
  say "seccomp: on by default; jailer needs root (docs/jailer.md) and copies/hard-links every drive into its chroot"
}

# ---- identical OCI workload -------------------------------------------------
# oci.raw is built from the pinned python:3.12-alpine manifest by the companion
# builder. Its init mounts the minimum pseudo-filesystems, loads the Ubuntu
# kernel's vsock transport, and starts the same Python ready agent on both VMMs.
# The root is read-only so every round consumes byte-identical input.
chv_oci_spawn() { # chv_oci_spawn <dir> [extra Cloud Hypervisor args...]
  local d="$1"
  shift
  rm -f "$d/api.sock" "$d/vsock.sock"
  setsid "$CHV" --api-socket "$d/api.sock" \
    --kernel "$KERNEL" --initramfs "$INITRD" \
    --cmdline "console=$CHV_CONSOLE root=/dev/vda ro init=/sbin/asterism-bench-init panic=1" \
    --cpus "boot=$VCPUS,max=$VCPUS" --memory "size=${MEM_MIB}M" \
    --disk "path=$OCI,readonly=on,image_type=raw" \
    --vsock "cid=3,socket=$d/vsock.sock" \
    --serial "file=$d/serial.log" --console off \
    "$@" \
    > "$d/chv.log" 2>&1 &
  echo $!
}

fc_oci_config() { # fc_oci_config <dir> <out.json> [writable-data-disk]
  local d="$1" out="$2" data="${3:-}"
  python3 - "$d" "$out" "$KERNEL" "$INITRD" "$FC_CONSOLE" "$VCPUS" "$MEM_MIB" "$OCI" "$data" <<'PY'
import json, sys
d, out, kernel, initrd, con, vcpus, mem, root, data = sys.argv[1:]
cfg = {
  "boot-source": {"kernel_image_path": kernel, "initrd_path": initrd,
                  "boot_args": f"console={con} root=/dev/vda ro init=/sbin/asterism-bench-init panic=1"},
  "drives": [{"drive_id": "rootfs", "path_on_host": root,
              "is_root_device": True, "is_read_only": True}],
  "machine-config": {"vcpu_count": int(vcpus), "mem_size_mib": int(mem)},
  "vsock": {"guest_cid": 3, "uds_path": f"{d}/vsock.sock"},
}
if data:
    cfg["drives"].append({"drive_id": "data", "path_on_host": data,
                          "is_root_device": False, "is_read_only": False})
json.dump(cfg, open(out, "w"), indent=1)
PY
}

stop_oci_vmm() { # stop_oci_vmm <vmm> <dir> <pid>
  local vmm="$1" d="$2" pid="$3"
  if [ "$vmm" = chv ] && [ -S "$d/api.sock" ]; then
    "$CHR" --api-socket "$d/api.sock" shutdown-vmm >/dev/null 2>&1 || true
  fi
  sleep 0.2
  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

bench_oci_burst() {
  local vmm="$1" d="$OUT/oci/burst-$1" i t0 t1 pid lpid total_rss=0
  local -a pids=() listeners=()
  rm -rf "$d"
  mkdir -p "$d"
  t0=$(now)
  for i in $(seq 1 "$BURST"); do
    mkdir -p "$d/$i"
    lpid=$(ready_listener "$d/$i/vsock.sock_5000" "$d/$i/ready")
    listeners+=("$lpid")
    if [ "$vmm" = chv ]; then
      pid=$(chv_oci_spawn "$d/$i")
    else
      fc_oci_config "$d/$i" "$d/$i/cfg.json"
      pid=$(fc_spawn "$d/$i" "$d/$i/cfg.json")
    fi
    pids+=("$pid")
  done
  for i in $(seq 1 "$BURST"); do
    if ! wait_ready "$d/$i/ready" >/dev/null; then
      say "oci $vmm burst: instance $i NOT READY in ${READY_TIMEOUT}s"
      for pid in "${pids[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
      for lpid in "${listeners[@]}"; do kill "$lpid" 2>/dev/null || true; done
      return 1
    fi
  done
  t1=$(awk 'BEGIN { m=0 } { if ($1 > m) m=$1 } END { printf "%.6f", m }' "$d"/*/ready)
  sleep 10
  for pid in "${pids[@]}"; do total_rss=$((total_rss + $(rss_kib "$pid"))); done
  for i in $(seq 1 "$BURST"); do
    say "oci $vmm burst workload $i: $(vs_cmd "$d/$i/vsock.sock" 'python3 -c "print(6 * 7)"' | head -1)"
  done
  say "oci $vmm launch burst: count=$BURST all-ready=$(ms "$t1" "$t0") ms; summed idle RSS=$total_rss KiB; runtime files=$(du -sk "$d" | awk '{print $1}') KiB"
  for i in $(seq 1 "$BURST"); do stop_oci_vmm "$vmm" "$d/$i" "${pids[$((i-1))]}"; done
  for lpid in "${listeners[@]}"; do wait "$lpid" 2>/dev/null || true; done
}

bench_oci_recovery() {
  local vmm="$1" d="$OUT/oci/recovery-$1" pid lpid t0 t1 after
  rm -rf "$d"
  mkdir -p "$d"
  truncate -s 64M "$d/data.raw"
  mkfs.ext4 -q -F "$d/data.raw"
  rm -f "$d/ready"
  lpid=$(ready_listener "$d/vsock.sock_5000" "$d/ready")
  sleep 0.2
  if [ "$vmm" = chv ]; then
    pid=$(chv_oci_spawn "$d" --disk "path=$d/data.raw,image_type=raw")
  else
    fc_oci_config "$d" "$d/cfg.json" "$d/data.raw"
    pid=$(fc_spawn "$d" "$d/cfg.json")
  fi
  if ! wait_ready "$d/ready" >/dev/null; then
    say "oci $vmm recovery: initial boot NOT READY in ${READY_TIMEOUT}s"
    kill -9 "$pid" "$lpid" 2>/dev/null || true
    return 1
  fi
  after=$(vs_cmd "$d/vsock.sock" 'mkdir -p /mnt; mount /dev/vdb /mnt && echo survived-vmm-crash > /mnt/marker && sync && umount /mnt && echo written' | head -1)
  [ "$after" = written ] || { say "oci $vmm recovery: marker write FAILED ($after)"; stop_oci_vmm "$vmm" "$d" "$pid"; return 1; }
  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f "$d/ready"
  lpid=$(ready_listener "$d/vsock.sock_5000" "$d/ready")
  sleep 0.2
  t0=$(now)
  if [ "$vmm" = chv ]; then
    pid=$(chv_oci_spawn "$d" --disk "path=$d/data.raw,image_type=raw")
  else
    fc_oci_config "$d" "$d/cfg.json" "$d/data.raw"
    pid=$(fc_spawn "$d" "$d/cfg.json")
  fi
  if ! t1=$(wait_ready "$d/ready"); then
    say "oci $vmm failure recovery: restart NOT READY in ${READY_TIMEOUT}s"
    kill -9 "$pid" "$lpid" 2>/dev/null || true
    return 1
  fi
  after=$(vs_cmd "$d/vsock.sock" 'mkdir -p /mnt; mount /dev/vdb /mnt && cat /mnt/marker && umount /mnt' | head -1)
  if [ "$after" = survived-vmm-crash ]; then
    say "oci $vmm failure recovery: PROVEN, ready in $(ms "$t1" "$t0") ms; block marker=$after; data disk=$(stat -c %s "$d/data.raw") B"
  else
    say "oci $vmm failure recovery: FAILED, block marker=$after"
    stop_oci_vmm "$vmm" "$d" "$pid"
    return 1
  fi
  stop_oci_vmm "$vmm" "$d" "$pid"
  wait "$lpid" 2>/dev/null || true
}

report_oci_gate() {
  python3 - "$OUT/summary.txt" <<'PY' | tee -a "$OUT/summary.txt"
import re
import statistics
import sys

text = open(sys.argv[1], encoding="utf-8").read()
samples = {}
for vmm in ("chv", "fc"):
    rows = re.findall(
        rf"^oci {vmm} round \d+: boot-to-vsock-ready (\d+) ms; idle RSS (\d+) KiB",
        text,
        re.MULTILINE,
    )
    if not rows:
        raise SystemExit(f"no completed OCI rounds for {vmm}")
    samples[vmm] = ([int(row[0]) for row in rows], [int(row[1]) for row in rows])

chv_boot = statistics.median(samples["chv"][0])
fc_boot = statistics.median(samples["fc"][0])
chv_rss = statistics.median(samples["chv"][1])
fc_rss = statistics.median(samples["fc"][1])
boot_delta = (fc_boot / chv_boot - 1) * 100
rss_saving = (1 - fc_rss / chv_rss) * 100
boot_pass = fc_boot <= chv_boot * 0.70
rss_pass = fc_rss <= chv_rss * 0.60
decision = "PASS" if boot_pass or rss_pass else "REJECT"
print(
    f"== OCI PERFORMANCE GATE: {decision}; median ready chv={chv_boot:g} ms "
    f"fc={fc_boot:g} ms ({boot_delta:+.1f}%); median idle RSS chv={chv_rss:g} KiB "
    f"fc={fc_rss:g} KiB ({rss_saving:.1f}% lower); requires >=30% faster OR >=40% lower"
)
PY
}

bench_oci() {
  local d="$OUT/oci"; mkdir -p "$d/chv" "$d/fc"
  say "== identical OCI workload: $(cat "$BENCH/oci.manifest")"
  say "oci.rootfs: $(stat -c %s "$OCI") B sha256 $(sha256sum "$OCI" | cut -c1-16)…; read-only; init=/sbin/asterism-bench-init"
  local vmm r vd t0 t1 pid lpid boot_ms
  for vmm in chv fc; do
    vd="$d/$vmm"
    for r in $(seq 1 "$ROUNDS"); do
      rm -f "$vd/ready"
      lpid=$(ready_listener "$vd/vsock.sock_5000" "$vd/ready"); sleep 0.2
      t0=$(now)
      if [ "$vmm" = chv ]; then
        pid=$(chv_oci_spawn "$vd")
      else
        fc_oci_config "$vd" "$vd/cfg.json"
        pid=$(fc_spawn "$vd" "$vd/cfg.json")
      fi
      if ! t1=$(wait_ready "$vd/ready"); then
        say "oci $vmm round $r: NO READY in ${READY_TIMEOUT}s"
        tail -20 "$vd/serial.log" || true
        kill -9 "$pid" "$lpid" 2>/dev/null || true
        continue
      fi
      boot_ms=$(ms "$t1" "$t0")
      sleep 10
      say "oci $vmm round $r: boot-to-vsock-ready ${boot_ms} ms; idle RSS $(rss_kib "$pid") KiB (guest ${MEM_MIB} MiB, ${VCPUS} vcpu)"
      say "oci $vmm workload: $(vs_cmd "$vd/vsock.sock" 'python3 -c "print(6 * 7)"' | head -1)"
      if [ "$vmm" = chv ]; then
        "$CHR" --api-socket "$vd/api.sock" shutdown-vmm >/dev/null 2>&1 || true
      else
        fc_api "$vd/api.sock" PUT /actions '{"action_type":"SendCtrlAltDel"}' >/dev/null || true
        sleep 1
        kill -9 "$pid" 2>/dev/null || true
      fi
      wait "$pid" 2>/dev/null || true
    done
    bench_oci_burst "$vmm"
    bench_oci_recovery "$vmm"
  done
  report_oci_gate
}

# ---- footprint ---------------------------------------------------------------
say "== host: $(uname -srm); $(grep -m1 PRETTY /etc/os-release); nested=$(systemd-detect-virt 2>/dev/null || echo ?); kvm=$(stat -c %A /dev/kvm)"
say "== inputs: base.raw $(stat -c %s "$BASE") B sha256 $(sha256sum "$BASE" | cut -c1-16)…; Image $(stat -c %s "$KERNEL") B; initrd $(stat -L -c %s "$INITRD") B"
say "== artifacts: cloud-hypervisor $(stat -L -c %s "$CHV") B, ch-remote $(stat -L -c %s "$CHR") B, virtiofsd $(stat -c %s /usr/libexec/virtiofsd) B ($(dpkg-query -W -f='${Version}' virtiofsd)); firecracker $(stat -L -c %s "$FC") B, jailer $(stat -L -c %s "$BENCH/jailer") B"
say "== OCI common disk: rootfs $(stat -c %s "$OCI" 2>/dev/null || echo absent) B, kernel $(stat -c %s "$KERNEL") B, initrd $(stat -L -c %s "$INITRD") B; VMM shipped bytes: chv $(stat -L -c %s "$CHV") B, firecracker+jailer $(( $(stat -L -c %s "$FC") + $(stat -L -c %s "$BENCH/jailer") )) B"

case "$MODE" in
  chv) bench_chv ;;
  fc) bench_fc ;;
  oci) bench_oci ;;
  all) bench_chv; bench_fc; bench_oci ;;
  *) echo "usage: $0 {all|chv|fc|oci}" >&2; exit 2 ;;
esac
say "== done; raw logs under $OUT"
