#!/usr/bin/env bash
# Build the byte-identical OCI workload used by bench-linux-vmm.sh from a
# pinned multi-arch index. The current evidence host is linux/arm64; update the
# platform manifest pin deliberately before using another architecture.
set -euo pipefail

BENCH="${BENCH:-$HOME/bench}"
INDEX_DIGEST="sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31"
ARM64_MANIFEST="sha256:c95cd47204b8f236725fc8cf94726abe3f32755a062393597efadd9a5d24fbe1"
IMAGE="docker.io/library/python@$INDEX_DIGEST"
PLATFORM="linux/arm64"

[ "$(uname -m)" = aarch64 ] || {
  echo "this evidence pin is for aarch64; pin the target platform manifest first" >&2
  exit 1
}
[ -e "$BENCH/base.raw" ] || { echo "missing $BENCH/base.raw" >&2; exit 1; }

tmp=$(mktemp -d "$BENCH/oci-build.XXXXXX")
root="$tmp/rootfs"
container="asterism-oci-bench-$$"
loop=""
mounted=0
cleanup() {
  nerdctl container rm -f "$container" >/dev/null 2>&1 || true
  if [ "$mounted" -eq 1 ]; then sudo umount "$tmp/cloud" >/dev/null 2>&1 || true; fi
  if [ -n "$loop" ]; then sudo losetup -d "$loop" >/dev/null 2>&1 || true; fi
  sudo rm -rf "$tmp"
}
trap cleanup EXIT

nerdctl pull --quiet --platform "$PLATFORM" "$IMAGE"
nerdctl container create --name "$container" --platform "$PLATFORM" "$IMAGE" /bin/true >/dev/null
nerdctl container export -o "$tmp/rootfs.tar" "$container"
mkdir -p "$root"
sudo tar --numeric-owner -xf "$tmp/rootfs.tar" -C "$root"

# Asterism's OCI builder uses the matching Ubuntu cloud kernel/initrd. Copy the
# matching module tree from that pinned cloud image so the vsock transport can
# load after switch_root, exactly as a production OCI rootfs must arrange.
mkdir -p "$tmp/cloud"
loop=$(sudo losetup --find --show --partscan "$BENCH/base.raw")
sudo mount -o ro "${loop}p1" "$tmp/cloud"
mounted=1
kernel_release=$(uname -r)
[ -d "$tmp/cloud/lib/modules/$kernel_release" ] || {
  echo "cloud image has no module tree for host-matching kernel $kernel_release" >&2
  exit 1
}
sudo mkdir -p "$root/lib/modules"
sudo cp -a "$tmp/cloud/lib/modules/$kernel_release" "$root/lib/modules/"
sudo umount "$tmp/cloud"
mounted=0
sudo losetup -d "$loop"
loop=""

sudo tee "$root/usr/local/bin/bench-agent" >/dev/null <<'PY'
#!/usr/bin/env python3
import socket
import subprocess
import time

for _ in range(600):
    try:
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.connect((2, 5000))
        sock.sendall(b"ready\n")
        sock.close()
        break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("vsock ready timeout")

listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
listener.bind((socket.VMADDR_CID_ANY, 5001))
listener.listen(8)
while True:
    conn, _ = listener.accept()
    stream = conn.makefile("rwb", buffering=0)
    line = stream.readline().decode().rstrip("\n")
    proc = subprocess.run(line, shell=True, capture_output=True, text=True)
    stream.write((proc.stdout + proc.stderr + f"\n[rc={proc.returncode}]\n").encode())
    stream.close()
    conn.close()
PY
sudo chmod 0755 "$root/usr/local/bin/bench-agent"

sudo tee "$root/sbin/asterism-bench-init" >/dev/null <<'SH'
#!/bin/sh
export PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
export PYTHONDONTWRITEBYTECODE=1
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /run /tmp
mount -t tmpfs tmpfs /run
modprobe vmw_vsock_virtio_transport 2>/dev/null || true
exec /usr/local/bin/bench-agent
SH
sudo chmod 0755 "$root/sbin/asterism-bench-init"

sudo mke2fs -q -F -t ext4 -b 4096 -E root_owner=0:0 -L asterism \
  -d "$root" "$tmp/oci.raw" 768M
sudo chown "$(id -u):$(id -g)" "$tmp/oci.raw"
mv "$tmp/oci.raw" "$BENCH/oci.raw"
config_digest=$(nerdctl image inspect docker.io/library/python:3.12-alpine --format '{{.Id}}')
cat > "$BENCH/oci.manifest" <<EOF
image=$IMAGE platform=$PLATFORM platform_manifest=$ARM64_MANIFEST config=$config_digest kernel_modules=$kernel_release
EOF
sha256sum "$BENCH/oci.raw"
cat "$BENCH/oci.manifest"
