# Native NBD exporter, no QEMU on either end — 2026-08-27

Real-host evidence for AST-109. The provider side of a remote block volume is
a fixed-newstyle NBD server inside `astd`; this records what happened when the
two-device storage lane was run against it on a host where no QEMU binary of
any kind was reachable.

Source under test: `4973dae37e885bb04082c18fdf5998dce05b1aa0` on
`claude/ast-109-native-nbd`.

## macOS / VZ — ran, green

- host: arm64 Mac, macOS 26.5.2 (25F84)
- consumer: VZ's `VZNetworkBlockDeviceStorageDeviceAttachment` over
  `nbd+unix://`, against a real Debian 13 guest
- provider: the second daemon's in-process exporter, spliced over the local
  mesh

QEMU is installed on this machine under Homebrew, so the lane was run with a
`PATH` that does not contain it:

```console
$ PATH=/usr/bin:/bin:/usr/sbin:/sbin:$HOME/.cargo/bin \
    command -v qemu-storage-daemon qemu-img qemu-system-aarch64
$ echo $?
1
$ PATH=/usr/bin:/bin:/usr/sbin:/sbin:$HOME/.cargo/bin \
    ASTERISM_MESH=local ASTERISM_NBD_TRACE=1 \
    E2E_VOLUME_BACKEND=vz E2E_VOLUME_GIB=1 \
    E2E_VOLUME_TRANSFER_BYTES=1048576 \
    E2E_VOLUME_SKIP_COMPUTE_MOVE=1 E2E_VOLUME_SKIP_LIVE_THROUGHPUT=1 \
    scripts/e2e-volume.sh
...
VOLUME E2E GREEN
```

All 78 assertions passed, including the sections this issue is about: the
export is a private Unix socket with no child process and no TCP listener
(§3); a live guest formats and writes the remote volume (§5); a second
claimant, a live re-attach and deletion under lease are refused (§6); detach
and reassignment advance the epoch and retire the old socket (§7); the export
dies under a live guest and comes back at the *same* epoch (§8); the
consumer's own daemon restarts under that live guest and re-establishes the
bridge at that epoch (§8b); and provider loss degrades only the volume, then
returns without rebinding (§9).

Sparse behaviour, measured on the provider's own image: a 1 GiB volume, after
the guest ran `mkfs.ext4` and wrote a 1 MiB marker, occupied **1988 KiB**. The
guest's `mkfs` discard reached the provider as `NBD_CMD_TRIM` and
`NBD_CMD_WRITE_ZEROES` and was answered by punching holes, so the volume's
advertised size was never allocated on the device holding the bytes.

### What VZ actually negotiates

Recorded by the provider under `ASTERISM_NBD_TRACE=1` across the whole lane
(six sessions, one per epoch the guest used):

```text
6 negotiated selected_by=GO no_zeroes=true structured=false base_allocation=false
6 first READ
6 first WRITE
1 first TRIM
2 first WRITE_ZEROES
```

So VZ selects the export with `NBD_OPT_GO`, takes `NBD_FLAG_C_NO_ZEROES`, and
asks for neither structured replies nor `base:allocation`. It never sent
`NBD_CMD_BLOCK_STATUS`, and in this lane never sent `NBD_CMD_FLUSH` either.
Structured replies, `base:allocation` and `BLOCK_STATUS` remain implemented
because the kernel `nbd-client` and QEMU's client do negotiate them; nothing
beyond that list is advertised.

### A bug this lane found

The first attempt at this run did not finish. With the trace on, the provider
showed 10451 sessions, each of which had negotiated successfully, issued
exactly one `NBD_CMD_TRIM`, and been disconnected with `NBD request exceeds
33554432 bytes`. The guest was running `mkfs`, which discards the whole
device in one request; the export was applying its maximum block size to a
command that carries no payload, and VZ reconnected and reissued it forever.

`TRIM`, `WRITE_ZEROES` and `BLOCK_STATUS` are now bounded only by the export's
own size, refused past the end in frame with `EINVAL` rather than by closing.
The run above is the same lane after that fix.

## macOS / QEMU compatibility consumer — ran, green

The same lane, same host, same commit, with QEMU 10 on the `PATH` and
`E2E_VOLUME_BACKEND=qemu`. This is the other half of the contract: the
retired exporter's consumer must still work against the one that replaced it.
All 78 assertions passed and it ended `VOLUME E2E GREEN`.

QEMU's client negotiates more of the protocol than VZ does, which is why the
optional halves exist at all:

```text
6 negotiated selected_by=GO no_zeroes=true structured=true base_allocation=true
6 first READ
6 first WRITE
6 first FLUSH
2 first WRITE_ZEROES
2 first DISC
```

It asked for structured replies and `base:allocation` on every session, and
sent `FLUSH` and `DISC`, which VZ never did. It sent no `TRIM` and no
`BLOCK_STATUS` in this lane: its guest's `mkfs` discards did not reach the
export, and the provider image ended at 51184 KiB for the same 1 GiB volume
that the VZ lane left at 1988 KiB. That difference is the consumer's, not the
exporter's.

## Linux / Cloud Hypervisor — attempted, did not run

This lane was set up on dev5 and started, but the host became unreachable
before it produced a verdict, and it had not come back at the time of
writing. **Nothing about the CHV consumer, the kernel `nbd-client` path, or
the root-owned `asterism-nbd` wrapper is claimed here.**

What was prepared on dev5 (`DESTOP-DEV5`, WSL2 kernel
`6.6.87.2-microsoft-standard-WSL2`, x86_64, Ubuntu 26.04) and what a human
should re-run:

```console
# once: the runtime the lane needs, and nothing from QEMU
$ apt-get install -y nbd-client virtiofsd
$ curl -fsSLo /root/ast109-run/bin/cloud-hypervisor \
    https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v53.0/cloud-hypervisor-static
$ echo "448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc  /root/ast109-run/bin/cloud-hypervisor" | sha256sum -c -
$ chmod 0755 /root/ast109-run/bin/cloud-hypervisor
$ install -d -m 0755 /usr/local/libexec/asterism
$ install -m 0755 -o root -g root packaging/asterism-nbd /usr/local/libexec/asterism/asterism-nbd
$ install -d -m 0700 -o root -g root /run/asterism-nbd
$ touch /run/lock/asterism-nbd.lock && chmod 0600 /run/lock/asterism-nbd.lock
$ modprobe nbd nbds_max=64

# the gate, in a mount namespace where no QEMU binary is executable
$ unshare -m --propagation private sh -c '
    : >/tmp/blocked; chmod 0000 /tmp/blocked
    for f in /usr/bin/qemu* /usr/local/bin/qemu* /usr/sbin/qemu* /bin/qemu*; do
      [ -e "$f" ] && mount --bind /tmp/blocked "$f"
    done
    command -v qemu-storage-daemon qemu-img qemu-system-x86_64   # must print nothing
    AST_BIN=$PWD/target/release/ast ASTD_BIN=$PWD/target/release/astd \
    ASTERISM_CLOUD_HYPERVISOR=/root/ast109-run/bin/cloud-hypervisor \
    ASTERISM_VIRTIOFSD=/usr/bin/virtiofsd \
    ASTERISM_MESH=local ASTERISM_NBD_TRACE=1 \
    E2E_VOLUME_BACKEND=chv E2E_VOLUME_GIB=1 \
    E2E_VOLUME_TRANSFER_BYTES=1048576 \
    E2E_VOLUME_SKIP_COMPUTE_MOVE=1 E2E_VOLUME_SKIP_LIVE_THROUGHPUT=1 \
      bash scripts/e2e-volume.sh'
```

The bind mounts live only inside that namespace and disappear with it; the
host's own QEMU is untouched. The state left on dev5 by the attempt —
`/root/ast109`, `/root/ast109-run`, `/root/.cache/asterism`, the two
`apt` packages, `/usr/local/libexec/asterism/asterism-nbd`,
`/run/asterism-nbd`, `/run/lock/asterism-nbd.lock`, the loaded `nbd` module,
and whatever the interrupted lane left running under `/tmp/ast-vol-*` — has
not been cleaned up, because the host has not been reachable since.

## Host-neutral

```console
$ cargo fmt --all --check
$ cargo clippy -p asterism-core -p asterism-daemon --all-targets -- -D warnings
$ cargo test -p asterism-core -p asterism-daemon
```

The exporter's own tests drive it through a real socket with an in-crate
client, because macOS has no kernel `nbd-client` to borrow: fixed-newstyle
negotiation through `GO`, `INFO`, `EXPORT_NAME` and `ABORT`; every command it
advertises; out-of-bounds and oversize requests; malformed option payloads and
a wrong export name; a client torn away mid-request; the session cap; two
claimants on one socket; a stale process identity refused at revocation; and
hole preservation for `TRIM` and `WRITE_ZEROES` on both sides of
`NBD_CMD_FLAG_NO_HOLE`.

## Proves

- a remote block volume works end to end, through a real guest, with no QEMU
  binary reachable on the machine serving the bytes or the machine running the
  guest — on macOS with the VZ consumer;
- the epoch-fenced single-writer lease survives the exporter becoming part of
  the daemon: same-epoch re-establishment after a provider daemon restart, and
  after a consumer daemon restart under a live guest;
- a guest's discard returns space to the provider rather than allocating the
  volume's whole advertised size there;
- what the VZ and QEMU consumers each negotiate, measured rather than
  assumed;
- that the QEMU compatibility consumer still works against the exporter which
  replaced `qemu-storage-daemon`.

## Does not prove

- the Linux/Cloud Hypervisor consumer, the kernel `nbd-client` path, or the
  root-owned `asterism-nbd` wrapper — see the section above for what was
  prepared and what a human still has to run;
- the OCI guest-control variant of this lane (`E2E_VOLUME_OCI=1`);
- compute move or the live-throughput assertion, both skipped by the flags
  above;
- Windows, where Hyper-V advertises no NBD disk capability at all;
- any volume larger than 1 GiB, or any filesystem other than APFS on the
  provider side. The Linux hole-punching path
  (`FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE`) has host-neutral test coverage
  only; no real Linux filesystem measured it here.
