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

## Linux / Cloud Hypervisor — ran, 57 of 78, one consumer-side failure

- host: `DESTOP-DEV5`, WSL2 kernel `6.6.87.2-microsoft-standard-WSL2`,
  x86_64, Ubuntu 26.04, real KVM
- consumer: the kernel `nbd-client` through the root-owned `asterism-nbd`
  wrapper, below Cloud Hypervisor v53.0, with a real Debian 13 guest

QEMU is installed at `/usr/bin` on that host, so the lane was run inside a
mount namespace where a mode-0000 file is bind-mounted over every QEMU
binary. Nothing outside the namespace is affected, and the refusal is real:

```console
== proof the paths are unusable:
/usr/bin/qemu-storage-daemon: Permission denied
```

Cloud Hypervisor booted with the remote volume as an ordinary disk —
`--disk path=/dev/nbd10,readonly=off,image_type=raw,id=astvol0` — after the
kernel client negotiated with the in-process exporter across the mesh:

```text
Negotiation: ..size = 1024MB
Connected /dev/nbd10
```

57 assertions passed: catalog and placement, attach, the export being a
private Unix socket with no child process, a real boot, the guest formatting
and mounting the volume and writing a 1 MiB marker whose SHA-256 matched on
the provider, down/up survival, the second-claimant and live-re-attach
refusals, backup recording the external part, detach stopping the export and
removing its socket, and reattach advancing to a new epoch with the old
door gone.

The lane then failed at the provider-daemon-restart step:

```text
ok: restarted the provider daemon serving epoch 6 under a live guest
VOLUME E2E FAIL: the provider returned but the volume did not reconnect
```

**This is a consumer-side gap, not an exporter one, and it is not fixed
here.** The bridge's recovery is written for a client that reconnects: when
the remote session ends the consumer marks the part degraded and waits for
the next connection to its local bridge socket, which is what VZ and QEMU
both do. The kernel `nbd-client` does not — it holds one connection for the
life of the device, so when that connection closes the `/dev/nbd10` device
stays dead until something re-attaches it. The provider's own state was
correct throughout: the lease and epoch 6 survived on disk, and the export is
re-established at the same epoch by the next `open_export`. Closing this
needs a change in `backend/chv.rs`, which belongs to the Cloud Hypervisor
lane, so it is reported rather than patched.

### What the kernel `nbd-client` actually negotiates

```text
2 negotiated selected_by=GO no_zeroes=true structured=false base_allocation=false
2 first READ
1 first WRITE
1 first FLUSH
1 first TRIM
1 first DISC
```

Like VZ, and unlike QEMU, it asks for neither structured replies nor
`base:allocation`. So of the three consumers only QEMU negotiates the context
that `NBD_CMD_BLOCK_STATUS` needs, and none of the three was observed sending
that command.

Nothing was left behind on dev5: the lane's own cleanup removed its homes,
daemons and guests, `/dev/nbd10` was detached afterwards, and the checkout,
the pinned Cloud Hypervisor, the NBD wrapper and its `/run` state were
removed. The `nbd-client` and `virtiofsd` packages and the loaded `nbd`
kernel module were left in place; both are what the Linux installer puts
there anyway.

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
  binary reachable on the machine serving the bytes or the machine running
  the guest — on macOS with the VZ consumer, and on Linux/KVM through the
  kernel `nbd-client` below Cloud Hypervisor up to the point noted above;
- the epoch-fenced single-writer lease survives the exporter becoming part of
  the daemon: on macOS, same-epoch re-establishment after a provider daemon
  restart and after a consumer daemon restart, both under a live guest;
- a guest's discard returns space to the provider rather than allocating the
  volume's whole advertised size there;
- what all three consumers negotiate, measured rather than assumed;
- that the QEMU compatibility consumer still works against the exporter which
  replaced `qemu-storage-daemon`.

## Does not prove

- provider-daemon-restart recovery under a live Cloud Hypervisor guest: that
  step failed, for the consumer-side reason recorded above, and remains open;
- the OCI guest-control variant of this lane (`E2E_VOLUME_OCI=1`);
- compute move or the live-throughput assertion, both skipped by the flags
  above;
- Windows, where Hyper-V advertises no NBD disk capability at all;
- any volume larger than 1 GiB, or any filesystem other than APFS on the
  provider side. The Linux lane's provider image sat on WSL2's `/private/tmp`
  and its sparse behaviour was not measured the way the macOS lane's was.
