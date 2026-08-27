# Orbit storage catalog and provider selection

Block storage is a **data** part, and data is the thing that legitimately
crosses devices: bytes have one owning device, an instance running on any
device in the orbit can attach them, and the guest sees only an ordinary local
disk. (Compute is not like this. An instance uses the CPU, RAM, and GPU of the
device it runs on — see
[Compute is the device an instance runs on](compute-device.md).)

The catalog is the management view of that contract; the existing NBD bridge
over the authenticated mesh is the transport implementation and never enters
guest configuration.

"Placement" below always means one thing: choosing which device's bytes back a
volume attachment. It is not a compute scheduler and it never decides where an
instance runs.

`ast volume ls` asks every reachable provider and reports one row per part:

| Field | Meaning |
| --- | --- |
| owner | Device identity responsible for the bytes and lease authority. |
| latency | Live round-trip observation from the device reading the catalog; local is zero and an unmeasured live path is explicit. |
| durability | `single-device`: this provider is the only promised durable failure domain. |
| sharing | `single-writer`: at most one writable lease, fenced by a durable monotonic epoch. |
| held by | Current instance, compute device and epoch, or availability. |

Provider-local administration remains available with `ast --device DEVICE
volume ...`. This is useful for creation, removal and diagnosis, but consumers
do not need to query devices one at a time.

## Choosing a provider

`ast attach INSTANCE --volume NAME` reads the live catalog before mutation.
Eligible candidates must advertise the required durability and sharing mode,
must be available to that instance, and must satisfy `--max-latency-ms` when a
ceiling is supplied. Placement prefers local storage, then the lowest measured
latency, with device identity as a deterministic tie-breaker.

`DEVICE:NAME` constrains placement to one owner. It does not select a network
transport. A missing, busy, slow or unreachable candidate is refused before a
lease or instance row changes. The provider lease is then acquired as the
race-safe final check: another attach that won after catalog observation is
still refused by the single-writer fence.

## Durability and recovery

The catalog does not weaken the volume store's existing durability rules.
Epoch, holder, holder device, export identity, durability and sharing semantics
live in the provider's atomic, recoverable volume book. Every grant advances
the epoch only after the previous export process is proven dead; unlinking its
Unix socket alone is not a fence because already-connected clients survive an
unlink. A provider restart recreates a current export without changing its
epoch only when the lease proves no untracked predecessor may still exist. A
consumer restart reconnects a live guest at exactly the epoch it already
holds. A stale reconnect cannot learn or open the current door. Grant,
release, export identity, and device-revocation transitions are confirmed in
both the live volume book and its recovery copy before acknowledgement.
Before spawning an export, the provider also confirms a conservative
"process may run" marker; definitely pre-spawn dependencies such as the
storage daemon binary and volume image are validated before that marker is
armed, and only the captured process identity replaces it. Thus a missing
dependency is retryable without inventing an unknown writer, while a crash or
failed identity commit after the launch boundary refuses a second export even
when the first process cannot be safely signalled.

Attach is a recoverable cross-device saga. The consumer first commits a
pending intent to both the live journal and its recovery copy, then asks the
provider for the lease, commits the instance row, and finally clears the
intent. If a registry save reports ENOSPC, EIO, or an ambiguous post-rename
failure, the daemon reloads the durable row: a matching row rolls forward;
otherwise it marks the intent aborting, removes any consumer row and releases
the provider lease. Startup performs the same reconciliation before guest
resurrection, so an incomplete attachment cannot reach a hypervisor. An
aborting marker makes compensation itself restartable rather than allowing an
ambiguous rollback to be mistaken for a commit.

Detach is the forward-only mirror. Before asking the provider to release its
writer fence, the consumer confirms a separate release intent in both journal
copies. The request carries the expected epoch, so a delayed retry cannot
release a later boot's renewal. Only after the provider is free does the
consumer remove and confirm its instance row; a lost reply, ENOSPC/EIO, or a
crash leaves the intent for startup to replay. Provider-first ordering means
recovery never forgets a row while its lease might still exist, and runs
before guest resurrection so a released row cannot reach a hypervisor.
Boot and further block attachment are refused while a release intent remains,
so neither can renew or obscure the epoch that recovery is settling.
Legacy consumer rows without an immutable provider identity are never rebound
to the device currently holding the same human name: detach, removal and
release replay preserve their row and any pending intent until authority can
be repaired explicitly.

Guest launch has its own durable fence. Before a boot renews any provider
lease, the consumer confirms a launch intent in both registry copies. Renewed
epochs are then confirmed on the instance row before the hypervisor is called.
The running handle atomically clears the launch intent. If that commit fails,
the daemon either reloads and confirms the exact handle or kills the guest and
proves it stopped before releasing provider leases and publishing a stopped
row. Once the backend's boot method is invoked, even an error is ambiguous: a
guest process may exist despite a failed process-identity or endpoint capture,
so the daemon retains the renewed leases and launch intent. A crash in the same
handle-capture window likewise leaves the launch intent in place and the row
conservatively running. Startup reconciliation, resurrection and the
steady-state supervisor all preserve that marker, exclude it from restart
scheduling, and keep the device awake; only explicit compensation after proven
guest death may publish stopped authority. Thus restart refuses a second guest
instead of guessing that the first is dead.

Startup attach/release recovery never holds the shard mutex while contacting a
provider and each attempt has a 30-second deadline. A timeout leaves the
durable intent fenced for the next retry; it cannot stall every registry read
or silently admit a guest.

Moving an instance between devices (see
[Compute is the device an instance runs on](compute-device.md)) is independent
of this. It changes which device supplies CPU and RAM, while attached volume
ownership stays fixed: the volume is not copied, it is re-attached from the
new device and the bridge becomes local or remote as required.
Portable backups record the external volume binding and
restore it as a part that must be rebound rather than copying or silently
claiming provider bytes.

## Memory and cache volumes

A root disk and an agent's memory are two different things stored the same
way. Rewinding a box twenty minutes should undo what the agent *did* and keep
what it *learned*: `claude --resume` has to still find the conversation. And
three forks of one box should share one warm cargo registry rather than each
downloading the crates world.

Neither can be inferred from a mount point, so a volume declares it:

```console
$ ast volume create brain --size 8G --lifecycle memory
$ ast volume create warm  --size 64G --lifecycle cache --key agent-toolchain
```

| Lifecycle | Owned by | `ast snapshot` captures | `ast restore` rolls back | On fork |
| --- | --- | --- | --- | --- |
| `instance` (default) | one instance | yes | yes | copied |
| `memory` | one instance | yes | only with `--include-memory` | copied |
| `cache` | every instance with the same `--key` | no | never | shared |

"`ast restore` rolls back" reads the same for `ast rewind`: they are two ways
of naming a snapshot, not two rollback policies.

`instance` is what every volume created before this field existed loads as,
which is what those volumes meant — and it is a change in what a restore does
to them: an attached instance-lifecycle volume on the device taking the
snapshot is now captured with the instance and rolled back with it. That is
the reading of "roll this instance back" the flag exists to carve an exception
out of, and the clone is copy-on-write, so capturing costs nothing until the
two diverge. `ast volume ls` shows the lifecycle in its
TYPE column, and `ast status` shows it on each attached part.

### The one predicate

Both rollback surfaces call the same function, so `ast restore` and
`ast rewind` cannot drift into disagreeing about what a rewind means:

```rust
asterism_core::volume::reverts_with_instance(lifecycle, include_memory) -> bool
```

`ast restore TAG --include-memory` and `ast rewind 20m --include-memory` are
the same flag on the two surfaces, and `daemon/rewind.rs`'s `roll_back` reads
the predicate above rather than deciding for itself which parts a rewind may
put back. `include_memory` is the user having asked for the stronger thing. A
cache is never rolled back, with or without it: it is shared with instances
that are not being rewound, and its contents are derivable.

A snapshot is deliberately wider than a restore —
`volume::captured_by_snapshot(lifecycle)` excludes only `cache`. A snapshot
that had not captured memory could never honour `--include-memory` later, and
capturing is a copy-on-write clone while *not having captured* is
unrecoverable. A cache is excluded because the clone would be the largest file
in the orbit and nothing will ever roll it back.

Volume snapshots live beside the volume's bytes, in
`$ASTERISM_HOME/volumes/<name>/snapshots/<tag>.raw`, under the same tag as the
instance's root-disk snapshot — because a volume outlives every instance that
ever mounted it, and its clones belong with it rather than inside one
instance's directory. Deleting a tag therefore has to reach two places, and
does: `ast snapshot rm` and the automatic-snapshot pruner both release the
volume clones a tag captured before removing the instance's own.

`ast snapshot` and the automatic snapshotter go through one engine
(`daemon::rewind::take`), so a hand-typed tag captures exactly what an
automatic one does. They used to differ, and the difference was invisible
until it mattered: a manual tag captured only the root disk, appeared on the
timeline beside the automatic ones, and then rolled back less than they did —
`ast rewind --to <it>` left every attached directory where it was. Only volumes whose bytes are on the device
taking the snapshot are captured: a clone is a filesystem operation, and a
file on another device's disk is not one this device can clone. A memory
volume served from elsewhere is reported at snapshot time rather than
silently producing a tag that `--include-memory` would find nothing behind.

### Sharing, and what "shared" means today

`cache` volumes are shared *by key*, not shared *concurrently*. The volume
plane still offers exactly one `Sharing` mode — `single-writer`, fenced by a
monotonic epoch — so two running instances cannot hold one cache volume at
the same time. What the key buys is that the second instance attaches the
*same* warm volume instead of creating a parallel copy, and that a fork
inherits the key rather than the bytes. Copy-on-write sharing between
simultaneous writers would need a new `Sharing` variant and a filesystem that
tolerates two writers; neither exists yet, and claiming it would be a promise
nothing enforces. Fork behaviour itself is AST-152.

### Two kinds of part, one lifecycle

A lifecycle is a property of the *bytes*, so both kinds of part carry one.

A **block volume** gets it at creation (`ast volume create … --lifecycle`) and
carries it into every attachment. A **directory share** has nowhere to keep
one, so it is given one at attach time:

```console
$ ast attach bot --volume ~/.asterism/memory/bot --at /root/.claude --lifecycle memory
```

Directory shares matter here because that is what an agent preset uses. The
workspace, the agent's memory and its shared caches are host directories
shared into the guest — the host can see them, a fork can copy one with `cp`,
and `ast rewind` already knows how to clone and restore a tree. Naming a
lifecycle on a block volume's attachment is refused rather than accepted as a
second answer to a question `ast volume ls` already answers.

### Preset mounts

`presets/*.json` declare what an agent needs past its workspace:

```json
"mounts": [
  { "at": "/root/.claude", "lifecycle": "memory" },
  { "at": "/root/.npm",    "lifecycle": "cache", "key": "agent-toolchain" },
  { "at": "/root/.cache",  "lifecycle": "cache", "key": "agent-toolchain" }
]
```

`ast create --agent claude-code` makes and attaches each of them. A memory
mount is `~/.asterism/memory/<instance>/…` and belongs to one box; a cache
mount is `~/.asterism/cache/<key>/…`, so the second agent box attaches the
directory the first one warmed. Two cache mounts under one key are two
directories under that key — a single directory mounted at both `~/.npm` and
`~/.cache` would have each guest path eating the other's contents.

The workspace itself stays `instance`: rolling the box back and leaving the
repository as it was would be a rewind that undid nothing anybody cares about.

A preset with no `mounts` is the preset it was before the field existed.

### Profile defaults

The cloud-image lane has the same idea in its own vocabulary: a
`--profile claude` guest gets block volumes rather than directory shares,
because a cloud image is a machine that formats and mounts its own disks.
`ast create --profile claude` makes what the profile declares, if it is not
already there:

| Volume | Lifecycle | Guest path |
| --- | --- | --- |
| `<instance>-claude-memory` | `memory` | `/home/ast/.claude` |
| `cache-agent-toolchain` | `cache`, key `agent-toolchain` | `/var/cache/asterism` |

`--profile codex` declares `/home/ast/.codex` and the same cache. Two agent
profiles on one box is one cache volume, not two disks fighting over one
directory: the resolution drops a second request for a guest path already
claimed.

The cache volume serves several paths through symlinks the profile creates —
`~/.cargo/registry`, `~/.npm`, `~/.cache/pip` — because a cache is one
failure domain and one lease, and which paths a toolchain uses is the
toolchain's business. A directory that already holds bytes is moved onto the
volume the first time and left alone afterwards, so attaching a cache to a box
that ran without one does not lose its registry.

Failures here do not undo the instance. A box with its agent state on the root
disk is a working box that will lose its conversation at the first rewind —
worth a loud warning, not worth refusing to create what somebody asked for.
`ast status` shows which volumes actually attached, and the profile's
`asterism-check` says so from inside the guest.

### The guest side, and why the ordering matters

A block volume has always reached the guest as a bare disk that the guest
formats and mounts itself. `ast attach bot --volume brain --at /home/ast/.claude`
asks the guest to do that once, at boot, before anything looks there.

The seed carries three things for it: a table at `/etc/asterism/blockmounts`,
the script `/usr/local/lib/asterism/blockmount`, and
`asterism-blockmount.service`, which is `Before=multi-user.target` and enabled,
so the mounts come back on every later boot without cloud-init running again.

Identity is solved once. A volume is claimed under a filesystem *label*
derived from `host:volume`, so from the second boot onwards "which disk is
`~/.claude`" is answered by the filesystem and not by a device name that moves
when another volume is attached. Only the first boot has to guess, and it
guesses from the one thing the host knows and the disk shows — its size —
under three rules that keep the guess from ever being destructive:

* only a disk with no filesystem signature at all is a candidate, so a disk
  somebody else formatted is never touched, whatever its size;
* the root disk and anything already mounted are excluded before size is
  looked at;
* a size that matches nothing leaves the volume unmounted and says so. An
  unmounted `~/.claude` is a slow day; a reformatted one is a lost
  conversation.

The mount fragment is emitted into `runcmd` *before* the bootstrap fragment,
and cloud-init concatenates those into one script. So by the time the profile
that installs the agent runs — and long before anybody attaches to the guest's
tmux session, which happens over ssh after boot — `~/.claude` is the volume.
An agent that wrote its first transcript into the wrong filesystem would lose
it at the first rewind, silently, which is why the ordering is asserted in
`seed.rs` rather than left to the order the fragments happen to be written in.

## The exporter

The provider serves a volume from inside `astd` itself. There is no
`qemu-storage-daemon`, and no QEMU binary is required on either end of a
remote attach: the exporter is a fixed-newstyle NBD server in Rust
(`crates/asterism-daemon/src/nbd.rs`) bound to one Unix socket per lease
epoch, `~/.asterism/volumes/<name>/nbd-e<epoch>.sock`, mode `0600`. It never
listens on TCP, and no byte a client sends is ever used as a path: the image
and the export name both come from the already-authorized lease.

What it offers is bounded by what its consumers actually ask for — the Linux
kernel's `nbd-client` below Cloud Hypervisor, VZ's
`VZNetworkBlockDeviceStorageDeviceAttachment` over `nbd+unix://`, and QEMU's
own client when the compatibility backend is installed. Setting
`ASTERISM_NBD_TRACE=1` on the provider daemon makes it report the options each
consumer negotiated and the first of each command it issued, which is how that
list is checked against real clients rather than assumed:

- `NBD_OPT_GO`/`NBD_OPT_INFO` with export, name and block-size info, plus
  `NBD_OPT_EXPORT_NAME` and `NBD_OPT_ABORT` for older clients. Only the
  lease's own export name is accepted; any other name is refused and the
  connection closed.
- `NBD_OPT_STRUCTURED_REPLY` and `base:allocation` through
  `NBD_OPT_SET_META_CONTEXT`. Of the three consumers only QEMU's client asks
  for these; VZ and the kernel `nbd-client` ask for neither, and none of the
  three has been observed sending `NBD_CMD_BLOCK_STATUS`. That command is
  answered only when the context was negotiated, and refused with `EINVAL`
  otherwise. It stays implemented because QEMU negotiates the context that
  promises it, not because anything has been seen to need it.
- `NBD_CMD_READ`, `WRITE`, `FLUSH`, `TRIM`, `WRITE_ZEROES`, `DISC` and
  `BLOCK_STATUS`, with `FUA`, `DF`, `NO_HOLE` and `REQ_ONE`. Nothing else is
  advertised, and an unknown command flag closes the connection rather than
  guessing at framing.

Every request is bounds-checked against the exported size before it reaches
the image, and only `ENOSPC` and `EINVAL` from the host are passed through as
themselves; anything else becomes `EIO`, which is what a guest's block layer
knows how to handle. A `WRITE` that would fall outside the export still has
its payload consumed, so the next request header stays aligned.

Volumes are sparse and stay sparse. `TRIM`, and `WRITE_ZEROES` without
`NBD_CMD_FLAG_NO_HOLE`, punch a hole through the block-aligned interior of the
requested range — `fallocate(FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE)` on
Linux, `F_PUNCHHOLE` on macOS — so a guest's `mkfs` or `blkdiscard` returns
space to the device that holds the bytes instead of allocating the volume's
whole advertised size there. The unaligned edges are written literally,
because the blocks under them still hold a neighbour's data. A filesystem
that cannot punch keeps the bytes, which the protocol explicitly permits, and
the length of the image never changes either way. `BLOCK_STATUS` reports what
`SEEK_DATA`/`SEEK_HOLE` say, degrading to "allocated" — which promises
nothing — when the kernel will not answer.

The server is the lease's fence. Stopping it closes the listener and every
accepted stream before returning, so revocation ends clients that connected
before the socket was unlinked, and a daemon restart re-establishes the export
at the *same* epoch rather than minting a new one under a running guest.

## Real-process verification

`scripts/e2e-volume.sh` is the authoritative two-device lane. It uses two real
daemons, real provider storage processes and a real guest to cover local and
remote access, catalog discovery, automatic placement, single-writer
contention, detach/reattach, stale epochs, provider and consumer restarts,
provider loss, and refusal before mutation. It runs against the native
backends — VZ on macOS and Cloud Hypervisor on Linux — and needs no QEMU
binary on either device. `E2E_VOLUME_QEMU_COMPAT=1` adds the optional QEMU
consumer lane against the same native exporter.

The adjacent lanes cover the cross-feature durability boundaries:

```console
$ scripts/e2e-volume.sh
$ E2E_VOLUME_OCI=1 scripts/e2e-volume.sh
$ scripts/e2e-move.sh
$ scripts/e2e-durability.sh
```

The OCI mode drives the same lane through authenticated `ast exec` instead of
SSH. It proves a direct-kernel OCI VM sees and writes the remote part as an
ordinary block disk. Provider loss is fail-closed: an operation already in
flight may fail, and new I/O is asserted only after status declares the same
epoch reconnected. See the
[2026-08-26 real-host evidence](evidence/oci-parts-parity-2026-08-26/README.md).

`scripts/e2e-volume-lifecycle.sh` is the lane for what a rollback does to
which bytes. It drives a real daemon through the real snapshot and restore
path with an `instance`, a `memory` and a `cache` volume attached, writes
markers into the images themselves, and asserts on those markers afterwards —
so what a restore replaces is observed rather than inferred from an exit
status. It drives both rollback surfaces — `ast restore` and `ast rewind`,
with and without `--include-memory` — against the same volumes, which is the
assertion that the one shared predicate is really shared. It also creates a
second box with `--profile claude` and proves the
declared volumes are made, attached at the guest paths the profile names, and
that the cache the first box warmed is the one the second box attaches. See
the [2026-08-27 real-host evidence](evidence/volume-lifecycle-2026-08-27/README.md).

The move lane proves attached-part records survive compute relocation without
turning a remote provider into guest-visible topology. The durability lane
power-cuts and damages real on-disk stores. Portable backup/restore is also
exercised by `asterism-daemon`'s `control_plane` integration tests.
