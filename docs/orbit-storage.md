# Orbit storage catalog and placement

Block storage is an orbit part. Its bytes have one owning device, but an
instance can attach the part from any device and sees only an ordinary local
disk. The catalog is the management view of that contract; the existing NBD
bridge over the authenticated mesh is the transport implementation and never
enters guest configuration.

`ast volume ls` asks every reachable provider and reports one row per part:

| Field | Meaning |
| --- | --- |
| owner | Device identity responsible for the bytes and lease authority. |
| latency | Live round-trip observation from the device reading the catalog; local is zero and an unmeasured live path is explicit. |
| durability | `single-device`: this provider is the only promised durable failure domain. |
| sharing | `single-writer`: at most one writable lease, fenced by a durable monotonic epoch. |
| held by | Current instance, CPU device and epoch, or availability. |

Provider-local administration remains available with `ast --device DEVICE
volume ...`. This is useful for creation, removal and diagnosis, but consumers
do not need to query devices one at a time.

## Placement

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

CPU placement is independent. Moving an instance changes where its CPU and RAM
run, while attached volume ownership stays fixed; the bridge becomes local or
remote as required. Portable backups record the external volume binding and
restore it as a part that must be rebound rather than copying or silently
claiming provider bytes.

## Real-process verification

`scripts/e2e-volume.sh` is the authoritative two-device lane. It uses two real
daemons, real provider storage processes and a real guest to cover local and
remote access, catalog discovery, automatic placement, single-writer
contention, detach/reattach, stale epochs, provider and consumer restarts,
provider loss, and refusal before mutation. It runs against both QEMU and VZ.

The adjacent lanes cover the cross-feature durability boundaries:

```console
$ scripts/e2e-volume.sh
$ scripts/e2e-move.sh
$ scripts/e2e-durability.sh
```

The move lane proves attached-part records survive CPU relocation without
turning a remote provider into guest-visible topology. The durability lane
power-cuts and damages real on-disk stores. Portable backup/restore is also
exercised by `asterism-daemon`'s `control_plane` integration tests.
