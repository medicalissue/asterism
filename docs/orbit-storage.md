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
the epoch and retires the previous export door. A provider restart recreates
the current export without changing its epoch; a consumer restart reconnects a
live guest at exactly the epoch it already holds. A stale reconnect cannot
learn or open the current door.

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
