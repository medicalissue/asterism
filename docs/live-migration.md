# Live instance migration

`ast move NAME DEVICE` keeps a running instance up when both devices expose a
compatible live-migration backend. `--down` continues to select the portable
offline move and is the fallback for stopped guests, incompatible hypervisor
machines, OCI-rootfs guests, or instances with attached volumes.

The live path deliberately extends the offline move transaction instead of
creating a second authority model:

1. The target proves the same backend, hypervisor major version, machine type,
   CPU model and architecture before either shard changes.
2. The source persists the ordinary monotonic move-epoch fence while its guest
   keeps running. Mutating instance commands are refused behind that fence.
3. The target creates the non-authoritative staging tree and exports its root
   disk through `qemu-storage-daemon` and NBD. The source runs a full QEMU
   `blockdev-mirror` with write-blocking dirty-write convergence and waits for
   the job to report `READY`. Root-disk bytes are never copied from a running
   file with the ordinary sparse-file transfer. Before touching staging, an
   import proves the exact source id/epoch/token fence; its durable receipt is
   bound to that same identity, so a stale import or commit cannot reuse
   another attempt's bytes.
4. The target starts its backend on an incoming Unix migration socket. The
   source pre-copies RAM and device state through a separate authenticated,
   opaque mesh splice until QEMU reports `pre-switchover`.
5. After both QEMU jobs prove readiness, the source asks the target to
   durably change its token-bound authority transaction from `Prepared` to
   `Reserved`. This target-local transition is serialized against abort:
   `Reserved` and `Aborted` are the two CAS winners, and neither can overwrite
   the other after a delayed reply or restart.
6. Only after the exact id/epoch/token reservation replies does the source
   durably change its move record from `Fenced` to `Committed`. This is the
   one-way no-return decision and it is written before `migrate-continue`.
7. The source cancels the `READY` mirror without pivoting, drains the NBD pump
   to EOF, runs `migrate-continue`, and drains the RAM/device pump to EOF. The
   target records both EOF observations in its authority WAL.
8. Before publishing anything, the target independently proves the source
   decision is `Committed`, both pumps reached EOF, and its own
   `query-migrate` is `completed` with the incoming guest running. It then
   publishes the directory and higher-epoch row.
9. Only after target-commit proof does the source fence its post-migration
   QEMU, write a permanent completion WAL, and remove its lower-epoch row and
   bytes. The WAL is id/epoch/token-bound and does not expire, so a lost reply
   can replay cleanup even after the courtesy “moved to” note has expired.

Disk and RAM EOF updates share the target's serialized monotonic authority
updater. They cannot lose one another's bits or roll `Aborted`/`Committing`
back to `Prepared`. Every bulk opening frame and EOF carries a monotonic lane
generation in addition to id/epoch/token and authenticated device identity.
If either daemon restarts after the source decision, the target durably
allocates one replacement lane, fences its old incoming backend, recreates
the required QEMU/NBD endpoints, and the still-paused source repeats any
unproved full-disk or RAM/device stream. A reply-loss replay finishes the same
lane. The source durably records the accepted lane before opening either new
stream; stale opens and callbacks from prior lanes are refused. A completed
incoming QEMU is itself terminal RAM evidence and is recorded before recovery
decides whether a replacement is needed.

An abort is legal only while the source decision is still `Fenced`, and the
source resumes only after the target has durably recorded `Aborted` *before*
killing its incoming processes. Once `Reserved` wins, target abort is
permanently refused and source recovery drives the marker and target commit
forward. An aborted source consumes the attempted epoch, so a fresh token
uses a strictly newer target key while stale frames keep replaying the old
`Aborted` winner. Every RPC, bulk opening frame and WAL record is bound to
immutable instance id, epoch, attempt token and authenticated device
identities, so lost replies replay the same phase and stale coordinators
cannot claim a newer attempt. The first target intent also records and checks
the coordinator attempt identity, while restart recovery remains deliberately
coordinator-free after that durable intent. Incoming QMP and disk export endpoints are
deterministic inside staging, allowing restart cleanup to fence a process
across the launch-to-handle recording window.

These frames require orbit protocol 7. Protocol 6 remains reserved for the
storage-part lease/attach wire, so rolling upgrades refuse migration cleanly.

The backend interface remains capability-driven. Product orchestration asks
for live migration only through `Caps::live_migration` and the migration
methods; host-specific QMP commands and Unix-socket launch details remain in
the QEMU backend.
