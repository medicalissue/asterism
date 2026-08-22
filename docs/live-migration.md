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
3. The target pulls the ordinary sparse disk tree into an unlisted staging
   directory. This is the pre-copy; it is not authoritative or bootable by an
   Asterism command.
4. The target backend starts paused on an incoming Unix migration socket in
   staging. The source backend sends dirty disk blocks, RAM and device state
   through an authenticated, opaque mesh splice.
5. QEMU's `pause-before-switchover` boundary stops source execution after
   convergence. Only then does the target directory rename and higher-epoch
   shard row become durable.
6. The source receives the commit, releases QEMU's switchover, kills its
   post-migration process, and deletes its lower-epoch row and bytes.

Any failure before step 5 kills the staged target, cancels the backend
migration, resumes the source and clears only that epoch's fence. A failure
after step 5 never runs abort: the target's higher epoch is authoritative and
the source remains fenced until its cleanup can be retried. Incoming handles
are recorded inside staging so a target-daemon restart can kill an orphaned
incoming process before sweeping its directory.

The backend interface remains capability-driven. Product orchestration asks
for live migration only through `Caps::live_migration` and the migration
methods; host-specific QMP commands and Unix-socket launch details remain in
the QEMU backend.
