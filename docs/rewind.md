# Automatic snapshots and `ast rewind`

Run the agent with every permission granted. If it goes wrong, put the machine
back.

That is the whole feature. `astd` takes a copy-on-write disk snapshot of every
running instance every ten minutes and keeps a day of them, so there is
somewhere to go back to whether or not anybody thought about it in advance.

```console
$ ast rewind bot
 14:20  auto    (now)
 14:10  auto
 14:00  named   before-refactor
 13:50  auto
$ ast rewind bot 20m
bot rewound to 14:00 (3.1 s) — current state kept as "before-rewind"
```

Three columns: when, what kind, and what it is called. `(now)` marks the end
of the timeline you are standing on. Times are yours, not the daemon's.

## Going back

```console
ast rewind bot 20m                  # back twenty minutes
ast rewind bot 1h30m                # s, m, h, d; a bare number is refused
ast rewind bot --to before-refactor # by name
```

A duration picks the newest snapshot taken at or before that moment. A rewind
then, in this order:

1. stops the guest, and lets go of everything the daemon was holding for it —
   its block volume sockets, its egress door, its published host ports;
2. snapshots what is on the disk right now as `before-rewind`, so the rewind
   can itself be rewound;
3. rolls the root disk back, and any local directory volume with it;
4. starts the guest again;
5. re-publishes the ports, on exactly the numbers they were declared with.

Only one thing can fail for a reason you can do something about — the target —
and that is checked first, before the guest is stopped:

```console
$ ast rewind bot --to before-refractor
Error: no snapshot "before-refractor" for bot — the timeline:
 14:20  auto    (now)
 14:10  auto
 14:00  named   before-refactor
```

`before-rewind` is rolling: there is one, it is the last rewind's undo, and it
never expires. Rewinding *to* it is how you undo a rewind, and doing so keeps
the state you are leaving in its place.

## Keeping one forever

```console
ast snapshot bot before-migration
```

`ast snapshot` and `ast restore` are unchanged and work on the same files. A
snapshot you name is never pruned, and appears on the timeline as `named`. The
`auto-` prefix is reserved — retention deletes what is called `auto-…` and
nothing else, so a hand-typed tag that would pass for the scheduler's is
refused rather than quietly becoming a snapshot that expires.

Two other things take named snapshots for the same reason — so that what they
are measured against never expires. [`ast fork`](fork.md) takes a `fork-…` at
the moment it clones an instance, and `ast pick` keeps the working volume it
replaced as `before-pick`, which is what makes a pick undoable:
`ast rewind bot --to before-pick`.

## What it costs

```console
$ ast rewind bot --usage
 17:01  rewind  before-rewind  (now)
 17:01  auto
 17:00  auto
 16:59  auto

4 snapshots, 318.35 MiB — auto every 1m, kept 1h
```

The size is `st_blocks`, which charges every shared block to every file that
references it. On a filesystem with reflinks that is a considerable
over-statement: on APFS, cloning a stopped 79 MiB root disk moved this Mac's
free space by **12 KiB**. Clones cost nothing until the live disk moves away
from them, and then they cost the difference.

Per backend, the mechanism and its honest cost:

| backend | root disk | how a snapshot is taken | cost at rest |
|---|---|---|---|
| VZ (macOS) | raw | `clonefile(2)` into `snapshots/<tag>.raw` | free — APFS shares the blocks |
| Cloud Hypervisor | raw, or qcow2 | the same file clone | free with reflinks (APFS, btrfs, XFS); a sparse copy otherwise |
| Hyper-V | VHDX | the same file clone | a sparse copy on NTFS, which has no reflink |
| QEMU (raw) | raw | the same file clone | as Cloud Hypervisor |
| QEMU (legacy `disk.qcow2`) | qcow2 | qcow2 *internal* snapshots, inside the disk | free, and not on the timeline |

Every modern instance uses the same engine — `asterism_core::snapshot`, a
copy-on-write clone of the root disk into the instance's own directory — so a
snapshot means the same thing on every backend, and survives the instance
moving between them. The one exception is an instance created before raw
disks, whose root is still a `disk.qcow2` overlay carrying its snapshots
inside it. Those are real snapshots and `ast snapshots` / `ast restore` still
work on them; they are simply not files this engine can date, clone or prune,
so `ast rewind` says so and points at the commands that do work.

## Volumes

A local directory volume — `ast attach bot --volume ~/work --at /work` — is
cloned into `snapshots/<tag>.vol<N>/` alongside the root disk and comes back
with it. Rewinding a root disk and leaving `/work` at whatever the agent left
it in would rewind nothing that matters.

A block volume served over NBD is **not** snapshotted. The volume protocol has
no snapshot request to send its provider, so instead of pretending, the
snapshot's sidecar records the fact and both the timeline and the rewind report
print it:

```text
 14:20  auto    (now)
        volume not snapshotted: "scratch" is a block volume on dev5 and its
        provider has no snapshot request
```

Everything else the daemon keeps beside the instance — its cost ledger, its
console log, its guest key, its egress material — is host-side state, not part
of the disk image, and a rewind does not touch it.

## Retention

Automatic snapshots are kept for 24 hours by default. Pruning happens on every
scheduler pass, and three things are never pruned:

* a snapshot you named;
* `before-rewind`;
* the newest automatic snapshot, however old it is — an instance that was busy
  yesterday and idle since keeps its last one, because a timeline with nothing
  on it is the one state this feature may not reach.

## Configuring it

```console
ast rewind bot --every 5m --keep 6h   # this instance
ast rewind bot --reset                # follow the device default again
```

The device-wide default is `ASTERISM_REWIND_EVERY` and `ASTERISM_REWIND_KEEP`
in the daemon's environment, defaulting to 10 minutes and 24 hours. The
shortest interval accepted is 30 seconds, and retention shorter than the
interval is refused — it would delete each snapshot before the next was taken.

## What an automatic snapshot is, exactly

`ast snapshot` refuses a running instance, because a clone taken under a live
guest catches its disk mid-write. An automatic snapshot has no such option: an
agent that runs for a day is running when every one of them falls due. So it
takes the clone anyway, and what it produces is **crash consistent** — exactly
the disk a power cut would have left. A journalling filesystem replays it and
comes up; a database with its own write-ahead log gets whatever a power cut
would have given it. Quiescing the guest through its control agent before the
clone is the obvious next improvement, and is not something this does today.

The `before-rewind` snapshot is not in that category: the guest is already
stopped when it is taken, so it is a clean copy.

## Has anything changed?

A pass that finds the disk exactly as the last snapshot left it takes nothing.
An agent waiting on a human overnight would otherwise accumulate 144 identical
clones on a timeline whose whole job is to be readable.

The check is the root disk's length and modification time, plus the same for
each cloned directory volume. That is the honest limit of what the hypervisor
boundary exposes — none of VZ, Cloud Hypervisor, QEMU or Hyper-V offers a dirty
bitmap through `Hypervisor`, and all four leave behind a file whose mtime moves
when the guest writes. It over-reports (a guest rewriting the same bytes still
moves the mtime, and the cost of that is a clone that shares every block) and
under-reports nothing that matters.

## When the guest will not come back

The rollback and the boot are separate halves, and a report says which one
happened:

```text
bot rewound to 16:55 (4.2 s) — current state kept as "before-rewind"
boot failed: "bot" cannot publish 127.0.0.1:59511 -> :80/tcp on this device …
— the disk is rolled back, so `ast up bot` is the retry, not another rewind
```

The disk is already back. Rewinding again would only lose the state you asked
for.

## Proof

`scripts/e2e-rewind.sh` runs the whole of this against a real guest with the
interval turned down to a minute; `docs/evidence/rewind-2026-08-27/` is what it
printed on a real Mac.
