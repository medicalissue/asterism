# Automatic snapshots and `ast rewind` on a real VZ guest — 2026-08-27

`scripts/e2e-rewind.sh`, run on real hardware with the snapshot interval turned
down to one minute so a test run can watch three passes. In production it is
ten.

**Host.** MacBook Pro, macOS 26.5.2 (25F84), arm64. Backend `vz`
(Virtualization.framework 26.5.2) through the ad-hoc-signed `astd-vz` helper
built from this tree. Image `docker.io/library/nginx:alpine`, an OCI rootfs
booted with a direct kernel. Scratch `ASTERISM_HOME` under `/private/tmp`,
`ASTERISM_MESH=local`, `ASTERISM_REWIND_EVERY=1m`, `ASTERISM_REWIND_KEEP=1h`.

Files here:

| file | what it is |
|---|---|
| `e2e-rewind.log` | the whole run, green |
| `astd.log` | the daemon's own log for that run |
| `timeline-before.txt` | `ast rewind bot` before the rewind |
| `timeline-after.txt` | the same afterwards |
| `rewind.txt` | what `ast rewind bot 2m` printed |
| `cow-usage.txt` | what a clone appears to cost, and what it costs |

## What the run did

An agent instance called `bot`, with a published host port (`-p <free>:80`) and
a local directory volume mounted at `/work`. Left running. Markers `t0`, `t1`
and `t2` written from inside the guest — one on the root disk, one in `/work` —
each followed by waiting for the daemon to take a snapshot on its own with
nobody typing anything. Then everything deleted, from inside the guest. Then
`ast rewind bot 2m`.

```text
--- ast rewind bot (before)
 17:03  auto    (now)
 17:02  auto
 17:01  auto

--- ast rewind bot 2m
bot rewound to 17:01 (5.1 s) — current state kept as "before-rewind"

--- ast rewind bot (after)
 17:03  rewind  before-rewind  (now)
 17:03  auto
 17:02  auto
 17:01  auto
```

Elapsed for the whole cycle — stop, keep the current state, roll back the root
disk and the volume, boot, re-publish — was **5.1 s** on this run, and 4.2 s to
11.2 s across five runs of the lane on this Mac. The spread is the machine's,
not the engine's: the slowest run shared the host with two other agents' VM
lanes. The published port answered HTTP 200 again on exactly its own number
every time.

## Cost

```text
live disk                                          81 396 KiB
du of the snapshots directory                     244 180 KiB
free space consumed by one clone of the disk           12 KiB
```

Three clones of an 80 MiB disk read as 240 MiB, and occupy twelve kilobytes.
`du`, and the `--usage` footer, both report `st_blocks`, which charges every
shared block to every file that references it; `clonefile(2)` shares them. The
free-space delta was measured across `ast snapshot bot before-migration` with
the guest stopped, so the clone is the only thing that touched the filesystem
during it.

## Proves

* astd takes a disk snapshot of a running instance on a timer, with nobody
  typing anything — three passes, one a minute, announced at startup and
  visible on the timeline.
* A local directory volume is snapshotted beside the root disk
  (`auto-<stamp>.vol0/`) and holds the guest's writes.
* `ast rewind bot 2m` stops the guest, keeps the state it replaces as
  `before-rewind`, rolls back **both** the root disk and `/work`, starts the
  guest again, and re-publishes the declared host port — 5.1 s, port answering
  200 afterwards, both markers back, and the rewound `/work` still the same
  directory the host shares.
* `--to <snapshot>` is deterministic: a second rewind, by name, to the very
  first automatic snapshot of the run, with the port surviving that too.
* Refusals happen before mutation. `--to before-refactor` on an instance with
  no such snapshot printed the timeline and left the guest running; a bare
  `20` was refused as not a duration; `ast snapshot bot auto-mine` was refused
  because retention deletes what is called `auto-…`.
* Retention rules: the named `before-migration` snapshot outlived every
  automatic one; `before-rewind` is on the timeline and never expires.
* `--usage` prints the footer and not a column; `--every 5m --keep 2h` takes,
  `--every 10m --keep 1m` is refused, `--reset` puts the instance back on the
  device default.
* Copy-on-write is real on APFS: 12 KiB for a clone of an 80 MiB disk.

## Does not prove

* **Cloud Hypervisor and Hyper-V were not run here.** The lane takes
  `E2E_BACKEND=chv` and would run on a Linux host with `/dev/kvm`; Hyper-V has
  no lane in this suite at all. All four backends take a snapshot through the
  same `asterism_core::snapshot` file clone, so the engine is shared, but the
  claim on those two backends is by construction and not by observation. On a
  filesystem without reflinks (NTFS, ext4) the clone is a sparse copy and the
  cost is what the disk holds, not twelve kilobytes.
* **The legacy qcow2 QEMU path.** An instance whose root is still a
  `disk.qcow2` overlay keeps its snapshots inside the disk; `ast rewind` refuses
  it by name and points at `ast snapshots` / `ast restore`. That refusal is unit
  tested and was not exercised on a real guest here.
* **The "nothing changed, so skip the pass" rule was not observed here.** The
  guest was an nginx serving HTTP probes, so its disk moved on every pass. The
  rule is unit tested (`asterism_core::rewind::due`, `changed_since`) and the
  fingerprint it rests on is length and mtime — see `docs/rewind.md` for what
  each backend can and cannot tell us.
* **Crash consistency was not stress tested.** An automatic snapshot is taken
  while the guest runs, so it is the disk a power cut would have left. ext4
  replayed and booted on every rewind in this run; nothing here proves that
  for a guest in the middle of a database write.
* **A rewind across a compute move, or of an instance with a remote NBD
  volume.** The block-volume path records "volume not snapshotted" and is unit
  tested; no NBD volume was attached in this run.

## Two known bugs this touches

* **AST-161** — a boot whose backend outcome is ambiguous leaves a durable boot
  fence, and the row then disagrees with itself about whether it is running. A
  rewind that cannot start the guest again reports `boot failed: <why>` and
  names that state rather than clearing the fence, which is exactly the
  compensation the fence exists to prevent. Not fixed here.
* A **pre-existing intermittent** guest-control handshake failure on VZ — "the
  host did not prove the instance key" — was reproduced on this tree with the
  snapshot scheduler switched off entirely (roughly one probe in twelve over
  four minutes). It predates this change. The lane retries the handshake and
  says so where it does.

## Two bugs this found

**The daemon held the port it was about to need.** The first green-adjacent
run failed with:

```text
boot failed: "bot" cannot publish 127.0.0.1:59511 -> :80/tcp on this device:
binding 127.0.0.1:59511 — another process or instance holds it
```

The daemon was holding the instance's own published host port. `ast down`
released it (`publish::retire`) but the rewind engine called the inner stop
directly and did not. Fixed by giving both paths one
`instance::down_completely`, which stops the guest and lets go of its volume
sockets, its egress door and its published ports together.

**`ast` was one subcommand from running out of stack on Windows.** CI's
`windows-compile` and `windows-hyperv` jobs both failed with `thread 'main'
has overflowed its stack` on the very first `ast` command, whichever one it
was. Windows gives a process's first thread whatever the executable header
asks for — one megabyte by default, an eighth of what Linux and macOS give —
and `Cli::parse()` builds the whole subcommand tree in one unwound frame in an
unoptimised build. Adding `ast rewind` was enough to exhaust it. Rationing
subcommands to fit a linker default is not a design, so `main` now runs the
CLI on a thread it sizes itself (8 MiB, which is what a main thread gets
everywhere else), on every platform rather than only on Windows.
