# `ast fork`, `ast diff` and `ast pick` on real VZ guests — 2026-08-27

`scripts/e2e-fork.sh`, run on real hardware. Four machines: one parent and
three forks of it, all booted, all edited independently, one picked.

**Host.** MacBook Pro, macOS 26.5.2 (25F84), arm64. Backend `vz`
(Virtualization.framework) through the ad-hoc-signed `astd-vz` helper built
from this tree. Image `docker.io/library/nginx:alpine`, an OCI rootfs booted
with a direct kernel. Scratch `ASTERISM_HOME` under `/private/tmp`,
`ASTERISM_MESH=local`, automatic snapshots turned down to `1h` so the
scheduler could not land a clone in the middle of the measurement.

`/work` is a real git repository on the host share, committed before the
parent boots, so `ast diff` takes its git path — the one an agent's own
numbers come from. The parent also carries a `cache` volume at `/cache` and a
`memory` volume at `/memory`, so the lane exercises AST-158's lifecycles.

Files here:

| file | what it is |
|---|---|
| `e2e-fork.log` | the whole run, green |
| `astd.log` | the daemon's own log for that run |
| `fork.txt` | `ast fork bot --n 3 --each ...` |
| `ls.txt` | `ast ls` with the NOTE column, four rows |
| `diff.txt` | `ast diff` for each of the three forks |
| `pick.txt` | `ast pick bot-2 --yes` |
| `ls-after-pick.txt` | `ast ls` afterwards: the siblings gone, the winner still here |
| `undo.txt` | `ast rewind bot --to before-pick` |
| `cost.txt` | wall clock, and the free space the three clones really cost |

## The run

```console
$ ast fork bot --n 3 --each "A: rewrite the parser" "B: patch the tokenizer" "C: add a fallback path"
bot-1 bot-2 bot-3 up — cloned from bot in 9.0 s, 316.55 MiB shared
the forks publish no ports: 1 host port belongs to bot and cannot be in two places — `ast exec <fork>` and `ast ssh <fork>` reach them

$ ast ls
NAME           STATUS    IMAGE          SHAPE            COMPUTE   AGE    TODAY    ACCESS                NOTE
bot            running   nginx:alpine   2c/1024M/4G      …         14s    -        192.168.64.35:22      -
bot-1          running   nginx:alpine   2c/1024M/4G      …         10s    -        192.168.64.39:22      fork of bot @ 20:10 · A: rewrite the parser
bot-2          running   nginx:alpine   2c/1024M/4G      …         10s    -        192.168.64.40:22      fork of bot @ 20:10 · B: patch the tokenizer
bot-3          running   nginx:alpine   2c/1024M/4G      …         10s    -        192.168.64.41:22      fork of bot @ 20:10 · C: add a fallback path

$ ast diff bot-1
/work: 1 file changed, +2 −1 (vs bot @ 20:10)
$ ast diff bot-2
/work: 3 files changed, +4 −2 (vs bot @ 20:10)
$ ast diff bot-3
/work: 1 file changed, +1 −0 (vs bot @ 20:10)

$ ast pick bot-2 --yes
bot ← bot-2 (/work replaced; bot-1, bot-3 removed)
the /work it replaced is kept as "before-pick" — `ast rewind bot --to before-pick` undoes this

$ ast rewind bot --to before-pick
bot rewound to 20:10 (3.4 s) — current state kept as "before-rewind"
```

## Proves

1. **Three forks of a running instance, in nine seconds, on one command.**
   The parent was running and stayed running throughout; nothing stopped it.
   All three forks booted.

2. **The clone is copy-on-write and the report is honest about it.** The line
   says `316.55 MiB shared` — that is what three copies of the snapshotted
   root disk and `/work` would have cost had every byte been written, minus
   how far APFS free space actually moved while they were made. Four
   independent runs measured around the *whole command* instead put it at
   8.5 MiB, 9.8 MiB, 29 MiB, 90 MiB, minus 11.5 MiB and minus 1.2 GiB — which is the
   caveat below making itself very visible, and why that window is reported
   and never asserted on.

3. **Every fork is its own machine.** Each reported its own hostname
   (`bot-1`, `bot-2`, `bot-3`) over its own authenticated guest-control
   channel — a fresh `agent.key` per fork, since `agent.key` is not copied —
   on its own NAT address with its own MAC.

4. **No fork publishes the parent's port.** The parent held a published host
   port; the forks declared none, and the line said so. All three booted,
   rather than two of them refusing a port that was taken.

5. **Each fork writes into its own `/work` and nobody else's.** Three
   independent edits, from inside three guests, verified absent from the
   parent's own host share and from each other.

6. **`--each` reaches the guest.** Each fork read its own message out of
   `/work/.asterism-fork-note`, and `ast ls` printed the same message in the
   NOTE column beside the row it belongs to.

7. **`ast diff` counts each fork's own work, against the fork point, with
   git.** bot-2 touched three files (one edit, one edit, one new) and its
   diff says three; bot-1 and bot-3 touched one each and say one. The
   `.asterism-fork-note` Asterism wrote is excluded — a diff is about what
   the agent did.

8. **`ast pick` moves the winner's work onto the parent and retires the
   rest.** After the pick the parent's guest read bot-2's edited `parser.txt`
   and bot-2's new `fallback.txt`, on both sides of the share; `ast ls`
   showed bot-1 and bot-3 gone and bot-2 still there.

9. **A `cache` volume is shared and a `memory` volume is copied** — AST-158's
   lifecycles, at the one place a fork asks about them. `ast fork` said out
   loud that `/cache` is shared; fork 1 wrote into `/cache` and fork 2, the
   parent and the host directory all saw it. Fork 1 and fork 2 then wrote
   different things to `/memory/notes`, each kept its own, and neither
   reached the parent's.

10. **A pick is undoable.** `before-pick` was on the parent's timeline, and
   `ast rewind bot --to before-pick` put the parent's own `/work` back — the
   guest read `three`, not `THREE` — and the parent came back up.

11. **Refusals happen before anything moves.** A parent that is not in the
    orbit, twelve forks without `--yes`, and `--each` with two messages for
    three forks were all refused, and the parent was still `running`
    afterwards.

## Does not prove

* **Nothing about the accuracy of `316.55 MiB shared` beyond the window it
  measures.** That figure is `st_blocks` of what was cloned minus a
  free-space delta taken across the clone and *before* the forks boot. The
  `cost.txt` figure is a different window — `df` around the whole `ast fork`,
  three guest boots included, on a shared machine — and it is **not evidence
  of anything**. It came out at 8.5 MiB, 90 MiB and minus 1.2 GiB on different
  runs of the same code, because everything else on the host writes to the
  same filesystem. It is printed because a lane that measured nothing would be
  worse, and asserted on nowhere. Neither number is a claim about steady-state
  cost, which grows as each fork's disk diverges from its parent's.

* **Nothing on a filesystem without reflinks.** APFS clones. The headroom
  refusal for a filesystem that copies is exercised by a unit test and by the
  three-byte probe, not by this lane.

* **Nothing about `chv` or Hyper-V.** The lane runs on either `vz` or `chv`;
  this evidence is `vz` only.

* **Nothing about secret or credential parts surviving a fork.** Bindings —
  plain secrets and AST-157 credential parts alike — are carried verbatim,
  which is a design decision (see `docs/fork.md`) exercised only by the type
  system. The parent here binds none.

* **Nothing about forking an instance with a block volume, a GPU, or a
  non-local directory share.** Those are reported as not carried, and the
  wording of that report is covered by unit tests rather than here. The two
  volume lifecycles the lane *does* exercise are `cache` and `memory`; a
  `memory` volume rolled back on a fork with `ast rewind --include-memory`
  is not covered.

* **Nothing about `--each` reaching a real agent session.** The parent in
  this lane is a plain `ast create` instance, not an `ast create --agent` one,
  so it has no `agent.json` and no tmux session. What the lane proves is the
  fallback: every fork got `.asterism-fork-note` in its own volume and its own
  line in the NOTE column. That an agent fork's `agent.json` is carried and
  the message is typed into its session needs a preset, an agent image and
  real credentials, and is not in this lane.

* **Nothing about the interactive confirmation.** The lane uses `--yes`. That
  a bare `ast pick` asks first, and that the sentence it asks with is the one
  the daemon planned, is covered by the two-round-trip structure and by the
  CLI's own path, not by this run.

* **Nothing about concurrency.** One `ast fork` at a time. Two overlapping
  forks of the same parent would race on name allocation, which the registry
  refuses at adopt rather than this lane demonstrating.
