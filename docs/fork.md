# `ast fork` — one agent becomes five

There are three plausible ways to fix the bug. Pick one and you find out in an
hour. Fork the machine and you find out in three minutes.

```console
$ ast fork bot --n 3 --each "A: rewrite the parser" "B: patch the tokenizer" "C: add a fallback path"
bot-1 bot-2 bot-3 up — cloned from bot in 6.4 s, 1.9 GiB shared
$ ast ls
NAME   STATUS   …  TODAY   ACCESS   NOTE
bot    running  …  $0.06   …
bot-1  running  …  -       …        fork of bot @ 17:12 · A: rewrite the parser
bot-2  running  …  -       …        fork of bot @ 17:12 · B: patch the tokenizer
bot-3  running  …  -       …        fork of bot @ 17:12 · C: add a fallback path
$ ast diff bot-2
/work: 3 files changed, +41 −7 (vs bot @ 17:12)
$ ast pick bot-2
bot ← bot-2 (/work replaced; bot-1, bot-3 removed)   [confirm: y]
```

This is the thing tmux and ssh cannot do. A process cannot be copied; a
machine can.

## What a fork is

A crash-consistent snapshot of the parent — the same one
[`ast rewind`](rewind.md) takes on a timer, and taken the same way, so the
parent keeps running throughout — cloned copy-on-write into N new instances
that boot beside it. Same disk, same working directory, same secrets, same
profiles.

Because it is the rewind engine pointed sideways, it costs what a rewind
snapshot costs: on a filesystem with reflinks, almost nothing. Five forks of a
two-gigabyte agent are two gigabytes and change, not ten.

The forks are named `<parent>-1`, `<parent>-2`, … skipping any number already
spoken for, so forking twice in a row gives you `bot-4 bot-5 bot-6` rather
than a refusal.

## What a fork is not

A fork is not the parent, and gets its own identity and only its own:

| | |
|---|---|
| **name** | `bot-1`. The hostname, the cloud-init `instance-id` and the MAC are all derived from it, so a fork is a different machine on the network. |
| **guest key** | Minted at the fork's first boot. `agent.key` is deliberately not copied. |
| **uuid** | Fresh: a fork is constructed, not a cloned record. |
| **ports** | None. A host port is one number on one device and two instances cannot both have it — so five forks of a published instance all boot, rather than four of them refusing. `ast exec <fork>` and `ast ssh <fork>` reach them. |

What a fork *does* carry is the parent's **secret bindings, verbatim** — same
authority, same env name, same guest handle. The handle is a stand-in that was
baked into the disk the fork was cloned from, and it is honoured only by that
instance's own egress door. Minting a new one would leave the guest holding a
handle nothing answers. Credential parts ride the same bindings, so a forked
agent's `gh` still works for the same reason.

Two parts are not carried, and the report says so rather than dropping them
quietly:

* a **block volume** is single-writer and epoch-fenced; two instances cannot
  hold one;
* a **GPU** projection is a lease on a provider, and there is one of it.

## Volumes: copied, or shared

A fork's volumes follow the lifecycles from `ast attach --lifecycle`:

| lifecycle | on fork | why |
|---|---|---|
| `instance` (the default) | **copied** | It is the work. A fork that shared its parent's `/work` would not be a fork. |
| `memory` | **copied** | It is what the agent remembers. Three agents writing one set of notes is three agents overwriting each other. |
| `cache` | **shared** | It is rebuildable by definition — that is what declaring it a cache says — so three forks warm one of it between them rather than three. |

A copied volume keeps its mount point and its lifecycle, so a forked
`memory` volume is still that fork's memory and `ast rewind <fork>
--include-memory` rolls it back exactly as it would the parent's.

A `cache` is never the volume `ast diff` measures or `ast pick` replaces. It
is shared with the parent, so "what did this fork change in it" is a question
about a directory the fork does not own; an instance whose only local
directory is a cache is refused rather than guessed at.

## `--each` reaches the agent, not a file

A fork of an agent instance is an agent instance: its `agent.json` is copied
with it, so `ast session <fork>` and `ast logs <fork>` work on the fork the way
they work on the parent. The tmux session inside keeps the name it was created
with, because that name belongs to the guest — `ast session bot-1` attaches to
bot-1's own session, whatever it is called in there.

So `--each` is **typed into that session**, where a person sitting at
`ast session bot-1` would have typed it. The fork boots from a cloned disk, so
its agent comes up holding the same context the parent had, and the only thing
missing is the sentence saying which of the three approaches this copy is
meant to take.

```console
$ ast fork bot --n 3 --each "A: rewrite the parser" "B: patch the tokenizer" "C: add a fallback path"
bot-1 bot-2 bot-3 up — cloned from bot in 8.2 s, 316.48 MiB shared
bot-1 was told: A: rewrite the parser
bot-2 was told: B: patch the tokenizer
bot-3 was told: C: add a fallback path
```

The message goes in through a file and a tmux paste buffer rather than through
`send-keys -l`: an instruction is a sentence somebody wrote, and putting it in
argv would mean quoting it correctly through the daemon, `/bin/sh` and tmux in
turn.

A fork of a plain instance has no session to type into. Its message is
`.asterism-fork-note` in its own working volume — written by every fork,
agent or not — and the NOTE column of `ast ls`, which is where a human reads
it either way. `--stopped` forks get the file and nothing typed, because there
is nothing running to type into.

## What it costs

```console
$ ast fork bot --n 3
bot-1 bot-2 bot-3 up — cloned from bot in 6.4 s, 1.9 GiB shared
```

"Shared" is measured, not asserted: it is what the clones would have cost had
every byte been copied, minus how far this filesystem's free space actually
moved while they were made. Where the free-space reading is unavailable — or
where something else on the disk moved it further than the clone could have —
the line says `cloned` instead of `shared`, which is a number that is true
rather than one that flatters.

A fork is refused before anything moves when:

* the parent is not in this orbit, is in conflict, or is mid-move;
* more than nine forks were asked for without `--yes` (and more than 64 ever);
* `--each` was given a different number of messages than there are forks;
* a fork's name is free in the registry but its directory is still on disk;
* the disk cannot hold the clones. This last one is only checked where it
  matters: a three-byte probe decides whether this filesystem shares blocks,
  and where it does the check is a floor rather than an estimate — refusing a
  reflink clone of a 2 GiB disk because 10 GiB are not free would be refusing
  the feature on the machines it works best on.

## `ast diff` — what one fork changed

```console
$ ast diff bot-2
/work: 3 files changed, +41 −7 (vs bot @ 17:12)
$ ast diff bot-2 --against bot          # against the parent as it stands now
$ ast diff bot-2 --against before-pick  # against a snapshot of the parent
```

Both trees are on this device's disk — the fork's working volume, and the
parent's snapshot of it at the fork point — so this is read from the host
side and no guest has to be running.

`git` counts it when the volume is a repository, because that is where the
agent's own numbers come from: it honours the repository's ignore rules, so a
`/work` with a rebuilt `target/` in it reports the source that changed rather
than the artefacts. Specifically, the fork is diffed against **the commit the
parent was on at the fork point** — that object is in the fork's own store,
because the store was cloned with everything else — plus whatever is untracked
and not ignored. A fork whose agent has committed is therefore still measured
against where it started.

Without `git`, or on a volume that is not a repository, both trees are walked
and compared file by file. Every file counts then, including ones a
`.gitignore` would have hidden, and the summary says so.

## `ast pick` — keep one and retire the rest

```console
$ ast pick bot-2
bot ← bot-2 (/work replaced; bot-1, bot-3 removed)   [confirm: y]
the /work it replaced is kept as "before-pick" — `ast rewind bot --to before-pick` undoes this
```

In order: stop the parent, snapshot what it currently has as `before-pick`,
replace its working volume with the fork's, start it again, remove the sibling
forks.

The parent's **root disk is deliberately untouched**. What the agent produced
is in the working volume; the rest of the fork's disk is a copy of the
parent's own from an hour ago, and putting that back would undo everything the
parent did while the forks ran.

The winning fork **survives** the pick. It is still running the agent that
won, and it is often the thing you want to look at next; `ast rm bot-2`
retires it when you are done. Only its siblings go.

`before-pick` is a named snapshot, so it never expires. Two round trips make
the confirmation honest: the daemon is asked what it *would* do, the exact
sentence it answers with is the sentence you agree to, and only then does
anything move. `--yes` skips the question; a pipe with nothing in it is not a
yes.

## Refusals

| | |
|---|---|
| `ast pick` on something that is not a fork | it has no parent to hand work back to |
| `ast pick` when the parent has no local directory volume | there is nothing to replace |
| `ast diff` on something that is not a fork | say what to compare against: `--against <instance>` |
| either, on an instance with no local directory volume | there is nothing on this disk to compare |

## Where the forks live

A fork's copy of the working volume lives inside the fork's own instance
directory, at `instances/<fork>/volumes/vol<n>`, so `ast rm` takes it with it
and no two forks ever point at one directory. The parent's volume stays
exactly where it was — a fork never writes to somebody's real checkout.

## Known limits

* `--each` is delivered once, at fork time. There is no `ast tell <fork>` for
  a second instruction; `ast session <fork>` is.
* Fork names are checked against this device's own registry, not claimed
  orbit-wide the way `ast create` claims one. They are derived from a name
  that *is* orbit-unique, and an actual clash surfaces as the ordinary
  `conflict` row.
