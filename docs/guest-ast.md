# `ast` inside the box

```
agent@bot:~$ ast snapshot before-schema-migration
snapshot "before-schema-migration" taken (0.02 s)
agent@bot:~$ ast cost
today      $0.06   3500 in · 790 out · cache 54k   claude-sonnet-5 (12 calls)
agent@bot:~$ ast ask "Change the prod schema now (A) or tomorrow morning (B)?"
waiting for a reply… (your owner has been notified)
A
agent@bot:~$ ast notify "PR #42 opened — ready for review"
agent@bot:~$ ast fork --n 3 --each "rewrite it in one pass" --each "port the tests first" --each "leave the API alone"
bot-1 bot-2 bot-3 up — cloned from bot in 6.4 s, 1.9 GiB shared
agent@bot:~$ ast snapshot other-bot x
error: "other-bot" is not this instance — inside the box, ast acts on bot only
```

and, on the machine the box is running on:

```
$ ast tell bot "run the test suite and fix what fails"
sent to bot — follow with: ast logs bot -f
$ ast inbox
 14:02  bot  ask     Change the prod schema now (A) or tomorrow morning (B)?   [reply: ast inbox reply 1 …]
 14:31  bot  notify  PR #42 opened — ready for review
$ ast inbox reply 1 A
replied to bot
```

## What this is for

An agent that runs unattended for a week is not short of a shell. It is short
of everything *about* the machine, and short of any way to reach the person
who owns it. It cannot take a snapshot before it migrates a schema. It cannot
see what it has spent. It cannot say "the pull request is open", and it cannot
ask a question and wait for the answer. It has a terminal and no channel.

That is the gap between "an agent on a VM" and "an agent on Asterism", and it
is the only thing in this document.

**Leverage, never restriction.** Nothing here can refuse work the agent was
going to do anyway. There is no approval gate, no allowlist of tasks, and no
path by which a person blocks an agent. `ast ask` blocks because *the agent
chose to ask*, and it stops blocking on its own. The moment a daemon can hold
an agent's work pending a human, the product is a slower human rather than a
faster agent.

## The six verbs

| | |
|---|---|
| `ast snapshot [name]` | keep this disk exactly as it is. Fractions of a second, and it works on a *running* machine — which is the only kind an agent can snapshot of itself |
| `ast rewind` | the timeline. `--to <name>` or a duration goes back, which restarts the machine, so the command that asked for it does not return |
| `ast cost` | what this instance has spent on model calls today |
| `ast fork --n 3` | three copies of this machine, running. `--each "…"` once per fork tells each one what to try |
| `ast notify "…"` | tell the owner something. Does not wait |
| `ast ask "…"` | ask the owner something and wait. The answer arrives on stdout |

`ast rewind --include-memory` is the same flag it is on the outside: memory
volumes are left alone unless somebody asks, so `claude --resume` on the other
side of a rewind is still the same conversation.

When something the agent asked for fails, it reads the daemon's own sentence
rather than a second translation of it: the box's `ast rewind --to x` whose
guest will not come back prints the same *boot failed: … — the disk is rolled
back, so* `ast up bot` *is the …* a person gets on the host, because
`Response::Error` is passed through verbatim.

`ast fork` inside the box forks *this* machine and takes `--yes` for granted:
there is nobody at a terminal for it to confirm the soft limit to, and asking
would be the approval gate this feature does not have. The children inherit
nothing of the channel — each gets its own pump and its own freshly minted
token when it boots, so forking is not a way to copy somebody's authority.

`ast ask` waits four hours by default and `--timeout 30m` changes it. A
timeout is the agent carrying on, not the question being thrown away: the
question stays in the inbox and can still be answered — the reply then says so
rather than pretending it unblocked anything.

There is no `ast secret` in the box, and asking for one is answered rather than
ignored:

```
agent@bot:~$ ast secret ls
error: the values behind this box's credentials are not in it, and `ast` here cannot read them — that is the feature
  fix: ast ask "I need <what> to do <why> — can you bind it to bot?"
```

## The two verbs on the outside

`ast tell <name> "…"` types one line into the instance's agent session and
presses Enter, so the agent reads it the way it reads anything else you type.
It routes by bare name across the orbit like every other instance command —
you never say which device. With no session to type into it refuses and names
the command that makes one.

`ast inbox` lists what this device's agents have said. It is **device-local**,
the way `ast cost --all` is: the daemon holding the open guest-control session
an `ast ask` is parked on is the only one that can hand an answer back, and a
listing that spanned the orbit while the reply did not would be the worse half
of two designs. `ast inbox reply <n> <text>` is the answer.

When something arrives while you are watching, `ast logs <name> -f`
interleaves one line and rings the terminal bell:

```
── bot ask     Change the prod schema now (A) or tomorrow morning (B)?   [reply: ast inbox reply 1 …]
```

## How it works

### One binary, two names

`ast` in the guest is a symlink to the guest agent Asterism already injects
into every OCI guest at boot. Invoked as `ast`, that binary is a client that
writes one JSON object to a guest-local unix socket and prints what comes
back. It knows nothing about any command — every sentence an agent reads,
including the refusals and the help, is written by the daemon on the host.

That is why `ast cost` inside the box and `ast cost bot` outside it print the
same line: it is the same function
(`asterism_core::ledger::line`), called once.

No second artifact is built, audited, or shipped, and no agent image changes.
The symlink is made at boot beside the binary itself, so an agent image stays
a plain OCI image anyone can `docker run`.

### Which way the wire points

Guest control is host-initiated and stays that way. The guest never dials the
host — there is no listener on the host for a guest to reach, and adding one
would be a new attack surface for a feature that does not need it. So the
daemon parks one authenticated session per running instance on a long poll:

```text
   agent in the box        the guest agent            astd on the host
   ast ask "…"      --->  queued, blocks
                          <---------------------  agent_next (400 ms poll)
                          ---------------------->  {id, token, ["ask", "…"]}
                                                   write it to the inbox
                          <---------------------  agent_reply {id, no status}
   "waiting…"       <---  interim write
                               … minutes …
                                                   ast inbox reply 1 A
                          <---------------------  agent_reply {id, 0, "A"}
   "A"              <---  final, and the socket closes
```

Three guest-control operations, all behind protocol version **3**:
`agent_arm`, `agent_next`, `agent_reply`. A guest from before this feature
negotiates version 2 and no pump is started — nothing is wrong, `ast` simply
is not in that box. The older Python agent on cloud-image guests speaks
version 1, so this is an OCI-guest feature.

### The token

Every pump mints 32 bytes of fresh randomness and hands it to the guest agent
over the channel that has already proved the instance key. The guest agent
keeps it in memory and stamps it on every call it forwards.

**The agent in the box never sees it.** It is not written to any file, so it is
absent from the disk image, from every snapshot, and from a bug report. A
reboot, a rewind and a fork each end a pump and start another, which mints a
new one and makes the old one meaningless.

What it buys is scope. The daemon decides which instance a call is about from
the token *it* minted, never from anything the call said. So `ast snapshot
other-bot x` inside the box does not become a snapshot of `other-bot`; it
becomes the sentence at the top of this page. The agent is root in its own
machine and this does not pretend otherwise — it says that being root in one
machine is not authority over a second one.

The guest-local socket is deliberately reachable by anything in the guest.
Everything in the box *is* the agent, and a call through it can do nothing the
instance could not already do to itself.

### The inbox file

`$ASTERISM_HOME/inbox.jsonl`, append-only, two record shapes folded on read:

```json
{"record":"said","seq":1,"at":1756303320,"instance":"bot","kind":"ask","text":"…"}
{"record":"replied","seq":1,"at":1756305180,"text":"A"}
```

Append-only because the interesting failure is a crash between "the agent
asked" and "the owner answered", and a file that is only ever appended to
cannot lose the first half while writing the second. A torn last line is
skipped rather than fatal. `$ASTERISM_HOME/inbox/<name>.idx` holds one
sequence number per line — the answer to "which of these are bot's" without
reading anybody else's inbox, which is what `ast logs bot -f` watches.

The set of `ast ask` calls currently parked is in memory only. A daemon
restart therefore ends every wait, and the agent is told so; the questions
themselves survive, because they are in the file.

## What is not here

**Pushing to a phone.** That is AST-154, and the hook it will attach to is
`crate::inbox::Event` plus `crate::inbox::subscribe` in the daemon — emitted
for every message an agent leaves, with nothing subscribed in this build. It
is there so the hosted client has one place to attach rather than a reason to
reach into the file.

**Cloud-image guests.** The Python agent that serves them speaks protocol 1.
Adding these operations to it is possible and has not been done, because the
agent presets this feature exists for are all OCI images.

## See also

- `presets/AGENT-SNIPPET.md` — what to put in a `CLAUDE.md` or `AGENTS.md` so
  the agent knows these verbs exist. `ast create --agent` writes it to
  `<workdir>/.asterism/AGENT-SNIPPET.md` in the box.
- `docs/agents.md` — the agent scene it sits inside.
- `docs/rewind.md`, `docs/cost.md` — the two features it exposes.
- `docs/evidence/guest-ast-2026-08-27/` — the real-hardware run.
