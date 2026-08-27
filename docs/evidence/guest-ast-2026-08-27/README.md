# `ast` inside the box, on a real VZ guest — 2026-08-27

The agent runs `ast snapshot`, `ast cost`, `ast fork`, `ast notify` and
`ast ask` for itself; the person who owns it runs `ast tell` and `ast inbox`;
and the per-instance token that scopes all of it is written down nowhere.

Device: Apple Silicon MacBook Pro, `Darwin 26.5.2`, native
Virtualization.framework backend through an ad-hoc signed `astd-vz` built from
this tree, `ASTERISM_MESH=local`, scratch `ASTERISM_HOME`. Reproduce with
`scripts/e2e-guest-ast.sh`.

The guest agent — which is also `ast` in the box, under a second name — was
cross-built for `aarch64-unknown-linux-musl` in a `rust:alpine` container,
because `scripts/build-guest-control-artifact.sh` requires a Linux builder and
this host has no musl cross toolchain. The ELF was checked before use: 64-bit,
AArch64, and no `INTERP` (statically linked, which is what lets it run in a
`FROM scratch` image).

- guest agent SHA-256:
  `444c2e3c52190bb1451f1e698a7de0da6cfbe08685498b97d2fb43b95ff3d0ca`

The image is built by `docker` on the device and served from a throwaway
registry pair the lane starts, because this repository has no GHCR publishing
credential (`.github/workflows/agent-images.yml` has never run). Asterism pulls
it over HTTPS **by digest**, through the product's own puller, with every blob
verified against the digest its manifest named. The key is a dummy,
`sk-ant-test-0000-<pid>-<random>`; no real credential was used.

## Command

The lane ran outside the tool sandbox, which deliberately forbids the local
unix socket the real daemon owns:

```sh
CARGO_TARGET_DIR=<scratch>/target-ast156 \
ASTERISM_GUEST_AGENT_ARTIFACT=<scratch>/guestbuild/asterism-guest \
bash scripts/e2e-guest-ast.sh
```

## What it printed

```text
== building the agent image
ok: built the agent image
ok: a local registry pair is serving on localhost:5110 and localhost:5453
ok: pushed the agent image as sha256:a605e5981084647f895f13af56fcdb93c07ebb812392ce4766850be04f633196
ok: a user preset points claude-code at the locally built image, pinned by digest
pulling localhost:5453/agent-claude-code@sha256:a605e598… … done (1.0 GiB, 30 s)
bot is up — claude-code 2.1.247, session "bot" running
ok: an agent instance is up on the native VZ backend
ok: the workspace carries the snippet that tells the agent about all this
ok: ast in the box is a symlink to the agent Asterism injected, not a second artifact
today      -   0 in · 0 out   1 call
ok: ast cost in the box printed this instance's spend
snapshot "before-schema-migration" taken (0.01 s)
ok: an agent snapshotted its own running machine, and the host sees it
 20:54  bot  notify  PR #42 opened — ready for review
ok: ast notify reached the host's inbox and said nothing in the box
 20:54  bot  notify  PR #42 opened — ready for review
 20:54  bot  ask     Change the prod schema now (A) or tomorrow morning (B)?   [reply: ast inbox reply 2 …]
ok: the agent's question is in the inbox, with the command that answers it
replied to bot
waiting for a reply… (your owner has been notified)
A
ok: the agent asked, blocked, and read the answer a person typed on the host
bot-1 bot-2 defined — cloned from bot in 0.0 s, 1.80 GiB shared
ok: the agent forked its own machine, and the host has the children
error: "other-bot" is not this instance — inside the box, ast acts on bot only
ok: naming another instance is refused by the sentence, for snapshot and for fork
error: the values behind this box's credentials are not in it, and `ast` here cannot read them — that is the feature
  fix: ast ask "I need <what> to do <why> — can you bind it to bot?"
ok: reading a credential value is refused, with the reason and the way to ask
sent to bot — follow with: ast logs bot -f
ok: ast tell reached the running agent's session and said so
ok: the line and its Enter both landed in the session named after the instance
ok: telling a machine that is not there is refused
ok: the box has the socket and no copy of the token
ok: a bug report has no token in it
ok: no file this device wrote holds a channel token
GUEST AST E2E GREEN (vz, localhost:5453/agent-claude-code@sha256:a605e598…)
```

The two transcripts the issue asked for, as they actually came out — the guest
half run through `ast exec bot -- sh -c 'cd /work && ast …'`, which is how a
harness types what a person would type at the agent's own prompt:

```
agent@bot:/work$ ast cost
today      -   0 in · 0 out   1 call
agent@bot:/work$ ast snapshot before-schema-migration
snapshot "before-schema-migration" taken (0.01 s)
agent@bot:/work$ ast notify "PR #42 opened — ready for review"
agent@bot:/work$ ast ask "Change the prod schema now (A) or tomorrow morning (B)?"
waiting for a reply… (your owner has been notified)
A
agent@bot:/work$ ast fork --n 2 --stopped
bot-1 bot-2 defined — cloned from bot in 0.0 s, 1.80 GiB shared
agent@bot:/work$ ast snapshot other-bot x
error: "other-bot" is not this instance — inside the box, ast acts on bot only
agent@bot:/work$ ast secret ls
error: the values behind this box's credentials are not in it, and `ast` here cannot read them — that is the feature
  fix: ast ask "I need <what> to do <why> — can you bind it to bot?"
```

```
$ ast inbox
 20:54  bot  notify  PR #42 opened — ready for review
 20:54  bot  ask     Change the prod schema now (A) or tomorrow morning (B)?   [reply: ast inbox reply 2 …]
$ ast inbox reply 2 A
replied to bot
$ ast tell bot "run the test suite and fix what fails"
sent to bot — follow with: ast logs bot -f
```

The money column is `-` rather than a figure because the run's key is a dummy:
Claude Code made exactly one call through the door on startup, the provider
answered 401, and a 401 carries no token counters and no model name — so there
is one call, nothing to price, and the ledger says so instead of guessing. The
line's shape is `asterism_core::ledger::line`, the same function `ast cost bot`
prints on the host.

## Proves

* **`ast` is in the box, and it is not a second artifact.**
  `/usr/local/bin/ast` is a symlink to `/.asterism/guest`, the same audited
  static ELF Asterism already injects into pid 1's generated init at boot. The
  agent image is unchanged and still a plain OCI image.
* **An agent can snapshot its own *running* machine**, in hundredths of a
  second, and the snapshot lands on the timeline `ast rewind bot` prints on the
  host. This is the thing `ast snapshot bot <tag>` on the outside refuses to do
  and the automatic snapshots behind `ast rewind` already do.
* **`ast cost` inside the box answers about this instance** and prints the
  host's own line.
* **`ast notify` reaches a person and says nothing to the agent.** The entry is
  in `$ASTERISM_HOME/inbox.jsonl` and `ast inbox` renders it.
* **`ast ask` is a real round trip.** The agent blocked; the question appeared
  in the inbox carrying the exact command that answers it; a reply typed on the
  host arrived on the agent's stdout as `A`; the agent exited 0.
* **`ast fork` from inside forks this machine.** Two children, copy-on-write,
  1.79 GiB shared, and they are in the host's registry.
* **Scoping holds.** `ast snapshot other-bot x` and `ast fork other-bot --n 2`
  are both refused with the same sentence, and nothing was created. The daemon
  decides which instance a call is about from the token it minted, not from the
  words in the call.
* **A credential value cannot be read from inside**, and the refusal says why
  and how to ask for one instead. The dummy key does not appear in the refusal.
* **`ast tell` delivers keystrokes to the session named after the instance.**
  Proved by putting a plain shell in that session and telling it
  `echo asterism-tell-landed`, then finding that string in `tmux capture-pane`
  — which requires the literal line *and* the Enter to have arrived at the
  right session. Telling an instance that does not exist is refused.
* **The channel token is written down nowhere.** Nothing under `/etc`, `/run`,
  `/work` or `/root` in the guest names it; `ast bugreport` has no token in it;
  and after `ast down` and a fresh `ast snapshot`, no file anywhere under
  `$ASTERISM_HOME` holds one. By construction it exists only in the daemon's
  memory, the guest agent's memory, and on the wire between them — the agent in
  the box is never given it.

## Does not prove

* **That the token is unguessable in the sense a cryptographer would want.**
  It is 32 bytes from `asterism_core::guest::nonce()`, the same source the
  guest-control handshake nonces come from, and the run does not test that.
  What the run tests is that it is *absent* from every place a person or an
  agent could read it.
* **That a compromised guest cannot make calls as itself.** It can, and that is
  correct: everything in the box is the agent, and a call through the
  guest-local socket does nothing the instance could not already do to itself.
  The property under test is that it cannot act on a *second* instance.
* **Anything about cloud-image guests.** They run the older Python agent, which
  speaks guest protocol 1; negotiation refuses the new operations cleanly and
  no pump is started, so `ast` is simply not in those boxes. Not exercised here.
* **Any backend but VZ.** QEMU, Cloud Hypervisor and Hyper-V reach guest
  control through the same `Session`, and the code paths are shared, but this
  run was macOS/VZ only.
* **A hosted push.** Nothing rings a phone. `crate::inbox::Event` and
  `crate::inbox::subscribe` are the documented hook and have no subscriber in
  this build — that is AST-154.
* **`ast logs bot -f` interleaving.** The bell and the one-line notice are
  written and unit-tested against the renderer, but following a log is an
  interactive command and this lane does not drive one.
* **The forks' own channels.** The two forks were made `--stopped`, so this run
  did not observe them booting and minting tokens of their own.
* **Long waits.** The `ast ask` in this run was answered in seconds. The
  four-hour default, the `--timeout` override and the timeout sentence are
  covered by unit tests, not by this lane.
