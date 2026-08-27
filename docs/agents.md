# Agents

```
$ ast secret add ANTHROPIC_API_KEY
$ ast create bot --agent claude-code --repo https://github.com/me/app.git
pulling ghcr.io/medicalissue/agent-claude-code:0.1.0 … done (410 MiB, 21 s)
bot is up — claude-code 2.1.247, repo cloned to /work/app, session "bot" running
$ ast attach bot
# inside the tmux session with Claude Code's prompt; Ctrl-b d detaches, the
# agent keeps running
```

`ast session bot` and `ast ssh bot` land in the same place, and `ast session`
is the spelling to reach for: `ssh` is about a shell, `attach` is about parts,
and this is about neither. A bare `ast attach <agent>` works because that is
what people type, and because it used to be an error.

That is the whole surface. This document is about what is behind it, and how
to point it at an agent Asterism does not ship.

## What this gets you that tmux, ssh and a VPN do not

Two things.

**The key never enters the box.** `ast secret add ANTHROPIC_API_KEY` (the
older spelling, `ast secret create`, is the same command) reads the value on
stdin and puts it in this device's OS credential store. The guest is given an
*opaque handle* in `$ANTHROPIC_API_KEY`, shaped like the credential it stands
in for — `sk-ant-ast-…` for Anthropic, `sk-ast-…` for OpenAI, `ast-…` for an
authority with no house style — and this device's egress door swaps that
handle for the real value on its way to `api.anthropic.com` and to nothing
else. The consequences are the point:

* the root disk has a handle in it, not a key, so a snapshot of it does not
  carry a credential and can be moved, copied, or handed to somebody;
* `ast logs`, `ast bugreport` and the guest's console have a handle in them;
* an agent that runs code it found on the internet cannot exfiltrate a key it
  was never given, and cannot spend the one it has anywhere but the one
  authority the binding names;
* `ast detach bot --secret ANTHROPIC_API_KEY` stops the handle being honoured
  immediately, on connections the guest already has open.

**It is one command and it is repeatable.** The agent, the runtime it needs,
git, and tmux are in a pinned image, so the second machine you do this on gets
the same thing as the first. The workspace is a shared directory on this
device, so the root disk stays disposable — snapshot and restore it, or throw
the instance away and make it again, and the repository and the session's
history are where you left them — and the clone is a directory you can open in
your own editor while the agent works in it.

## The pieces

| | |
|---|---|
| **Preset** | `presets/<name>.json` — the image, the secrets, the start command, the workdir |
| **Image** | `ghcr.io/medicalissue/agent-<name>` — Debian + node LTS + the agent CLI + git + tmux + sshd |
| **Instance** | An OCI-rootfs VM, `restart=always`, with the preset's secrets bound as handles |
| **Workspace** | `~/.asterism/work/<name>`, shared into the guest at the preset's `workdir` (`/work`), holding the repo, the session's start script and the pane log |
| **Session** | tmux, named after the instance, started at create and again at every boot |

## `ast create --agent`, step by step

1. Resolve the preset.
2. **Refuse, before anything is made**, if a required secret is not in the
   orbit:
   ```
   $ ast create bot2 --agent codex
   error: preset codex needs secret OPENAI_API_KEY — run `ast secret add OPENAI_API_KEY` first
     fix: ast secret add OPENAI_API_KEY
   ```
   Nothing is pulled, nothing is created, nothing needs cleaning up.
3. Pull the preset's image, by digest when the preset pins one.
4. Create the instance from that image, with no bootstrap profiles: everything
   the agent needs is already in the image.
5. Make `~/.asterism/work/<name>` and share it into the guest at the preset's
   workdir.
6. Bind each of the preset's secrets that this orbit has, to the one authority
   the preset names, in the environment variable the preset names.
7. `ast up --restart always`.
8. Wait for the guest to be a *workspace*, not merely booted: the workspace is
   mounted, sshd is up, and the image's entrypoint has touched
   `/run/asterism-agent.ready`.
9. Through the authenticated guest-control channel, write this device's guest
   public key, the list of variable names to publish to login shells, and the
   session's start script — all into the workspace.
10. Clone `--repo` into the workspace. When the preset declares `GITHUB_TOKEN`
    and the orbit has one, git is handed the handle as an `Authorization`
    header rather than in the url, so nothing lands in `.git/config`.
11. Ask the agent its version, start the tmux session, and print one line.

## Presets are not profiles

`ast create --profile claude` and `ast create --agent claude-code` both end
with a machine that has Claude Code on it, and they are not the same thing.

A **profile** installs into a general-purpose cloud image at first boot: it is
additive, it composes with other profiles, and it is what you want when the
guest is a machine you also do other things with. It costs a minute of network
per first boot and it follows whatever npm publishes today.

A **preset** boots an image that already is the agent, pinned by digest. It is
what you want when the guest is *for* the agent: it is the same bytes on every
device, it comes up in the time it takes to copy a filesystem, and it brings
the session, the workspace volume and the secret bindings with it.

They are refused together — `--agent` and `--profile` in one command is a
question with no answer — and neither is going away.

## `ast session`, `ast attach`, `ast logs`

`ast session <name>` is ssh with a tty running `tmux new-session -A -s <name>`
— attach if it is there, start it with the preset's command if it is not.
`Ctrl-b d` detaches and the agent keeps running, because the session belongs to
the guest and not to your terminal.

`ast logs <name>` prints the agent's tmux pane, captured by `tmux pipe-pane`
into `<workdir>/.asterism/agent.log` on the volume. `-f` follows it. The
guest's serial console — Asterism's init and the image's entrypoint — is still
there under `ast logs <name> --console`.

## The agent can run `ast` too

The other half of what this gets you over tmux and a VPN, and the half that
only matters once the agent has been running for a day: inside the box, `ast`
is there.

```
agent@bot:~$ ast snapshot before-schema-migration
snapshot "before-schema-migration" taken (0.02 s)
agent@bot:~$ ast ask "Change the prod schema now (A) or tomorrow morning (B)?"
waiting for a reply… (your owner has been notified)
A
agent@bot:~$ ast notify "PR #42 opened — ready for review"
```

and you are the other end of it:

```
$ ast tell bot "run the test suite and fix what fails"
sent to bot — follow with: ast logs bot -f
$ ast inbox
 14:02  bot  ask     Change the prod schema now (A) or tomorrow morning (B)?   [reply: ast inbox reply 1 …]
 14:31  bot  notify  PR #42 opened — ready for review
$ ast inbox reply 1 A
replied to bot
```

Six verbs in the box — `snapshot`, `rewind`, `cost`, `fork`, `notify`, `ask`
— and two outside it. Nothing in there can refuse the agent anything: `ast ask`
blocks because the agent chose to ask and times out on its own, and there is
no approval gate anywhere in the feature. `docs/guest-ast.md` is the whole of
it, including the per-instance token that makes `ast snapshot other-bot` a
sentence rather than a snapshot.

### Telling the agent it has them

An agent only uses a tool it has been told about. `presets/AGENT-SNIPPET.md`
is the paragraph to put in a `CLAUDE.md` or an `AGENTS.md`: snapshot before
risky work, ask when a decision is expensive, notify when something is worth
knowing. `ast create --agent` writes it into the box at
`<workdir>/.asterism/AGENT-SNIPPET.md` — beside `start.sh` rather than into
the repository, because the repository belongs to whoever cloned it. Point the
agent at that path, or paste the file into whatever it already reads.

## Removing one

`ast rm <name>` deletes the instance, its root disk and its snapshots. It does
**not** touch `~/.asterism/work/<name>`, for the same reason it never deletes a
volume's bytes: the repository and the pane log are in there, and a week of an
agent's work is not something a command about an instance should be able to
remove. Deleting that directory is yours to do.

## Writing your own preset

Drop a file in `~/.asterism/presets/`. A file whose `name` matches one
Asterism ships replaces it, which is how you pin your own build of an agent
image without patching Asterism. `ast agents` lists what this device knows.

```json
{
  "name": "claude-code",
  "summary": "Anthropic's Claude Code CLI, in a tmux session that outlives your terminal.",
  "image": "ghcr.io/me/my-claude-code:2026-08-27",
  "digest": "sha256:1f0c…",
  "start": "claude",
  "workdir": "/work",
  "version_probe": "claude --version",
  "docs": "https://docs.claude.com/en/docs/claude-code",
  "experimental": false,
  "secrets": [
    {
      "name": "ANTHROPIC_API_KEY",
      "authority": "api.anthropic.com",
      "placement": "x-api-key",
      "env": "ANTHROPIC_API_KEY",
      "required": true
    },
    {
      "name": "GITHUB_TOKEN",
      "authority": "github.com",
      "placement": "bearer",
      "required": false
    }
  ]
}
```

| field | |
|---|---|
| `name` | what `--agent` takes: ascii lowercase, digits, `-` |
| `summary` | one line, for `ast agents` |
| `image` | an OCI reference, written the way `--image` accepts it |
| `digest` | `sha256:…`; when set, the tag is ignored and this is what is pulled |
| `start` | the command tmux runs — one command line, not a script |
| `workdir` | absolute; the mount point of the data volume |
| `version_probe` | a command whose first line names the installed version |
| `docs` | where to read about the agent itself |
| `experimental` | shipped to be tried, not relied on |
| `secrets[].name` | an orbit secret, as `ast secret ls` shows it |
| `secrets[].authority` | the one host the value may be spent against |
| `secrets[].placement` | `bearer`, `x-api-key`, or `header:<Name>`; omit for the authority's default |
| `secrets[].env` | the variable the guest finds its handle in; defaults to `name` |
| `secrets[].required` | `true` refuses the create when the orbit has no such secret |

JSON rather than TOML because Asterism's boot path already parses JSON for
three other things and a preset is not worth a new dependency in it.

### What the image has to do

A preset can point at any OCI image, but `ast create --agent` expects three
things of it, and says so when they are missing:

1. **Notice the workspace.** Asterism's generated init mounts the shared
   directory at `workdir` before the entrypoint runs. An image may also accept
   a block volume, which arrives as a bare virtio disk for the guest to format
   and mount itself — `images/agent-entrypoint.sh` handles both, checking for
   the share first so that it never formats over a workspace that is already
   there.
2. **Run an ssh server** that trusts `<workdir>/.asterism/authorized_keys`,
   which Asterism writes through guest control. That is what `ast attach`
   talks to.
3. **Touch `/run/asterism-agent.ready`** once the two above are done, and then
   stay alive — pid 1's child exiting powers the machine off.

It should also re-run `<workdir>/.asterism/start.sh` at boot, which is what
makes the agent survive a reboot without anyone typing anything.

`images/agent-entrypoint.sh` does all of that in about eighty lines and is
shared by every image in `images/`. The Asterism guest agent is *not* baked
in: the host injects it into pid 1's generated init at boot, so an agent image
stays a plain OCI image that anyone can `docker run`.

## Building and publishing the images

```
cd images
docker build -f agent-claude-code/Dockerfile -t agent-claude-code:dev .
```

`.github/workflows/agent-images.yml` builds both images for `linux/amd64` and
`linux/arm64` and pushes them to `ghcr.io/medicalissue/agent-*` on a
`agent-images-v*` tag or a manual dispatch.

**That workflow has never run.** Publishing to GHCR needs package publishing
enabled for this repository, which nobody has turned on yet, so the images the
shipped presets name do not exist on the registry. Until they do, point a
preset in `~/.asterism/presets/` at an image you built and loaded yourself.

## What is not here

`openclaw` and `hermes` are deliberately absent. Neither has an install that
Asterism can state and pin the way `@anthropic-ai/claude-code` and
`@openai/codex` can be stated and pinned, and a preset that names a package
nobody has verified is worse than no preset: it fails at `docker build` time
for whoever cuts the image, or — worse — installs something that is not what
the name suggests. Add them as user presets, or open a PR with an image whose
contents can be read.
