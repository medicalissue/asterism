# The agent scene on a real VZ guest — 2026-08-27

`ast create --agent`, `ast attach` / `ast session`, `ast logs`, and the claim
underneath all three: **the key never enters the box**.

Device: Apple Silicon MacBook Pro, `Darwin 25.5.0`, native
Virtualization.framework backend through an ad-hoc signed `astd-vz` built from
this tree, `ASTERISM_MESH=local`, scratch `ASTERISM_HOME`. Reproduce with
`scripts/e2e-agent-preset.sh`.

The image is built by `docker` on the device and served from a throwaway
registry pair the lane starts, because this repository has no GHCR publishing
credential (`.github/workflows/agent-images.yml` has never run). Asterism pulls
it over HTTPS **by digest**, through the product's own puller, with every blob
verified against the digest its manifest named — the only thing that differs
from a published image is which host served the bytes, and `CURL_CA_BUNDLE` is
how the puller was pointed at the run's throwaway certificate. A user preset in
the scratch `~/.asterism/presets/` is what points at it, so the run also
exercises the override path a user has for pinning their own build.

The key is a dummy: `sk-ant-test-0000-<pid>-<random>`. No real credential was
used, and the whole point of the run is that this value is absent from
everything the guest can reach.

The handles below are truncated after their first few characters. They are
worth nothing — an opaque handle honoured only by one instance's door, and
that instance no longer exists — but a secret scanner cannot tell one from the
key it stands in for, and a repository should not be the place that teaches it
to try.

## The transcript

```
$ ast create bot2 --agent codex
error: preset codex needs secret OPENAI_API_KEY — run `ast secret add OPENAI_API_KEY` first
  fix: ast secret add OPENAI_API_KEY

$ printf %s "$KEY" | ast secret add ANTHROPIC_API_KEY
ANTHROPIC_API_KEY  version 1  1 source

$ ast create bot --agent claude-code --repo https://github.com/octocat/Hello-World.git \
    --backend vz --cpus 4 --mem 4G --disk 12G
pulling localhost:5443/agent-claude-code@sha256:d42a9ad593675bb060b4a11f68726b0f43e1d963e299fd00e4fdc8dcaeb830a5 … done (1.0 GiB, 26 s)
bot is up — claude-code 2.1.247, repo cloned to /work/Hello-World, session "bot" running
                                                            # 35 s, command to ready line

$ ast attach bot        # and `ast session bot`, and `ast ssh bot`
Welcome to Claude Code v2.1.247
Let's get started.
...                     # Ctrl-b d detaches; the session is still there afterwards

$ ast status bot
name:    bot
status:  running
restart: always (up to 3 tries after a crash)
machine: vz 26.5.2 (generic, cpu host)
running: vz pid 558, authenticated guest control 192.168.64.35:1023

parts:
  compute  macbook-pro…  4 cores · 4096 MiB
  disk     macbook-pro…  12 GiB · localhost:5443/agent-claude-code@sha256:d42a9ad5…  (oci rootfs, direct kernel boot)
  volume   macbook-pro…  /private/tmp/ast-agent-97790/work/bot -> /work
  secret   macbook-pro…  ANTHROPIC_API_KEY -> api.anthropic.com  (x-api-key · $ANTHROPIC_API_KEY in the guest, holding sk-ant-ast-… · bound at v1)
  network  macbook-pro…  private guest network

$ ast exec bot -- /bin/sh -c 'printenv ANTHROPIC_API_KEY'
sk-ant-ast-5HHPYR1T…

$ ast exec bot -- /bin/sh -c 'curl -o /dev/null -w "%{http_code}" -X POST \
    https://api.anthropic.com/v1/messages -H "x-api-key: $ANTHROPIC_API_KEY" …'
401
```

And what the lane asserted, in order:

```
ok: built the agent image
ok: a local registry pair is serving on localhost:5100 and localhost:5443
ok: pushed the agent image as sha256:d42a9ad593675bb060b4a11f68726b0f43e1d963e299fd00e4fdc8dcaeb830a5
ok: a user preset points claude-code at the locally built image, pinned by digest
ok: a missing required secret is refused by name, and nothing is created
ok: the dummy key entered this device's credential store through stdin
ok: the transcript's two lines are the two lines
ok: the instance really is a native VZ guest
ok: the repository is in the shared workspace, and the host can see it too
ok: the agent's tmux session is running in the guest
ok: the guest holds an opaque handle (sk-ant-ast-5HHPYR1T…)
ok: the guest reached api.anthropic.com through the door and got 401
ok: the dummy key is absent from the live root disk
ok: the root disk contains the handle and not the value
ok: the dummy key is absent from every file Asterism wrote
ok: ast attach reached the running agent and detached from it
ok: ast session reached the running agent and detached from it
ok: the agent kept running after the detach
ok: ast logs read the agent's own pane
ok: what the agent writes in /work is on the host, outside the root disk
ok: the dummy key is absent from the snapshot
ok: the workspace and the session both came back on their own after a reboot
AGENT PRESET E2E GREEN (vz, localhost:5443/agent-claude-code@sha256:d42a9ad5…, 35s to ready)
```

### Timings

| | |
|---|---|
| `docker build` of the agent image, cold layers | ~90 s (not part of the scene; CI does this once per release) |
| Pull + ext4 build of a 223 MiB image, first time on this device | 26 s |
| Whole `ast create --agent`, command to ready line | **35 s** |
| A second create of the same preset (image already in the store) | ~10 s, dominated by boot |

`ast logs bot` at the end of the run is Claude Code's own first-run screen:
`Welcome to Claude Code v2.1.247`, the theme picker, its syntax-sample diff.
That is the agent process, in tmux, in the guest.

## Proves

* **`ast create <name> --agent claude-code --repo <url>` produces the scene in
  35 seconds** on a native VZ guest: an OCI-rootfs VM booted from an image
  pinned by manifest digest, `restart=always`, a workspace shared at `/work`, a
  cloned repository in it, the preset's secret bound as a handle, and a running
  tmux session named after the instance — and prints exactly the two lines the
  issue's transcript asks for.
* **The refusal comes first and costs nothing.** With no `OPENAI_API_KEY` in
  the orbit, `ast create bot2 --agent codex` prints exactly
  `error: preset codex needs secret OPENAI_API_KEY — run `ast secret add
  OPENAI_API_KEY` first`, with `fix: ast secret add OPENAI_API_KEY` under it,
  and `ast status bot2` finds no instance: no image was pulled, nothing was
  created, nothing needs cleaning up. (The `fix:` line arrived with AST-141
  after this run; the lane asserts both lines now.)
* **The user-preset override works.** A file in `~/.asterism/presets/` replaced
  the shipped `claude-code` preset and pointed it at a different registry and a
  different digest, with no change to the binary.
* **The guest holds a handle, not a key.** `$ANTHROPIC_API_KEY` in the guest is
  `sk-ant-ast-…` — the Anthropic-shaped opaque handle — and is not the dummy
  value.
* **The guest reached Anthropic through the door.** Its own HTTPS POST to
  `api.anthropic.com/v1/messages`, carrying `$ANTHROPIC_API_KEY` as `x-api-key`,
  answered `401`: the request left the guest, went through the egress door, and
  was served by Anthropic.
* **The dummy value is nowhere the guest or a copy of it can reach.** Absent
  from the live root disk and from a snapshot of it (both checked with
  `scripts/sparse-contains.py`, which reads allocated extents rather than
  trusting a hole), and absent from every non-disk file under `ASTERISM_HOME` —
  registry, metadata, console log, `ast bugreport`. The *handle* is present in
  both the live disk and the snapshot, which is the control that proves the
  search would have found the value if it were there.
* **`ast attach bot`, `ast session bot` and `ast ssh bot` all land in the
  running session** over a real tty (driven through `script`), and `Ctrl-b d`
  detaches leaving the agent running — `tmux list-sessions` still shows `bot`
  afterwards.
* **`ast logs bot` reads the agent's own pane**, not the serial console.
* **The session comes back by itself.** After `ast down`, a snapshot, and
  `ast up`, both the file the agent wrote in `/work` and the tmux session were
  there again with nobody typing anything: the image's entrypoint re-runs the
  recorded start script at every boot.
* **The workspace is outside the root disk.** What the guest writes to `/work`
  is a file on the host, so a restore of the root disk does not rewind it and
  the clone is openable in an editor while the agent works in it.
* **The `codex` image builds and works too**: `docker build -f
  agent-codex/Dockerfile` reports `codex-cli 0.150.1`, `node v22.23.2`,
  `tmux 3.3a`.

## Does not prove

* **Nothing about a real credential.** The value was a dummy, and `401` is what
  an invalid key earns. The 401 shows the request reached Anthropic *through
  the door*; it does not by itself distinguish a substituted-but-wrong value
  from an unsubstituted handle. The substitution mechanism is proved
  separately, by the echo lanes in `scripts/e2e-vz-oci-parts.sh` and
  `scripts/e2e-profile-oci-keychain.sh`, which read the substituted bytes back
  off the wire.
* **Nothing about ghcr.io.** The image was served from a local registry over
  HTTPS with a certificate this run generated. `.github/workflows/agent-images.yml`
  has never run, and the images the shipped presets name do not exist yet.
* **Nothing about running `codex` end to end.** Only its refusal path was
  exercised; no codex instance was booted.
* **Nothing about `linux/amd64`.** `linux/arm64` only, on one machine.
* **Nothing about a second device.** A single-device orbit with
  `ASTERISM_MESH=local`: no mesh, no remote compute, no remote workspace.
* **Nothing about `openclaw` or `hermes`.** They are not shipped; see
  `docs/agents.md`.
* **The pull line's size is the image on this device's disk** (the built ext4,
  1.0 GiB), not the compressed bytes downloaded (223 MiB). That is the number
  `ast pull` has always reported and the number that matters for the disk, but
  it is not a download size.
* **A block-volume workspace is not what shipped, and why is worth writing
  down.** The first two attempts used a block volume (`ast volume create` +
  `ast attach --volume`). On this device that lost the NBD connection on an
  instance's *first* boot roughly half the time — the VMM exited with it and
  the boot rolled back, once surfacing instead as `the host did not prove the
  instance key` from guest control. Every later boot of the same instance was
  fine. The workspace is a shared directory now, which removes NBD from this
  path entirely and is better UX besides; `ast create --agent` also retries a
  failed boot up to three times and says when it had to. **The underlying
  VZ + NBD first-boot race is not fixed here and is worth its own issue.**

## Reproducing

```
scripts/sign-vz.sh
ASTERISM_GUEST_AGENT_ARTIFACT=<static aarch64 linux asterism-guest> \
  bash scripts/e2e-agent-preset.sh
```

Needs `docker` (it builds the image and runs the registry pair) and a machine
that can run Virtualization.framework. `KEEP=1` leaves the scratch home behind
for inspection. The lane is not in `scripts/rc.sh`: like the other VZ parts
lanes it needs a signed helper and a guest artifact that CI does not have.
