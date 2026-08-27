# One orbit-wide namespace, on two real devices — 2026-08-27

Real-host evidence for AST-167. It answers one question: with a Mac and a WSL2
Linux box in one orbit, is a **bare name** enough to reach either an instance
or a device from either machine — and is a name that would mean two things
refused before anything is written down?

**Result: green.** Every line below was typed against two daemons on two
physical machines over Tailscale, not against a loopback pair.

## Hosts

| | |
|---|---|
| device `macbook` | this Mac, Darwin 25.5.0 arm64 (macOS 26.5.2), tailnet `100.121.213.11` |
| device `dev5` | `DESTOP-DEV5`, Linux `6.6.87.2-microsoft-standard-WSL2` x86_64, 12 cores / 11 GiB, tailnet `100.91.138.55` |
| build | `f09a0481` on `claude/ast-167-orbit-names`, then on top of `9df8be05` |
| mesh | `LocalOnly` on both — no relay, no directory. Each daemon was pointed at
its own tailnet address by writing `mesh-local.addr` before first start, so
pairing and every later frame took a **direct** path between the two hosts. |
| protocol | 18 on both at run time (`astd: stamped … as Asterism 0.0.2 (protocol 18)`). The branch was afterwards rebased over `48c8c2db` (AST-152 fork), which had taken 18; the `resolve` frame is **19** on the branch as it stands, and nothing else about it moved. |
| homes | scratch `ASTERISM_HOME` on both (`…/scratchpad/mac-home`, `/root/ast167/home`); no user orbit was touched |

Pairing, from `ast devices` on each side after the ticket was redeemed:

```
NAME                     DEVICE ID      STATUS   HOSTED    PATH         RTT
macbook (this device)    cdfee44b3903   online   -         -              -
dev5                     ec48199a17a0   online   -         direct    73.0ms
```

## The transcript

One instance, `web`, sourced from `nginx:alpine` and running on `dev5`. Every
command below was typed on the **Mac** unless it says otherwise, and none of
them names a device.

```console
$ ast ls
NAME           STATUS    IMAGE          SHAPE            DEVICE       AGE    TODAY    ACCESS
web            running   nginx:alpine   2c/1024M/4G      dev5         52s    -        -

$ ast status web
name:    web
id:      926d7605-6102-4c8e-90f0-df20c374609a
status:  running
restart: never
age:     52s
machine: qemu 10.2.1 (q35, cpu host)

parts:
  compute  dev5  2 cores · 1024 MiB
  disk     dev5  4 GiB · docker.io/library/nginx:alpine  (follows compute · oci rootfs, direct kernel boot)
  network  dev5  private guest network · 127.0.0.1:8080 -> :80/tcp  (exit default: same as compute)
  gpu      -     none

$ ast logs web
error: no console log for "web" yet — `ast up web` starts one
```

That last line is dev5's own refusal, arriving on the Mac: this Mac's shard
holds no instance called `web` at all, so a refusal about *its console* is a
refusal that crossed the mesh.

### A name means one thing

```console
$ ast create dev5 --image nginx:alpine
error: "dev5" is already a device in this orbit — Instance and device names share one namespace
  fix: ast create dev5-bot --image …

$ ast create macbook --image nginx:alpine
error: "macbook" is already a device in this orbit — Instance and device names share one namespace
  fix: ast create macbook-bot --image …
```

Both are refused before a byte is downloaded — the first run of this evidence
pulled 356 MB of `nginx:alpine` *and then* refused the name, which is the
wrong order to find out in, and is what the second commit on this branch
fixes. The daemon still enforces the rule on the create frame; the CLI now
asks the same question first, because it costs one unix-socket round trip.

The other direction, typed on **dev5** while `web` was on it:

```console
dev5$ ast create dev5 --image nginx:alpine
error: "dev5" is already a device in this orbit — Instance and device names share one namespace
  fix: ast create dev5-bot --image …
```

The pairing direction — a device that wants to join under an instance's name —
is covered by `scripts/e2e-orbit-names.sh` (below) rather than here, because
it needs a third daemon and the refusal has to be observed *before* the peer
reaches the orbit store.

### A name that is neither

```console
$ ast ssh nope
error: unknown name "nope" (orbit has devices: macbook, dev5; instances: web)

dev5$ ast ssh nope
error: unknown name "nope" (orbit has devices: dev5, macbook; instances: web)
```

### `ast ssh <device>` — the host shell, and its gate

`astd` on dev5 runs as root, so that device honestly declines to offer a host
shell at all:

```console
$ ast ssh dev5 -- uname -a
error: unavailable: device shell is unavailable because astd is running as root; it only serves an unprivileged user's account
```

The Mac's daemon runs as an ordinary user, so the same command in the other
direction works — after that machine's owner enables it, and not before:

```console
macbook$ ast device shell status
device shell: disabled  epoch 0

macbook$ ast device shell enable
device shell: enabled for the approved orbit  epoch 1
warning: every device currently in this orbit now has this user account's full authority. …

dev5$ ast ssh macbook -- uname -a
Darwin macbook-pro.tail0de304.ts.net 25.5.0 Darwin Kernel Version 25.5.0: Tue Jun  9 22:28:34 PDT 2026; root:xnu-12377.121.10~1/RELEASE_ARM64_T6041 arm64

dev5$ ast ssh macbook -- sw_vers -productVersion
26.5.2
```

One bare name, two entirely different operations: `ast ssh web` splices a
guest, `ast ssh macbook` runs a login shell on another machine over the
authenticated mesh. `web` is an OCI guest with no ssh server in it, and says
so rather than hanging:

```console
$ ast ssh web
error: web boots an OCI image, which has no ssh server in it — run a command with `ast exec web -- /bin/sh -c '...'`; its console is `ast logs web`, and it is reachable on 127.0.0.1:8080 -> :80/tcp
```

### `--device` and `--host` are gone, and say so

```console
$ ast --device dev5 ls
error: --device is gone: an orbit has one namespace, so a bare name is enough — `ast ssh dev5` for that device's host shell, `ast ssh <instance>` and every other instance command by bare name from any device, and `--on dev5` for the few commands that really are about one device's own storage or images

$ ast ssh dev5 --host dev5
error: --host is gone: say `ast ssh dev5` — one orbit, one namespace

$ ast volume ls --on dev5
no volumes on this device — make one: ast volume create tank --size 100G
```

The last one is the replacement working: `--on` is the same proxy envelope the
retired flag put a frame in, kept for the handful of commands that really are
about one machine's own disk.

`ast move` still takes two bare names and refuses for the right reason:

```console
$ ast move web macbook
error: instance "web" is running on dev5. Moving compute is an offline operation on every backend Asterism has — pass --down to shut the guest down first
```

### A device that is asleep is not a typo

dev5's `astd` was then stopped, leaving the orbit with a row it can see and a
device it cannot reach:

```console
$ ast ls
NAME           STATUS    IMAGE          SHAPE            DEVICE       AGE    TODAY    ACCESS
web            unknown   nginx:alpine   2c/1024M/4G      dev5         6m     -        -

unknown: the device supplying that instance's compute is out of touch

$ ast ssh web
error: dev5 is offline (last seen 5 min ago) — web is unreachable

$ ast logs web
error: dev5 is offline (last seen 5 min ago) — web is unreachable

$ ast status web
error: dev5 is offline (last seen 5 min ago) — web is unreachable

$ ast ssh nope
error: unknown name "nope" (orbit has devices: macbook, dev5; instances: web)
```

The last two lines are the point of routing every instance command through one
resolver. Before this branch, `ast logs web` and `ast status web` in this
state answered with the local shard's "no such instance" — the same sentence a
typo gets. They are different situations and now they are different sentences.

## What this run did not prove

* **The guest's own workload.** `web` was launched on dev5 and its registry row
  says `running`, but its console never came up: this WSL2 host has no packaged
  Linux OCI guest-control agent (`scripts/build-guest-control-artifact.sh`
  needs a `rustup` musl target that is not installed there), so `ast up web`
  reported a fenced boot intent. Nothing in AST-167 depends on the guest
  serving traffic — every assertion above is about names, routing and
  refusals — and `ast logs web` crossing the mesh to be refused *by dev5* is
  the routing proof either way.
* **Pairing under an instance's name.** Needs a third device; covered by the
  e2e below, which stands up three daemons.
* **A relayed path.** Both devices were on one tailnet and every frame took a
  direct path. Relay behaviour is `scripts/e2e-relay.sh`'s subject.
* **Fork names against devices.** `ast fork` names its children `<parent>-<n>`
  and now steps over a number a device in the orbit answers to; that landed
  after this run, over AST-152, and is covered by a unit test rather than by a
  transcript here.

## Reproducing it

`scripts/e2e-orbit-names.sh` is the automated form and asserts everything
above plus the pairing direction, on any one host with two (briefly three)
daemons:

```console
$ bash scripts/e2e-orbit-names.sh
ok: paired two real daemons (names-a-19230 <-> names-b-19230)
ok: an instance is defined on names-b-19230
ok: ast ls on names-a-19230 lists web-19230 with DEVICE names-b-19230
ok: status resolves across the orbit by bare name
ok: logs resolve across the orbit by bare name
ok: an instance may not take a device's name, and nothing was written
ok: a device may not take an instance's name, and nothing was written
ok: an unknown name is refused with both halves of the namespace listed
ok: a device that has not enabled its shell refuses
ok: the retired --device names the form that replaced it
ok: the retired --host names the bare-name form
ok: ast ssh names-b-19230 opened the target's host shell once its owner enabled it
ok: disabling closes the host shell again
ok: an instance on a stopped device is unreachable, not unknown
ok: ast ls keeps the row and its device, with the state marked unknown
ORBIT NAMES E2E GREEN
```

The two-host run above is the same story with the loopback removed: two
machines, two architectures, two operating systems, one namespace.
