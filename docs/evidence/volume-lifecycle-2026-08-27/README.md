# Memory and cache volumes on a real macOS VZ host — 2026-08-27

`scripts/e2e-volume-lifecycle.sh`, run against a real `astd` with the native
VZ backend named explicitly. Transcript:
[`e2e-volume-lifecycle.txt`](e2e-volume-lifecycle.txt).

| | |
| --- | --- |
| host | macOS 26.5.2, arm64 |
| backend | `vz` (`--backend vz`, ad-hoc-signed `astd-vz` beside `astd`, entitlements `com.apple.security.virtualization` and `.network.client`) |
| build | `ast`/`astd` 0.0.2, release, from this branch |
| image | `debian:13` |
| home | scratch `ASTERISM_HOME` under `/private/tmp`, removed on exit |

## Proves

* `ast volume create --lifecycle memory|cache [--key KEY]` records the
  lifecycle in the volume book, and `ast volume ls` shows it in a TYPE column.
* A lifecycle the catalog does not have is refused by name, listing the three
  that exist. `--key` on a non-cache volume is refused rather than silently
  dropped.
* `ast attach … --volume V --at /path` records a guest mount point on a block
  volume, and `ast status` shows both the mount point and the lifecycle
  (`memory · nbd on this device · lease epoch N`).
* `ast snapshot` captures the instance's local `memory` and `instance`
  volumes beside their own bytes
  (`volumes/<name>/snapshots/<tag>.raw`) and does **not** capture the `cache`
  volume.
* `ast restore TAG` rolls back the root disk and the `instance` volume, and
  leaves the `memory` and `cache` volumes exactly as the guest last wrote
  them. It says so on stdout rather than leaving the user to discover it.
* `ast restore TAG --include-memory` additionally rolls the `memory` volume
  back, and still leaves the `cache` volume alone.
* A **directory share** carries a lifecycle too, which is what the agent
  presets use: a share attached with `--lifecycle memory` is left exactly
  where the agent left it by `ast rewind`, while the `instance`-lifecycle
  workspace share beside it is rolled back — and `--include-memory` rolls the
  memory share back as well. Naming `--lifecycle` on a block volume's
  attachment is refused, because `ast volume create` already answered that.
* Deleting a tag (`ast snapshot rm`) releases the volume clones that tag
  captured, and leaves every other tag's alone. Those clones live beside the
  volume's own bytes, where the instance's snapshot directory cannot see
  them, so without this an automatic snapshot every few minutes would leave a
  clone per volume per tick that nothing ever pruned.
* `ast rewind --to TAG` and `ast rewind --to TAG --include-memory` do exactly
  the same things to exactly the same bytes. That is the assertion that
  matters most here: the two rollback surfaces read one predicate
  (`asterism_core::volume::reverts_with_instance`), and a lane that exercised
  only one of them would not notice them drifting apart.
* `ast create --profile claude` makes and attaches the volumes the profile
  declares: `<instance>-claude-memory` at `/home/ast/.claude` with lifecycle
  `memory`, and the cache keyed `agent-toolchain` at `/var/cache/asterism`.
* A cache is shared *by key*: the second box created with `--profile claude`
  attached the very volume the first box had warmed, with the first box's
  bytes still in it — not a second copy.

The byte-level assertions are made against the images themselves: a 64-byte
marker at a fixed offset in the root disk and in each volume's `disk.raw`,
written before the snapshot and overwritten after it. What a rollback
replaces is therefore observed, not inferred from a command's exit status.

The directory-share half is proven through `ast rewind`, because that is the
engine that clones and restores a tree; the block-volume half is proven
through both `ast restore` and `ast rewind`.

## Does not prove

* **Nothing was booted.** Markers are written from the host and the instance
  never runs, because the question here is which bytes a rollback replaces,
  not what a guest does with them. That the guest formats and mounts a block
  volume at `/home/ast/.claude` before the agent session starts is covered by
  `asterism-core`'s seed tests — including that the mount fragment is ordered
  ahead of the bootstrap fragment in `runcmd`, and that
  `/usr/local/lib/asterism/blockmount` parses as `sh` and never touches a
  disk that already has a filesystem — and is described in
  `docs/orbit-storage.md`. A booted lane that reads `~/.claude` from inside a
  guest across a rewind is worth adding and is not here.
* **Fork is not tested.** "Copied on fork" for `memory` and "shared on fork"
  for `cache` are the declared contract; fork itself is AST-152.
* **The rewind here is `--to`, not a duration.** `ast rewind 20m` selects a
  snapshot by clock arithmetic against the automatic timeline; this lane
  names the tag, because what is under test is which volumes a rollback
  touches and not how a target is chosen. Target selection is AST-153's own
  lane.
* **Auto-snapshots are not exercised.** Every snapshot here is taken
  explicitly. The scheduler that takes them on an interval is AST-153's.
* **No cross-device volume.** Every volume here is local. A `memory` volume
  whose bytes are on another device is deliberately *not* captured — a clone
  is a filesystem operation and there is no file to clone — and the daemon
  says so at snapshot time. That refusal path is not exercised here.
* **No agent preset was created.** The preset mounts are asserted as data
  (`asterism-core`'s preset tests: every shipped preset declares exactly one
  memory mount and at least one cache; a cache directory is named after its
  key so two boxes share it, a memory directory after its instance so they do
  not). `ast create --agent` needs the published agent image and is the
  agent-preset lane's own ground.
* **No concurrent sharing.** A cache volume is shared by key, not by two
  writers at once: the first box detaches it before the second attaches. The
  volume plane still offers exactly one `Sharing` mode, `single-writer`.
* **One backend, one host.** VZ on this Mac. The Cloud Hypervisor lane is the
  same script with `E2E_BACKEND=chv` and has not been run here.

## Reproducing

```console
$ scripts/sign-vz.sh --release
$ AST_BIN=target/release/ast ASTD_BIN=target/release/astd \
    scripts/e2e-volume-lifecycle.sh
```

`E2E_BACKEND` names a different backend; `KEEP=1` leaves the scratch
`ASTERISM_HOME` behind for inspection.
