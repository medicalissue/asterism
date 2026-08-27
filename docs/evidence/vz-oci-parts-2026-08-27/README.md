# Native VZ OCI parts and the guest-only egress door — macOS, 2026-08-27

This is AST-114's real-host gate. It proves that on the **product** macOS
backend — Virtualization.framework, never QEMU — an OCI-sourced microVM can
carry a same-device directory part, apply and verify `base@2` over
authenticated guest control, and use a login-Keychain secret through a door
that binds no host interface at all.

The QEMU half of the same contract is
`docs/evidence/oci-parts-parity-2026-08-26/README.md`. The one thing that is
different here is the one thing this lane exists for: QEMU's door is its
user-mode NAT gateway proxied to host loopback, and VZ has no such path. The
decision and its alternatives are `docs/adr/0003-vz-egress-door.md`.

## Build and host

- branch: `claude/ast-114-vz-egress-door`, on top of `bc544190`
- build id: `ast 0.0.2` (debug build of the working tree)
- `ast` SHA-256:
  `126011d6733f80f9db3fbaf7074c98ab5c7bcbec2561ef2463411f0f6167c412`
- `astd` SHA-256:
  `fbcb0e92d95623b5b6497969dcc0877feb0541212bc57a8175d0e278bec050cc`
- `astd-vz` SHA-256 (before ad-hoc signing):
  `27e0b58eccca3e177fd1675a6e60b6fb2ec271946479e85ecff82f918145386d`
- guest agent SHA-256 (static aarch64 musl ELF, no `INTERP`):
  `f03c503f6cf2fe221fc375168df3ecc88e46eb560f1408759347a462c440fe57`
- host: macOS 26.5.2 build 25F84, arm64 Apple silicon
- backend: the source-built `astd-vz`, ad-hoc signed with
  `com.apple.security.virtualization` by `scripts/sign-vz.sh`
- image: `docker.io/library/nginx:alpine`, the same image as the QEMU lane

The guest agent was cross-built for `aarch64-unknown-linux-musl` in a
`rust:alpine` container, because `scripts/build-guest-control-artifact.sh`
requires a Linux builder and this host has no musl cross toolchain. The
resulting ELF is static and was verified as such before use.

## Command and result

The gate ran outside the tool sandbox, which deliberately forbids the local
unix socket the real daemon owns:

```sh
CARGO_TARGET_DIR=<worktree>/target-ast114 \
ASTERISM_GUEST_AGENT_ARTIFACT=<dir>/asterism-guest \
bash scripts/e2e-vz-oci-parts.sh
```

Its successful terminal record, trimmed of the signing preamble:

```text
== VZ OCI parts + Keychain e2e in /private/tmp/ast-vzparts-18732
ok: doctor names the login Keychain with no file fallback
ok: create an OCI VM on the native VZ backend
ok: the instance really recorded vz
ok: its source remains an OCI rootfs
ok: attach a same-device directory part
ok: the raw sentinel entered the login Keychain through stdin
ok: bind only an opaque guest handle on vz
ok: boot the bound OCI VM with persistent restart policy
ok: first boot: the VMM process is .../bin/astd-vz (19657)
ok: the VZ guest read and wrote through the directory part
ok: the guest marker reached the host through virtiofs
ok: base@2 verifies over authenticated OCI guest control on vz
ok: the guest reaches the door at its own loopback (http://127.0.0.1:1021)
ok: the host end of the door is a unix socket, not a port
ok: nothing on this device listens on TCP 1021 — the door is not on the wire
ok: the VZ OCI guest sees an opaque handle, not the Keychain value
ok: real HTTPS is substituted only through the vsock door
ok: the raw sentinel is absent from the live OCI root disk
ok: the live OCI root disk contains the handle but not the Keychain value
ok: the raw sentinel is absent from registry, metadata and logs
ok: the adopted guest is still the same VZ guest
ok: after daemon adoption: the VMM process is .../bin/astd-vz (19657)
ok: the door still serves the adopted guest
ok: launchd resurrected astd; astd recreated astd-vz as 21015
ok: after daemon+VMM loss: the VMM process is .../bin/astd-vz (21015)
ok: the resurrected OCI profile still verifies
ok: the opaque handle survives daemon and VZ guest resurrection
ok: snapshot the bound OCI root
ok: the raw sentinel is absent from the OCI snapshot
ok: the OCI snapshot contains the handle but not the Keychain value
ok: restore the OCI snapshot
ok: restore returned the OCI disk marker
ok: the restored handle still resolves through the vsock door
ok: detach the secret
ok: the detached handle is no longer substituted by the door
ok: the running guest still holds only its opaque handle, which now means nothing
ok: bugreport contains neither value nor handle
VZ OCI PARTS E2E GREEN (docker.io/library/nginx:alpine, vz, vsock egress door)
```

The lane exited 0 after `down` and `rm`, and removed its scratch home,
launchd label and Keychain entry.

## Proves

1. **The refusal is gone where it was wrong, and the door is real.**
   `ast attach --secret` succeeds on `--backend vz`, and a real HTTPS request
   to `httpbin.org/bearer` from inside the guest comes back carrying the
   Keychain value, whose SHA-256 the guest compares without ever holding it.
   The guest's environment carries only `ast-…`.
2. **The door is guest-only by construction, not by claim.** The guest's
   `HTTPS_PROXY` is `http://127.0.0.1:1021` — its own loopback, asserted
   exactly. The host end is a unix socket under the instance directory,
   asserted to be a socket. `lsof -nP -iTCP:1021 -sTCP:LISTEN` finds nothing
   on this device, so there is no port for another guest on the shared VZ NAT
   bridge, or for the LAN, to reach.
3. **No QEMU fallback.** `--backend vz` is forced at create, `ast status`
   reports `machine: vz`, and the running VMM's `comm` is checked to end in
   `astd-vz` at five separate points: first boot, after daemon adoption,
   after daemon+VMM loss, after snapshot, and after restore.
4. **The directory part works on the same guest.** A host-written marker is
   read inside the guest through virtiofs and a guest-written marker appears
   on the host, both from the image's own entrypoint hook directory.
5. **`base@2` over authenticated guest control.** `git` and `tmux` verify,
   SSH keepalive is reported not applicable for a direct-kernel guest, and
   the profile still verifies after resurrection and after restore.
6. **Recovery.** `launchd` resurrects `astd`; `astd` adopts the still-running
   helper without rebooting it, and the door goes on serving that guest.
   After both daemon and VMM are killed, `restart=always` recreates the guest
   and the handle works again.
7. **Snapshot and restore.** The bound instance snapshots and restores, the
   disk marker returns, and the handle resolves through the door afterwards.
8. **Plaintext absence.** The raw sentinel is absent from the live OCI root
   disk and the snapshot (sparse-aware scan), from every non-image file under
   `$ASTERISM_HOME` (registry, metadata, logs) both before and after the run,
   and from `ast bugreport`, which also omits the host-bound handle. The
   useful opaque handle is positively present in the root disk and snapshot,
   so the absence assertions are not vacuous.
9. **Detach fails closed.** After `ast detach --secret`, the same request
   from the same still-running guest is no longer substituted, while the
   guest still holds only its now-meaningless handle.

## Does not prove

- **Reboot recovery.** The daemon and the VMM were killed; the machine was
  not restarted. `launchd` resurrection is a host-reboot *equivalent*, not a
  reboot.
- **Two-device volume fencing.** This lane has one device, `ASTERISM_MESH=local`,
  and a same-device directory part. No peer-owned block volume, lease epoch,
  or single-writer contention was exercised on VZ.
- **A clean PATH without QEMU.** QEMU 11.1.0 is installed on this host. The
  lane forces `--backend vz` and asserts the VMM process, which proves the
  guest ran on VZ, but it does not prove VZ works on a machine where QEMU is
  absent. That is `docs/evidence/native-no-qemu-macos-vz-2026-08-27/README.md`
  for the catalog lane, and it has not been repeated for this one.
- **The VZ cloud-image lane.** The door is opened by the guest agent Asterism
  injects into an OCI root filesystem. A VZ instance created from a cloud
  image runs the cloud-init Python agent, which does not carry the door;
  `egress::check_can_bind` refuses such a binding by name, before the row
  changes. That refusal has a host-neutral test and was not exercised here.
- **Cloud Hypervisor, native Hyper-V, portable backup on VZ,** a multi-device
  secret source, another platform secret store, or a release install matrix.
- **Anything about QUIC/HTTP-3, pinned SDKs, OAuth, quotas or audit,** all of
  which remain design in `SECRETS.md`.

## A correction this gate forced

The QEMU lane's substitution check (`scripts/e2e-profile-oci-keychain.sh`)
ended a `/bin/sh -c` script with an unconditional `echo sentinel-handle-works`
on the line after the digest comparison. `sh` without `set -e` runs it whether
the comparison passed or not, so that step could not fail and the harness's
`eventually` matched its own echo. It was only noticed because this lane uses
the same helper *negatively*, to prove a detached handle stops working, and
that assertion could never pass.

Both scripts now join the comparison and the echo with `&&`. The QEMU lane was
re-run on this same host after the change and still ends
`PROFILE OCI KEYCHAIN E2E GREEN (docker.io/library/nginx:alpine, qemu)` — so
the earlier claim was true, but until now it had not actually been tested.
