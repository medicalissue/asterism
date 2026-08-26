# OCI VM parts parity evidence — 2026-08-26

**PASS for AST-112's implemented QEMU VM parts path, with explicit release
boundaries below.** The real-host lanes cover an OCI service with a writable
directory and profile, an OCI VM with a remote block disk and recovery, and a
macOS Keychain secret through snapshot/restore on both cloud-image and OCI
VMs. Host-neutral tests cover capability refusal, rollback and plaintext
exclusion.

## Hosts and commands

The OCI lanes ran on `DESTOP-DEV5` WSL2, x86_64, QEMU 10.2.1 with KVM. The
guest agent was a static x86_64 Linux artifact built from this checkout.

```console
$ ASTERISM_MESH=local ASTERISM_GUEST_AGENT_ARTIFACT=<static-agent> \
    E2E_PROFILE_TIMEOUT=300 scripts/e2e-oci.sh
$ ASTERISM_MESH=local ASTERISM_GUEST_AGENT_ARTIFACT=<static-agent> \
    E2E_VOLUME_BACKEND=qemu E2E_VOLUME_OCI=1 E2E_VOLUME_GIB=1 \
    E2E_VOLUME_TRANSFER_BYTES=1048576 \
    E2E_VOLUME_SKIP_COMPUTE_MOVE=1 \
    E2E_VOLUME_SKIP_LIVE_THROUGHPUT=1 scripts/e2e-volume.sh
```

The secret/profile lane ran on an arm64 Mac with macOS 26.5.2 and its login
Keychain:

```console
$ E2E_BOOTSTRAP_TIMEOUT=1800 scripts/e2e-profile.sh
$ E2E_PROFILE_OCI=1 ASTERISM_GUEST_AGENT_ARTIFACT=<arm64-static-agent> \
    E2E_PROFILE_TIMEOUT=600 scripts/e2e-profile.sh
$ ulimit -n 4096
$ ASTERISM_HOME=/private/tmp/asterism-workspace-test-ast112-serial \
    cargo test --workspace -- --test-threads=1
```

All four real-host lanes ended green. The final remote-volume artifact is
retained on dev5 at `/tmp/asterism-harness-artifacts-68922/volume`; the final
OCI-Keychain diagnostics are under the macOS temporary harness artifact
`asterism-harness-artifacts-86955/profile-oci-keychain`.

The workspace command used a newly created empty `ASTERISM_HOME` and a macOS
open-file limit of 4096, then removed that scratch home. This keeps a stale
developer image cache and parallel daemon-socket tests out of the result.

## Observed OCI parts behavior

1. `nginx:alpine` booted as a QEMU/KVM VM, served its published endpoint, and
   exposed authenticated guest control without claiming SSH.
2. A same-device directory was mounted through 9p. Host-to-guest and
   guest-to-host writes survived down/up.
3. The `base` profile applied inside the OCI rootfs. `ast profile --check`
   travelled over guest control, reported SSH keepalive as not applicable,
   and passed again after restart.
4. A second OCI `nginx:alpine` run attached a 1 GiB block volume owned by a
   peer device. The guest saw one ordinary `/dev/vdb` virtio disk, formatted
   it as ext4, and wrote 1 MiB of non-zero data whose SHA-256 was
   `287115ddb58b07eaa9cc2edede2398f878a5f505f1d24f3021b1a1c543d3fb5d`.
   The provider's sparse raw image contained the marker and allocated bytes.
5. The filesystem and directory survived down/up. A second holder, live
   reattach, live detach and deletion while leased were refused. Detach and
   reassignment advanced the epoch and retired the old export socket.
6. Provider restart recovered the same epoch. Status first reported the
   degraded part, then `reconnected (provider_returned)` with a bounded
   recovery duration; new guest I/O resumed without reattach or VM reboot.
   Consumer-daemon restart rebuilt the local bridge at that epoch and the
   guest wrote bytes that reached the provider.
7. Full provider loss degraded only the volume while the Instance remained
   running. The guest could stop; the next boot named the absent device and
   volume and refused before a guest or socket was created. After the provider
   returned at its durable local mesh address, the same Instance booted and
   read the original marker without rebinding.
8. The one-shot `hello-world` OCI image completed readiness admission before
   its entrypoint, printed, powered off, and was not treated as a crash.
9. A separate persistent fixture then exercised a real Ubuntu WSL distro
   restart. Two lingered systemd user services owned the compute and volume
   devices. `wsl.exe --terminate Ubuntu` replaced both `astd` processes
   (`70043/70071` to `883/884`) and QEMU (`70184` to `1026`). The `restart:
   always` OCI VM returned without an `ast up` or reattach, `base@2` passed,
   the host-directory marker and ext4 volume marker were intact, and the
   volume lease stayed with the same Instance/device while its epoch advanced
   from 2 to 4. Tailscale SSH and Docker also returned automatically; Docker
   had zero running containers both before and after the test.

WSL2 shares a Linux kernel between distro lifetimes, so its kernel `boot_id`
did not change. This lane asserts the distro userspace boundary instead: PID 1
had a new start time, the old daemon/VMM PIDs were gone, the enabled lingered
units were active below `user@0.service`, and the guest accepted fresh
authenticated control and I/O after recovery.

## Secret and refusal evidence

The original macOS cloud-image lane put a sentinel into the login Keychain
through stdin, attached only an opaque guest handle, and proved the egress
proxy substituted the value only for the allowed authority. The handle
survived daemon+VM resurrection and snapshot restore. The raw value was absent
from the snapshot's allocated bytes and from `ast bugreport`; the handle was
also absent from the bug report. The profile changed from `base@2 node@1
claude@1` to include `codex@1` only after the next boot.

The added arm64 macOS lane repeated that contract on a QEMU OCI VM sourced
from `nginx:alpine`. `base@2` verified over authenticated guest control, the
guest saw only the opaque handle, and a real HTTPS request received the
Keychain value only through the per-instance egress proxy. Launchd recreated
`astd`, which recreated the killed QEMU guest without a new attachment. The
live root disk, snapshot, content-addressed backup chunks, registry, metadata,
logs and bug report contained no raw sentinel. Snapshot restore returned the
disk marker, profile and working handle. The backup manifest and bug report
contained neither the value nor the host-bound handle. The lane ended
`PROFILE OCI KEYCHAIN E2E GREEN`.

The workspace suite additionally proves that plaintext never enters the
secret registry, backup manifests scrub binding rows and handles, a failed
attach refresh restores the prior policy without publishing a binding, and a
failed revoke refresh leaves the binding durably revoked. Unsupported shared
directories, NBD clients and egress doors refuse from declared capabilities
even when backend probing itself fails.

## Boundaries

- The OCI parts evidence covers x86_64 QEMU/KVM on WSL2 and the arm64 macOS
  QEMU compatibility path. It is not native VZ, Cloud Hypervisor or Hyper-V
  parts evidence.
- The restart lane terminates and recreates the Ubuntu WSL distro userspace.
  It is not a Windows host reboot, physical power cycle, or fresh WSL kernel
  boot.
- A write already in flight at provider death may fail. Asterism does not
  journal and replay NBD requests; it fails closed, declares degradation, and
  guarantees new I/O only after status declares the same epoch reconnected.
- The compute-move segment was skipped because the target device did not yet
  have the OCI/base image transfer path. That is separate from storage-owner
  recovery and remains open work.
- The recovered active session did not publish throughput in status on this
  host. Recovery state, RTT, duration, epoch and real post-recovery bytes were
  asserted; the live-throughput display assertion was skipped and remains a
  telemetry gap.
