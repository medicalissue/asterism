# OCI VM parts parity evidence — 2026-08-26

**PASS for AST-112's implemented QEMU VM parts path, with explicit release
boundaries below.** The real-host lanes cover an OCI service with a writable
directory and profile, an OCI VM with a remote block disk and recovery, and a
platform-store secret through snapshot/restore on a VM. Host-neutral tests
cover capability refusal, rollback and plaintext exclusion.

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
$ cargo test --workspace
```

All three scripts ended green. The final remote-volume artifact is retained
on dev5 at `/tmp/asterism-harness-artifacts-68922/volume`.

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

## Secret and refusal evidence

The macOS lane put a sentinel into the login Keychain through stdin, attached
only an opaque guest handle, and proved the egress proxy substituted the value
only for the allowed authority. The handle survived daemon+VM resurrection
and snapshot restore. The raw value was absent from the snapshot's allocated
bytes and from `ast bugreport`; the handle was also absent from the bug report.
The profile changed from `base@2 node@1 claude@1` to include `codex@1` only
after the next boot.

The workspace suite additionally proves that plaintext never enters the
secret registry, backup manifests scrub binding rows and handles, a failed
attach refresh restores the prior policy without publishing a binding, and a
failed revoke refresh leaves the binding durably revoked. Unsupported shared
directories, NBD clients and egress doors refuse from declared capabilities
even when backend probing itself fails.

## Boundaries

- This is one x86_64 QEMU/KVM OCI host, not native VZ, Cloud Hypervisor or
  Hyper-V parts evidence.
- The macOS Keychain lane used a cloud-disk VM. It proves the common VM secret
  broker and snapshot boundary, not an OCI rootfs plus Keychain on the same
  boot.
- Killing/restarting daemon and VMM processes exercises the durable recovery
  path but is not an actual operating-system reboot.
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
