# Native catalog lifecycle without QEMU — dev5, 2026-08-27

This is bounded real-host evidence for AST-108. It proves that the packaged
Linux candidate can pull a catalog qcow2, materialise sparse raw in-process,
boot it with Cloud Hypervisor on real KVM, reach the guest, and clean it up
without a QEMU binary or package in the userspace under test.

## Artifact and host

- source: public `08fc336a4087651fa9f4c3be5d972ff6f309b1eb`
- build id: `0.0.2+08fc336a4087`
- archive: `asterism-0.0.2-linux-x86_64.tar.gz`
- archive SHA-256:
  `141d714ab29273d329d4ccfa1bd7abf64a4465b6a4c2fd0adb53efe609c1c7e7`
- host kernel: Linux `6.6.87.2-microsoft-standard-WSL2`, x86_64
- clean userspace: Ubuntu 26.04 container
  `ubuntu@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b`
- hardware boundary: the container received only `/dev/kvm`, `/dev/net/tun`,
  `NET_ADMIN`, and `NET_RAW`; it did not share the host PID or network
  namespace and was not privileged
- storage: an ext4 loop filesystem backed by a dedicated disposable image on
  dev5's D drive, so sparse allocation was measured on Linux ext4 rather than
  WSL DrvFS

The container installed ordinary runtime diagnostics and Linux prerequisites
(`e2fsprogs`, `iproute2`, OpenSSH client, and related utilities), but no package
matching `qemu*`. The gate checked both dpkg inventory and the fixed/PATH
locations for `qemu-img` and `qemu-system-*` before and after the lifecycle.

## Command under test

The candidate archive was extracted at `/release`; the source tree was mounted
read-only at `/src`. The focused gate ran as:

```sh
AST_BIN=/release/ast \
ASTD_BIN=/release/astd \
E2E_HOME=/work/home-1 \
ASTERISM_TEST_ARTIFACTS=/work/artifacts-1 \
bash /src/scripts/e2e-native-no-qemu.sh
```

The gate itself is the reproducible protocol. Its successful terminal record
was:

```text
ok: pull verified qcow2 without QEMU and deferred raw materialisation
ok: create records the explicit chv backend
ok: first chv use atomically published sparse raw with provenance
ok: ssh reached the guest running on chv (Linux x86_64)
NATIVE NO-QEMU GREEN (chv, debian:13; allocated 1056120832 of 3221225472 bytes)
```

The script then completed `down` and `rm`; its exact-home cleanup found no
remaining instance row. The container exited 0.

## Separate converter-equivalence evidence

On the arm64 macOS development host, `scripts/qcow2-catalog-gate.sh` fetched
the currently pinned Ubuntu 24.04 and Debian 13 images, verified their
publisher digests, and compared every byte of the pure-Rust sparse raw output
with `qemu-img convert -f qcow2 -O raw -S 4k`. Both matched. QEMU was used only
as the reference converter in that separate gate, never in the CHV lifecycle
above.

## Does not prove

- a clean physical Linux installation or the public installer transaction;
- macOS VZ with QEMU absent from Homebrew inventory;
- CHV remote NBD, directory, secret, or endpoint parity;
- another CPU architecture, Linux kernel, or filesystem;
- Windows Hyper-V or QEMU compatibility behavior.

Those remain independent gates; this result must not be promoted into them.
