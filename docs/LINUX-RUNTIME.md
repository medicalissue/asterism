# Linux runtime components

Linux uses Cloud Hypervisor over KVM as the product backend. QEMU is an
explicit compatibility/development backend; it is not in Linux's default
selection order ahead of Cloud Hypervisor.

Binary releases contain `ast`, `astd`, the exact `cloud-hypervisor` v53.0
static binary published upstream, and `virtiofsd` v1.14.0 built from its
tagged source. The immutable URLs, input digests and licenses are recorded in
`packaging/linux-components.env`. The release archive is checksummed as one
unit, so installation requires neither a Rust toolchain nor a separately
installed VMM. The installer grants the bundled VMM only `CAP_NET_ADMIN`,
which it needs to create per-instance TAP devices; KVM access remains governed
by `/dev/kvm` ownership.

Catalog cloud images remain in their publisher-verified qcow2 form on Linux;
Cloud Hypervisor reads those bytes directly. The clean product path therefore
does not invoke or install `qemu-img`. Raw-only compatibility backends still
materialize the portable raw form when explicitly selected on a host that
provides their converter.

Remote volumes use the kernel NBD client below the backend seam. On a clean
host the installer adds `nbd-client` plus `kmod` (`nbd` plus `kmod` on
Fedora-family systems), loads `nbd` with 64 devices, and records the same
setting under `modules-load.d` and `modprobe.d` for reboot. The daemon has no
general root or `nbd-client` permission: sudoers allows the installing account
to run only `/usr/local/libexec/asterism/asterism-nbd` without a prompt. That
root-owned wrapper accepts only attach/detach forms used by Asterism and only
for `/dev/nbd0` through `/dev/nbd63`. Uninstall removes that account's sudoers
rule. If detach fails, the instance keeps its device-and-kernel-pid ownership
record so later stop or state reconciliation can retry safely.

Component updates are deliberate release changes, never a moving download:
update the lock file, run the common backend suite on Ubuntu and Fedora, boot
the pinned cloud and OCI lanes on KVM, and publish a new Asterism tag. Existing
guests keep the VMM process that started them. A daemon upgrade may adopt that
process by its executable plus instance-owned API/pid paths, and no installer
rewrites a running executable in place.

Cloud Hypervisor is Apache-2.0 and BSD-3-Clause; virtiofsd is Apache-2.0 and
BSD-3-Clause. Their license texts are included by the Linux release packaging
under `share/asterism/licenses/`.
