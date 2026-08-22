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

Component updates are deliberate release changes, never a moving download:
update the lock file, run the common backend suite on Ubuntu and Fedora, boot
the pinned cloud and OCI lanes on KVM, and publish a new Asterism tag. Existing
guests keep the VMM process that started them. A daemon upgrade may adopt that
process by its executable plus instance-owned API/pid paths, and no installer
rewrites a running executable in place.

Cloud Hypervisor is Apache-2.0 and BSD-3-Clause; virtiofsd is Apache-2.0 and
BSD-3-Clause. Their license texts are included by the Linux release packaging
under `share/asterism/licenses/`.
