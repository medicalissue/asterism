# Linux VMM validation evidence — 2026-08-22

These are review-friendly extracts from the `summary.txt` outputs behind
[`docs/adr/0001-linux-vmm.md`](../../adr/0001-linux-vmm.md). The run host was
Ubuntu 24.04.4 arm64, kernel 6.8.0-137-generic, with `/dev/kvm` exposed by
Lima 2.1.1 nested virtualization on an Apple M4. Consequently feature results
are evidence, while absolute timing and RSS are indicative and do not satisfy
the non-nested Firecracker gate in ADR §6.

Files:

* `cloud-hypervisor-summary.txt`: three cloud-image boot/RSS rounds and the
  Cloud Hypervisor capability matrix.
* `firecracker-summary.txt`: one clean-disk cloud-image boot/RSS round and the
  Firecracker capability matrix. A separate successful warm-disk attempt
  measured 130,763 ms and 479,856 KiB; a following boot stalled in cloud-init
  on the unsupported 6.8 host kernel, so it was not promoted to a matrix run.
* `oci-summary.txt`: three rounds per VMM using the same read-only ext4 built
  from pinned `python:3.12-alpine`, the same kernel/initrd, and the same Python
  vsock workload. Each `workload: 42` line proves the guest workload answered
  through host-to-guest vsock after its guest-to-host ready signal.

The harness is `scripts/bench-linux-vmm.sh`; the OCI builder and complete pins
are in `scripts/build-linux-vmm-oci-rootfs.sh`.
