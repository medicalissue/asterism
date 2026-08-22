# Firecracker OCI fast-lane gate — 2026-08-22

## Decision

**Reject the Firecracker OCI fast lane. Keep Cloud Hypervisor as the single
native Linux backend.** No Firecracker product backend was implemented.

The dispatched gate allowed a lane only when the same pinned workload showed
either at least 30% faster boot-to-vsock readiness or at least 40% lower VMM
overhead, without losing Asterism lifecycle and parts semantics. Firecracker
met neither performance condition:

| Measure | Cloud Hypervisor v53.0 | Firecracker v1.16.1 | Firecracker result |
|---|---:|---:|---:|
| Median boot-to-vsock-ready, 5 rounds | 14,322 ms | 36,670 ms | 156.0% slower |
| Median steady VMM RSS | 231,776 KiB | 215,912 KiB | 6.8% lower |
| Four-instance launch burst, all ready | 26,252 ms | 87,363 ms | 232.8% slower |
| Burst summed steady VMM RSS | 914,520 KiB | 867,596 KiB | 5.1% lower |
| Shipped VMM bytes | 5,468,264 | 5,171,168 including jailer | 5.4% lower |
| Runtime files for four-instance burst | 148 KiB | 164 KiB | 10.8% higher |
| Restart after VMM SIGKILL | 9,325 ms | 15,559 ms | 66.9% slower |

The 768 MiB OCI rootfs, 59,079,048-byte kernel, 29,239,653-byte initrd,
2-vCPU/1-GiB shape, readiness protocol, and Python workload were identical.
Every single and burst guest returned `42` over vsock. Both VMMs recovered the
same marker from an attached 64 MiB writable block device after their VMM was
killed, so the rejection is not caused by a deliberately broken Firecracker
recovery path.

Steady RSS is the VMM process's `VmRSS` ten seconds after readiness. It includes
resident guest-memory pages, but does not add the nominal 1 GiB separately.
With byte-identical guests and commands it is a conservative, reproducible
proxy for relative VMM overhead; Firecracker's 6.8% saving is far short of the
40% threshold even without trying to subtract shared guest residency.

## Semantic stop condition

The performance disjunction failed before a Firecracker backend could be
considered. The prerequisite matrix in `../linux-vmm-2026-08-22/` proves that
Firecracker can mechanically provide vsock, snapshots, local and remote block
devices, console logs, and crash recovery, while also recording its absent
shared filesystem and live migration support. A product lane would still have
to prove the common backend conformance suite for secrets, logs, snapshots,
block volumes, networking, and recovery. Because performance does not pass,
building that lane merely to attempt semantic parity would violate the gate.

## Host and interpretation

The run used the available Ubuntu 24.04.4 arm64 KVM host under Apple nested
virtualization (`systemd-detect-virt=apple`, kernel 6.8.0-137). This is not a
bare-metal certification host and kernel 6.8 is outside Firecracker's supported
host-kernel set. A positive result would therefore require the non-nested,
supported-kernel reproduction described in ADR 0001 §5. It is sufficient for
this bounded rejection because Firecracker is not close to either threshold,
the prior three-round run showed the same direction, and the lane is optional:
there is no product reason to pay for a second backend in hope that a different
host reverses a 2.56× median-readiness and 3.33× burst deficit.

Run:

```sh
ROUNDS=5 BURST=4 scripts/bench-linux-vmm.sh oci
```

`summary.txt` is the captured run. Detailed VMM and serial logs remain on the
evidence host under `/home/medicalissue.guest/bench/out/`.
