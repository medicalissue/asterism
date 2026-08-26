# OCI network and egress evidence — dev5, 2026-08-26

**PASS for the Linux/QEMU/KVM AST-111 vertical slice.** This proves real TCP
and UDP publication, lifecycle restoration, daemon adoption and
host-loss-equivalent recovery on one x86_64 WSL2/KVM host. It does not prove a
native VZ, Cloud Hypervisor or Hyper-V endpoint door, an actual OS reboot, or
secret storage inside a real guest.

## Host and fixture

- Host: `DESTOP-DEV5` WSL2, x86_64, `/dev/kvm`
- VMM: QEMU 10.2.1, `q35`, `cpu host`, KVM
- OCI source: `nginx:alpine`
- Instance: `ast111net`, ID `8f9295f5-c1bd-4358-97a7-d9ecea0d58e2`
- Declaration: `127.0.0.1:18080 -> :80/tcp` and
  `127.0.0.1:15353 -> :5353/udp`
- UDP guest fixture: BusyBox `nc -u` echo launched through authenticated
  `ast exec`; it handles one datagram per launch, so the fixture was relaunched
  after each guest boot before the UDP assertion.

## Observed lifecycle

1. `ast up` returned only after guest-control readiness and printed both
   protocol-qualified mappings.
2. `curl http://127.0.0.1:18080/` returned `Welcome to nginx`.
3. A UDP datagram sent to `127.0.0.1:15353` returned
   `ast111-udp-ok` from guest port 5353.
4. `down -> up` preserved the Instance ID and machine, then returned
   `Welcome to nginx` and `ast111-after-up` through the same host ports.
5. Daemon-only restart changed daemon PID 36565 -> 37202 while QEMU PID stayed
   37151. Status retained the same ID/machine/declaration; TCP returned nginx
   and the relaunched guest UDP fixture returned `ast111-after-daemon`.
6. Daemon plus VMM loss changed daemon PID 37202 -> 43416 and QEMU PID
   37151 -> 43450. `restart=always` restored the same ID/machine/declaration;
   TCP returned nginx and UDP returned `ast111-after-host-loss`.
7. A create with duplicate `18081/tcp` mappings failed with a structured
   pre-mutation refusal, and `ast status ast111bad` proved no row existed.

The final `down -> remove` completed. The isolated daemon, source/build/image
tree and exact temporary home were deleted; no matching QEMU process or
listener on 18080/15353 remained.

## Egress boundary exercised on the same host

Focused real-socket tests passed for:

- selective CONNECT/TLS termination and delivery of the real value only to
  the upstream request;
- no plaintext or opaque handle in the cross-device request frame;
- refusal of a revoked binding on an already-open connection;
- exact-port, fail-closed restoration for an already-running guest.

Those tests use real loopback TCP/TLS but a fake source store, not a booted VM
and OS secret service. A real multi-device secret-store-to-guest run remains a
separate release gate.
