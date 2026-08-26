# OCI guest-control real-host gate — dev5, 2026-08-26

## Result

**PASS for the Linux/QEMU/KVM AST-110 vertical slice.** This evidence covers
one x86_64 WSL2 Linux host with `/dev/kvm`; it is not evidence for native Cloud
Hypervisor, VZ, Hyper-V, a full operating-system reboot, PTY support, or a
release installation.

## Host and build

- Host: `DESTOP-DEV5`, Linux x86_64 under WSL2
- VMM: QEMU 10.2.1, `q35`, `cpu host`, KVM detected
- Workload: `docker.io/library/nginx:alpine`
- Guest kernel observed in the console: Linux 6.8.0-137-generic
- Guest agent: 829 KiB static PIE x86-64 ELF, stripped

The static agent's three Linux tests passed, including a real TCP/HMAC session
and exec. The workspace check and all-target Clippy gate passed on the source
branch before this run.

## Lifecycle evidence

1. `ast create ast110-nginx --image nginx:alpine --backend qemu` recorded
   Instance ID `e9f3e96c-6268-4a23-aebc-917ca1902ad3` and machine
   `qemu 10.2.1 (q35, cpu host)`.
2. `ast up ast110-nginx` returned only after protocol-v2 HMAC readiness on the
   recorded guest-control forward.
3. `ast exec` preserved separate stdout/stderr and both a zero exit and an
   explicit exit 7. A later command returned `lifecycle-ok`.
4. `ast logs ast110-nginx -n 5` returned exactly the last five console lines
   and reported that older lines were omitted.
5. The daemon was terminated and restarted. Its PID changed from 14709 to
   16553 while QEMU PID 15037, the Instance ID, machine identity, and control
   endpoint `127.0.0.1:43405` remained unchanged. The first post-adoption exec
   returned `restart-adopted-ok`.
6. `down -> up -> exec -> logs -> down -> rm` completed, and no QEMU process
   for the removed Instance remained.

## Host-reboot-equivalent recovery

A second `nginx:alpine` Instance was booted with `restart=always`. Before
process loss it had Instance ID `b2c1eb07-cc22-45c4-9b54-942f1486031a`, daemon
PID 29683, QEMU PID 29785, and machine `qemu 10.2.1 (q35, cpu host)`.

The exact daemon and QEMU processes were then terminated, reproducing the
process state Asterism observes after a host reboot without rebooting the
shared dev5 machine. A new daemon (PID 29835) loaded the durable row and booted
a new QEMU process (PID 29866). The Instance ID, restart policy, image and
recorded machine were unchanged; the ephemeral host control forward was
correctly replaced for the new VM. Authenticated readiness completed and the
first exec returned `host-loss-recovered-ok`. The recovered Instance then
completed a normal down/remove and no test QEMU remained.

## Proven failed-boot rollback

`busybox:1.37` uses an entrypoint that exits before guest control becomes
ready. The QEMU process exited, `ast up` returned a structured non-zero error,
and the backend proved that exact process stopped. The daemon then cleared the
durable launch fence, reported the Instance as `stopped`, and allowed immediate
`ast rm`.

An earlier build without the proven-stopped outcome retained the launch fence;
that conservative behavior prevented a duplicate VM but also prevented normal
cleanup. The gate above was rerun after the structured outcome and compensation
path were added.

## Explicitly unproven

- an actual WSL/Windows operating-system reboot (the equivalent daemon+VMM
  process-loss recovery path is proven above);
- native CHV, VZ, or Hyper-V OCI lifecycle;
- interactive stdin, terminal resize, or PTY semantics;
- tagged release install/update on a clean host;
- binary-transparent CLI output beyond the current UTF-8 response surface.
