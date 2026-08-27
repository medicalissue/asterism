# Native published ports — macOS/VZ, 2026-08-27

**PASS for Virtualization.framework (AST-139).** This proves that `ast create
-p` works on a product backend with no user-mode NAT: `astd` binds the declared
host port itself and splices it to the guest's private NAT address, for TCP and
UDP, across `down`/`up`, a daemon-only restart, and daemon-plus-VMM loss.

It does not prove the Cloud Hypervisor lane. That code path ships with the same
host-neutral tests and is unexercised on a real KVM host — see **Not proved
here** below.

## Host and fixture

- Host: macOS 26.5.2, Apple silicon (`arm64`)
- VMM: Virtualization.framework 26.5.2 behind a source-built, ad-hoc-signed
  `astd-vz` (`scripts/sign-vz.sh`), `generic` machine, `cpu host`
- Guest agent: static `aarch64-unknown-linux-musl` `asterism-guest`, built in a
  `rust:alpine` container from this worktree
- OCI source: `docker.io/library/nginx:alpine`, direct-kernel boot
- Instance: `ports`, `--restart always`, 2 cores / 1024 MiB / 4 GiB
- `ASTERISM_HOME`: a scratch `/private/tmp/ast-ports-84084`, never `~/.asterism`
- Lane: `scripts/e2e-native-ports.sh` with `E2E_BACKEND=vz`
- Declaration: `127.0.0.1:55668 -> :80/tcp` and `127.0.0.1:55669 -> :7777/udp`
  (both host ports picked free at run time, so the lane never collides with
  whatever else the device is doing)
- UDP guest fixture: BusyBox `nc -u -l -p 7777 -e /bin/cat`, launched through
  authenticated `ast exec`. It serves one exchange per launch, so it is
  relaunched after each guest boot before the UDP assertion.

The lane forces `--backend vz` everywhere and asserts the recorded machine, so a
silent fall-through to QEMU fails it rather than passing it.

## Observed

```
== native published ports on vz, in /private/tmp/ast-ports-84084
== tcp 127.0.0.1:55668 -> :80, udp 127.0.0.1:55669 -> :7777
ok: create a published OCI VM on the native vz backend
ok: the instance really recorded vz
ok: the declaration is durable and loopback-only
ok: the udp declaration carries its transport
ok: boot it with a persistent restart policy
ok: up names both endpoints it published, on 127.0.0.1
ok: the published TCP endpoint serves the guest's nginx (HTTP 200 on 127.0.0.1:55668)
ok: the TCP listener is bound on 127.0.0.1 and nowhere else
ok: a UDP echo server is listening on the guest's :7777
ok: the published UDP endpoint relays datagrams both ways (echoed "ast-udp-84084" through 127.0.0.1:55669/udp)
ok: a second instance is refused the host port ports publishes, by name
ok: take the guest down
ok: the host port is released with the guest behind it
ok: bring it back
ok: up recreated the endpoint on exactly the declared port (HTTP 200 on 127.0.0.1:55668)
ok: a UDP echo server is listening on the guest's :7777
ok: the UDP endpoint came back on its own port too (echoed "ast-udp-again-84084" through 127.0.0.1:55669/udp)
ok: a dead daemon takes its listeners with it
ok: the adopted guest is still the same guest
ok: a restarted daemon recovered the endpoint on its declared port (HTTP 200 on 127.0.0.1:55668)
ok: the recovered listener is still loopback-only
ok: astd was resurrected and recreated the VMM as 86726
ok: the endpoint survived daemon and VMM loss, on the same port (HTTP 200 on 127.0.0.1:55668)
ok: a UDP echo server is listening on the guest's :7777
ok: so did the UDP endpoint (echoed "ast-udp-resurrect-84084" through 127.0.0.1:55669/udp)
ok: stop the completed lane
ok: removing the guest gives the host port back
ok: remove the completed lane
NATIVE PORTS E2E GREEN (docker.io/library/nginx:alpine, vz, tcp 55668/udp 55669)
```

Read against the design, that is:

1. The create that AST-97 used to refuse on this host succeeded, and recorded
   `vz`.
2. `ast up` returned only after guest-control readiness, and named both
   protocol-qualified mappings on `127.0.0.1`.
3. `curl http://127.0.0.1:55668/` returned **HTTP 200** from the guest's real
   nginx, over a TCP splice to the guest's macOS NAT address.
4. A datagram to `127.0.0.1:55669` came back from guest port 7777.
5. `lsof -nP -iTCP:55668 -sTCP:LISTEN` showed `astd` on `127.0.0.1:55668` and
   nothing on any other address — repeated after daemon adoption.
6. A second Instance declaring `55668` was refused, and the refusal named the
   port.
7. `down` released the host port (the endpoint stopped answering); `up`
   recreated it on **the same** port.
8. Killing `astd` while the VZ guest kept running took the listeners with it;
   the daemon started by the scratch launchd service adopted the same guest and
   recovered the endpoint on **the same** port.
9. `kill -9` of both `astd` and the VMM under `restart=always` produced a new
   daemon and a new VMM (`86726`), and the endpoint came back on **the same**
   port for both transports.
10. `down` and `rm` gave the host ports back. The scratch home, its daemon and
    its launchd unit were removed.

## What this run caught

The first attempt failed only at step 4: TCP worked, UDP did not. The relay's
per-flow socket was bound on `127.0.0.1`, which has no route to a guest on
macOS's NAT, so the datagram left and never arrived. Every loopback fixture in
`publish.rs` passed either way; the real guest is what found it. The fix binds
the wildcard of the target's family and lets `connect(2)` choose the source
address, and ships with the test those fixtures could not have written.

## Not proved here

- **Cloud Hypervisor.** `chv` declares `port_forward: true` and takes the same
  `crate::publish` path, and its capability contract is covered by the shared
  host-neutral tests, but no real KVM host ran this lane for this change.
  `scripts/e2e-native-ports.sh` is backend-selectable (`E2E_BACKEND=chv`) and is
  what that run should be.
- **Hyper-V**, which declares `port_forward: false` and still refuses `-p`
  before an Instance row exists.
- An actual host reboot, as opposed to the daemon-plus-VMM loss above.
- Any behaviour on a non-loopback bind address: there is none, by design.
