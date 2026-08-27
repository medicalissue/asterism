# ADR 0004 — the Cloud Hypervisor secret-egress door is the guest's own loopback, carried over the instance's virtio socket to the daemon itself

| | |
|---|---|
| Status | **Accepted** for the AST-115 implementation |
| Date | 2026-08-27 |
| Context | `SECRETS.md` §1 and §4; `OCI-RUNTIME.md` "Non-negotiable tests"; `docs/adr/0003-vz-egress-door.md`; `docs/evidence/oci-parts-parity-2026-08-26` (the proven QEMU lane) |
| Supersedes | the `guest_egress: None` row for `chv` in `crates/asterism-daemon/src/backend/chv.rs` |
| Does not change | QEMU, VZ, or native Hyper-V. `hyperv` still declares no door and still refuses before mutation |

## 1. The problem this decides

A bound secret is served at a CONNECT proxy on the compute device. The guest
holds only an opaque handle; the proxy substitutes the value on the way out.
That proxy has to be reachable **from exactly one guest and from nothing
else** — it is an unauthenticated proxy for somebody's API keys.

QEMU gets this for free: its user-mode NAT maps the virtual gateway `10.0.2.2`
to host loopback, so a listener on `127.0.0.1` is reachable from that guest and
from no interface at all. That is `GuestEgress::LoopbackGateway`.

Cloud Hypervisor has no user-mode NAT. Asterism gives each CHV instance a
**per-instance TAP** with a host-side address (`crates/asterism-daemon/src/backend/chv.rs`,
`Network::for_instance`). That host address is a real interface on the device:
it is in the host's route table, other guests' TAPs are in the same table, and
forwarding or a future bridge change makes it reachable from more than one
guest. So `chv` declared `guest_egress: None`, and `ast attach --secret`
refused before registry mutation on the product backend for Linux — the
backend `ast` picks by default on a KVM host.

## 2. Options considered

**A. Put the door inside the guest and carry it out over vsock.**
The guest's own agent listens on the guest's loopback. What it accepts leaves
over this VM's virtio socket, proves the per-Instance key, and is spliced to a
private unix socket the daemon's egress plane owns.

**B. Bind the door on the per-instance TAP's host address and authenticate it.**

**C. Do nothing; keep refusing on CHV.**

## 3. Decision

**Option A, and the same `GuestEgress::AgentVsock` variant AST-114 introduced
for VZ.** `chv` declares
`GuestEgress::AgentVsock { gateway: "127.0.0.1", vsock_port: 1021 }`. The
protocol is `asterism_core::egress_door`; the guest half is the one in
`asterism-guest`, unchanged and backend-agnostic; the daemon end is the
per-instance unix socket in `crates/asterism-daemon/src/egress.rs`.

The one structural difference from VZ is in the middle of the diagram, and it
removes a process rather than adding one:

```text
 guest                            astd (backend/chv.rs)          astd (egress.rs)
 -----                            ---------------------          ----------------
 HTTPS_PROXY=http://127.0.0.1:1021
 asterism-guest listens on the
 guest's own loopback ------.
                            | AF_VSOCK connect (CID_HOST, 1021)
                            v
                    cloud-hypervisor dials the host end of its
                    *hybrid* vsock, which is a unix socket:
                        <instance>/chv-vsock.sock_1021
                            |
                            v
                    astd accepts it directly and proves the
                    per-Instance key (HMAC-SHA256, label
                    asterism-guest-egress)
                                            |
                                            v
                                  $ASTERISM_HOME/instances/<name>/
                                      egress/proxy.sock
                                  (the CONNECT/TLS plane, unchanged)
```

VZ needs `astd-vz` in the middle because `VZVirtioSocketListener` is a
Virtualization.framework object that only the process owning the VM may
install. Cloud Hypervisor's virtio socket is a **hybrid** one: the VMM owns a
unix socket, and a guest that connects to host port `p` makes the VMM connect
out to `<socket>_p` on the host and splice the two streams. So on this backend
the daemon binds that path itself, and the hop has one fewer participant than
on VZ.

## 4. Why A rather than B

The reasoning in ADR 0003 §4 applies unchanged, and one clause of it is
*stronger* here.

- Under A the address the guest is told to use is `127.0.0.1` — its own
  loopback, inside its own network namespace. Another guest has a different
  loopback. There is nothing to reach.
- Under A **nothing binds a host interface at all**. On CHV the host end is
  not merely "a unix socket instead of a port" as a matter of implementation
  choice — it is the transport Cloud Hypervisor actually offers, so choosing
  it costs nothing and invents nothing.
- Under B the listener would sit on a per-instance TAP address. Asterism's
  own `docs/instance-network.md` describes those as addresses on this device;
  they are in the host route table alongside every other instance's TAP. "Only
  this guest can reach it" would then be a claim about routing and firewall
  state on a machine Asterism does not own, defended by an HMAC key that lives
  in the guest root filesystem of the instance it belongs to. The refusal this
  ADR removes exists precisely because that is not a claim worth making.

**C was rejected** because `chv` is the *default* backend on a Linux/KVM host
(`backend::default` resolves chv ahead of qemu there). Refusing the flagship
feature on the default backend means the proven lane is the compatibility one.

## 5. Consequences

1. `GuestEgress` gains no new variant. AST-115 reuses AST-114's `AgentVsock`
   exactly — same shape, same protocol module, same guest agent, same
   transcript label — so a reviewer reads one door design and two backends
   that mount it, not two designs.
2. The seed's `HTTPS_PROXY` for a `chv` guest is `http://127.0.0.1:1021`, the
   same fixed guest-side port as VZ and for the same reason: it is in the
   guest's own namespace, so two instances never collide and a daemon restart
   reclaims exactly what a running guest was seeded with.
3. A direct-kernel OCI guest on this door loads the pinned
   `vsock` / `vmw_vsock_virtio_transport_common` / `vmw_vsock_virtio_transport`
   chain from the verified module store before its agent starts. An unbound
   guest, and every QEMU guest, loads none of it. `InstanceParts::needs_vsock`
   is what decides, and it is backend-declared rather than inferred.
4. The door is opened for **every OCI guest on this backend**, not only bound
   ones, and is closed by `cleanup_stopped` on every stop, kill, and
   observed-stopped transition. What makes a door serviceable is the plane's
   socket at the far end, which exists exactly while a secret is bound — so an
   unbound guest's door carries nothing, and `ast attach --secret` on a
   running instance needs no listener to appear from somewhere mid-flight.
5. `carry_door` dials the plane's socket **after** the key proof, never
   before. Detach removes that socket, so the next hop fails at a closed door
   rather than reaching a proxy on its way down. Revocation is therefore the
   same shape as QEMU's and strictly no weaker.
6. The key is read from `paths::guest_agent_key_path` per connection rather
   than held by the accept thread, so a rotated key is honoured without
   restarting anything and no thread owns key material between sessions.
7. Adoption re-binds the door from the path the VMM already holds
   (`recovered_handle`), so a daemon restart under a running guest is
   invisible to a guest mid-request.
8. `Caps` still describes what is *offered*; `egress::check_can_bind` still
   refuses from the recorded backend's declared identity rather than from a
   probe, so an impossible binding still cannot mutate the registry on a
   machine that lacks the backend.

## 6. What this does not decide

- Native Hyper-V. It attaches Hyper-V sockets and could carry the same
  protocol; it is not implemented here and still refuses before mutation.
- The cloud-image (non-OCI) CHV lane. Its guest agent is the Python one
  installed by cloud-init, which does not open the door. `check_can_bind`
  refuses a bound secret on a CHV instance created from a cloud image, before
  the row changes and by name.
- Two-device volume fencing over native NBD, which waits on AST-109.
- QUIC/UDP downgrade, pinned-SDK refusal, OAuth, quotas and audit — all still
  design, and all named as such in `SECRETS.md`.
