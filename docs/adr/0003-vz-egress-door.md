# ADR 0003 — the VZ secret-egress door is the guest's own loopback, carried over the instance's virtio socket

| | |
|---|---|
| Status | **Accepted** for the AST-114 implementation |
| Date | 2026-08-27 |
| Context | `SECRETS.md` §1 and §4; `OCI-RUNTIME.md` "Non-negotiable tests"; `docs/evidence/oci-parts-parity-2026-08-26` (the proven QEMU lane) |
| Supersedes | the `guest_egress: None` row for `vz` in `crates/asterism-daemon/src/backend/vz.rs`, and the sentence in `SECRETS.md` §1 that says VZ has no equally private host door |
| Does not change | QEMU, Cloud Hypervisor, or native Hyper-V. `chv` and `hyperv` still declare no door and still refuse before mutation |

## 1. The problem this decides

A bound secret is served at a CONNECT proxy on the compute device. The guest
holds only an opaque handle; the proxy substitutes the value on the way out.
That proxy has to be reachable **from exactly one guest and from nothing
else** — it is an unauthenticated proxy for somebody's API keys, and the one
thing worse than not having the feature is having it on the LAN.

QEMU gets this for free. Its user-mode NAT maps the virtual gateway
`10.0.2.2` to host loopback, so a listener on `127.0.0.1` is reachable from
that guest and from no interface at all. That is `GuestEgress::LoopbackGateway`,
and it is why the whole secrets feature shipped on QEMU first.

Virtualization.framework has no such path. `VZNATNetworkDeviceAttachment`
puts every guest on a **shared** bridge with an address of its own. There is
no host address that only one guest can reach: the bridge's host address is a
real interface, reachable by every other guest on it and, on some
configurations, from the LAN. So `vz` declared `guest_egress: None`, and
`ast attach --secret` refused before registry mutation on the product backend
for macOS.

## 2. Options considered

**A. Put the door inside the guest and carry it out over vsock.**
The guest's own agent listens on the guest's loopback. What it accepts leaves
over this VM's virtio socket to the per-instance `astd-vz` helper, which
proves the per-Instance key and splices the stream to a private unix socket
the daemon's egress plane owns.

**B. Bind the door on the bridge's host address and authenticate it.**
Put a listener on the VZ NAT host address and gate it with the per-Instance
HMAC key, so another guest that reaches it cannot use it.

**C. Do nothing; keep refusing on VZ.**

## 3. Decision

**Option A.** `vz` declares `GuestEgress::AgentVsock { gateway: "127.0.0.1",
vsock_port: 1021 }`. The protocol is `asterism_core::egress_door`; the guest
half is in `asterism-guest`, the host half in `astd-vz`, and the daemon end is
a per-instance unix socket in `crates/asterism-daemon/src/egress.rs`.

```text
 guest                              astd-vz helper                astd
 -----                              --------------                ----
 HTTPS_PROXY=http://127.0.0.1:1021
 asterism-guest listens on the
 guest's own loopback --------.
                              | AF_VSOCK connect (CID_HOST, 1021)
                              v
                      VZVirtioSocketListener on port 1021
                      prove the per-Instance key
                      (HMAC-SHA256, label asterism-guest-egress)
                                              |
                                              v
                                    $ASTERISM_HOME/instances/<name>/
                                        egress/proxy.sock
                                    (the CONNECT/TLS plane, unchanged)
```

## 4. Why A rather than B

**B is not provably guest-only, and A is guest-only by construction.**

- The address the guest is told to use under A is `127.0.0.1` — the guest's
  own loopback, inside its own network namespace. Another guest on the same
  bridge has a different loopback. There is nothing to reach.
- Under A **nothing binds a host interface at all**. The host end is a unix
  socket under `$ASTERISM_HOME`, governed by filesystem permissions. There is
  no TCP port on the device for another guest, another instance, another
  process on the LAN, or a future misconfiguration to aim at. This is a
  *narrower* door than QEMU's loopback listener, not a weaker substitute.
- A virtio socket belongs to one VM, and one `astd-vz` helper owns one
  instance. Cross-instance reachability is not defended against; it does not
  exist.

Under B, the listener is real and on a real interface. The HMAC key would be
the only thing between another guest on that bridge and an open proxy — and
that key lives in the guest root filesystem of the instance it belongs to, so
"another guest cannot use it" reduces to "no other guest ever reads a disk or
a snapshot it should not". The refusal that this ADR removes exists precisely
because that is not a claim worth making. B also leaks a port into `ast doctor`,
`lsof`, and every firewall audit, where a reviewer has to be told why it is
safe. A leaks nothing.

The cost of A is real and was accepted: three moving parts instead of one
(guest agent, helper listener, daemon socket), a vsock transport that a
direct-kernel OCI guest has to load as a module, and a hop that must be
authenticated even though the transport is already point-to-point.

**C was rejected** because macOS is the product backend on macOS. Shipping the
flagship feature only on the compatibility backend means the proven lane is
the one nobody should be running.

## 5. Consequences

1. `GuestEgress` gains a second variant. `Caps` still describes what is
   *offered*; `egress::check_can_bind` still refuses from the recorded
   backend's declared identity rather than from a probe, so an impossible
   binding still cannot mutate the registry on a machine that lacks the
   backend.
2. The seed's `HTTPS_PROXY` for a `vz` guest is `http://127.0.0.1:1021`. The
   guest-side port is **fixed**, not allocated: it lives in the guest's own
   namespace, so two instances never collide and a daemon restart reclaims
   exactly what a running guest was seeded with without remembering anything.
   The stable-port file remains the QEMU path's mechanism and is untouched.
3. A direct-kernel OCI guest on this door loads the pinned
   `vsock` / `vmw_vsock_virtio_transport_common` / `vmw_vsock_virtio_transport`
   chain from the verified module store before its agent starts. An unbound
   guest, and every QEMU guest, loads none of it.
4. The hop is authenticated with the per-Instance key under its own transcript
   label, `asterism-guest-egress`. A guest-control proof (`asterism-guest`) or
   a GPU-hop proof (`asterism-guest-gpu`) does not open the door, and the
   reverse holds. That is an executable test, not a convention.
5. Revocation is unchanged in shape and stricter in effect: dropping the
   instance's `Proxy` aborts the accept loop, sets the revoked flag every
   in-flight request reads, **and removes the unix socket**, so a new hop has
   nothing to connect to.
6. `astd-vz` gains the `VZVirtioSocketListener` feature and one delegate
   class. The delegate does two things that cannot block — duplicate the
   descriptor and start a thread — because it runs on the queue the VM is
   bound to (VZ-SPIKE-NOTES landmine 9). The framework connection objects it
   accepts are released by the run loop as their sessions end.
7. `Config` (`vz.json`) gains an additive `egress` object holding two paths
   and no key material, consistent with `agent_key`. A helper older than this
   change reads a config without it and installs no listener; a helper newer
   than a daemon without it does the same.

## 6. What this does not decide

- Cloud Hypervisor and native Hyper-V. Both attach virtio/Hyper-V sockets and
  could carry the same protocol; neither is implemented here and both still
  refuse before mutation.
- The cloud-image (non-OCI) VZ lane. Its guest agent is the Python one
  installed by cloud-init, which does not open the door. `check_can_bind`
  therefore refuses a bound secret on a VZ instance created from a cloud
  image, before the row changes and by name — the door is only as real as the
  agent that opens it, and a capability that is true of a backend but not of
  one of its guests must refuse rather than boot a guest holding a handle
  nothing honours.
- QUIC/UDP downgrade, pinned-SDK refusal, OAuth, quotas and audit — all still
  design, and all named as such in `SECRETS.md`.
