# Instance networking and egress

An Instance has one backend-neutral network declaration. The declaration is a
part of the Instance; NAT, TAP, HCN and backend-specific guest addresses are
implementation details behind it.

## Published service endpoints

`ast create NAME -p HOST:GUEST` publishes TCP by default. The explicit forms
are `HOST:GUEST/tcp` and `HOST:GUEST/udp`; one number uses the same port on both
sides. Every host endpoint binds only on `127.0.0.1` of the device the
instance runs on. It is not LAN or Internet ingress.

The declaration is durable, and the same declaration means the same endpoint on
every backend that can serve it. `down`/`up`, a VMM restart and a daemon
restart never invent a new service endpoint. TCP and UDP have separate
host-port spaces; duplicate protocol/host pairs are refused before Instance
creation, as is a mapping whose *guest* side is Asterism's own guest-control
port (1023) on an OCI Instance — that is where `ast exec`, `ast logs` and boot
readiness go, and no service of the user's is behind it.

There is no flag that widens the bind address. Every host endpoint is
`127.0.0.1` on the device the instance runs on; `0.0.0.0` is not reachable
through any declaration Asterism accepts today.

### Two mechanisms behind one declaration

A backend either forwards inside its own network stack or hands the guest a
private address, and publication follows from that.

* **QEMU** has a user-mode NAT. The recorded mappings are rebuilt as `hostfwd`
  arguments on every boot and the VMM binds the host ports. `astd` is not on
  the data path. QEMU's private SSH and OCI-control forwards are also allocated
  outside declared TCP host ports, so they can never take one.
* **Virtualization.framework** (macOS NAT) and **Cloud Hypervisor**
  (per-instance TAP) give the guest a private address of its own that this host
  routes to and nothing outside the device can name. There is nothing to
  configure in the VMM, so `astd` is the forward: for each mapping it binds
  `127.0.0.1:HOST` itself and carries traffic to `<guest private
  address>:GUEST` — TCP by splicing both directions of an accepted connection,
  UDP by giving each client address a socket of its own and expiring it after
  two minutes without a datagram. See `crates/asterism-daemon/src/publish.rs`.

Both are the same promise to the user, and `Caps::port_forward` is deliberately
true for both: callers gate on the capability, never on which mechanism is
behind it.

Current capability boundary:

| Backend | Published TCP/UDP | How | Guest-only secret egress door |
|---|---:|---|---:|
| QEMU + HVF/KVM | yes | loopback `hostfwd` in the VMM | yes, `10.0.2.2` to host loopback |
| Virtualization.framework | yes | `astd` listener to the guest's NAT address | yes, guest loopback over the instance's virtio socket (OCI guests) |
| Cloud Hypervisor/KVM | yes | `astd` listener to the guest's TAP address | yes, guest loopback over the instance's virtio socket (OCI guests) |
| native Hyper-V | no | — | yes, guest loopback over this VM's Hyper-V Socket (OCI guests) |

An explicit incapable backend refuses before registry mutation, and automatic
selection never silently drops a mapping. Publication is no longer a reason to
reach for QEMU: on a Mac the product backend serves `-p` itself, so the AST-97
"install the compatibility backend" refusal now belongs only to what remains
QEMU's alone — a qcow2 base image the user pointed at directly, and foreign
architecture guests.

### Lifecycle of a daemon-side listener

The listeners `astd` binds are attached to the Instance's running record, not
to a process that happens to be alive:

* **Created after guest readiness.** Both native backends return from `boot`
  only once the guest has proved it is up and named its address, so the address
  is known before anything is bound. A declaration on an Instance with no
  address yet publishes nothing — it is deferred, not dropped.
* **Refused early where it can be.** `ast up` proves each declared host port is
  free before a guest is created, so a port somebody else holds is a refusal
  while there is still nothing running.
* **Torn down on `down` and `rm`**, and when the crash supervisor notices the
  guest has died. The host port goes back to the device the moment the guest
  behind it is gone; the durable declaration is what puts it back.
* **Recreated on `up`**, including the supervisor's `restart=always` retry.
* **Recovered on exactly the declared port.** A daemon restarting on top of
  guests that outlived it rebuilds every mapping from the registry. If the port
  is taken it reports that and leaves the mapping down. It never picks another:
  a published endpoint is a promise about one number, and moving it would
  report success while every client that read `ast status` points at nothing.

## Orbit-scoped secret egress

This is what lets you hand an always-on agent the keys you actually use. A
bound guest receives an opaque per-Instance handle, a per-Instance CA, and a
proxy endpoint; the plaintext credential stays in its source device's platform
secret store. Bound HTTPS requests cross the authenticated orbit seam with the
credential position empty, and the source device inserts the real value into
the upstream request on its way out.

The proxy is reachable from one guest and from nothing on the wire, and the
four backends that offer that reach it two different ways. On QEMU it is a
loopback listener the guest reaches through its user-mode NAT gateway.

None of the other three has such a gateway — a VZ guest holds an address on a
shared NAT bridge, a CHV guest holds one on a per-instance TAP that is a real
interface on this device, and a Hyper-V guest holds one on an HCN NAT whose
gateway every guest on it shares — so on all three the door is the guest's own
loopback: the injected guest agent listens there and carries what it accepts
over this instance's socket. The per-Instance key is proved on that hop and
the stream is spliced onto a private endpoint the egress plane owns. Nothing
binds a host interface on any of these paths.

They differ only in who answers that socket, and the guest cannot tell:

* **VZ** needs the signed `astd-vz` helper, because a
  `VZVirtioSocketListener` can only be installed by the process that owns the
  VM.
* **Cloud Hypervisor**'s virtio socket is a hybrid one — the VMM dials
  `<socket>_<port>` on the host for a guest-initiated connection — so `astd`
  binds that path itself and the hop has one fewer participant.
* **Hyper-V** has no virtio socket at all. The guest's `hv_sock` driver
  presents Hyper-V Sockets through the same AF_VSOCK ABI with the host at
  CID 2, so the agent dials the same address; on the host,
  `astd-hyperv.exe` binds an `AF_HYPERV` listener against *that one compute
  system* and the door's service GUID
  (`000003fd-facb-11e6-bd58-64006a7986d3`, the `hv_sock` template with the
  vsock port in the first double word). The VM's own `HvSocketConfig` service
  table admits that bind with `AllowWildcardBinds: false`, so a listener
  bound to any other VM never sees this guest and there is no machine-wide
  registry key to add or clean up. The private endpoint on the host end is a
  named pipe whose security descriptor names only `astd`'s own SID, because
  Windows has no socket file under `$ASTERISM_HOME` to keep private with
  permissions.

See `docs/adr/0003-vz-egress-door.md`, `docs/adr/0004-chv-egress-door.md` and
`docs/adr/0005-hyperv-oci-boot-and-door.md`.

Because every agent door is opened by the agent Asterism injects into an OCI
root filesystem, an instance created from a cloud image still refuses a secret
binding before the row changes on all three. Detach revokes the old proxy
context, including already-open connections, before restarting against the
remaining policy.

The proxy port and CA persist with the Instance. Every agent door's guest-side
port is fixed rather than allocated: it is in the guest's own namespace, so
two instances never collide and a daemon restart reclaims it by construction.
When `astd` restarts while a QEMU guest remains alive, it reclaims that exact
port before serving requests.
If it cannot, recovery reports an error and remains fail-closed; choosing a new
port would leave the already-booted guest pointed at the old one. If the VMM is
restarted, the boot path reissues the seed and may safely choose a new free
port.

UDP service publication is independent of secret interception. The secret
plane currently handles HTTP/1.1 CONNECT and selective TLS termination; QUIC
blocking/downgrade, audit logs, quotas, query/body injection and managed OAuth
remain outside the built boundary.
