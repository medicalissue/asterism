# Instance networking and egress

An Instance has one backend-neutral network declaration. The declaration is a
part of the Instance; NAT, TAP, HCN and backend-specific guest addresses are
implementation details behind it.

## Published service endpoints

`ast create NAME -p HOST:GUEST` publishes TCP by default. The explicit forms
are `HOST:GUEST/tcp` and `HOST:GUEST/udp`; one number uses the same port on both
sides. Every host endpoint binds only on `127.0.0.1` of the device supplying
compute. It is not LAN or Internet ingress.

The declaration is durable. QEMU rebuilds its user-mode NAT `hostfwd` arguments
from the recorded mappings on every boot, so `down`/`up` and VMM recovery do
not invent a new service endpoint. TCP and UDP have separate host-port spaces;
duplicate protocol/host pairs are refused before Instance creation. QEMU's
private SSH and OCI-control forwards are also allocated outside declared TCP
host ports.

Current capability boundary:

| Backend | Published TCP/UDP | Guest-only secret egress door |
|---|---:|---:|
| QEMU + HVF/KVM | yes, loopback `hostfwd` | yes, `10.0.2.2` to host loopback |
| Virtualization.framework | no | yes, guest loopback over the instance's virtio socket (OCI guests) |
| Cloud Hypervisor/KVM | no | yes, guest loopback over the instance's virtio socket (OCI guests) |
| native Hyper-V | no | no |

An explicit incapable backend refuses before registry mutation. Automatic
selection may choose QEMU when publication is required; it never silently
drops a mapping.

## Orbit-scoped secret egress

A bound guest receives an opaque per-Instance handle, a per-Instance CA, and a
proxy endpoint. The plaintext credential stays in its source device's platform
secret store. Bound HTTPS requests cross the authenticated orbit seam with the
credential position empty; the source device inserts the value only into the
upstream request.

The proxy is reachable from one guest and from nothing on the wire, and the
three backends that offer that reach it two different ways. On QEMU it is a
loopback listener the guest reaches through its user-mode NAT gateway.

Neither Virtualization.framework nor Cloud Hypervisor has such a gateway — a
VZ guest holds an address on a shared NAT bridge, and a CHV guest holds one on
a per-instance TAP that is a real interface on this device — so on both of
them the door is the guest's own loopback: the injected guest agent listens
there and carries what it accepts over this instance's virtio socket. The
per-Instance key is proved on that hop and the stream is spliced onto a
private unix socket the egress plane owns. Nothing binds a host interface on
either path.

The two differ only in who answers the virtio socket. VZ needs the signed
`astd-vz` helper, because a `VZVirtioSocketListener` can only be installed by
the process that owns the VM. Cloud Hypervisor's virtio socket is a hybrid one
— the VMM dials `<socket>_<port>` on the host for a guest-initiated connection
— so `astd` binds that path itself and the hop has one fewer participant. See
`docs/adr/0003-vz-egress-door.md` and `docs/adr/0004-chv-egress-door.md`.

Because both doors are opened by the agent Asterism injects into an OCI root
filesystem, a VZ or CHV instance created from a cloud image still refuses a
secret binding before the row changes, and so does Hyper-V. Detach revokes the
old proxy context, including already-open connections, before restarting
against the remaining policy.

The proxy port and CA persist with the Instance. Both agent doors' guest-side
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
