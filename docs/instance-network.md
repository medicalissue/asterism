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
| Virtualization.framework | no | no |
| Cloud Hypervisor/KVM | no | no |
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

The proxy listens on loopback only. Today the secure guest-only door exists on
QEMU user-mode networking, so VZ, Cloud Hypervisor and Hyper-V refuse a secret
binding before the binding row changes. Detach revokes the old proxy context,
including already-open connections, before restarting against the remaining
policy.

The proxy port and CA persist with the Instance. When `astd` restarts while a
QEMU guest remains alive, it reclaims that exact port before serving requests.
If it cannot, recovery reports an error and remains fail-closed; choosing a new
port would leave the already-booted guest pointed at the old one. If the VMM is
restarted, the boot path reissues the seed and may safely choose a new free
port.

UDP service publication is independent of secret interception. The secret
plane currently handles HTTP/1.1 CONNECT and selective TLS termination; QUIC
blocking/downgrade, audit logs, quotas, query/body injection and managed OAuth
remain outside the built boundary.
