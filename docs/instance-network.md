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

## Opening a port from another device

`ast open NAME:PORT` puts a port served *inside* a guest on the loopback of
the device you are sitting at, whichever device in the orbit is supplying that
guest's compute. The scene it exists for: an agent has been building a UI all
night on the machine with the RAM, and in the morning you look at it from your
laptop.

```
$ ast open bot:3000
http://127.0.0.1:53000 → bot:3000 on dev5 (direct, 3 ms)
^C
closed bot:3000
```

The compute does not move. What crosses the mesh is one TCP connection at a
time: `ast` asks the daemon in front of it for a listener, that daemon binds
`127.0.0.1:<ephemeral>` and, for each accepted connection, opens a mesh stream
to the device supplying the compute, whose daemon dials the guest's private
address on `PORT` and splices the two together. TCP only. The bytes are
encrypted twice on the wire — once by whatever the service speaks, once by
QUIC — and nothing is exposed beyond loopback at either end.

### It is not a published endpoint

| | `ast create -p HOST:GUEST` | `ast open NAME:PORT` |
| --- | --- | --- |
| Where the listener is | the device running the guest | the device you are on |
| Durable | yes, part of the Instance | no, lives with the command |
| Survives a daemon restart | rebuilt from the registry | gone |
| Requires the port be declared | it *is* the declaration | no |
| Changes anything on the far device | binds a host port there | nothing |

So the port does not have to have been published with `-p`, and opening one
never publishes it. `ast down` does not close it either: a published port is
released with the declaration it belongs to, but an opened one belongs to the
command that opened it. Connections through it fail while the guest is
stopped — which is what a stopped service looks like from a browser — and
`ast up` makes the same URL work again. Ctrl-C is a complete teardown because there is nothing
written down: `ast` holds its unix socket open for the life of the command,
and dropping it drops the listener and every connection under it.

### Flags

* `--no-browser` prints the address and opens nothing.
* `--json` prints one object — `{"local","instance","device","port","path"}` —
  and opens nothing. `path` is the same vocabulary `ast devices` and `ast ping`
  use: `direct`, `relay`, or `local` when there is no mesh hop at all.
* `--local-port N` binds that port here instead of an ephemeral one, for a URL
  that has to be the same twice. Refused if something else holds it, never
  moved.

### Refusals, all of them before a listener exists

A URL that is printed and then does not work is worse than no URL, so every
check happens first:

```
$ ast open nope:3000
unknown instance "nope" (orbit has: bot, web)

$ ast open bot:3000          # dev5 is not answering
dev5 is offline (last seen 4 min ago) — bot:3000 is unreachable

$ ast open bot:3000          # bot is down
instance "bot" is not running — `ast up bot` first

$ ast open bot:1023
guest port 1023 is Asterism's own guest-control endpoint on an OCI instance …
```

The command never names a device, because it does not have to: instance names
are unique across an orbit. Resolving one — this device first, then every peer
— is `astd`'s `resolve::locate`, shared rather than owned by `ast open`, so
every other command that addresses an instance by bare name gets the same
answer and the same two refusals.

The unknown-instance refusal lists the orbit's instance names because that is
the next thing you would ask for. The offline refusal is worded as a fact
about the *device*, because that is the thing to go and fix; "last seen" is
the most recent of two facts the local daemon holds — when it last dialled
that device successfully, and when that device last handed over its shard.

Guest port 1023 is refused here for the same reason a published mapping may
not name it, and it is refused **twice**: once by the daemon in front of you,
so you get a sentence, and again by the daemon supplying the compute, which is
the side the rule protects. The asking side is the party the rule constrains,
so its check alone would not be one.

### Wire

Protocol 16. One unix-socket frame (`open_port`) and one new mesh stream kind
(`port_splice`), which carries `{name, port}` in its opening frame, one
`splice_ready` reply, and then raw bytes in both directions. A peer older than
16 refuses the stream by name — `an opened guest port` — rather than dropping
it, because a dropped stream reads as a device that is switched off.

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
