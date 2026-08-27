# astrelay

`astrelay` is Asterism's relay server. It forwards ciphertext between two
devices that cannot reach each other directly, and it is the meter the relayed
half of an orbit's traffic is billed from.

It lives in this repository, under the same MIT/Apache-2.0 as `ast` and `astd`,
and running your own is a supported configuration rather than a tolerated one.

## What a relay is

Two devices in an orbit want a direct QUIC path. Most of the time hole punching
finds one: each asks a server what address the world sees it on, both send
packets at the other's, and the NATs on either side open. When that fails —
symmetric NAT on both ends, a corporate network that drops UDP to anything it
has not seen first, carrier-grade NAT — the connection falls back to a relay
that forwards packets between them.

A relay does two jobs, and it is worth keeping them apart:

- **Rendezvous.** Every connection between two NATed devices starts here,
  because it is the only place they can meet before hole punching has
  succeeded. This cost is unavoidable and small: a handshake, then a few
  seconds of traffic while the direct path comes up.
- **Fallback.** For the pairs that never punch through, the relay carries
  everything, for as long as the connection lasts. This cost is unbounded and
  scales with usage.

The daemon meters both, and reports them separately — see
[Metering](#metering-on-the-device) — because a relay bill that does not
distinguish them cannot be reasoned about.

## What a relay can and cannot see

**It forwards ciphertext.** The QUIC session is terminated on the two devices
and nowhere else. Its keys are derived, during a handshake the relay only
carries bytes for, from the two device identities — Ed25519 keys that never
leave the machines they were generated on. The `astrelay` process holds **no
orbit key material of any kind**. Its own TLS certificate authenticates *the
relay* to connecting clients and is unrelated to the keys that encrypt what
passes through it.

An operator of a relay can see: which public keys are connected, when, how many
packets pass between which pair of keys, and how large they are. That is
traffic analysis, and it is real. What they cannot see is a single byte of
anyone's content.

This is why the default access policy is to accept everyone. Gating a relay
costs operational effort and buys no confidentiality the transport did not
already provide; it only protects bandwidth. See [Access](#access).

`scripts/e2e-relay.sh` demonstrates the property from outside: it runs a real
relay, moves real traffic through it, and then checks that nothing in the
relay's log or its metrics is anything but a count. The stronger claim — that
no key material is present to leak — is structural: the crate links no orbit
key code, generates no device identity, and reads no `$ASTERISM_HOME`.

## Modes

Cross-network connectivity is something a device is *given*. There is no
default relay fleet compiled into Asterism and no default directory. A device
is in one of three states.

| Mode | Relay | Directory | How you get there |
|---|---|---|---|
| **Local** | none | none | the default: a fresh install, no login, no configuration |
| **Logged in** | ours, supplied at login | the account's private device directory | `ast login` (AST-118) |
| **Self-hosted** | yours | yours, or none | `ASTERISM_RELAY_URL` / `ast config set relay` |

**Local** is loopback only: no relay, no address publication, no packet that
leaves the host. Devices reach each other wherever a direct path already
works, dialling the addresses a pairing ticket carried. Nothing about the
device — not its public key, not its addresses — is published anywhere. The
daemon says so at startup.

**Logged in** is what a coordinator supplies. It answers "which relays does
this account use, and where is its device directory", and that answer becomes a
`MeshInfra` (see [The seam](#the-seam)). The directory is per-account, not
public.

**Self-hosted** is the same code path with the values coming from the
environment instead of from a coordinator. It is first class: run `astrelay`,
point `ASTERISM_RELAY_URL` at it, and you are done. An environment variable
outranks whatever a coordinator supplied, so it is also how you override a
hosted relay you would rather not use.

Earlier builds rode n0's public infrastructure (`*.relay.n0.iroh.link`,
`dns.iroh.link`) by default. That was the Phase 2 bootstrap and it is gone: it
meant an unconfigured device published its public key and its current addresses
to a public directory run by strangers as a side effect of being installed.

## Running one

```console
$ astrelay --dev                       # plaintext on 127.0.0.1:3340, for tests
$ astrelay --tls lets-encrypt \
    --acme-domain relay.example.com \
    --acme-contact ops@example.com \
    --acme-cache /var/lib/astrelay/acme \
    --metrics-bind 127.0.0.1:9090
$ astrelay --tls manual --cert /etc/astrelay/fullchain.pem \
                        --key  /etc/astrelay/privkey.pem
```

Then, on each device:

```console
$ ASTERISM_RELAY_URL=https://relay.example.com astd
```

### Flags

| Flag | Default | What it does |
|---|---|---|
| `--dev` | off | Plain HTTP on `127.0.0.1:3340`. Overrides `--tls`. Never use on a public address. |
| `--http-bind ADDR` | `[::]:80` | The plain HTTP listener. Serves the relay when TLS is off, and only the captive-portal probe when it is on. |
| `--tls MODE` | `none` | `none`, `manual`, or `lets-encrypt`. |
| `--https-bind ADDR` | `[::]:443` | The HTTPS listener, when TLS is on. |
| `--cert PATH` / `--key PATH` | — | PEM chain and key, for `--tls manual`. |
| `--acme-domain HOST` | — | Repeatable. Hostnames to obtain a certificate for. |
| `--acme-contact EMAIL` | — | ACME account contact. Required for Let's Encrypt. |
| `--acme-cache DIR` | — | Where to cache issued certificates. **Set this**: without it every restart requests a fresh certificate and Let's Encrypt will eventually refuse. |
| `--acme-staging` | off | Use Let's Encrypt's staging environment. |
| `--quic-bind ADDR` | off | QUIC address discovery — the probe that tells a device its public address, which is what makes hole punching work. Requires TLS. Relays nothing itself. |
| `--metrics-bind ADDR` | off | Prometheus metrics. Bind it to a private interface. |
| `--access MODE` | `open` | `open` or `token`. See below. |
| `--client-rx-limit BYTES` | unlimited | Per-connection inbound **throttle**, in bytes per second. A token bucket on the read side: an over-eager client is slowed, not disconnected. |
| `--client-rx-burst BYTES` | — | Burst allowance above the throttle. |
| `--per-client-metrics` | off | Break the connection counters out per client public key. |
| `--per-client-metrics-max N` | 1024 | How many distinct keys may hold a label. |

`--client-rx-limit` is deliberately unlimited by default. A relay that starts
throttling before anyone has measured what normal traffic looks like is a
mystery outage waiting to happen. Set it once you have a baseline.

### Access

`--access open` (the default) admits every device. This is the right default
for the reason above: a relay forwards ciphertext, so refusing a stranger
protects nobody's data, only bandwidth.

`--access token` admits only clients presenting a bearer token, read from
`ASTRELAY_ACCESS_TOKEN` in the relay's environment. It is a shared secret, not
an identity: use it to stop a private relay being used as free bandwidth, not
as an authorisation system. The token is compared in constant time, and the
relay refuses to start if the mode is set and the variable is not — starting
wide open would be the failure nobody notices until the bandwidth bill arrives.

The token goes in the environment rather than in a flag because a flag is
visible in `ps` output to every user on the host.

### Metrics

`--metrics-bind` serves OpenMetrics at `/metrics`. Two groups appear there.

From iroh-relay, `relayserver_*`: `bytes_sent`, `bytes_recv`,
`send_packets_sent`, `send_packets_recv`, `send_packets_dropped`, `accepts`,
`disconnects`, `http_connections*`, `qad_*`, `bytes_rx_ratelimited_total`.
`bytes_sent` and `bytes_recv` count QUIC datagram payload forwarded — the
figure to reconcile against the devices' meters.

From `astrelay` itself, `astrelay_*`: `connections_admitted`,
`connections_denied`, `connections_closed`, `clients_seen`,
`clients_untracked`, and — only with `--per-client-metrics` —
`client_connections{client="…"}` and `client_disconnects{client="…"}`.

**Per-key byte counters are not available.** iroh-relay 1.0.3's byte counters
are process-global and it exposes no hook on the forwarding path where a
per-key counter could be kept. Producing one would mean forking the crate,
which AST-119 decided against. Per-key accounting on the relay is therefore
connection-level; the byte-level accounting lives on the device, and the
relay's global totals are what corroborates it.

**Per-client labels are off by default** because each key becomes a Prometheus
time series and a public relay meets an unbounded number of keys. When on,
`--per-client-metrics-max` caps the distinct keys that get a label; past it,
connections are counted in the aggregates only and `astrelay_clients_untracked`
records that it happened rather than letting the cap hide. A refused connection
never gets a label at all, so the label set is never attacker-controlled.

## Metering, on the device

`astd` keeps a per-peer byte count split by path, in
`$ASTERISM_HOME/relay-meter.json`. This is the billing basis.

It is read from QUIC's own per-path byte counters — iroh keeps them per path,
and a path is either an IP address or a relay URL, so the direct/relayed split
needs no estimation. The numbers are UDP payload bytes as the QUIC stack
counted them, which includes acknowledgements and retransmissions. That is
deliberate: those bytes crossed the relay, the relay counted them too, and a
figure that excluded them would disagree with the bandwidth invoice.

Per peer, the meter records:

| Field | Meaning |
|---|---|
| `direct_sent` / `direct_recv` | bytes over a direct path — free to the operator |
| `relayed_sent` / `relayed_recv` | bytes through a relay — the billing basis |
| `relayed_before_direct` | bytes relayed before hole punching moved a connection direct: the cost of the rendezvous |
| `last_upgrade_millis` | how long the most recent relay-to-direct upgrade took |
| `upgrades` | how many observed connections made the move |

`relayed_before_direct` against `relayed_sent + relayed_recv` is the number
worth watching. If they are close, nearly everything relayed was the cost of
meeting, and the relay bill scales with the number of connections. If the total
is far above it, traffic is not getting off the relay, and the bill scales with
usage instead.

**The file records device ids and integers, and nothing else.** No addresses,
no device names, no per-instance or per-stream attribution.

**Reset policy: never automatically.** Totals are cumulative since the moment
the file was first created. Nothing rolls them over, zeroes them at a month
boundary, or forgets a peer that went quiet. Deleting the file starts a new
accounting period, and that is the only reset there is. A consumer that wants
monthly figures takes differences of snapshots — the only form that survives a
daemon that was not running at midnight. Removing a device from the orbit
forgets its counters, because keeping them would be keeping a record of a
relationship the user ended.

**Known limitation.** The meter samples every 10 seconds and on a clean
shutdown, and a path takes its counters with it when it closes — so a
connection that opens and closes entirely between two samples is not counted.
`scripts/e2e-relay.sh` therefore compares *bracketed deltas* rather than
lifetime totals; see the comment in that file.

### Reading it

```console
$ ast ping laptop
pong from laptop (bd38d09702d0) via relay in 0.5ms
  bytes    direct 0 B sent / 0 B recv, relayed 14.9 KiB sent / 13.5 KiB recv
  path     relay, still relayed — no direct path yet
  relay    https://relay.example.com/

$ ast devices                # DIRECT, RELAYED and RELAY columns on the end
$ ast devices --json         # exact counters, for anything that reconciles
```

The `relay` line is what `STATUS.md`'s path-speed investigation asked for. A
latency figure with no route named beside it cannot be attributed to anything;
`68–78 ms where 5 ms was possible` was unattributable precisely because nothing
said which socket carried the bytes.

`path` is four words rather than two:

- `direct` — a direct path is selected and no relay path is open
- `mixed` — a direct path is selected with the relay path still warm beneath
  it as the fallback. **This is the healthy steady state**, not a warning
- `relay` — the relay is carrying the bytes
- `-` — nothing is open yet

### The relay-to-direct upgrade

iroh moves the *same* QUIC connection from the relay onto a direct path once
hole punching succeeds; the connection is not re-established and the
application sees nothing. That is what makes the relay a rendezvous rather than
a pipe, and it is why `mixed` is normal.

`ast ping` reports `went direct after <n>ms` once the move has been observed.
The measurement is honest about its clock: it is timed from the meter's first
*sample* of the connection, not from the QUIC handshake, so it is accurate to
within one sample interval. `relayed_before_direct` is the byte count that
matters more, and it is exact.

Port mapping helps this happen. **UPnP / NAT-PMP / PCP are enabled by default**
in Asterism's endpoints — iroh ships its `portmapper` feature in its default
set and `PortmapperConfig::default()` is `Enabled`, so this is inherited rather
than chosen, and it is stated here rather than left to be discovered. What it
does is ask the local router to forward a port back to the device, which buys
direct connectivity behind NATs that would otherwise force everything through a
relay. Its cost is a little SSDP multicast on the LAN and, on macOS, a firewall
dialog the first time. `ASTERISM_MESH_NO_PORTMAP=1` declines it, at the price
of more relayed bytes.

### What the meter cannot tell apart

**Control streams from bulk streams.** iroh's byte counters are per *path*, not
per stream: by the time a byte is counted it is inside a QUIC packet that may
carry frames from several streams at once, and no per-stream byte counter is
exposed. So the meter can say "this peer relayed 4 GiB" but not "3.9 GiB of it
was an NBD attachment". Any policy that wants to treat bulk transfers
differently over a relay-only path — AST-129 — will have to account at the
point where the daemon opens the stream, not here.

## The seam

`MeshInfra` in `crates/asterism-mesh/src/endpoint.rs` carries the relay list
and the directory. It is empty by default, and:

```rust
// The hosted coordination plane calls this (AST-118).
MeshInfra::with_hosted(relays: Vec<RelayUrl>, discovery: HostedDiscovery) -> MeshInfra

// The environment then overrides it, field by field. A variable a human set
// on this machine outranks whatever a coordinator supplied.
MeshInfra::with_env_overrides(self) -> MeshInfra

// What a device with no login and no configuration reads.
MeshInfra::from_env() -> MeshInfra   // == MeshInfra::default().with_env_overrides()
```

`HostedDiscovery::none()`, `::pkarr(url)` and `::pkarr_and_dns(url, origin)`
cover the directory half, which is separately optional: a relay with no
directory is a coherent configuration, with peers dialled from pairing tickets
and stored hints.

No code in `asterism-mesh` performs a coordinator call. It is the seam, not the
client.

### Environment

| Variable | Sets | Unset means |
|---|---|---|
| `ASTERISM_RELAY_URL` | relay servers, comma-separated, first preferred | no relay |
| `ASTERISM_PKARR_RELAY` | pkarr publish/resolve | publish nothing |
| `ASTERISM_DNS_ORIGIN` | DNS lookup zone | no DNS lookup |
| `ASTERISM_MESH=local` | forces local-only whatever else is set | discovery is permitted, if configured |
| `ASTERISM_MESH_NO_PORTMAP=1` | declines UPnP/NAT-PMP/PCP | port mapping is on |
| `ASTERISM_MESH_RELAY_ONLY=1` | removes every IP transport, so no direct path can exist | direct paths are preferred |
| `ASTRELAY_ACCESS_TOKEN` | the relay's shared secret, for `--access token` | — |

`ASTERISM_MESH_RELAY_ONLY=1` is a test seam. iroh has no "relay only" policy
knob, but its endpoint builder has `clear_ip_transports`, and an endpoint with
no IP transport has no direct path for iroh to select. That is what lets
`scripts/e2e-relay.sh` prove a byte was relayed as a property of the
configuration rather than as an inference from a counter. It is a stronger
statement than `ASTERISM_MESH_NO_DIRECT=1`, which only hides the addresses a
device advertises and still permits an upgrade.

## Operating cost

*Approximate, dated 2026-08. Verify before committing to anything.*

The cost driver is **egress bytes**, and relay traffic is fallback-only: direct
paths are the norm, and the rendezvous is a handshake and a few seconds. A
relay is therefore mostly idle capacity with occasional sustained flows from
the pairs that never punch through. CPU and memory are not the constraint — the
relay forwards opaque datagrams and does no crypto on them.

So the shape is: **a small VM per region**, and choose the region for latency
and the provider for egress pricing.

| Option | Rough cost | Egress | Notes |
|---|---|---|---|
| Fly.io machine | ~$5/mo | ~$0.02/GB | Anycast, easy multi-region. Good first deployment. |
| Hetzner Cloud | ~€4/mo | 20 TB included | Cheapest by a distance, but EU and US only. |
| Vultr / Linode Seoul | ~$5–6/mo | 1–2 TB included | The realistic option for Korean latency. |
| AWS / GCP | — | ~$0.09/GB | Avoid. Egress pricing is an order of magnitude worse and egress is the whole cost. |

**Cloudflare Workers cannot host this.** A relay needs a long-lived TCP/WebSocket
listener per client and a UDP listener for QUIC address discovery; Workers
provide neither. The relay lives outside the Worker, whatever else of the
coordination plane runs in one.

Start with one region, watch `relayserver_bytes_sent_total`, and add regions
when the latency numbers — not the bandwidth numbers — say to.

## What production still needs

This pass is the code. Not done, and named rather than implied:

- **Deployment.** No relay is deployed. Target, region and provider are
  unchosen; see the table above for the shape of the decision.
- **TLS in anger.** `--tls lets-encrypt` and `--tls manual` are configured and
  unit-tested but have not served a certificate. That needs a public hostname.
- **DNS.** A stable hostname per relay, and a plan for what a device does when
  the one it was given stops resolving.
- **The coordinator supplying the list.** `MeshInfra::with_hosted` exists and
  nothing calls it yet — AST-118.
- **Two-NAT proof.** `scripts/e2e-relay.sh` runs on one host and forces
  relaying by removing IP transports. Whether a real pair of devices behind two
  real NATs falls back correctly, and how long their upgrade takes, is a
  two-network test that has not been run.
- **Relay-side bulk policy.** AST-129.
