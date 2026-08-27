# Path matrix, Mac ↔ dev5, 2026-08-27 (AST-138)

The only latency number this project had for Mac↔dev5 was a warm `ast ping` of
68–78 ms, recorded during AST-36 with nothing attached to it: no path kind, no
relay name, no control measurement beside it. Three causes were suspected and
none was ever chosen between — the n0 public relay, the portmapper, or a QUIC
handshake on every ping. This run measures the path on the real hardware and
picks one.

**The 68–78 ms is not Asterism's.** It is the wire underneath it. Plain ICMP
between the same two hosts is 68.2–78.3 ms, and `ast ping` on the same wire is
69.7 ms at p50 — the mesh adds essentially nothing. The wire is slow because
dev5's Tailscale node cannot hole-punch out of WSL2's NAT and falls back to
Tailscale's DERP relay in **Tokyo**, while the same physical machine's Windows
host, which is not behind WSL2's NAT, answers in 3 ms.

Everything below was produced by `scripts/bench-path.sh` at git
`6454198d`; the raw samples are in `measurements.jsonl`, one JSON object per
line.

## Hosts and topology

| | Mac (`mac-a`) | dev5 Windows host | dev5 WSL2 (`dev5-b`) |
|---|---|---|---|
| device id | `62036c21cc3d` | — (not an Asterism device) | `c6934c269e00` |
| LAN address | `192.168.50.205` | `192.168.0.21` | `172.19.250.136` (WSL2 NAT) |
| Tailscale | `100.121.213.11` | `100.65.60.28` | `100.91.138.55` |

Reachability, measured rather than assumed:

| From → to | Result |
|---|---|
| Mac → dev5 Windows host `192.168.0.21`, ICMP | 100% loss (filtered) |
| Mac → dev5 Windows host, Tailscale | **direct `192.168.0.21:41641`, 3 ms** |
| dev5 WSL → its own Windows host `192.168.0.21` | 0.46 ms |
| dev5 WSL → Mac `192.168.50.205`, ICMP | 100% loss |
| dev5 WSL → Mac `192.168.50.205`, TCP | connection fails outright |
| dev5 WSL → Mac Tailscale `100.121.213.11`, TCP | succeeds |
| Mac ↔ dev5 WSL, `tailscale ping` | **`via DERP(tok)` 68–71 ms, "direct connection not established"** |

The Mac and dev5 are on different subnets (`192.168.50.0/24` vs
`192.168.0.0/24`) and the Mac's side is not reachable inbound at all. dev5's
WSL2 sits behind a second NAT on top of that. **There is no same-LAN path
between these two hosts**, which is why row A below is "not run" rather than
slow.

## The matrix

Per-path numbers. `ast ping` is 20 samples; the first is reported separately
and excluded from the percentiles. `ast mesh bench` pulls N bytes down one mesh
stream and touches no disk on either end.

| Path | `ast ping` cold | p50 | p95 | min–max | reported path | 1 MiB | 64 MiB |
|---|---|---|---|---|---|---|---|
| **A. Same LAN, direct** | — | — | — | — | — | — | — |
| **C1. Relay configured, not forced** | 69.9 ms | **69.7 ms** | 72.1 ms | 68.3–81.8 ms | `direct` / `mixed`, upgrade 0 ms | 1.90 MB/s | **2.79 MB/s** |
| **C2. Relay forced** (`ASTERISM_MESH_RELAY_ONLY=1`) | 69.0 ms | **69.9 ms** | 72.7 ms | 68.9–73.2 ms | `relay`, never upgraded | 1.55 MB/s | 2.42 MB/s |

Cold, measured properly (daemon restarted, connection pool empty): **72.1 ms**,
about 2 ms above warm p50. Note that `ast ping` times only the request/reply on
an already-live connection — `Mesh::live_connection` dials and probes *before*
the timer starts — so a handshake was never inside this number to begin with.

### Controls, same wire, nothing to do with Asterism

| Measurement | Result |
|---|---|
| ICMP Mac → dev5 WSL (`100.91.138.55`), 20 samples | min 68.2 / avg 71.0 / **max 78.3 ms** |
| ICMP Mac → dev5 Windows host (`100.65.60.28`), 15 samples | min 3.5 / **avg 5.0** / max 15.3 ms |
| TCP connect Mac → dev5 WSL `:2222` | ~75 ms |
| `tailscale ping` Mac → dev5 WSL | 68–71 ms, via DERP Tokyo |
| `tailscale ping` Mac → dev5 Windows host | 3 ms, direct |
| Mac → dev5 relay `http://100.91.138.55:3340` TCP connect | 74 ms |

The ICMP band **68.2–78.3 ms** is the AST-36 band **68–78 ms**, on the nose.

### Rows not run

| Row | Why |
|---|---|
| **A. Same LAN, direct** | **No same-LAN path exists between these two hosts.** Different subnets, and dev5→Mac fails at TCP, not just ICMP. Cannot be fixed without moving hardware, which this run could not do. |
| **B. Different networks / WAN** | Would need the Mac on another network. Cannot move the Mac. |
| **D. Constrained / lossy link** | Same reason as B; no second network available. |
| **NBD volume IOPS from a CHV guest** | **Refused by the product, not by the harness.** See below. |
| **`ast move` of a ~1 GiB instance** | Not attempted. It moves an instance's disk over the same mesh stream `ast mesh bench` measures, and the bench already gives the path's ceiling (2.79 MB/s ⇒ ~6 min per GiB) without booting anything. A move would have measured the disk as well as the path, which is the conflation this issue exists to end. |

## The NBD row is a finding, not a gap

A volume created on the Mac is visible from dev5 — the orbit catalog resolves it
and prints its latency:

```
NAME                 OWNER              SIZE   LATENCY DURABILITY    SHARING        HELD BY
ast138bench          mac-a                1G    68.9ms single-device single-writer -
```

Attaching it is refused before anything is mutated:

```
$ ast attach ast138vm --volume mac-a:ast138bench
Error: remote volume placement on mac-a refused before mutation:
       direct-path RTT is 71.0ms; at most 5ms is required
```

That bound is `REMOTE_VOLUME_MAX_RTT = 5ms` in
`crates/asterism-daemon/src/volume.rs`, plus a requirement that the selected
path be direct. This pair misses it by **14×**. So there are no remote-NBD IOPS
numbers for this hardware pair, and the reason is the number at the top of this
document: remote block volumes are unusable between this Mac and this dev5 for
exactly as long as dev5's mesh traffic is detouring through Tokyo.

(Independently, dev5 has no `cloud-hypervisor`/`virtiofsd` on `PATH` in this
scratch home — the CHV lane runs inside a container, per
`docs/evidence/chv-oci-parts-2026-08-27/`. Even with the SLO satisfied, the
guest would have needed that lane. The SLO refusal is the binding reason.)

## Attribution of the 68–78 ms

**Attributed to Tailscale's DERP relay in Tokyo, because dev5's WSL2 NAT
prevents a direct Tailscale path — and Asterism's traffic rides that tunnel.**

The evidence, in the order it settles the question:

1. **The number is not Asterism's.** Plain ICMP to the same host over the same
   interface is 68.2–78.3 ms; `ast ping` is 69.7 ms p50. The mesh's own
   contribution is within noise of zero.
2. **The slow leg is the WSL2 node specifically.** The dev5 *Windows host* — the
   same physical machine — answers `tailscale ping` in **3 ms over a direct
   path**. The WSL2 guest on that machine answers in **68–71 ms via DERP(tok)**,
   and Tailscale reports `direct connection not established` after five tries.
   The ~66 ms delta is the Tokyo round trip.
3. **Asterism's bytes really are inside that tunnel.** During a 64 MiB
   `ast mesh bench`, Tailscale's per-peer counter for `dugdb-dev5-wsl` rose by
   **+72.7 MB** (`rx 4,778,540 → 77,498,396`). Essentially the entire payload
   crossed the Tailscale interface, i.e. the DERP relay.
4. **iroh calls this path `direct`, and is not lying.** `ast ping` reports
   `path: direct`, `upgrade_millis: 0`, `relayed_before_direct: 0` and ~0
   relayed bytes, because no *iroh* relay is in the path. The relaying happens
   one layer below iroh, inside Tailscale, where iroh cannot see it. The only
   address the two daemons share is a Tailscale `100.x` address, so iroh's
   "direct" UDP path is a direct path *to a tunnel endpoint*.

Ruled out, with the evidence that rules each one out:

- **The n0 public relay** — not merely unused but unreachable: this build has
  **no default relay at all** (`MeshInfra::default()` is empty; an unconfigured
  device binds `LocalOnly` on loopback). The relay in this run is our own
  `astrelay` on dev5, named in every sample as
  `http://100.91.138.55:3340/`.
- **A QUIC handshake per ping** — `Mesh::ping` reuses a pooled connection and
  times only one stream round trip on it; the dial happens before the timer
  starts. Measured: a truly cold ping after a daemon restart is 72.1 ms against
  a 69.7 ms warm p50, a ~2 ms difference.
- **The portmapper** — forcing the relay (`ASTERISM_MESH_RELAY_ONLY=1`, which
  clears IP transports outright) changes p50 by 0.2 ms, from 69.7 to 69.9 ms.
  Whatever direct-path machinery the portmapper serves is not what costs the
  70 ms; both paths cross the same slow wire.

The relay-forced row is the cleanest control in the run: forcing every byte
through a relay leaves latency **unchanged**, because the relay is on dev5 and
so sits at the far end of the same 69 ms leg. What changes is throughput —
2.42 MB/s forced vs 2.79 MB/s unforced.

## The two numbers AST-94 needs

Relay meter deltas over a measured window, reported per minute.

| Condition | Relayed bytes/min | Direct bytes/min | Notes |
|---|---|---|---|
| Idle paired pair, relay **forced** | **1,868 B/min** (~2.7 MB/month) | 0 | 3,735 B over 120 s |
| Idle paired pair, relay configured, **not forced** | **8,692 B/min** (~12.5 MB/month) | 47,467 B/min | 17,384 B relayed over 120 s |
| NBD workload | **not measurable on this pair** | — | Remote volumes are refused at 71 ms vs a 5 ms SLO — there is no NBD workload to meter here. |

Both figures are upper bounds: the window is closed by an `ast ping`, whose own
bytes land inside the delta.

The counter-intuitive result is the one worth carrying into AST-94: an idle pair
on a *relay-forced* path relays **less** than one on an upgradeable path —
1.9 KB/min against 8.5 KB/min. Forcing the relay clears the endpoint's IP
transports, so there is nothing left to probe; the upgradeable path keeps
hole-punching and path-quality traffic alive on both the relay and the direct
leg, and some of that maintenance is relayed by construction. Idle relay cost is
therefore not "zero once direct" — budget for it on every paired pair that has a
relay configured at all, whether or not it is using one.

For scale: 8.7 KB/min is ~12.5 MB per device-pair per month of billable relayed
traffic with nobody doing anything. The NBD workload figure the issue also asked
for cannot be produced on this hardware, for the reason in the section above.

## Proves / does not prove

**Proves**

- The AST-36 figure of 68–78 ms reproduces exactly, and is a property of the
  network between these two hosts, not of Asterism. ICMP on the same wire
  gives the same band.
- The cause is Tailscale's DERP-Tokyo fallback for the WSL2 node, and the
  cause of *that* is WSL2's NAT defeating hole-punching. The same physical
  machine reached outside WSL2 is 3 ms.
- Asterism's mesh adds no measurable latency over the underlying wire, and
  `ast ping` never included a QUIC handshake.
- Forcing a relay costs throughput (2.79 → 2.42 MB/s at 64 MiB) and not
  latency, when the relay sits at the far end of the slow leg.
- Remote NBD volumes are unusable between these hosts today, and the daemon
  refuses them before mutating anything, naming the RTT.
- An idle paired pair costs 1.9 KB/min of relayed traffic when the relay is
  forced, and 8.7 KB/min when it is merely configured — idle relay cost does
  not fall to zero just because the path went direct.

**Does not prove**

- Anything about a genuine same-LAN path. Row A was not run because no such
  path exists here; the "LAN should be ~5 ms" expectation remains untested
  against Asterism. The 3 ms Mac↔Windows-host Tailscale figure is the closest
  proxy and is not an Asterism measurement.
- Anything about Asterism's own relay under load, or over a WAN. Our
  `astrelay` was on dev5, at the far end of the slow leg, and carried one
  client pair.
- That 2.79 MB/s is Asterism's throughput ceiling. It is this path's ceiling
  at a 69 ms RTT; the same code on a 3 ms path was not measured.
- That iroh would fail to hole-punch on a network where Tailscale succeeds.
  Both were defeated by the same WSL2 NAT here, but only Tailscale's failure
  was observed directly.
- Any NBD, `ast move`, or guest-level number whatsoever.

## Reproducing

```sh
# a relay both sides can reach
astrelay --http-bind 0.0.0.0:3340

# each daemon, with a scratch home
ASTERISM_HOME=... ASTERISM_RELAY_URL=http://<relay>:3340 astd
#   add ASTERISM_MESH_RELAY_ONLY=1 for the relay-forced row

# pair, then measure
ast device invite --name mac-a --yes      # on one
ast device add astdev1... --name dev5-b --yes   # on the other

scripts/bench-path.sh --peer dev5-b --label upgradeable-relay-configured \
  --samples 20 --icmp-target 100.91.138.55 --tcp-port 2222 \
  --out measurements.jsonl
```

`scripts/bench-path.sh --help` lists the rest, including `--idle-secs` for the
AST-94 figures.
