# `ast open` across two real devices — Mac ↔ dev5, 2026-08-27

**PASS (AST-159).** A port served inside a Cloud Hypervisor guest on dev5,
opened on a MacBook's loopback and answered with HTTP 200 — with nothing
published, nothing declared, and nothing left behind after Ctrl-C.

This is the cross-device sibling of the native port publication in
`docs/evidence/native-ports-2026-08-27`. That one proved a daemon binding a
*declared* host port on the device running the guest. This one proves the
opposite arrangement: an undeclared port, bound on the device the user is
sitting at, carried over the mesh to the device supplying the compute.

## Hosts

| | laptop | dev5 |
| --- | --- | --- |
| name in the orbit | `laptop` | `dev5` |
| device id | `0564cd873dab` | `e15562cdafc1` |
| OS | macOS 26.5.2, `arm64` | Ubuntu 26.04 in WSL2, kernel `6.6.87.2-microsoft-standard-WSL2`, `x86_64` |
| role | runs `ast open`; no guest | supplies the compute |
| `ASTERISM_HOME` | a scratch dir under the agent's scratchpad | `/root/ast159/home` |

Both daemons were built from `c926a576` on branch `claude/ast-159-open`
(`cargo build --bin astd --bin ast`, debug), and both stamped their homes as
protocol 15.

The lane was re-run from scratch every time `main` moved under this branch,
and the wire version this change introduces moved with it: AST-151 took 14,
AST-153 took 15, and on `main` today it is **16**. The transcripts below are
from the `c926a576` run, where it was 15. What the rebases since changed is
the number both daemons print in their startup line and nothing else — no
frame, no rule and no wording — so the lines here were not re-observed at 16
and this record does not claim they were.

- VMM on dev5: `cloud-hypervisor v53.0`, reused from the AST-115 release
  layout via `ASTERISM_CLOUD_HYPERVISOR`; guest agent likewise via
  `ASTERISM_GUEST_AGENT_ARTIFACT`. Neither is product code changed here.
- Instance: `web`, `--backend chv`, 2 cores / 1024 MiB / 4 GiB, image
  `docker.io/library/nginx:alpine`, direct-kernel boot, guest at `10.88.85.2`.
- **Created with no `-p` at all.** `ast status web` lists no published
  endpoint. If `ast open` needed one, this record could not exist.
- Mesh: both daemons configured with `ASTERISM_RELAY_URL=http://100.91.138.55:3340`
  (an `astrelay` on dev5), paired with a ticket and `--yes` on both ends. No
  hosted account, no login.

## The transcript

```
$ ast ls
NAME           STATUS    IMAGE          SHAPE            COMPUTE      AGE    TODAY    ACCESS
web            running   nginx:alpine   2c/1024M/4G      dev5         1h     -        10.88.85.2:22

$ ast open web:80 --no-browser
http://127.0.0.1:54840 → web:80 on dev5 (direct, 83 ms)

$ curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:54840/
200

$ curl -sI http://127.0.0.1:54840/ | head -4
HTTP/1.1 200 OK
Server: nginx/1.31.4
Date: Thu, 27 Aug 2026 09:05:03 GMT
Content-Type: text/html

^C
closed web:80

$ curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:54840/   # after Ctrl-C
curl: (7) Failed to connect to 127.0.0.1 port 54840 after 0 ms: Couldn't connect to server
```

```
$ ast open web:80 --json
{"local":"127.0.0.1:54978","instance":"web","device":"dev5","port":80,"path":"direct"}

$ ast open web:80 --no-browser --local-port 53000
http://127.0.0.1:53000 → web:80 on dev5 (direct, 78 ms)
$ curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:53000/
200
closed web:80
```

The refusals, each of them before any listener was created:

```
$ ast open nope:3000
error: unknown instance "nope" (orbit has: web)

$ ast open web:1023
error: guest port 1023 is Asterism's own guest-control endpoint on an OCI
instance — `ast exec`, `ast logs` and boot readiness use it, and no service of
yours is listening there. Open the port your image actually serves

$ ast open web
error: "web" is not NAME:PORT — say which port the instance serves
  fix: ast open web:3000

$ ast open web:80        # after `ast down web` on dev5
error: instance "web" is not running — `ast up web` first

$ ast open web:80        # after dev5's daemon was stopped
error: dev5 is offline (last seen 37 s ago) — web:80 is unreachable
```

The same command on the device that *does* hold the guest takes the local path
and says so, with no mesh hop in it:

```
dev5$ ast open web:80 --no-browser
http://127.0.0.1:42917 → web:80 on dev5 (local)
dev5$ curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:42917/
200
closed web:80
```

## About the 70–83 ms

That number is the wire, not this feature. AST-138 measured this exact pair at
68–78 ms and attributed it: dev5's WSL2 node reaches Tailscale over DERP in
Tokyo, and the same physical machine's *Windows* host answers in 3 ms over a
direct path. `path: direct` is iroh telling the truth about its own layer — no
iroh relay is in the path — while the relaying happens one layer below, inside
Tailscale, where iroh cannot see it. See
`docs/evidence/path-matrix-2026-08-27`. The target transcript for this issue
was written with a 3 ms LAN pair in mind; on this pair the honest number is
70-odd ms, and the code prints what it measures.

Even at 70-odd ms round trip, nginx over the tunnel answered every request; the
page is a page, not a benchmark.

## Proves

- A TCP port served **inside a guest on another device** is reachable on this
  device's loopback, and really carries HTTP — status line and headers from
  the guest's own nginx, not a socket that accepted and hung.
- **No publication is involved.** The instance declares no port mapping, and
  none appeared on dev5. `ast open` needs no cooperation from the instance
  beyond a service that is already listening.
- The printed line names the instance, the guest port, the device really
  supplying the compute, and the mesh path with its measured RTT; `--json`
  says the same in one object.
- `--local-port` binds exactly the number asked for.
- **Ctrl-C is a complete teardown.** The loopback port refuses connections
  immediately afterwards, and the closing line names what was closed.
- Every refusal precedes the listener: unknown instance (with the orbit's
  names), Asterism's guest-control port, a malformed target, a stopped
  instance, and an unreachable device with a last-seen.
- A malformed target carries a remedy through AST-141's `fix:` line, which is
  the machine-readable half of "say which port".
- Both ends negotiated the wire version this change introduces, and the new
  `port_splice` stream carried a real service across it.
- On the device holding the guest the same command takes the local path and
  reports `(local)` rather than inventing a mesh path.
- **No device is ever named on the command line.** `ast open web:80` is the
  same command on both machines; `astd`'s `resolve::locate` decides which one
  holds `web` and says so in the output.

## Does not prove

- **Nothing about an old peer refusing the stream.** Both daemons were this
  build. That a pre-16 peer refuses `port_splice` by name rather than dropping
  it — and that the asking side checks the peer's version before it binds
  anything — is covered by unit tests
  (`mesh::tests::a_peer_that_predates_open_refuses_the_stream_by_name`), not by
  this run.
- **No UDP.** `ast open` is TCP only, by design, and no UDP was attempted.
- **Not a throughput or concurrency measurement.** One browser-shaped client
  at a time; no load, no long-lived streams, no WebSocket upgrade, no
  many-connection page.
- **Not a no-QEMU gate.** The dev5 *host* has QEMU installed. `--backend chv`
  was forced and `ast status` recorded `chv 53.0`, so nothing fell through to
  a compatibility backend — but this lane makes no claim about QEMU's absence.
  That claim belongs to `docs/evidence/native-no-qemu-dev5-2026-08-27`.
- **Nothing about relay-carried mesh paths.** Every sample reported
  `path: direct`. The `relay` word in the output was never exercised here.
- **Nothing about the phone or the Web Console.** Reaching an instance's port
  from a device that is not in the orbit is a separate problem and a separate
  issue.
- **The offline refusal's latency is not a claim.** The orbit query takes tens
  of seconds to conclude a device is unreachable, which is the same cost
  `ast ls` pays and is not specific to this command. The "37 s ago" in the
  transcript is partly a consequence of that wait.
- **The `--browser` path is untested here.** Every run used `--no-browser` or
  `--json`; nothing launched a browser on the test host.
- **The refusals that come back over the mesh carry no `fix:` line.** Only the
  locally-generated parse error does. A `Response::Error` is a string on the
  wire, so a daemon-side remedy has nowhere to ride today; closing that is a
  protocol change and not this one.

## Reproducing

```sh
# on dev5
astrelay --http-bind 0.0.0.0:3340 &
ASTERISM_HOME=... ASTERISM_RELAY_URL=http://100.91.138.55:3340 \
  ASTERISM_CLOUD_HYPERVISOR=.../cloud-hypervisor \
  ASTERISM_GUEST_AGENT_ARTIFACT=.../asterism-guest astd &
ast pull docker.io/library/nginx:alpine
ast create web --backend chv --image docker.io/library/nginx:alpine \
  --cpus 2 --mem 1G --disk 4G          # note: no -p
ast up web

# on the laptop
ASTERISM_HOME=... ASTERISM_RELAY_URL=http://100.91.138.55:3340 astd &
ast device invite --name laptop --yes                  # ticket to dev5
#   dev5: ast device add <ticket> --name dev5 --yes
ast open web:80 --no-browser
```

The single-host version of all of this — two daemons, separate homes, one
kernel — is `scripts/e2e-open.sh`, which is what CI can run.
