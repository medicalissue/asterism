# Hosted coordination boundary

`asterism-coordinator` is an optional, provider-neutral control-plane core. It
is not an orbit authority and is never on the VM, volume, shell, or mesh data
path. Local orbit creation and pairing require no account. A paired orbit keeps
using local trust, cached address hints, and its configured relay list when the
hosted service is unavailable.

## Ownership

The canonical `asterism.run` Cloudflare Worker owns Google and GitHub OAuth,
including client secrets, provider redirects and callbacks, PKCE/state, browser
cookies, RFC 8628 pending transactions, and bearer-session issuance. The public
core owns none of those things. It also has no Supabase, email/password, magic
link, OTP, or Cloudflare Access surface.

An edge adapter implements `VerifiedIdentitySource`. After it has verified a
session's signature, audience, expiry, and revocation, it returns only a
`VerifiedIdentity { authority, subject }`. The core immediately derives a
keyed, domain-separated `AccountId`; the authority and subject are never
persisted. `site-nca` can place the returned opaque `AccountBinding` in its
session. The binding includes a random account generation, not a provider
credential or core-owned session token.

Native clients and the Worker share these stable values and wire shapes. Both
OAuth endpoints read `application/x-www-form-urlencoded`; only the
account-management endpoints read JSON.

- protocol: `asterism-device-authorization/1`, sent as a request header. The
  Worker does not echo it, so clients treat a missing response header as
  silence rather than as an incompatible deployment.
- grant type: `urn:ietf:params:oauth:grant-type:device_code`
- public client id: `asterism-cli`, registered with scopes
  `openid orbit.read orbit.write`. RFC 8628 public clients are identified, not
  authenticated, so this is not a secret.
- transaction request (form): `client_id`, `scope`, an advisory `provider`
  (`google` or `github`), and optional Desktop `redirect_uri` /
  `deep_link_state`. The Worker resolves the provider from the browser session
  that approves the user code and ignores form fields it does not know.
- authorization response (JSON): `device_code`, `user_code`,
  `verification_uri`, `verification_uri_complete`, `expires_in`, `interval`
- polling request (form): `client_id`, `grant_type`, `device_code`
- token response (JSON): `access_token`, `token_type`, `expires_in`, `scope`.
  There is no account document on this endpoint: the bearer is a signed token
  whose payload names the account it was minted for.
- error envelope (JSON): `error` and `error_description`

The core validates that authorization responses are bounded and use HTTPS. It
does not initiate a browser flow, exchange a code, handle a callback, set a
cookie, or retain bearer material. `as-4j7` owns bounded polling, browser/deep
link behavior, and OS credential-store integration using the same wire shape.
Session bearers are rejected above 8 KiB before the trusted verifier is called.

## Minimal coordinator state

The durable record contains only opaque account ids, random account
generations, enrolled public device keys, and deliberately selected public
discovery endpoints. It must never contain an external subject, provider
token, session id, human name, email, orbit name, membership, instance data,
observed address, or secret device material.

Enrollment is account-bound and requires a fresh ten-minute challenge signed
by the device's existing Ed25519 mesh key. The challenge wire token and signed
message include a domain-separated commitment to the account generation, never
the generation itself. Challenges are memory-only, single-use, and capped at 32
per account. Hosted state is capped at 64 devices per account, 4 KiB per
discovery configuration, 4,096 accounts, and 16 MiB in total. Revocation removes
hosted discovery configuration; it cannot mutate a local orbit ACL. Export
includes only the minimal durable record.

Encoded challenges, signatures, and account generations are checked at their
exact base64url lengths before decoding. Startup checks file metadata before
allocation, caps the high-watermark sidecar at 32 bytes and the JSON encrypted
envelope at the worst-case representation of a 16 MiB ciphertext, and then
rechecks both encrypted ciphertext and decrypted plaintext bounds before JSON
state parsing.

Deletion checks the caller's account generation and removes the account in one
durable transaction. Every existing binding becomes invalid as soon as the
record is absent. Signing in again with the same verified external identity
creates the same opaque account id with a new random generation, so no
pre-deletion session can regain authority. Enrollment begin/completion,
revocation, discovery reads, export, and deletion all accept `AccountBinding`
rather than a bare `AccountId`; each revalidates the generation against the
same serialized state snapshot it reads or mutates. A separate `authorize`
check returns no account capability and therefore cannot be carried across a
delete/recreate boundary.

Device-authorization codes, user codes, verification URIs (including complete
URIs and query material), session bindings, enrollment challenges, and key
bytes are redacted from `Debug`; adapters must use these redacted forms for
diagnostic logging.

## Device enrollment and presence

This is the wire contract shared by `asterism-coordinator` (the provider-neutral
core and the native client's protocol types) and the canonical `asterism.run`
Worker. The Worker is the hosted implementation; the crate is the same protocol
expressed as a self-contained, testable core. Where they used to disagree the
Worker and this document win, and the crate was adjusted to match.

Every endpoint is authenticated by an existing bearer session issued through
`asterism-device-authorization/1`. Nothing here creates a session, and nothing
here is on the orbit data path. The coordinator never receives a private key,
an orbit name, membership, instance data, or an observed address.

### Shared encodings

| Value | Encoding | Exact length |
| --- | --- | --- |
| `device_id` | Ed25519 public key, lowercase hex | 64 characters |
| `challenge` | base64url without padding of 64 bytes | 86 characters |
| `signature` | base64url without padding of 64 bytes | 86 characters |
| account generation | base64url without padding of 32 bytes | 43 characters |

A challenge is `nonce(32) || generation_binding(32)`. The nonce is fresh
random. The generation binding is

```
generation_binding = SHA-256("asterism.coordinator/enroll-generation/1\0" || generation)
```

where `generation` is the account's random generation as its 43-character
base64url text. The binding, not the generation, is on the wire and in the
signed message, so a challenge commits to the account generation without
disclosing it.

The device signs

```
message = "asterism.coordinator/enroll/1\0" || generation_binding(32) || nonce(32)
```

with its existing Ed25519 mesh key — 94 bytes, no hashing step of its own.
Both domain strings include their trailing NUL byte. Verification is a plain
Ed25519 verify against `device_id`; the Worker uses WebCrypto's `Ed25519`
algorithm, which is available at `compatibility_date` `2026-08-20`.

`tests/fixtures/enrollment-vectors.json` in the site repository is the single
source of these vectors. `crates/asterism-coordinator/tests/fixtures/enrollment-vectors.json`
is a byte-identical copy with a comment naming that source, so the Rust and
Worker suites verify the same bytes.

Challenges are memory-only in the account's Durable Object, single-use, expire
after ten minutes, and are capped at 32 live per account. An evicted object
loses its outstanding challenges; a client simply begins again. An account is
capped at 64 enrolled devices and 4 KiB of discovery configuration per device.

### `POST /api/v1/devices/enroll/begin`

Bearer session. A `asterism-cli` session additionally needs the `orbit.write`
scope. No request body.

```json
{ "challenge": "<86 chars>", "expires_in": 600 }
```

Rate limited per account. `401 unauthorized`, `403 forbidden`,
`409 too_many_challenges`, `429 rate_limited`.

### `POST /api/v1/devices/enroll/complete`

Bearer session, `application/json`, at most 4 KiB.

```json
{
  "device_id": "<64 hex>",
  "challenge": "<86 chars>",
  "signature": "<86 chars>",
  "discovery": { "relays": ["https://…"], "pkarr_relay": "https://…", "dns_origin": "https://…" },
  "endpoints": { "addrs": ["192.0.2.10:41641", "[2001:db8::1]:41641"], "relay_url": "https://…" }
}
```

`endpoints` is optional and defaults to `{}`. It is the device speaking about
itself: the literal socket addresses it currently answers on and the relay it
is currently reachable through. `addrs` entries must parse as socket addresses
(a bare IPv4 literal or a bracketed IPv6 one, plus a port), at most 24 of them;
`relay_url` must be an https URL. Hostnames, device names, and anything else
are refused rather than stored, so the record cannot become a place to keep
arbitrary device metadata.

`discovery` is optional and defaults to `{}`. Its fields are the same shape as
`DiscoveryConfig` in the crate and map one-to-one onto `MeshInfra`. Every
endpoint must be a whitespace-free `https://` URL, and the serialized object
must be at most 4 KiB. These are deliberately selected public routing
endpoints; the coordinator stores nothing else about the device.

```json
{
  "device": {
    "device_id": "<64 hex>",
    "discovery": { "relays": [] },
    "enrolled_at": 1756000000
  },
  "devices_enrolled": 2
}
```

Re-enrolling an already enrolled key is idempotent and refreshes its discovery
configuration. `400 invalid_request`, `401 unauthorized`, `403 forbidden`,
`409 invalid_challenge` (unknown, expired, already used, or bound to a stale
generation), `409 invalid_proof`, `409 device_capacity`, `413 request_too_large`.

### `GET /api/v1/devices`

Bearer session. A `asterism-cli` session needs `orbit.read`.

```json
{
  "account_id": "usr_…",
  "devices": [
    {
      "device_id": "<64 hex>",
      "discovery": { "relays": [] },
      "endpoints": { "addrs": ["192.0.2.10:41641"], "relay_url": "https://…" },
      "endpoints_updated_at": 1756000200,
      "relay_bytes": 1048576,
      "enrolled_at": 1756000000,
      "presence": { "status": "online", "updated_at": 1756000300 }
    }
  ]
}
```

`account_id` is the coordinator's opaque account identifier. It is not an
external subject and cannot be reversed into one. `presence.status` is
`online` only while that device holds a live presence socket; otherwise it is
`offline` with the last transition time, or `null` if the device has never
connected.

### `POST /api/v1/devices/hints`

Bearer session, `orbit.write` for a CLI session. The refresh path a device
takes when its addresses change, without re-proving possession of its key: the
session already proves the account, and the device must already be enrolled to
it.

```json
{
  "device_id": "<64 hex>",
  "endpoints": { "addrs": ["198.51.100.7:41641"] },
  "relay_bytes": 1048576
}
```

```json
{ "ok": true, "endpoints_updated_at": 1756000400 }
```

`relay_bytes` is optional: one non-negative safe integer, the cumulative bytes
this device has moved through a relay as the device itself counts them. It is
the whole of what relay quota accounting needs, and deliberately all of what it
gets — there is no field for who the other end was, which address either side
used, or when any of it happened. The stored value only ever rises, so a device
that restarted and lost its counter cannot lower the account's total. Anything
that is not a non-negative safe integer is a `400`, never a silent clamp.

Hints are **replaced**, never appended. The coordinator therefore holds where a
device is now and never a history of where it has been. `404 not_found` for a
device this account has not enrolled. A successful publish sends
`devices.changed` to the account's other devices so they re-resolve.

### `POST /api/v1/devices/revoke`

Bearer session, same-origin when a browser cookie is present.

```json
{ "device_id": "<64 hex>" }
```

or `{ "all": true }`, which a `asterism-cli` session may not use.

```json
{ "ok": true, "revoked": 1 }
```

Revocation removes the hosted discovery configuration and closes that device's
presence socket. It cannot mutate a local orbit ACL: local removal stays an
explicit, peer-signed operation that works while this service is down.

### `GET /api/v1/devices/presence` (WebSocket)

`Upgrade: websocket`, bearer session, and `?device_id=<64 hex>` naming an
enrolled, unrevoked device of that account. Anything else is `426`, `401`,
`403`, or `404`.

The Worker deletes any public `x-asterism-user-*` and `x-asterism-device-*`
request headers and injects the verified identity before forwarding to the
Durable Object, exactly as the orbit socket already does. The object never
reads an unverified header.

Server frames:

```json
{ "type": "presence.snapshot", "devices": [ { "device_id": "…", "status": "online", "updated_at": 1756000300 } ] }
{ "type": "presence.changed", "device_id": "…", "status": "online" }
{ "type": "devices.changed" }
{ "type": "pong", "at": 1756000300123 }
{ "type": "error", "error": "invalid_message" }
```

Client frames are `{"type":"ping"}` only; the presence socket carries no
application data. Frames above 4 KiB close the socket with 1009. `devices.changed`
is a hint that the account's device list moved and the client should re-read
`GET /api/v1/devices`; it carries no device data itself.

Sockets are hibernatable. Authority — session validity, account deletion, and
the device still being enrolled — is revalidated on every callback, so an
evicted or hibernated socket cannot outlive its enrollment.

### Which Durable Object

Enrollment and device presence live in a sibling `AccountDevices` object named
by the account id, not in `OrbitCoordinator`.

`OrbitCoordinator` is named by orbit id, and its whole authority model is D1
orbit membership plus role; its presence rows are per user and are visible to
every co-member of that orbit. Device keys are per account. Putting them in the
orbit object would either publish one account's device keys to that orbit's
other members or force a second, different authority model into the same
object. The account object keeps one rule: this session's account owns these
devices.

### Account scope

The durable record is one row per `(account, device key)` in D1 —
`account_devices` — plus one `account_device_state` row holding the account's
random generation. Both cascade with the account, so deletion removes hosted
discovery configuration in the same transaction that removes the account.
Signing in again mints a new generation, so a challenge issued before deletion
can never complete afterwards. Presence is Durable Object state only and is
never durable beyond the object.

### Three modes, and why logging in is worth it

There is exactly one reason to sign in, and this is it: **signing in replaces a
public directory with a private one.**

**Local.** No account. The device has no directory and no relay unless the
operator configured one — `ASTERISM_RELAY_URL`, `ASTERISM_PKARR_RELAY`,
`ASTERISM_DNS_ORIGIN`. Pairing over a ticket works, an already-paired orbit on
one network works, and nothing about this device is published anywhere. Public
third-party infrastructure is not a default in this mode or any other.

**Enrolled.** Signed in and enrolled. The coordinator is the device's only
directory: it publishes the addresses it currently answers on to its own
account, and it resolves its peers from that same account's device list. That
list is readable only by the account that owns it, so two machines on
different networks find each other without either of them appearing in a public
directory. A dial that fails re-resolves the peer through the same account
list, which is what makes a laptop that moved reachable again. Enrolling does
not turn public publication on — it replaces it.

**Self-hosted.** Explicit `MeshInfra` overrides, with or without an account.
The operator names the relay and the directory, and `ast auth login
--coordinator <url>` points enrollment at a compatible Worker of their own —
the session records that origin, and every later hosted call is bound to it.
A persisted `ast config set coordinator` form is not built yet; the per-command
flag is the seam today. This is the "bring your own route" case: the hosted
plane is replaceable by construction, not by permission.

The daemon reports which of the three it is in — `ast auth status` prints the
coordinator and the presence state, and the daemon logs the account's selected
infrastructure at enrollment in the same words the endpoint uses at startup. A
device never silently changes whose servers it talks to.

The relay half of an account's `discovery` configuration is owned by the relay
work, which fills in `DiscoveryConfig::relays`. This document and the enrollment
code carry it end to end and hand it to `MeshInfra` unchanged; what they
deliberately do not do is decide what a default relay is. The daemon exposes
`hosted::account_relay_list()` for exactly that hand-off, and
`hosted::account_mesh_infra()` builds

```rust
MeshInfra::with_hosted(relays, HostedDiscovery::none())
    .with_env_overrides()
```

from it, parsing each entry into a `RelayUrl` and dropping — with a line on
stderr — any the account named that does not parse. A malformed entry costs one
relay, never the bind.

`HostedDiscovery::none()` is the load-bearing half: an enrolled device's
directory is the account's own device list read through `GET /api/v1/devices`,
not pkarr or DNS. Environment overrides still beat the coordinator field by
field, which is what keeps the self-hosted mode reachable from inside the
enrolled one.

A device also reports one number back — `relay_bytes` on the hints endpoint —
so an account's relay usage can be accounted for without the coordinator
learning anything about who it talked to. It comes from the daemon's relay
meter, summed over every peer and both directions: the same bytes `ast devices`
breaks down per peer, with the peers taken out. A relay bill does not need to
know which devices this one talks to, so that is not what gets sent.

### Local trust is not granted by enrollment

An enrolled device is *known to the account*, not *trusted by the orbit*. The
daemon merges the account's device list into local state as follows.

- For a peer that is already in `orbit.json`, the account's discovery hints
  refresh that peer's relay list. This is a routing refresh and grants nothing.
- For a peer that is not in `orbit.json`, the daemon records it in `hosted.json`
  and `ast devices` lists it under "enrolled with this account, not paired into
  this orbit". It is not added to the orbit ACL and nothing dials it.
- Only an explicit opt-in — `ast auth enroll --trust-account-devices`, recorded
  in `hosted.json` — may promote account-enrolled keys into the orbit ACL. The
  flag is carried end to end and is off by default; this first slice records
  the choice and still requires a pairing ticket, so no code path yet lets a
  coordinator's answer become a trusted key.

The default is off. The pairing ticket stays the single trust root, because a
compromised coordinator must not be able to add a device to an orbit. The
coordinator can withhold a hint; it cannot grant membership.

### What the daemon keeps

`hosted.json` in the Asterism home holds the coordinator origin, the opaque
account id, this device's own enrolled public key, the trust flag, and the
account's last-seen device list. Routing hints are republished only when they
actually change, and a `devices.changed` frame causes a read and never a write:
publishing is what produces that frame, so reacting to one by publishing would
turn a single address change into a conversation that never ends. The Worker
also declines to echo the frame back to the device that caused it. It has no field for a bearer, a session id, or
an account name, and a test asserts that.

The bearer is deliberately never persisted by the daemon. `ast` owns the OS
credential store and hands the daemon a session in memory over the control
socket, in a frame whose `Debug` is redacted. A daemon restart therefore keeps
the enrollment — which is durable on both sides — and loses only the live
session; `ast auth status` says `unarmed`, and `ast auth login` or `ast auth
enroll` re-arms it. Bearers expire on their own schedule regardless.

### Availability

Enrollment, the device list, and presence are all optional. `ast` and the
daemon start, pair, run instances, and use an already-paired orbit with the
coordinator unreachable. The daemon's presence socket reconnects with capped
exponential backoff and jitter and never blocks another operation; a failed
enrollment is reported once and retried in the background.

## Encrypted bounded transactions

`PersistentCoordinator` builds mutations on a candidate state and publishes
only after encryption and durable storage succeed. `EncryptedFileStore` seals
state with AES-256-GCM under a named, rotation-capable `MetadataKeyRing` loaded
through a KMS/HSM/secret-mount capability. The account-id key is separate.

The cumulative transaction gates remain explicit:

1. Refuse a second writer with an exclusive state-path lock.
2. Bound and serialize the complete candidate before publishing it.
3. Durably create every missing directory component in ancestor order.
4. Write encrypted state to a task-local temporary file.
5. `fsync` the temporary file before rename.
6. Atomically rename the candidate over the active state.
7. `fsync` the containing directory before acknowledging success; an ambiguous
   post-rename failure is fail-stop.
8. Persist a monotonic sequence and transaction id plus a separate durable
   high-watermark; reject rollback on restart.
9. Remove abandoned temporary files, reconcile a visible published
   transaction, and rewrap old key versions before serving.

The fault matrix covers directory-parent open/fsync, temporary write, file
fsync, rename, state-parent open/fsync, process crash, clean-host directory
loss, and rollback detection. A failed transaction never replaces live memory.

## Availability invariant

Discovery is a refresh optimization. Devices persist the last accepted public
discovery configuration locally, while pairing and authorization remain device
key operations. The test suite pairs real `LocalOnly` mesh endpoints, makes a
coordination endpoint unreachable, advances the lifecycle clock by exactly 24
hours, and transfers application data over the pre-existing connection.

Verification:

```sh
CARGO_INCREMENTAL=0 cargo test -p asterism-coordinator
CARGO_INCREMENTAL=0 cargo test -p asterism-mesh
CARGO_INCREMENTAL=0 cargo test --workspace --all-targets
CARGO_INCREMENTAL=0 cargo clippy -p asterism-coordinator --all-targets -- -D warnings
```
