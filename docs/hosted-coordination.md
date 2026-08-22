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

Native clients and the Worker share these stable values and JSON shapes:

- protocol: `asterism-device-authorization/1`
- grant type: `urn:ietf:params:oauth:grant-type:device_code`
- transaction request: `provider` (`google` or `github`) and optional Desktop
  `redirect_uri` / `deep_link_state`
- authorization response: `device_code`, `user_code`, `verification_uri`,
  `verification_uri_complete`, `expires_in`, `interval`
- polling request: `device_code`, `grant_type`

The core validates that authorization responses are bounded and use HTTPS. It
does not initiate a browser flow, exchange a code, handle a callback, set a
cookie, or retain bearer material. `as-4j7` owns bounded polling, browser/deep
link behavior, and OS credential-store integration using the same wire shape.

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
