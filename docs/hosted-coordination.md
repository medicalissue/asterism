# Hosted coordination boundary

`asterism-coordinator` is an optional hosted control plane. It is not an orbit
authority and it is never on the VM, volume, shell, or mesh data path. An
existing paired orbit continues from its local `orbit.json`, cached address
hints, and configured relay list while the coordinator is unavailable.

The runnable `asterism-coordinator --config /etc/asterism/coordinator.json`
entry point binds only through a configured TLS certificate and private key.
The production `HostedService` accepts only verified Google OIDC and GitHub
OAuth identities. Its HTTPS callback path binds a single-use `state` value to
the requested provider and a PKCE S256 verifier. `ProductionOAuth` exchanges
the code at the provider: Google ID tokens are checked through Google's token
information endpoint by POST (so an ID token is never placed in a URL) for
issuer, exact client audience and expiry; GitHub
tokens are checked through GitHub's authenticated `/user` endpoint and use its
immutable numeric id. Neither flow requests, returns, nor persists an email.
There is no local credential, password, magic-link, recovery, or provider-token
store.

OAuth starts are bound to an HttpOnly browser cookie, provider, one-time state,
and PKCE verifier. They expire after ten minutes and both pending logins and
authenticated sessions are hard-bounded. Callbacks return generic failures,
never OAuth provider response text. Authenticated JSON routes are
`POST /v1/enrollment/challenge`, `POST /v1/enrollment`,
`GET /v1/discovery/{device}`, `DELETE /v1/devices/{device}`,
`GET /v1/account/export`, and `DELETE /v1/account`.

`PersistentCoordinator` writes a restart-safe encrypted state file through
`EncryptedFileStore`, sealed with `EncryptedMetadata` under a KMS-managed
versioned AES-256-GCM key. The deployment manifest references an active named
key and optional decrypt-only predecessor versions; a successful mutation
rewraps state under the active version. Key bytes come from root-owned KMS
mounts and are never printed. A mutation first builds a candidate state, then
writes encrypted temporary data, fsyncs it, renames it, fsyncs the parent
directory, and only then swaps the running state. Every record carries a
monotonic sequence and transaction identity; an uncertain post-rename
directory sync forces a reload/reconciliation before another mutation can use
memory, preventing stale overwrite. Account IDs use keyed BLAKE3—not an enumerable hash
of a provider subject. Durable state contains only opaque account ids, public
device keys, and intentionally selected public discovery endpoints. It must
not contain an OAuth subject, provider token, human name, orbit name,
membership, instance data, address observations, or secret material.

Enrollment is account-bound and requires a fresh service challenge signed by
the device's existing Ed25519 mesh key. Revocation deletes its hosted
configuration; it cannot mutate a local orbit's trust list. Export returns
the same minimal record, and deletion removes the full hosted account record.
Challenges expire after ten minutes and are capped at 32 active values per
account; expiry is pruned before both issue and proof verification.

Deployment proof is the repository test target, run with production callback
secrets supplied only by the deployment environment:

The deployment manifest contains paths and key version names—not bearer
tokens, OAuth secrets, or raw key material:

```json
{
  "listen": "0.0.0.0:8443",
  "state_file": "/var/lib/asterism/coordinator.enc.json",
  "tls": { "certificate": "/run/secrets/tls.crt", "private_key": "/run/secrets/tls.key" },
  "google": { "client_id": "...", "client_secret_file": "/run/secrets/google", "redirect_uri": "https://coord.example/oauth/google/callback" },
  "github": { "client_id": "...", "client_secret_file": "/run/secrets/github", "redirect_uri": "https://coord.example/oauth/github/callback" },
  "keys": {
    "active": { "version": "kms-2026-08", "material_file": "/run/secrets/kms-current" },
    "previous": [{ "version": "kms-2026-05", "material_file": "/run/secrets/kms-previous" }],
    "account_id_file": "/run/secrets/account-id-key"
  }
}
```

Each KMS material file is a 32-byte base64url value on a root-owned secret
mount. Rotation installs the new active reference while retaining old versions
only until all encrypted state has been rewritten.

```sh
CARGO_INCREMENTAL=0 cargo test -p asterism-coordinator
CARGO_INCREMENTAL=0 cargo test -p asterism-mesh
CARGO_INCREMENTAL=0 cargo test --workspace --all-targets
CARGO_INCREMENTAL=0 cargo clippy -p asterism-coordinator --all-targets -- -D warnings
```

The coordinator test covers the two-provider allow-list, PKCE/state/redirect
construction, account-bound signed enrollment, one-time challenge replay
refusal, revocation, encrypted restart-safe export/deletion, keyed account
ids, AES-GCM confidentiality/integrity, key-version rotation, transactional
write failure (including injected temp-write, file-fsync, rename, parent-open,
and parent-fsync boundaries with retry/restart), and an actual refused HTTP
health request after an orbit was paired. It advances Tokio's paused lifecycle
clock by exactly 24 hours and proves that the
pre-existing encrypted mesh connection still carries application data using
its cached third-party discovery configuration.
