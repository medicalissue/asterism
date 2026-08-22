# Hosted coordination boundary

`asterism-coordinator` is an optional hosted control plane. It is not an orbit
authority and it is never on the VM, volume, shell, or mesh data path. An
existing paired orbit continues from its local `orbit.json`, cached address
hints, and configured relay list while the coordinator is unavailable.

The production `HostedService` accepts only verified Google OIDC and GitHub
OAuth identities. Its HTTPS callback path binds a single-use `state` value to
the requested provider and a PKCE S256 verifier. `ProductionOAuth` exchanges
the code at the provider: Google ID tokens are checked through Google's token
information endpoint for issuer, exact client audience and expiry; GitHub
tokens are checked through GitHub's authenticated `/user` endpoint and use its
immutable numeric id. Neither flow requests, returns, nor persists an email.
There is no local credential, password, magic-link, recovery, or provider-token
store.

`PersistentCoordinator` writes a restart-safe encrypted state file through
`EncryptedFileStore`, sealed with `EncryptedMetadata` under a KMS-managed
32-byte AES-256-GCM key. Account IDs use keyed BLAKE3—not an enumerable hash
of a provider subject. Durable state contains only opaque account ids, public
device keys, and intentionally selected public discovery endpoints. It must
not contain an OAuth subject, provider token, human name, orbit name,
membership, instance data, address observations, or secret material.

Enrollment is account-bound and requires a fresh service challenge signed by
the device's existing Ed25519 mesh key. Revocation deletes its hosted
configuration; it cannot mutate a local orbit's trust list. Export returns
the same minimal record, and deletion removes the full hosted account record.

Deployment proof is the repository test target, run with production callback
secrets supplied only by the deployment environment:

```sh
CARGO_INCREMENTAL=0 cargo test -p asterism-coordinator
CARGO_INCREMENTAL=0 cargo test -p asterism-mesh
CARGO_INCREMENTAL=0 cargo test --workspace --all-targets
CARGO_INCREMENTAL=0 cargo clippy -p asterism-coordinator --all-targets -- -D warnings
```

The coordinator test covers the two-provider allow-list, PKCE/state/redirect
construction, account-bound signed enrollment, one-time challenge replay
refusal, revocation, encrypted restart-safe export/deletion, keyed account
ids, AES-GCM confidentiality/integrity, and an actual refused HTTP health
request followed by pairing over the local encrypted mesh after a 24-hour
outage interval.
