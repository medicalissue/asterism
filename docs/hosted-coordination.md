# Hosted coordination boundary

`asterism-coordinator` is an optional hosted control plane. It is not an orbit
authority and it is never on the VM, volume, shell, or mesh data path. An
existing paired orbit continues from its local `orbit.json`, cached address
hints, and configured relay list while the coordinator is unavailable.

The service accepts only verified Google OIDC and GitHub OAuth identities. An
HTTP adapter must exchange an authorization code using PKCE, validate `state`,
the registered redirect URI, client/audience and the allow-listed issuer, then
pass only `VerifiedOAuth` to `Coordinator::sign_in`. It must not add a local
credential, email, password, magic-link, recovery, or provider-token store.

The durable record is `AccountExport`, sealed with `EncryptedMetadata` under a
KMS-managed 32-byte AES-256-GCM key. It contains only an opaque account hash,
public device keys, and intentionally selected public discovery endpoints. It
must not contain an OAuth subject, provider token, human name, orbit name,
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

The coordinator test covers the two-provider allow-list, account-bound signed
enrollment, one-time challenge replay refusal, revocation, export/deletion,
AES-GCM confidentiality/integrity, and a persisted paired orbit across a
simulated 24-hour control-plane outage.
