# Supply-chain gate exceptions

The release gate fails closed. Its Rust advisory/license policy and npm audit
have **no active exceptions**. The repository secret scan has exactly one,
recorded below.

An exception is a temporary risk decision, not a way to make CI green. Every
entry in this file and its matching tool configuration must include all of:

| Field | Required value |
| --- | --- |
| Identifier | Exact advisory ID, package and version, license expression, or gitleaks rule and path |
| Scope | The smallest affected lockfile package or file path |
| Rationale | Why the finding is not exploitable or not applicable |
| Owner | The person or team responsible for removing it |
| Removal condition | Upgrade/version/date/event that removes the exception |

Do not use workflow `continue-on-error`, broad path ignores, global gitleaks
allowlists, or unbounded advisory ignores. A proposed exception without all
five fields is rejected.

## Active exceptions

### gitleaks `generic-api-key` on the shared enrollment test vectors

| Field | Value |
| --- | --- |
| Identifier | gitleaks rule `generic-api-key`, path `crates/asterism-coordinator/tests/fixtures/enrollment-vectors.json` |
| Scope | That one file. No directory, no rule disabled anywhere else. |
| Rationale | Each vector carries a `device_secret_seed_hex`: the deterministic Ed25519 seed the vector's fixed device id and signature are derived from. It is a published constant, byte-identical with the copy in `medicalissue/asterism-site` so both suites prove the same wire bytes, and it authenticates nothing. The file holds test vectors and nothing else, which is why the path is the scope. |
| Owner | Coordinator contract owner (AST-118) |
| Removal condition | The vectors stop shipping a seed — the fixture carries only public inputs and expected outputs, with the signing key derived at test time — or the fixture is deleted. Either removes this entry and the `[allowlist]` block in `.gitleaks.toml` together. |
