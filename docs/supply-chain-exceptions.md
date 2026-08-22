# Supply-chain gate exceptions

The release gate fails closed. Its Rust advisory/license policy, npm audit,
and repository secret scan have **no active exceptions**.

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

None.
