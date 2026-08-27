# Credential parts on a real VZ guest — 2026-08-27 (AST-157)

`scripts/e2e-credentials.sh` on this host, green. A GitHub token this Mac's
own `gh` already held, imported as a credential part, attached to an agent VM,
and spent by the guest's own unmodified `curl` against the real
`api.github.com` — with the token itself never entering the guest.

The answer the guest got back is the proof, and it is the only kind of proof
this claim can have: `GET /user` returns `401` without a credential, and no
fixture can make it print an account name.

## Host

| | |
|---|---|
| machine | Apple Silicon MacBook Pro |
| os | macOS 26.5.2, Darwin 25.5.0 |
| backend | `vz` — `astd-vz`, built from source and ad-hoc signed by `scripts/sign-vz.sh` |
| image | `docker.io/library/nginx:alpine`, OCI rootfs, direct kernel boot |
| door | `GuestEgress::AgentVsock` — the guest's own loopback over this instance's virtio socket |
| store | the login Keychain, under a scratch `$ASTERISM_HOME`, removed at the end |
| upstream | `api.github.com` over real public TLS |
| account | `medicalissue` |
| binaries | this branch, debug |

Reproduce:

```
ASTERISM_GUEST_AGENT_ARTIFACT=<static aarch64 linux asterism-guest> \
  bash scripts/e2e-credentials.sh
```

The lane needs a host `gh` that is signed in; it skips rather than fails when
there is not one. Paths in the captures below are rewritten to
`$ASTERISM_HOME` and `$CARGO_TARGET_DIR`; the GitHub answer is trimmed to the
fields that matter. Nothing else is edited, and the token appears nowhere —
this lane never printed it and neither does this directory.

## Files

| file | what it is |
|---|---|
| `e2e-credentials.log` | the whole run, 21 assertions |
| `providers.txt` | `ast credential providers` — the declarations this build carries |
| `credential-ls.txt` | `ast credential ls` — kind, provider and door rule |
| `attach.txt` | `ast attach bot --credential <part>` — five authorities, one handle |
| `api-user.json` | what the guest's `curl` got back from `api.github.com/user` |
| `status-after-detach.txt` | `ast status bot` after the revocation |
| `not-executed.txt` | written by the lane itself: what it did not do |

## The transcript, as it actually ran

```
$ ast login gh --as gh-e2e-…
gh: using the token this device's `gh auth token` already holds
gh: signed in as medicalissue — stored on this device as credential part "gh-e2e-…"

$ ast credential ls
NAME                 KIND     PROVIDER   RULE        SOURCES
gh-e2e-…             login    github     substitute  macbook-pro.…ts.net

$ ast create bot --backend vz --image nginx:alpine --profile base
bot  defined

$ ast attach bot --credential gh-e2e-…
bot  gh-e2e-… -> api.github.com  (authorization: Bearer, from macbook-pro.…)
bot  gh-e2e-… -> github.com  (authorization: Bearer, from macbook-pro.…)
bot  gh-e2e-… -> uploads.github.com  (authorization: Bearer, from macbook-pro.…)
bot  gh-e2e-… -> raw.githubusercontent.com  (authorization: Bearer, from macbook-pro.…)
bot  gh-e2e-… -> codeload.github.com  (authorization: Bearer, from macbook-pro.…)
the guest gets $GH_TOKEN=sk-ast-gh-JHTY1PFV… and $GITHUB_TOKEN=sk-ast-gh-JHTY1PFV… —
an opaque handle, honoured only by this instance's proxy and only for
api.github.com and 4 more. The value stays on macbook-pro.…ts.net.

$ ast up bot
bot  running

agent@bot:~$ echo $GH_TOKEN
sk-ast-gh-JHTY1PFV…

agent@bot:~$ curl -sS -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/user
{"login":"medicalissue","id":97329153, …}

$ ast detach bot --credential gh-e2e-…
bot  gh-e2e-… revoked
the handle the guest holds is no longer honoured; it disappears from the guest
on the next boot: ast down bot && ast up bot

agent@bot:~$ curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/user
401
```

The handle is shown by its first characters only — not because it is worth
protecting (it is worth exactly the reach of one instance's proxy, that proxy
no longer honours it, and the instance it belonged to has been removed) but
because a 52-character random string next to the word TOKEN is what a secret
scanner exists to find, and this repository's gate is right to find it.

## Proves

* **An agent's tools arrive logged in.** `curl` inside the guest, unmodified,
  with nothing but `$GH_TOKEN` in its environment, reached `api.github.com`
  and was answered as `medicalissue`. Nothing was configured inside the guest
  and no proxy-aware client was used.
* **What the guest holds is a handle in the provider's shape.**
  `sk-ast-gh-…`, 240-odd random bits, not derived from the token — asserted
  both ways: the handle is not the token, and the token is not in the handle.
* **One credential is every authority its provider declares, under one
  handle.** Five bindings from one `--credential`, sharing a handle and both
  the environment variables `github.toml` names. That is what makes `gh`,
  `git clone` and a raw-content fetch all work off one sign-in.
* **The door reads both schemes GitHub's own tools send.** `Authorization:
  Bearer` and the older `Authorization: token` both carried the handle and
  both were substituted — the `accept` list in the declaration, exercised.
* **A handle this instance did not mint is refused.** A forged
  `sk-ast-gh-NOTTHISINSTANCES` got 401 from the door and never left the host.
* **The token is not on the guest, in the logs, or in a bug report.** A
  recursive content search of the guest's writable tree and of pid 1's
  environment found nothing; `ast logs`, `ast bugreport`, and every byte of
  `$ASTERISM_HOME` — the raw disk image included — were swept for the literal
  token and are clean.
* **Revocation is immediate and complete.** `ast detach --credential` removed
  all five bindings at once, and the handle the guest still had in its
  environment got 401 on the next call, on a guest that was still running.
* **The declarations parse and bind.** `ast credential providers` printed the
  catalog with all three door rules represented: `substitute` (github, npm,
  …), `refresh` (google), `sign` (aws).

## Does not prove

* **A real Google OAuth grant.** `ast oauth add google` opens a browser and
  needs a human; it was not executed. What *was* proved, and in the production
  door rather than a description of it, is the machinery underneath: the
  daemon test
  `egress::tests::a_refresh_rule_spends_a_grant_and_sends_only_what_it_bought`
  drives a real guest client through a real CONNECT and a real TLS
  termination, has the source device read a grant out of its store, spend it
  at a **local mock token endpoint over real TLS**, and send the access token
  it got back as a Bearer — asserting that the refresh token reached the token
  endpoint and never the API, that the handle reached neither, and that a
  second call inside the token's lifetime did not spend the grant again. The
  grant in that test is a fixture. The exchange, the substitution and the
  cache are not.
* **A real AWS call.** The SigV4 signer is proved against AWS's own published
  `get-vanilla` vector and against a mock verifier that recomputes the
  signature from the canonical request
  (`crates/asterism-core/src/sigv4.rs`); the door-side rule is proved by
  `egress::tests::a_sign_rule_signs_the_request_the_guest_actually_made`. No
  AWS account was involved. The `aws` declaration is also narrower than it
  looks — see `docs/credentials.md`: an unmodified AWS SDK is **not** carried,
  because recognising an SDK-signed `Authorization` header as a presentation
  of this instance's handle needs a SigV4 parser in front of a credential, and
  that is not something to add without a lane that exercises it.
* **npm, docker, slack, notion, linear.** Declared, marked `experimental`, and
  not proved against the real service. `ast login` and `ast oauth add` say so
  out loud before doing anything.
* **A second device.** One host, one source. The cross-device path is the
  existing secret plane's and is unchanged by this work.
* **The cost ledger under a credential part.** The ledger is shape-based and
  reads response bodies, so it is orthogonal to which rule filled the header;
  `scripts/e2e-cost.sh` remains its lane.
