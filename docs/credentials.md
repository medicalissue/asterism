# Credential parts

An agent running on Asterism should find its tools already logged in. `gh api
user` should work. `git push` should work. `gcloud` should work. And none of
the tokens that make them work should ever be on the machine the agent runs
on — because that machine is the one running code nobody read, and its disk
ends up in snapshots, backups and bug reports.

A **credential part** is how those two things are true at once. It is the
existing secret plane — the same store, the same opaque handle, the same
egress door, the same revocation — with one thing added: a declaration, kept
in this repository, of how a particular provider's credential is used. Which
hosts. Which header. Which environment variable the tool reads. Whether the
stored value is the credential, or buys one, or signs with one.

```
$ ast login gh
gh: using the token this device's `gh auth token` already holds
gh: signed in as medicalissue — stored on this device as credential part "gh"

$ ast oauth add google --scopes gmail.readonly,calendar.readonly
opening https://accounts.google.com/o/oauth2/v2/auth?…
google: granted — refresh token stored on this device as credential part "google"

$ ast create bot --profile claude --with gh,google
bot  defined
bot  gh -> api.github.com  (authorization: Bearer, from this-mac)
…

$ ast ssh bot
agent@bot:~$ gh api user --jq .login        # works: the door swaps the header
medicalissue
agent@bot:~$ echo $GH_TOKEN
sk-ast-gh-7c1e…                             # a handle, not a token
agent@bot:~$ curl -s https://gmail.googleapis.com/gmail/v1/users/me/profile
{"emailAddress": …}

$ ast detach bot --credential google
bot  google revoked
```

## What is a part

There are three kinds, and `ast credential ls` prints which is which.

| kind | made by | what is stored |
|---|---|---|
| `secret` | `ast secret create NAME < file` | the bytes you piped in |
| `login` | `ast login gh` | a provider token |
| `oauth` | `ast oauth add google` | a refresh token and the client identity that can spend it |

`ast secret ls` shows all three with their kind; `ast credential ls` adds the
provider and the door rule.

All three live in the same place — the login Keychain on macOS, the Secret
Service on Linux, the Credential Manager on Windows — carry the same
[`ValueRevision`][secret] commitment, replicate their metadata the same way,
and are removed by the same `ast secret rm`. A credential part is not a new
kind of storage. It is a secret that knows what it is for.

[secret]: ../crates/asterism-core/src/secret.rs

## What is *not* a part

An allowlist. A policy engine. A per-request approval prompt.

The design principle is leverage: hand the agent every key you own. What
Asterism removes is not the agent's authority, it is the agent's *possession*
of the credential — so a key can be revoked in one command, from the outside,
after the agent has already been given it. There is nothing here that decides
whether a particular request deserves a key, and adding one would be a
different product.

## The three door rules

When a bound request reaches the egress door, the source device — the one
whose store actually holds the material — does one of exactly three things.
The set is closed for the same reason [`Placement`][secret] is closed: a
template language in front of a credential is a place for an injection to
live.

### `substitute`

The stored bytes *are* the credential. Take the guest's handle out of the
header, put the value in, open the connection. GitHub, npm, Docker, Notion,
Linear, and every plain `ast secret`.

### `refresh`

The stored bytes are a **grant**, not a credential: a refresh token is not
something an API accepts, it is something that buys an hour of something an
API accepts. So the source device exchanges it at the provider's token
endpoint, seconds before the connection out, and substitutes what it got.

The access token is **never written down**. It lives in memory on the source
device, keyed by the revision of the grant it came from, until it expires.
That is not tidiness: a `ValueRevision` is this orbit's commitment to *which
bytes* a source holds, replicated to every other device, and a store that
rewrote itself every hour would make that commitment false every hour. A
daemon restart costs one exchange. A rotated grant invalidates every token
minted from the old one by construction.

Google is the implemented case.

### `sign`

The stored bytes are a key pair and the credential is an HMAC over the request
itself. Nothing is substituted; the request is signed, on the source device,
after it is final. The guest never holds anything that could sign anything —
which is a stronger statement than `substitute` can make, because a
substituted token is good for anyone who steals it and a signature is good for
one request.

AWS SigV4 is the implemented algorithm
([`asterism_core::sigv4`](../crates/asterism-core/src/sigv4.rs)), proved
against AWS's own published `get-vanilla` vector and against a verifier that
recomputes the signature the way a service would.

**Where AWS stops short, and why.** An AWS SDK does not send a token; it signs
with a secret key it believes it has, and puts `Credential=<key id>/…` in the
`Authorization` header. Recognising *that* as a presentation of this
instance's handle means parsing a SigV4 header, which is a parser standing in
front of a credential — not something to add without a lane that exercises it.
So today the guest presents the handle as a bearer token, which is what `curl`
does, what Bedrock's API-key mode does, and what any tool pointed at a plain
header does. An unmodified SDK is not yet carried, and the `aws` declaration is
marked `experimental` accordingly.

## The provider declarations

One TOML file per provider under
[`crates/asterism-core/providers/`](../crates/asterism-core/providers), parsed
at **compile time** with `include_str!`. Nothing on a user's disk can change a
door rule; a provider that is in the tree but not in `credential.rs`'s
`DECLARATIONS` list simply does not exist.

```toml
name = "github"
aliases = ["gh"]
kind = "login"                       # login | oauth
summary = "GitHub API, git over HTTPS, and the gh CLI"
experimental = false                 # declared but not proved against the real service

# The guest's handle wears this. Must contain "ast", so a handle found in a
# log is identifiable as one rather than reported as a leaked key.
handle_prefix = "sk-ast-gh-"

# Exact hosts. No wildcards: an authority nobody read out loud is not one.
authorities = ["api.github.com", "github.com", "codeload.github.com", …]

# What the guest exports. Every name gets the same handle.
env = ["GH_TOKEN", "GITHUB_TOKEN"]

[rule]
type = "substitute"                  # substitute | refresh | sign
placement = "bearer"                 # bearer | x-api-key | header:<Name>
# Extra schemes a *guest* may present the handle under. `gh` sends
# `Authorization: token …` to some endpoints and `Bearer …` to others.
accept = ["bearer", "token"]

# For type = "refresh":
#   token_url = "https://oauth2.googleapis.com/token"
#   refresh_skew_secs = 120
# For type = "sign":
#   algorithm = "aws-sigv4"
#   service = "sts"
#   region = "us-east-1"

# Config files for tools that read a file rather than an environment
# variable. The content may NAME a variable and may never carry a value —
# this lands on a guest's disk.
[[files]]
path = "/etc/npmrc"
mode = "0644"
content = "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"

[login]
import = ["gh", "auth", "token"]     # tried first; its absence is not an error
device_authorization_url = "https://github.com/login/device/code"
token_url = "https://github.com/login/oauth/access_token"
client_id = "178c6fc778ccc68e1d6a"   # RFC 8628 public clients are identified, not authenticated
scopes = ["repo", "read:org", "gist", "workflow"]
identity_url = "https://api.github.com/user"
identity_field = "login"

# [oauth] instead, for kind = "oauth":
#   device_authorization_url / authorize_url / token_url
#   device_flow_scopes, default_scopes, scope_prefix
#   client_id_required, client_secret_required
```

Every field is public configuration. If something here needed to be secret it
would be in the wrong file — a declaration is compiled into the binary and
printed by `ast credential providers`.

Parsing refuses, at build time, everything that would otherwise fail inside a
guest where nobody can read the message: a wildcard authority, a handle prefix
with no `ast` in it, a provider that names no environment variable, a `login`
part that claims to refresh, a token endpoint over plain HTTP, a signing
algorithm nobody wrote.

## What this build carries

```
$ ast credential providers
NAME       KIND     RULE        SUMMARY
aws        login    sign        AWS APIs, signed at the door with SigV4  (experimental, …)
docker     login    substitute  Docker Hub registry pulls and pushes  (experimental, …)
github     login    substitute  GitHub API, git over HTTPS, and the gh CLI
google     oauth    refresh     Google APIs: Gmail, Calendar, Drive, and anything gcloud reaches
linear     login    substitute  Linear GraphQL API with a personal API key  (experimental, …)
notion     login    substitute  Notion API as an internal integration  (experimental, …)
npm        login    substitute  the npm registry, for private packages and publishing
slack      oauth    substitute  Slack Web API as a workspace app  (experimental, …)
```

`experimental` means exactly one thing: the declaration was written from the
vendor's documentation and has not been run against the vendor's service. `ast
login` and `ast oauth add` say so before doing anything.

## Signing in

### `ast login <provider>`

Three ways in, tried in order, and the order is the whole user experience.

1. **Import.** If the provider declares an `import` command and this device
   already runs it successfully — `gh auth token` — that token is used. A
   device that is already signed in should not make a human sign in again.
   Every failure of that command (not installed, not signed in, printed
   nothing) is simply "no token here", not an error.
2. **Device flow.** RFC 8628 against the provider's own endpoints. A code and
   a URL go to *stderr*, so a script capturing the command's output gets the
   result and not the ceremony.
3. **Paste.** Read from stdin, never argv, for a provider with neither.

The token is spent once against the provider's identity endpoint so the
command can say *who* it signed in as, then goes into the platform store and
out of the process. It is never printed and never written to a file.

### `ast oauth add <provider> [--scopes …]`

A grant, not a token. Short scope names are expanded to the URLs the provider
published, so `--scopes gmail.readonly` means
`https://www.googleapis.com/auth/gmail.readonly`.

Which flow runs depends on what was asked for. Google's device flow covers a
limited scope set; anything outside it — Gmail and Calendar included — needs
the browser, so `ast oauth add` opens a **loopback redirect flow with PKCE**:
a listener on `127.0.0.1:0`, a `state` nonce checked on the way back, and an
S256 code challenge whose verifier never leaves the process. A loopback
redirect is a port anything else on the machine could also have bound; PKCE is
what makes a caught authorization code worthless.

Google issues no public client id, so a grant needs one you registered:

```
ast oauth add google --scopes gmail.readonly --client-id <your-oauth-client-id>
printf %s "$SECRET" | ast oauth add google --client-id … --client-secret-from-stdin
```

What is stored is the refresh token, the client id, the client secret if there
is one, the token endpoint, and the scopes. No access token — see `refresh`
above.

## Attaching

```
ast attach bot --credential gh
ast create bot --profile claude --with gh,google
```

No `--to` and no `--as`. That is the difference between `--credential` and
`--secret`: the provider already said which hosts, which header, and what the
guest's tools will look for.

One `--credential` makes **several bindings** — one per declared authority —
sharing a single handle and a single environment. All of them land or none
does: a `gh` that reached `api.github.com` but not `codeload.github.com`
because the second attach failed would be a guest whose `gh` works until it
clones. `--with` on `ast create` is exactly these commands run in order, so a
failure names the part it failed on rather than hiding behind one opaque
error.

Detaching takes them all back at once, immediately, including on connections
the guest already has open:

```
$ ast detach bot --credential gh
bot  gh revoked
```

Half a credential revoked is not a revocation: the handle the guest still
holds would go on being honoured everywhere it was left behind.

## What the guest gets

Every environment variable the provider declares, all carrying the one handle,
plus any config files it needs:

```
GH_TOKEN=sk-ast-gh-JHTY1PFV…
GITHUB_TOKEN=sk-ast-gh-JHTY1PFV…
```

That is the whole integration. `gh` reads `GH_TOKEN`; `gcloud` reads
`CLOUDSDK_AUTH_ACCESS_TOKEN`; `npm` reads `/etc/npmrc`, which says
`_authToken=${NPM_TOKEN}` and therefore holds the *name* of a variable that
holds a handle. No tool is patched and nothing inside the guest knows Asterism
exists.

A handle is 240-odd random bits behind a cosmetic prefix. The prefix is
cosmetic because SDKs check it — OpenAI's clients want `sk-`, Anthropic's want
`sk-ant-` — and a handle that failed a client-side shape check would fail
inside the guest, where there is no proxy to explain why. The entropy is not
cosmetic, and it is the same for every shape.

## Rewind

A credential part is a **host-side** part. What `ast rewind` rolls back is the
guest's disk and its volumes; the bindings live in this device's registry
shard, alongside the compute and network rows, and nothing in the rewind path
touches them. So an instance that is rewound to yesterday comes back up still
holding its handle — which is the behaviour you want, because a token is not
something the guest ever had and therefore not something a rewind could have
taken away.

## Evidence

[`docs/evidence/credential-parts-2026-08-27/`](evidence/credential-parts-2026-08-27/README.md)
— a real VZ guest reaching the real `api.github.com` and being answered as
`medicalissue`, with the token absent from the guest, the logs, the bug report
and the disk image, and with the handle stopping dead on detach. It also says
plainly what it did not prove.

## Where the code is

| | |
|---|---|
| declarations | `crates/asterism-core/providers/*.toml` |
| parsing, rules, grants, PKCE | `crates/asterism-core/src/credential.rs` |
| the SigV4 signer | `crates/asterism-core/src/sigv4.rs` |
| the handle, the binding, the placement | `crates/asterism-core/src/secret.rs` |
| the substitution rule | `crates/asterism-core/src/rewrite.rs` |
| the door, and the three rules applied | `crates/asterism-daemon/src/egress.rs` |
| the token exchange and its cache | `crates/asterism-daemon/src/credential.rs` |
| `ast login` / `ast oauth add` | `crates/asterism-cli/src/credential.rs` |
| the lane | `scripts/e2e-credentials.sh` |
