# Hosted authentication client contract

Asterism's hosted identity authority is an external coordinator at
`https://asterism.run`. This public repository contains clients and the
protocol seam only. It does not contain provider secrets, OAuth callbacks,
session authority, or hosted server code.

`ast auth login --provider google|github` sends
`Asterism-Protocol: asterism-device-authorization/1` to
`POST /oauth/device/code`, prints the returned verification URL and user code,
and then attempts to open the complete URL in the system browser. Browser-open
failure is non-fatal: the printed URL and code remain the recovery path. The
client polls `POST /oauth/token` with the RFC 8628 device grant, obeys
the server interval and `slow_down`, retries transient offline failures with a
capped backoff, and never polls beyond the server-issued expiry.

Both OAuth endpoints read `application/x-www-form-urlencoded` and identify the
caller by the registered public client id `asterism-cli`, whose scopes are
`openid orbit.read orbit.write`. A public client is identified, not
authenticated, so that id is not a secret.

| | request | response |
| --- | --- | --- |
| `POST /oauth/device/code` | form: `client_id`, `scope`, advisory `provider`, optional Desktop `redirect_uri` / `deep_link_state` | JSON: `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, `interval` |
| `POST /oauth/token` | form: `client_id`, `grant_type`, `device_code` | JSON: `access_token`, `token_type`, `expires_in`, `scope` |
| `POST /api/v1/account/sessions/revoke` | JSON body, bearer in `Authorization` | JSON: `ok`, `revoked` |

Errors on all three are `{ "error": ..., "error_description": ... }`.

`provider` is advisory. The authority resolves the provider from the browser
session that approves the user code, so `--provider` records the caller's
intent and does not pre-select a provider at the authority.

The authority does not echo `Asterism-Protocol`. A missing response header is
therefore silence, not an incompatible deployment; a header that is present
and disagrees is still refused.

The only accepted providers are `google` and `github`. Cloudflare Access,
Supabase, email/password, email OTP, and direct provider credentials are not
client protocol concepts.

The token endpoint returns a bearer and its scope, with no separate account
document. The bearer is a token signed by a key no client holds, and its
payload names the account it was minted for. Clients read those claims without
verifying that signature, for the name `ast auth status` prints and for the
local credential-store namespace, and for nothing else: no privilege is
granted locally, and every answer that matters still comes from the authority,
which does verify the signature. A bearer whose claims do not parse is refused
rather than stored under a guessed identity.

Successful bearer material is stored through the OS credential-store seam.
The CLI implementation uses the platform backend supplied by `keyring`:
Keychain on macOS, Secret Service on Linux, and Credential Manager on Windows.
There is no plaintext-file fallback. Every session records the canonical origin
that issued it, and its credential-store account is derived from that origin.
A separate non-secret pointer selects the active issuer. `ast auth status` and
`ast auth logout` use that stored issuer; an optional `--coordinator` is only an
assertion and a mismatch is rejected before an HTTP client is constructed.
Credentials written by older clients to the unbound `default` slot are removed
locally and never sent to any coordinator. Logout attempts revocation only at
the bound issuer and always removes the local entry after that attempt. Bearer
values redact their `Debug` representation and are never printed.

Desktop uses the same device-code request, polling state machine, browser
opener, and credential-store capabilities. Its request adds the exact callback
URI `asterism://auth/callback` and a URL-safe nonce. The deep link returns only
that nonce plus completion status; the app still obtains the bearer through the
device-token endpoint. This keeps tokens out of browser URLs and gives the
native app a narrow, testable deep-link seam. The deployed authority does not
yet act on `redirect_uri` or `deep_link_state`; it ignores unknown form fields,
so Desktop completes through the same browser page and polling channel as the
CLI until that seam exists at the edge.

Hosted authentication is optional. Local creation, pairing, instance use, and
the orbit data plane do not consult the credential store or coordinator.
