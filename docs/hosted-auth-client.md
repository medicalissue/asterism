# Hosted authentication client contract

Asterism's hosted identity authority is an external coordinator at
`https://auth.asterism.run`. This public repository contains clients and the
protocol seam only. It does not contain provider secrets, OAuth callbacks,
session authority, or hosted server code.

`ast auth login --provider google|github` sends
`Asterism-Protocol: asterism-device-authorization/1` to
`POST /oauth/device/code`, prints the returned verification URL and user code,
and then attempts to open the complete URL in the system browser. Browser-open
failure is non-fatal: the printed URL and code remain the recovery path. The
client polls `POST /oauth/device/token` with the RFC 8628 device grant, obeys
the server interval and `slow_down`, retries transient offline failures with a
capped backoff, and never polls beyond the server-issued expiry.

The only accepted providers are `google` and `github`. Cloudflare Access,
Supabase, email/password, email OTP, and direct provider credentials are not
client protocol concepts.

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
native app a narrow, testable deep-link seam.

Hosted authentication is optional. Local creation, pairing, instance use, and
the orbit data plane do not consult the credential store or coordinator.
