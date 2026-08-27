//! `ast login`, `ast oauth add`, `ast credential ls`.
//!
//! Signing in is the one part of a credential part that has to happen on a
//! person's own machine, in front of a browser they trust, and it is the only
//! part of the feature that is not the secret plane already. Everything this
//! module produces is bytes handed to `ast secret create`'s own frame with a
//! kind and a provider on it; from there the part is a part, and the door,
//! the handle and the revocation are the ones that were already there.
//!
//! # What never happens here
//!
//! The token is not printed, not put in argv, not written to a file, and not
//! sent anywhere but this device's own daemon over its own socket. `ast login
//! gh` says *who* it signed in as, which it learns by spending the token once
//! against the provider's identity endpoint, and then the token goes into the
//! platform credential store and out of this process.

use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use asterism_core::credential::{self, OAuthGrant, PartKind, Provider, TokenGrant, OAUTH_MARKER};
use asterism_core::fix::{Fix, Fixable};
use asterism_core::protocol::{Request, Response, SecretValue};
use zeroize::Zeroizing;

/// How long a device-flow or browser grant may take a human. Both providers
/// expire their own codes well inside this; it exists so a command that will
/// never finish stops rather than waits forever.
const GRANT_DEADLINE: Duration = Duration::from_secs(15 * 60);

/// `ast login <provider>` — put a provider token on this device.
///
/// Three ways in, tried in this order, and the order is the whole user
/// experience: a device that is already signed in should not make a human
/// sign in again; a provider with a device flow should not make them paste;
/// a provider with neither is asked for.
pub(crate) fn login(provider_name: &str, part: Option<String>) -> Result<()> {
    let provider = require(provider_name)?;
    let login = provider.login.as_ref().ok_or_else(|| {
        anyhow!(
            "{} is an {} part — sign in with `ast oauth add {}`",
            provider.name,
            provider.kind,
            provider.name
        )
    })?;
    let name = part.unwrap_or_else(|| provider.default_part_name().to_owned());
    if provider.experimental {
        eprintln!(
            "note: the {} provider is declared but has not been proved against the real \
             service — see docs/credentials.md",
            provider.name
        );
    }

    let token = match import(&login.import) {
        Some(token) => {
            eprintln!(
                "{}: using the token this device's `{}` already holds",
                provider.name,
                login.import.join(" ")
            );
            token
        }
        None if !login.client_id.is_empty() => device_flow(
            &login.device_authorization_url,
            &login.token_url,
            &login.client_id,
            &login.scopes.join(" "),
            provider,
        )?,
        None => paste(&login.paste_hint)?,
    };

    let who = identity(&login.identity_url, &login.identity_field, &token);
    store(
        &name,
        PartKind::Login,
        provider,
        SecretValue::new(token.as_bytes().to_vec()),
    )?;
    match who {
        Some(who) => println!(
            "{}: signed in as {who} — stored on this device as credential part {name:?}",
            provider.aliases.first().unwrap_or(&provider.name)
        ),
        None => println!(
            "{}: signed in — stored on this device as credential part {name:?}",
            provider.aliases.first().unwrap_or(&provider.name)
        ),
    }
    Ok(())
}

/// `ast oauth add <provider> --scopes …` — put an authorization grant on this
/// device.
///
/// What is stored is the refresh token and the client identity that can spend
/// it, never an access token: an access token is an hour old the moment it is
/// written down, and the door mints one per request instead. See
/// `asterism_core::credential::OAuthGrant`.
pub(crate) fn oauth_add(
    provider_name: &str,
    scopes: Vec<String>,
    client_id: Option<String>,
    client_secret_from_stdin: bool,
    part: Option<String>,
) -> Result<()> {
    let provider = require(provider_name)?;
    let spec = provider.oauth.as_ref().ok_or_else(|| {
        anyhow!(
            "{} is a {} part — sign in with `ast login {}`",
            provider.name,
            provider.kind,
            provider.name
        )
    })?;
    let name = part.unwrap_or_else(|| provider.default_part_name().to_owned());
    if provider.experimental {
        eprintln!(
            "note: the {} provider is declared but has not been proved against the real \
             service — see docs/credentials.md",
            provider.name
        );
    }

    let client_id = match (client_id, spec.client_id.is_empty()) {
        (Some(id), _) => id,
        (None, false) => spec.client_id.clone(),
        (None, true) => {
            return Err(Fixable::new(
                format!(
                    "{} issues no public client id, so a grant needs one you registered",
                    provider.name
                ),
                Fix::new(format!(
                    "ast oauth add {} --client-id <your-oauth-client-id>",
                    provider.name
                )),
            )
            .into())
        }
    };
    let client_secret = match client_secret_from_stdin {
        true => Some(Zeroizing::new(read_line_from_stdin(
            "the OAuth client secret",
        )?)),
        false if spec.client_secret_required => {
            return Err(Fixable::new(
                format!("{} requires a client secret for this grant", provider.name),
                Fix::new(format!(
                    "printf %s \"$CLIENT_SECRET\" | ast oauth add {} --client-id … \
                     --client-secret-from-stdin",
                    provider.name
                )),
            )
            .into())
        }
        false => None,
    };

    let wanted = credential::resolve_scopes(spec, &scopes);
    let grant = match spec.device_flow_covers(&wanted) && !spec.device_authorization_url.is_empty()
    {
        true => device_flow_grant(
            spec,
            &client_id,
            client_secret.as_ref().map(|s| s.as_str()),
            &wanted,
            provider,
        )?,
        false => {
            if spec.authorize_url.is_empty() && spec.device_authorization_url.is_empty() {
                bail!(
                    "{} declares no way to obtain a grant in this build",
                    provider.name
                );
            }
            loopback_grant(
                spec,
                &client_id,
                client_secret.as_ref().map(|s| s.as_str()),
                &wanted,
                provider,
            )?
        }
    };

    // Who the grant belongs to is deliberately not read out of it. Google
    // puts an `id_token` on the answer when `openid` was asked for, and this
    // process has no way to verify one — so the choice is between printing an
    // unverified claim as fact and not printing a name, and not printing it
    // is the honest half. `ast login` can say who because it *spends* the
    // token against the provider's own endpoint; a refresh token cannot be
    // spent that way without minting an access token nobody asked for.
    let account: Option<String> = None;
    let stored = OAuthGrant {
        marker: OAUTH_MARKER,
        provider: provider.name.clone(),
        refresh_token: grant.refresh_token.clone(),
        scopes: wanted,
        client_id,
        client_secret: client_secret.as_ref().map(|s| s.to_string()),
        token_url: spec.token_url.clone(),
        account: account.clone(),
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&stored).context("encoding the grant")?);
    store(
        &name,
        PartKind::OAuth,
        provider,
        SecretValue::new(bytes.to_vec()),
    )?;
    match account {
        Some(who) => println!(
            "{}: granted for {who} — refresh token stored on this device as credential part \
             {name:?}",
            provider.name
        ),
        None => println!(
            "{}: granted — refresh token stored on this device as credential part {name:?}",
            provider.name
        ),
    }
    Ok(())
}

/// `ast credential ls` — the parts this orbit holds, with what each one is.
pub(crate) fn list(secrets: &[asterism_core::secret::Secret]) {
    println!(
        "{:<20} {:<8} {:<10} {:<11} SOURCES",
        "NAME", "KIND", "PROVIDER", "RULE"
    );
    for secret in secrets {
        let provider = secret.provider.as_deref().and_then(credential::find);
        let rule = provider.map(|p| p.rule.as_str()).unwrap_or("substitute");
        let sources = secret
            .sources
            .iter()
            .map(|source| match source.version == secret.version {
                true => source.device.clone(),
                false => format!("{}@v{}", source.device, source.version),
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{:<20} {:<8} {:<10} {:<11} {}",
            secret.name,
            secret.kind.as_str(),
            secret.provider.as_deref().unwrap_or("-"),
            rule,
            sources
        );
    }
}

/// `ast credential providers` — what this build knows how to sign in to.
pub(crate) fn providers() {
    println!("{:<10} {:<8} {:<11} SUMMARY", "NAME", "KIND", "RULE");
    for provider in credential::catalog() {
        let mark = match provider.experimental {
            true => "  (experimental, not proved against the real service)",
            false => "",
        };
        println!(
            "{:<10} {:<8} {:<11} {}{mark}",
            provider.name,
            provider.kind.as_str(),
            provider.rule.as_str(),
            provider.summary
        );
    }
}

// ---- the ways a token gets here -------------------------------------------

/// The host's own CLI, if it is installed and signed in.
///
/// Every failure is `None` and none of them is an error: not installed, not
/// signed in, and printed nothing all mean the same thing to the caller —
/// there is no token here, open a device flow.
fn import(command: &[String]) -> Option<Zeroizing<String>> {
    let (program, args) = command.split_first()?;
    let output = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let token = Zeroizing::new(String::from_utf8(output.stdout).ok()?.trim().to_owned());
    match token.is_empty() {
        true => None,
        false => Some(token),
    }
}

/// A token pasted on stdin, the way `ast secret create` takes one.
fn paste(hint: &str) -> Result<Zeroizing<String>> {
    let what = match hint.is_empty() {
        true => "the token".to_owned(),
        false => hint.to_owned(),
    };
    read_line_from_stdin(&what).map(Zeroizing::new)
}

fn read_line_from_stdin(what: &str) -> Result<String> {
    use std::io::IsTerminal;
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(Fixable::new(
            format!("{what} is read from stdin, never argv"),
            Fix::new("printf %s \"$TOKEN\" | ast login <provider>"),
        )
        .into());
    }
    let mut buffer = String::new();
    stdin
        .read_to_string(&mut buffer)
        .with_context(|| format!("reading {what} from stdin"))?;
    let value = buffer.trim().to_owned();
    if value.is_empty() {
        bail!("refusing an empty value from stdin");
    }
    Ok(value)
}

/// RFC 8628, for a provider that grants a plain token.
fn device_flow(
    authorization_url: &str,
    token_url: &str,
    client_id: &str,
    scope: &str,
    provider: &Provider,
) -> Result<Zeroizing<String>> {
    let grant = run_device_flow(
        authorization_url,
        token_url,
        client_id,
        None,
        scope,
        provider,
    )?;
    Ok(Zeroizing::new(grant.access_token))
}

/// The same flow, when what is wanted is the refresh token underneath.
fn device_flow_grant(
    spec: &credential::OAuthSpec,
    client_id: &str,
    client_secret: Option<&str>,
    scopes: &[String],
    provider: &Provider,
) -> Result<TokenGrant> {
    let grant = run_device_flow(
        &spec.device_authorization_url,
        &spec.token_url,
        client_id,
        client_secret,
        &scopes.join(" "),
        provider,
    )?;
    if grant.refresh_token.is_empty() {
        bail!(
            "{} granted an access token but no refresh token — this device keeps only the \
             refresh token, so there would be nothing to keep",
            provider.name
        );
    }
    Ok(grant)
}

fn run_device_flow(
    authorization_url: &str,
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    scope: &str,
    provider: &Provider,
) -> Result<TokenGrant> {
    if authorization_url.is_empty() || token_url.is_empty() {
        bail!("{} declares no device flow in this build", provider.name);
    }
    let client = http()?;
    let opened: DeviceCode = json_or_form(
        client
            .post(authorization_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .body(credential::form_encode(&[
                ("client_id", client_id),
                ("scope", scope),
            ]))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            ),
    )?;
    let where_to = match opened.verification_uri_complete.is_empty() {
        true => opened.verification_uri.clone(),
        false => opened.verification_uri_complete.clone(),
    };
    // The URL and the code both go to stderr rather than stdout, so a script
    // capturing this command's output gets the result and not the ceremony.
    eprintln!("opening {where_to} (device code: {})", opened.user_code);
    let _ = open_browser(&where_to);

    let started = std::time::Instant::now();
    // The provider's own suggested interval, floored at RFC 8628's default
    // so a provider that says zero does not turn this into a hot loop.
    let mut interval = Duration::from_secs(opened.interval.max(5));
    loop {
        if started.elapsed() > GRANT_DEADLINE {
            bail!("nobody approved the device code in time");
        }
        std::thread::sleep(interval);
        let mut pairs = vec![
            ("client_id", client_id),
            ("device_code", opened.device_code.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ];
        if let Some(secret) = client_secret {
            pairs.push(("client_secret", secret));
        }
        let answer: TokenGrant = json_or_form(
            client
                .post(token_url)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(credential::form_encode(&pairs)),
        )?;
        match answer.error.as_deref() {
            None => return Ok(answer),
            // The two RFC 8628 states that are not failures.
            Some("authorization_pending") => continue,
            Some("slow_down") => {
                interval += Duration::from_secs(5);
                continue;
            }
            Some(_) => {
                answer.access()?;
                unreachable!("an error field always refuses");
            }
        }
    }
}

/// The authorization-code flow with a loopback redirect and PKCE.
///
/// Used when a provider has no device flow, or when the scopes asked for are
/// outside the set its device flow covers — which is the ordinary case for
/// Google, whose device flow does not carry Gmail or Calendar.
fn loopback_grant(
    spec: &credential::OAuthSpec,
    client_id: &str,
    client_secret: Option<&str>,
    scopes: &[String],
    provider: &Provider,
) -> Result<TokenGrant> {
    if spec.authorize_url.is_empty() {
        // Google publishes the authorization endpoint everyone knows; a
        // provider declaration that omits it cannot do this flow.
        bail!(
            "{} declares no browser authorization endpoint, and the scopes asked for are \
             outside its device flow",
            provider.name
        );
    }
    let pkce = credential::pkce();
    let state = credential::nonce();
    // Port zero, so nothing has to be reserved and two of these can run at
    // once. Loopback only: the redirect must not be reachable from the LAN.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .context("opening a loopback port for the redirect")?;
    let port = listener.local_addr()?.port();
    let redirect = format!("http://127.0.0.1:{port}");
    let url = format!(
        "{}?{}",
        spec.authorize_url,
        credential::query_encode(&[
            ("client_id", client_id),
            ("redirect_uri", &redirect),
            ("response_type", "code"),
            ("scope", &scopes.join(" ")),
            ("state", &state),
            ("code_challenge", &pkce.challenge),
            ("code_challenge_method", "S256"),
            // Without both of these Google returns an access token and no
            // refresh token on the second and later grants, and this device
            // keeps only the refresh token.
            ("access_type", "offline"),
            ("prompt", "consent"),
        ])
    );
    eprintln!("opening {url}");
    let _ = open_browser(&url);
    listener
        .set_nonblocking(false)
        .context("waiting for the redirect")?;
    let code = wait_for_code(&listener, &state)?;
    let mut pairs = vec![
        ("client_id", client_id),
        ("code", code.as_str()),
        ("code_verifier", pkce.verifier.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect.as_str()),
    ];
    if let Some(secret) = client_secret {
        pairs.push(("client_secret", secret));
    }
    let answer: TokenGrant = json_or_form(
        http()?
            .post(&spec.token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(credential::form_encode(&pairs)),
    )?;
    answer.access()?;
    if answer.refresh_token.is_empty() {
        bail!(
            "{} granted an access token but no refresh token — revoke this device's access in \
             the provider's console and grant it again, so consent is asked for afresh",
            provider.name
        );
    }
    Ok(answer)
}

/// Read exactly one redirect off the loopback listener and answer the browser.
///
/// The `state` check is the CSRF half of the flow: without it, anything that
/// can reach this port could hand this process an authorization code of its
/// own choosing, and this process would exchange it and store the result as
/// the user's grant.
fn wait_for_code(listener: &std::net::TcpListener, state: &str) -> Result<String> {
    listener
        .set_ttl(1)
        .context("limiting the redirect listener to this machine")?;
    let deadline = std::time::Instant::now() + GRANT_DEADLINE;
    loop {
        if std::time::Instant::now() > deadline {
            bail!("the browser did not come back in time");
        }
        let (stream, peer) = listener.accept().context("accepting the redirect")?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let mut stream = stream;
        let reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        reader
            .take(8 * 1024)
            .read_line(&mut line)
            .context("reading the redirect")?;
        let target = line.split_whitespace().nth(1).unwrap_or("/");
        let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut code = None;
        let mut got_state = None;
        let mut error = None;
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            match key {
                "code" => code = Some(percent_decode(value)),
                "state" => got_state = Some(percent_decode(value)),
                "error" => error = Some(percent_decode(value)),
                _ => {}
            }
        }
        let verdict = match (&code, &got_state, &error) {
            (_, _, Some(why)) => Err(format!("the provider refused: {why}")),
            (Some(_), Some(got), _) if got == state => Ok(()),
            (Some(_), _, _) => Err("the redirect carried the wrong state".to_owned()),
            _ => Err("the redirect carried no authorization code".to_owned()),
        };
        let body = match &verdict {
            Ok(()) => "Asterism has the grant. You can close this tab.",
            Err(why) => why.as_str(),
        };
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
        let _ = stream.flush();
        match verdict {
            Ok(()) => return Ok(code.expect("checked above")),
            Err(why) => bail!(why),
        }
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16)
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---- talking to a provider -------------------------------------------------

fn http() -> Result<reqwest::blocking::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        // A redirect on a token endpoint is the shortest path from "this
        // grant goes to Google" to "this grant went to somewhere Google
        // named".
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("constructing the provider client")
}

/// Send one request and read the answer in whichever of the two shapes a
/// token endpoint chose. Bounded, because the answer is a handful of fields
/// and an untrusted endpoint should not be able to make this allocate.
fn json_or_form<T: serde::de::DeserializeOwned + FromBytes>(
    request: reqwest::blocking::RequestBuilder,
) -> Result<T> {
    let response = request.send().context("contacting the provider")?;
    let status = response.status();
    let mut bytes = Vec::new();
    response
        .take(64 * 1024)
        .read_to_end(&mut bytes)
        .context("reading the provider's answer")?;
    if bytes.is_empty() {
        bail!("the provider answered {status} and nothing else");
    }
    T::from_bytes(&bytes)
}

/// Both answers this module reads know how to parse themselves out of JSON or
/// form encoding, and the trait is how one function serves both.
trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

impl FromBytes for TokenGrant {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        TokenGrant::parse(bytes)
    }
}

/// RFC 8628's device authorization response.
#[derive(Debug, Default, serde::Deserialize)]
struct DeviceCode {
    #[serde(default)]
    device_code: String,
    #[serde(default)]
    user_code: String,
    // Google spells this `verification_url`; RFC 8628 spells it
    // `verification_uri`, and both arrive in the field.
    #[serde(default, alias = "verification_url")]
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: String,
    #[serde(default)]
    interval: u64,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

impl FromBytes for DeviceCode {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("the provider answered in binary")?;
        let opened: Self = match text.trim_start().starts_with('{') {
            true => serde_json::from_str(text).context("the provider answered unreadable JSON")?,
            false => {
                let mut out = Self::default();
                for pair in text.trim().split('&') {
                    let Some((key, value)) = pair.split_once('=') else {
                        continue;
                    };
                    let value = percent_decode(value);
                    match key {
                        "device_code" => out.device_code = value,
                        "user_code" => out.user_code = value,
                        "verification_uri" | "verification_url" => out.verification_uri = value,
                        "verification_uri_complete" => out.verification_uri_complete = value,
                        "interval" => out.interval = value.parse().unwrap_or(5),
                        "error" => out.error = Some(value),
                        "error_description" => out.error_description = Some(value),
                        _ => {}
                    }
                }
                out
            }
        };
        if let Some(error) = &opened.error {
            let detail = opened.error_description.as_deref().unwrap_or("");
            bail!("the provider refused to open a device flow: {error} {detail}");
        }
        if opened.device_code.is_empty() || opened.verification_uri.is_empty() {
            bail!("the provider's device authorization answer is missing a code or a url");
        }
        Ok(opened)
    }
}

/// Who a token belongs to, spent once against the provider's own endpoint.
///
/// Best effort by design: a provider that does not answer, a scope that does
/// not cover the identity endpoint, and a field spelled differently all mean
/// "sign-in worked and this device cannot say whose", which is not a reason
/// to refuse the sign-in.
fn identity(url: &str, field: &str, token: &str) -> Option<String> {
    if url.is_empty() || field.is_empty() {
        return None;
    }
    let response = http()
        .ok()?
        .get(url)
        .bearer_auth(token)
        .header(reqwest::header::USER_AGENT, "asterism")
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut bytes = Vec::new();
    response.take(256 * 1024).read_to_end(&mut bytes).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get(field).and_then(|v| v.as_str()).map(str::to_owned)
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = std::process::Command::new("xdg-open");
    let status = command
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("opening the system browser")?;
    match status.success() {
        true => Ok(()),
        false => bail!("the system browser opener exited with {status}"),
    }
}

// ---- storing ---------------------------------------------------------------

/// Hand the bytes to the daemon as a credential part.
///
/// The same frame `ast secret create` sends, with the kind and the provider
/// on it. From here the part is a part: the store, the handle grammar, the
/// merge rules and the revocation are all the ones that already existed.
/// Writes a credential part into this device's store.
///
/// Always this one: a token that was just minted in this process's own
/// browser or `gh` lives here, and the orbit reads it from here. Which device
/// resolves a part at boot is the instance's business — `ast attach --from` —
/// and not the sign-in's.
fn store(name: &str, kind: PartKind, provider: &Provider, value: SecretValue) -> Result<()> {
    let request = Request::SecretCreate {
        name: name.to_owned(),
        value,
        source_device: None,
        kind,
        provider: Some(provider.name.clone()),
    };
    match crate::send(&request)? {
        Response::Secrets { .. } => Ok(()),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

fn require(name: &str) -> Result<&'static Provider> {
    credential::require(name)
        .map_err(|e| Fixable::new(format!("{e:#}"), Fix::new("ast credential providers")).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_authorization_answer_is_read_in_both_shapes_github_and_google_send() {
        // GitHub answers form-encoded by default; Google answers JSON and
        // spells the field `verification_url`.
        let form = DeviceCode::from_bytes(
            b"device_code=dc&user_code=ABCD-EFGH&verification_uri=https%3A%2F%2Fgithub.com%2Flogin%2Fdevice&interval=5",
        )
        .unwrap();
        assert_eq!(form.user_code, "ABCD-EFGH");
        assert_eq!(form.verification_uri, "https://github.com/login/device");
        assert_eq!(form.interval, 5);

        let json = DeviceCode::from_bytes(
            br#"{"device_code":"dc","user_code":"WXYZ","verification_url":"https://www.google.com/device","interval":5}"#,
        )
        .unwrap();
        assert_eq!(json.verification_uri, "https://www.google.com/device");

        // A refusal is a refusal and not a half-filled struct.
        assert!(DeviceCode::from_bytes(b"error=unauthorized_client").is_err());
        assert!(DeviceCode::from_bytes(b"user_code=ABCD").is_err());
    }

    #[test]
    fn a_redirect_query_is_decoded_the_way_a_browser_sent_it() {
        assert_eq!(percent_decode("a%2Fb+c"), "a/b c");
        assert_eq!(percent_decode("plain"), "plain");
    }

    #[test]
    fn the_transcript_names_are_the_ones_the_catalog_answers_to() {
        // `ast login gh`, not `ast login github`, is what the transcript
        // says — and the part it makes is called `gh`, because that is what
        // the next command types.
        let gh = require("gh").unwrap();
        assert_eq!(gh.default_part_name(), "gh");
        assert_eq!(require("github").unwrap().name, "github");
        assert_eq!(require("google").unwrap().default_part_name(), "google");
        // A name nobody declared says how to find out what there is.
        let refusal = require("hotmail").unwrap_err();
        assert!(asterism_core::fix::of(&refusal).is_some(), "{refusal:#}");
    }
}
