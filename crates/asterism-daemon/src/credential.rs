//! The source device's half of a credential part.
//!
//! [`crate::secret`] resolves bytes out of this device's platform store and
//! [`crate::egress`] puts them on a request. This module is what sits between
//! those two when the bytes are not themselves the credential: an
//! authorization grant that has to be exchanged for an access token first,
//! and the planning that turns one `ast attach --credential gh` into the set
//! of bindings a provider declares.
//!
//! # Why the access token is not written down
//!
//! An access token is material with an expiry, and the obvious place to keep
//! one is beside the grant that minted it. That would be wrong here, and the
//! reason is [`asterism_core::secret::ValueRevision`]: a revision is this
//! orbit's commitment to *which bytes* a source device holds, replicated to
//! every other device, and it is what lets two sources be treated as
//! interchangeable. A store that rewrote itself every hour would make that
//! commitment false every hour — or would need a rotation per refresh, which
//! is a metadata write and a mesh round trip to save an HTTPS call.
//!
//! So the grant on disk never changes, and the access token lives in the
//! process, in [`ACCESS`], keyed by the revision it was minted from. A daemon
//! restart costs one exchange. A rotated grant invalidates every token minted
//! from the old one by construction, because the key includes the revision.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use asterism_core::credential::{self, CredentialRule, OAuthGrant, Provider, TokenGrant};
use asterism_core::secret::{Binding, GuestHandle, Handle, Secret};
use zeroize::Zeroizing;

/// One minted access token and the moment it stops being usable.
struct Cached {
    token: Zeroizing<String>,
    /// Unix seconds. Already reduced by the rule's skew, so a token in here
    /// is one that is still worth sending.
    good_until: u64,
}

/// Access tokens minted on this device, keyed by the grant revision they came
/// from. Never serialised, never logged, and gone when the process is.
static ACCESS: OnceLock<Mutex<HashMap<String, Cached>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<String, Cached>> {
    ACCESS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The cache key: which secret, and which exact bytes of it.
///
/// The revision rather than the version, because a version is a counter two
/// devices can reach independently and a revision is a commitment to the
/// bytes. A grant rotated on one device and not yet on another must not be
/// able to serve a token minted from the other's.
fn key(handle: &Handle) -> String {
    format!("{}/{}", handle.secret_id.as_str(), handle.source.revision)
}

/// Forget every token minted from this device's grants.
///
/// Called when a part is removed or rotated. Not strictly necessary — the key
/// includes the revision, so a rotated grant's tokens are already
/// unreachable — but a token nobody can reach is still a token in memory, and
/// this is where it stops being one.
pub(crate) fn forget(id: &asterism_core::secret::SecretId) {
    let prefix = format!("{}/", id.as_str());
    if let Ok(mut cache) = cache().lock() {
        cache.retain(|held, _| !held.starts_with(&prefix));
    }
}

/// An access token for this grant: the cached one if it is still good, a
/// freshly exchanged one otherwise.
///
/// The exchange is a real HTTPS call from this device to the provider's token
/// endpoint, made with the same vetting the data plane uses — a token
/// endpoint that resolved to the host's own network would be a way to make
/// this daemon hand a refresh token to something on loopback.
pub(crate) async fn access_token(
    handle: &Handle,
    grant: &OAuthGrant,
    token_url: &str,
    skew_secs: u64,
    now: u64,
) -> Result<Zeroizing<String>> {
    let key = key(handle);
    if let Ok(cache) = cache().lock() {
        if let Some(held) = cache.get(&key) {
            if held.good_until > now {
                return Ok(held.token.clone());
            }
        }
    }
    // The endpoint the *frame* named, checked against the one the grant was
    // created with. They are the same string in every honest case; a frame
    // that named a different one would be a consumer daemon redirecting a
    // refresh token somewhere the source never agreed to.
    if !grant.token_url.is_empty() && grant.token_url != token_url {
        bail!(
            "this request asks to refresh {:?} at an endpoint the grant was not created \
             against",
            grant.provider
        );
    }
    let mut pairs = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", grant.refresh_token.as_str()),
        ("client_id", grant.client_id.as_str()),
    ];
    if let Some(secret) = &grant.client_secret {
        pairs.push(("client_secret", secret.as_str()));
    }
    let body = Zeroizing::new(credential::form_encode(&pairs));
    let answer = post_form(token_url, &body)
        .await
        .with_context(|| format!("refreshing the {} grant", grant.provider))?;
    let minted = TokenGrant::parse(&answer)?;
    let token = Zeroizing::new(minted.access()?.to_owned());
    // An endpoint that does not say how long is treated as five minutes,
    // which is short enough to be safe and long enough that a burst of calls
    // is one exchange.
    let lifetime = minted.expires_in.unwrap_or(300);
    let good_until = now + lifetime.saturating_sub(skew_secs).max(1);
    if let Ok(mut cache) = cache().lock() {
        cache.insert(
            key,
            Cached {
                token: token.clone(),
                good_until,
            },
        );
    }
    Ok(token)
}

/// POST a form body to a token endpoint and answer with what came back.
///
/// Deliberately narrow: one method, one content type, a bounded answer, no
/// redirects. A redirect on a token endpoint is the shortest path from "this
/// refresh token goes to Google" to "this refresh token went to somewhere
/// Google named".
async fn post_form(url: &str, body: &str) -> Result<Vec<u8>> {
    let (host, port, _) = split_https(url)?;
    let addrs = crate::egress::vet_public(&format!("{host}:{port}"))
        .await
        .map_err(|refusal| anyhow!("{refusal}"))?;
    let client = crate::egress::client_builder()
        .resolve_to_addrs(&host, &addrs)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let response = client
        .post(url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        // GitHub answers form-encoded unless asked for JSON. Both are read
        // ([`TokenGrant::parse`]); asking is politer.
        .header(reqwest::header::ACCEPT, "application/json")
        .body(body.to_owned())
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if bytes.len() > 64 * 1024 {
        bail!("the token endpoint answered with more than a token");
    }
    // Not an error yet: RFC 6749 §5.2 puts the reason in the body, and the
    // body is what the caller reads. A status is only reported when there is
    // nothing readable to report instead.
    if !status.is_success() && bytes.is_empty() {
        bail!("the token endpoint answered {status} and nothing else");
    }
    Ok(bytes.to_vec())
}

/// `https://host[:port]/path` → `(host, port, path)`.
///
/// Written out rather than pulled in because this is the only URL this crate
/// parses, and the refusals below are the point: a token endpoint that is not
/// https, or that names a userinfo section, is not one this device will send
/// a refresh token to.
pub(crate) fn split_https(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("{url:?} is not an https url"))?;
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    if authority.contains('@') {
        bail!("{url:?} carries a userinfo section, which this device will not send");
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .with_context(|| format!("{port:?} is not a port"))?,
        ),
        None => (authority, 443),
    };
    if host.is_empty() {
        bail!("{url:?} has no host in it");
    }
    Ok((host.to_ascii_lowercase(), port, path.to_owned()))
}

// ---- planning --------------------------------------------------------------

/// Every binding one `ast attach --credential <name>` makes.
///
/// One handle across all of them, and one environment variable set, because
/// that is what the guest's tools expect: `gh` has one `GH_TOKEN` and reaches
/// five hosts with it. Minting a handle per authority would mean `GH_TOKEN`
/// could only be one of them and the other four bindings would refuse every
/// request the guest actually made.
pub(crate) fn plan(
    provider: &Provider,
    part: &Secret,
    source: &asterism_core::secret::SourceDevice,
    bound_at: u64,
    binding_id: impl Fn() -> String,
) -> Result<Vec<Binding>> {
    if provider.authorities.is_empty() {
        bail!(
            "provider {:?} declares no authority, so attaching it would bind nothing",
            provider.name
        );
    }
    let handle = provider.mint_handle();
    let env = provider
        .env
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("provider {:?} names no environment variable", provider.name))?;
    Ok(provider
        .authorities
        .iter()
        .map(|authority| Binding {
            id: binding_id(),
            secret_id: part.id.clone(),
            secret: part.name.clone(),
            authority: authority.clone(),
            placement: provider.placement.clone(),
            accept: provider.accept.clone(),
            rule: provider.rule.clone(),
            provider: Some(provider.name.clone()),
            guest_handle: handle.clone(),
            env: env.clone(),
            source_device_id: source.device_id.clone(),
            source_device: source.device.clone(),
            version: part.version,
            bound_at,
        })
        .collect())
}

/// The environment and files an instance's credential bindings put in its
/// guest, deduplicated.
///
/// A credential part is several bindings sharing one handle, so the naive
/// "one entry per binding" would export `GH_TOKEN` five times — and a
/// provider that names two variables would export neither of the other four.
/// This is where the binding list becomes the guest's environment.
pub(crate) fn guest_environment(bindings: &[Binding]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut push = |name: String, handle: &GuestHandle| {
        if !out.iter().any(|(held, _)| *held == name) {
            out.push((name, handle.as_str().to_owned()));
        }
    };
    for binding in bindings {
        match binding.provider.as_deref().and_then(credential::find) {
            // A credential part exports every name its provider declares, so
            // that `gcloud` and the Google client libraries both find it.
            Some(provider) => {
                for name in &provider.env {
                    push(name.clone(), &binding.guest_handle);
                }
            }
            // A plain secret exports the one variable it was bound with.
            None => push(binding.env.clone(), &binding.guest_handle),
        }
    }
    out
}

/// The config files an instance's credential bindings put on its guest's
/// disk, deduplicated by path.
pub(crate) fn guest_files(bindings: &[Binding]) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    for binding in bindings {
        let Some(provider) = binding.provider.as_deref().and_then(credential::find) else {
            continue;
        };
        for file in &provider.files {
            if !out.iter().any(|(path, _, _)| *path == file.path) {
                out.push((file.path.clone(), file.mode.clone(), file.content.clone()));
            }
        }
    }
    out
}

/// Whether this rule can be honoured by this build at all.
///
/// Checked at attach time rather than at request time, so a guest is never
/// handed a handle that this device would refuse to redeem.
pub(crate) fn check_can_serve(rule: &CredentialRule) -> Result<()> {
    match rule {
        CredentialRule::Substitute => Ok(()),
        CredentialRule::Refresh { token_url, .. } => split_https(token_url).map(|_| ()),
        CredentialRule::Sign { .. } => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::secret::{SecretId, SourceDevice, ValueRevision};

    fn part(name: &str, provider: &str) -> Secret {
        let mut secret = Secret::new(SecretId::from_name(name).unwrap(), name.to_owned(), 1);
        secret.kind = asterism_core::credential::PartKind::Login;
        secret.provider = Some(provider.to_owned());
        secret
    }

    fn source() -> SourceDevice {
        let lineage = ValueRevision::mint();
        SourceDevice {
            device_id: "source-key".into(),
            device: "laptop".into(),
            version: 1,
            updated_at: 1,
            origin: lineage.clone(),
            revision: lineage,
        }
    }

    #[test]
    fn one_credential_is_every_authority_under_one_handle() {
        let provider = credential::require("gh").unwrap();
        let bindings = plan(provider, &part("gh", "github"), &source(), 7, || {
            "b".to_owned()
        })
        .unwrap();
        assert_eq!(bindings.len(), provider.authorities.len());
        // One handle, or `GH_TOKEN` could only be one of five bindings and
        // the other four would refuse every request the guest made.
        let handle = bindings[0].guest_handle.as_str().to_owned();
        assert!(handle.starts_with("sk-ast-gh-"));
        for binding in &bindings {
            assert_eq!(binding.guest_handle.as_str(), handle);
            assert_eq!(binding.env, "GH_TOKEN");
            assert_eq!(binding.provider.as_deref(), Some("github"));
            assert_eq!(binding.rule, CredentialRule::Substitute);
        }
        assert!(bindings.iter().any(|b| b.authority == "api.github.com"));

        // And the guest gets every name the provider declares, once each.
        let env = guest_environment(&bindings);
        assert_eq!(
            env,
            vec![
                ("GH_TOKEN".to_owned(), handle.clone()),
                ("GITHUB_TOKEN".to_owned(), handle),
            ]
        );
    }

    #[test]
    fn a_plain_secret_and_a_credential_part_share_one_guest_environment() {
        let gh = credential::require("gh").unwrap();
        let mut bindings = plan(gh, &part("gh", "github"), &source(), 7, || "b".into()).unwrap();
        let mut plain = bindings[0].clone();
        plain.provider = None;
        plain.secret = "anthropic".into();
        plain.env = "ANTHROPIC_API_KEY".into();
        plain.guest_handle = GuestHandle::mint(asterism_core::secret::HandleShape::Anthropic);
        bindings.push(plain.clone());
        let env = guest_environment(&bindings);
        assert_eq!(env.len(), 3);
        assert_eq!(
            env[2],
            (
                "ANTHROPIC_API_KEY".to_owned(),
                plain.guest_handle.as_str().to_owned()
            )
        );
    }

    #[test]
    fn a_provider_that_needs_a_config_file_gets_one_and_it_holds_no_value() {
        let npm = credential::require("npm").unwrap();
        let bindings = plan(npm, &part("npm", "npm"), &source(), 7, || "b".into()).unwrap();
        let files = guest_files(&bindings);
        assert_eq!(files.len(), 1);
        let (path, _, content) = &files[0];
        assert_eq!(path, "/etc/npmrc");
        // The file names a variable. It does not carry the handle, let alone
        // the token — this lands on a guest's disk, which is the one place a
        // credential part promises never to be.
        assert!(content.contains("${NPM_TOKEN}"), "{content}");
        assert!(!content.contains(bindings[0].guest_handle.as_str()));
    }

    #[test]
    fn a_token_endpoint_url_is_read_and_the_ones_that_are_traps_are_refused() {
        assert_eq!(
            split_https("https://oauth2.googleapis.com/token").unwrap(),
            ("oauth2.googleapis.com".into(), 443, "/token".into())
        );
        assert_eq!(
            split_https("https://Localhost:8443/t").unwrap(),
            ("localhost".into(), 8443, "/t".into())
        );
        for bad in [
            "http://oauth2.googleapis.com/token",
            "https://user:pass@evil.test/token",
            "https:///token",
            "https://host:notaport/token",
            "oauth2.googleapis.com/token",
        ] {
            assert!(split_https(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_rule_this_build_cannot_honour_is_refused_before_a_handle_exists() {
        assert!(check_can_serve(&CredentialRule::Substitute).is_ok());
        assert!(check_can_serve(&CredentialRule::Refresh {
            token_url: "https://oauth2.googleapis.com/token".into(),
            skew_secs: 120,
        })
        .is_ok());
        assert!(check_can_serve(&CredentialRule::Refresh {
            token_url: "http://oauth2.googleapis.com/token".into(),
            skew_secs: 120,
        })
        .is_err());
    }
}
