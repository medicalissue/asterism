//! The client-side contract for Asterism's optional hosted identity plane.
//!
//! This is deliberately a seam, not an identity implementation. The authority
//! is the Cloudflare Worker at `asterism.run`; local orbit and data-plane
//! operations never call this module. Both `ast` and the desktop app use these
//! protocol types and the [`CredentialStore`] / [`BrowserOpener`] capabilities,
//! so neither surface grows provider callbacks or a second session format.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const PROTOCOL: &str = "asterism-device-authorization/1";
pub const DEFAULT_AUTHORITY: &str = "https://asterism.run";
pub const CREDENTIAL_SERVICE: &str = "run.asterism.auth";
/// The public OAuth client id the authority has registered for `ast`. RFC 8628
/// public clients are identified, not authenticated, so this is not a secret;
/// the authority refuses every other id.
pub const CLI_CLIENT_ID: &str = "asterism-cli";
/// The scopes registered against [`CLI_CLIENT_ID`]. Asking for anything
/// outside the registered set is refused with `invalid_scope`.
pub const CLI_SCOPE: &str = "openid orbit.read orbit.write";
/// RFC 8628 grant vocabulary sent while polling for the bearer.
pub const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The pre-issuer credential slot. New clients only remove this entry: a
/// bearer read from it has no trustworthy destination and must never leave
/// the machine.
pub const CREDENTIAL_ACCOUNT: &str = "default";
/// A non-secret pointer to the issuer-scoped credential that is currently
/// active. The bearer itself never occupies this global slot.
pub const ACTIVE_ISSUER_ACCOUNT: &str = "active-issuer";

/// Derive an opaque OS credential-store namespace from a canonical issuer
/// origin. Keeping the full URL out of platform account names also avoids
/// backend-specific punctuation and length rules.
pub fn credential_account(issuer: &str) -> String {
    format!("issuer-{}", blake3::hash(issuer.as_bytes()).to_hex())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Google,
    Github,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Github => "github",
        }
    }
}

impl FromStr for Provider {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "google" => Ok(Self::Google),
            "github" => Ok(Self::Github),
            _ => bail!("provider must be google or github"),
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Both device codes and verification URLs are one-time authorization
        // material. Redact the base URL as well: it is supplied by the remote
        // coordinator and may contain query parameters even when the protocol
        // normally returns those only in `verification_uri_complete`.
        f.debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_uri", &"[REDACTED]")
            .field("verification_uri_complete", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceAuthorizationRequest {
    pub provider: Provider,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deep_link_state: Option<String>,
}

impl DeviceAuthorizationRequest {
    pub fn cli(provider: Provider) -> Self {
        Self {
            provider,
            redirect_uri: None,
            deep_link_state: None,
        }
    }

    /// Desktop uses the same device transaction and bounded polling as the
    /// CLI. The deep link carries only a caller nonce and completion signal;
    /// the bearer token still arrives through the device-token endpoint.
    pub fn desktop(provider: Provider, state: &str) -> Result<Self> {
        if !(32..=128).contains(&state.len())
            || !state
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            bail!("desktop deep-link state must be 32-128 URL-safe characters");
        }
        Ok(Self {
            provider,
            redirect_uri: Some("asterism://auth/callback".into()),
            deep_link_state: Some(state.into()),
        })
    }

    /// The authority reads `application/x-www-form-urlencoded`, not JSON, and
    /// identifies the caller by `client_id`.
    ///
    /// `provider` is advisory. The deployed authority resolves the provider
    /// from the browser session that approves the user code and ignores form
    /// fields it does not know, so sending the caller's choice costs nothing
    /// and keeps `--provider` meaningful if pre-selection is ever added.
    pub fn form_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = vec![
            ("client_id", CLI_CLIENT_ID.to_owned()),
            ("scope", CLI_SCOPE.to_owned()),
            ("provider", self.provider.as_str().to_owned()),
        ];
        if let Some(uri) = &self.redirect_uri {
            pairs.push(("redirect_uri", uri.clone()));
        }
        if let Some(state) = &self.deep_link_state {
            pairs.push(("deep_link_state", state.clone()));
        }
        pairs
    }
}

/// The RFC 6749 token response the authority returns once a user code is
/// approved. It carries a bearer and its scope; there is no separate account
/// document on this endpoint.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenResponse {
    pub access_token: Secret,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(default)]
    pub scope: Option<String>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

impl TokenResponse {
    /// Bind the bearer to the origin that issued it and name the account it
    /// belongs to. `now` is only a fallback for a bearer that carries no
    /// issue time of its own.
    pub fn into_session(self, issuer: &str, now: u64) -> Result<Session> {
        if !self.token_type.eq_ignore_ascii_case("Bearer") {
            bail!("the authorization service returned a non-bearer token");
        }
        let (account, issued_at) = account_of_unverified_bearer(self.access_token.expose())?;
        Ok(Session {
            access_token: self.access_token,
            token_type: self.token_type,
            account,
            issued_at: issued_at.unwrap_or(now),
            issuer: issuer.to_owned(),
        })
    }
}

/// Claims carried by the authority's bearer. Only the fields a client is
/// allowed to act on locally are named here.
#[derive(Deserialize)]
struct BearerClaims {
    sub: String,
    provider: Provider,
    name: String,
    #[serde(default)]
    iat: Option<u64>,
}

/// Read the account a bearer was minted for out of the bearer itself.
///
/// The authority signs its bearers with a key no client holds, so this
/// signature is deliberately **not** checked: these claims are read for the
/// name `ast auth status` prints and for the local credential-store
/// namespace, and for nothing else. No privilege is granted here. Every
/// answer that matters still comes from the authority, which does verify the
/// signature before it acts. A bearer that does not parse is refused outright
/// rather than stored under a guessed identity.
fn account_of_unverified_bearer(token: &str) -> Result<(Account, Option<u64>)> {
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("the authorization service returned a token in an unknown format");
    };
    if payload.is_empty() || payload.len() > 4096 {
        bail!("the authorization service returned an unbounded token payload");
    }
    let decoded = data_encoding::BASE64URL_NOPAD
        .decode(payload.as_bytes())
        .map_err(|_| anyhow::anyhow!("the authorization service returned an undecodable token"))?;
    let claims: BearerClaims = serde_json::from_slice(&decoded)
        .map_err(|_| anyhow::anyhow!("the authorization service returned unreadable claims"))?;
    if claims.sub.is_empty()
        || claims.sub.len() > 256
        || claims.name.is_empty()
        || claims.name.len() > 256
    {
        bail!("the authorization service returned an invalid account");
    }
    Ok((
        Account {
            id: claims.sub,
            provider: claims.provider,
            display_name: claims.name,
        },
        claims.iat,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopCallback {
    pub state: String,
    pub complete: bool,
}

impl DesktopCallback {
    pub fn parse(uri: &str) -> Result<Self> {
        let query = uri
            .strip_prefix("asterism://auth/callback?")
            .ok_or_else(|| anyhow::anyhow!("not an Asterism authorization callback"))?;
        let mut state = None;
        let mut status = None;
        for pair in query.split('&') {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("malformed authorization callback"))?;
            match key {
                "state" if state.is_none() => state = Some(value),
                "status" if status.is_none() => status = Some(value),
                _ => bail!("unexpected authorization callback field"),
            }
        }
        let state = state.ok_or_else(|| anyhow::anyhow!("authorization callback has no state"))?;
        // The state alphabet deliberately needs no percent decoding. Rejecting
        // encoded lookalikes leaves one canonical URI for a nonce.
        DeviceAuthorizationRequest::desktop(Provider::Google, state)?;
        Ok(Self {
            state: state.into(),
            complete: status == Some("complete"),
        })
    }
}

/// Bearer material is serializable for the credential-store boundary, but is
/// never printable. Wiping is best-effort defense for the owned heap buffer.
#[derive(Serialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty() || value.len() > 8192 {
            bail!("the authorization service returned an invalid token");
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Secret {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Session {
    pub access_token: Secret,
    pub token_type: String,
    pub account: Account,
    pub issued_at: u64,
    /// Canonical origin of the coordinator that issued `access_token`.
    ///
    /// `default` exists solely so old keyring JSON can be recognized and
    /// cleared locally. An empty issuer is never eligible for remote use.
    #[serde(default)]
    pub issuer: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Account {
    /// Opaque, coordinator-issued identity. Provider subjects never become
    /// local orbit identity and are not persisted by clients.
    pub id: String,
    pub provider: Provider,
    pub display_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ProtocolError {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PollFailure {
    Offline,
    Protocol(ProtocolError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PollAction {
    Wait(Duration),
    Complete,
    Denied,
    Expired,
    Failed(String),
}

/// Bounded RFC-8628-shaped polling policy shared by the CLI and Desktop.
/// The caller performs I/O and sleeping; this state machine decides whether
/// another attempt is permitted. Offline retries are bounded by the same
/// server-issued expiry as successful polling.
#[derive(Clone, Debug)]
pub struct PollPolicy {
    deadline_secs: u64,
    interval_secs: u64,
    offline_failures: u32,
}

impl PollPolicy {
    pub fn new(start_secs: u64, authorization: &DeviceAuthorization) -> Result<Self> {
        if authorization.expires_in == 0 {
            bail!("the authorization service returned a zero expiry");
        }
        Ok(Self {
            deadline_secs: start_secs.saturating_add(authorization.expires_in),
            interval_secs: authorization.interval.clamp(1, 30),
            offline_failures: 0,
        })
    }

    pub fn next(&mut self, now_secs: u64, result: &Result<Session, PollFailure>) -> PollAction {
        if now_secs >= self.deadline_secs {
            return PollAction::Expired;
        }
        match result {
            Ok(_) => PollAction::Complete,
            Err(PollFailure::Offline) => {
                self.offline_failures = self.offline_failures.saturating_add(1);
                let shift = self.offline_failures.saturating_sub(1).min(5);
                PollAction::Wait(Duration::from_secs(
                    self.interval_secs.saturating_mul(1_u64 << shift).min(30),
                ))
            }
            Err(PollFailure::Protocol(error)) => match error.error.as_str() {
                "authorization_pending" => {
                    self.offline_failures = 0;
                    PollAction::Wait(Duration::from_secs(self.interval_secs))
                }
                "slow_down" => {
                    self.offline_failures = 0;
                    self.interval_secs = error
                        .interval
                        .unwrap_or_else(|| self.interval_secs.saturating_add(5))
                        .clamp(self.interval_secs, 30);
                    PollAction::Wait(Duration::from_secs(self.interval_secs))
                }
                "temporarily_unavailable" | "server_error" => {
                    self.offline_failures = self.offline_failures.saturating_add(1);
                    let shift = self.offline_failures.saturating_sub(1).min(5);
                    PollAction::Wait(Duration::from_secs(
                        self.interval_secs.saturating_mul(1_u64 << shift).min(30),
                    ))
                }
                "access_denied" => PollAction::Denied,
                "expired_token" => PollAction::Expired,
                other => PollAction::Failed(other.to_owned()),
            },
        }
    }
}

/// OS credential stores implement this capability (Keychain, Secret Service,
/// or Credential Manager). Implementations must not fall back to plaintext.
pub trait CredentialStore {
    fn save(&self, session: &Session) -> Result<()>;
    fn load(&self) -> Result<Option<Session>>;
    fn delete(&self) -> Result<()>;
}

/// System-browser opening is a best-effort convenience. A failed opener is
/// never an authentication failure: callers must still show URL and code.
pub trait BrowserOpener {
    fn open(&self, url: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization() -> DeviceAuthorization {
        DeviceAuthorization {
            device_code: "device-secret".into(),
            user_code: "ABCD-EFGH".into(),
            verification_uri: "https://asterism.run/device".into(),
            verification_uri_complete: "https://asterism.run/device?user_code=ABCD-EFGH".into(),
            expires_in: 60,
            interval: 2,
        }
    }

    fn protocol(error: &str) -> Result<Session, PollFailure> {
        Err(PollFailure::Protocol(ProtocolError {
            error: error.into(),
            error_description: None,
            interval: None,
        }))
    }

    #[test]
    fn bearer_material_is_redacted_recursively() {
        let session = Session {
            access_token: Secret::new("super-secret".into()).unwrap(),
            token_type: "Bearer".into(),
            account: Account {
                id: "acct".into(),
                provider: Provider::Github,
                display_name: "Octo".into(),
            },
            issued_at: 1,
            issuer: DEFAULT_AUTHORITY.into(),
        };
        let debug = format!("{session:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
        assert!(serde_json::from_str::<Secret>(r#"""#).is_err());
        assert!(serde_json::from_str::<Secret>(&format!(r#""{}""#, "x".repeat(8193))).is_err());
    }

    /// A bearer minted by the authority for `asterism-cli`. The signature is
    /// deliberately not a real one: nothing in this crate verifies it.
    const BEARER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhc3Rlcmlzb\
S1jbGkiLCJzdWIiOiJ1c2VyLTQyIiwicHJvdmlkZXIiOiJnaXRodWIiLCJuYW1lIjoiT2N0byBDYXQiLCJpYXQiOjE3M\
DAwMDAwMDAsImV4cCI6MTcwMDA0MzIwMCwic2NvcGUiOiJvcGVuaWQifQ.c2lnbmF0dXJl";

    fn token(access_token: &str) -> TokenResponse {
        TokenResponse {
            access_token: Secret::new(access_token.into()).unwrap(),
            token_type: "Bearer".into(),
            expires_in: 43_200,
            scope: Some("openid".into()),
        }
    }

    #[test]
    fn a_token_response_names_its_account_and_binds_to_the_issuing_origin() {
        let session = token(BEARER)
            .into_session(DEFAULT_AUTHORITY, 1_800_000_000)
            .unwrap();
        assert_eq!(session.account.id, "user-42");
        assert_eq!(session.account.provider, Provider::Github);
        assert_eq!(session.account.display_name, "Octo Cat");
        // The bearer carries its own issue time; the clock is only a fallback.
        assert_eq!(session.issued_at, 1_700_000_000);
        assert_eq!(session.issuer, DEFAULT_AUTHORITY);
        assert!(!format!("{session:?}").contains(BEARER));
        assert!(!format!("{:?}", token(BEARER)).contains(BEARER));
    }

    #[test]
    fn a_bearer_that_does_not_name_an_account_is_refused_rather_than_guessed() {
        for rejected in [
            "not-a-token",
            "one.two",
            "a.b.c.d",
            // A payload that decodes but claims nothing usable.
            "eyJhIjoxfQ.eyJhIjoxfQ.sig",
            // A payload that is not base64url at all.
            "eyJhIjoxfQ.!!!!.sig",
        ] {
            assert!(
                token(rejected).into_session(DEFAULT_AUTHORITY, 1).is_err(),
                "{rejected} must not become a stored session"
            );
        }
        let mut wrong_type = token(BEARER);
        wrong_type.token_type = "mac".into();
        assert!(wrong_type.into_session(DEFAULT_AUTHORITY, 1).is_err());
    }

    #[test]
    fn the_device_code_request_is_form_encoded_and_names_the_registered_client() {
        assert_eq!(
            DeviceAuthorizationRequest::cli(Provider::Github).form_pairs(),
            vec![
                ("client_id", CLI_CLIENT_ID.to_owned()),
                ("scope", CLI_SCOPE.to_owned()),
                ("provider", "github".to_owned()),
            ]
        );
        let desktop =
            DeviceAuthorizationRequest::desktop(Provider::Google, &"a".repeat(32)).unwrap();
        let pairs = desktop.form_pairs();
        assert_eq!(
            pairs.iter().find(|(key, _)| *key == "redirect_uri"),
            Some(&("redirect_uri", "asterism://auth/callback".to_owned()))
        );
    }

    #[test]
    fn credential_namespaces_are_bound_to_the_exact_canonical_issuer() {
        let production = credential_account("https://asterism.run");
        assert_eq!(production, credential_account("https://asterism.run"));
        assert_ne!(production, credential_account("https://asterism.run:443"));
        assert_ne!(production, credential_account("https://other.example"));
        assert!(!production.contains("asterism.run"));
    }

    #[test]
    fn device_authorization_material_is_redacted_recursively() {
        let authorization = DeviceAuthorization {
            device_code: "device-grant-secret-7fba".into(),
            user_code: "USER-CODE-9C21".into(),
            verification_uri: "https://asterism.run/device?query-secret=base-uri-marker".into(),
            verification_uri_complete:
                "https://asterism.run/device?user_code=USER-CODE-9C21&complete-secret=marker".into(),
            expires_in: 60,
            interval: 2,
        };

        let debug = format!("{authorization:?}");
        assert_eq!(debug.matches("[REDACTED]").count(), 4);
        for sensitive in [
            authorization.device_code.as_str(),
            authorization.user_code.as_str(),
            authorization.verification_uri.as_str(),
            authorization.verification_uri_complete.as_str(),
            "device-grant-secret-7fba",
            "USER-CODE-9C21",
            "query-secret=base-uri-marker",
            "user_code=",
            "complete-secret=marker",
        ] {
            assert!(
                !debug.contains(sensitive),
                "DeviceAuthorization Debug leaked {sensitive:?}: {debug}"
            );
        }
        assert!(debug.contains("expires_in: 60"));
        assert!(debug.contains("interval: 2"));
    }

    #[test]
    fn pending_rate_limit_offline_denial_and_expiry_are_bounded() {
        let mut policy = PollPolicy::new(100, &authorization()).unwrap();
        assert_eq!(
            policy.next(100, &protocol("authorization_pending")),
            PollAction::Wait(Duration::from_secs(2))
        );
        assert_eq!(
            policy.next(102, &protocol("slow_down")),
            PollAction::Wait(Duration::from_secs(7))
        );
        assert_eq!(
            policy.next(109, &Err(PollFailure::Offline)),
            PollAction::Wait(Duration::from_secs(7))
        );
        assert_eq!(
            policy.next(116, &Err(PollFailure::Offline)),
            PollAction::Wait(Duration::from_secs(14))
        );
        assert_eq!(
            policy.next(130, &protocol("access_denied")),
            PollAction::Denied
        );
        assert_eq!(
            policy.next(160, &Err(PollFailure::Offline)),
            PollAction::Expired
        );
    }

    #[test]
    fn protocol_version_and_provider_vocabulary_are_stable() {
        assert_eq!(PROTOCOL, "asterism-device-authorization/1");
        assert_eq!(Provider::from_str("google").unwrap(), Provider::Google);
        assert_eq!(Provider::from_str("github").unwrap(), Provider::Github);
        assert!(Provider::from_str("email").is_err());
    }

    #[test]
    fn transient_server_failures_use_the_same_bounded_recovery_as_offline() {
        let mut policy = PollPolicy::new(100, &authorization()).unwrap();
        assert_eq!(
            policy.next(100, &protocol("temporarily_unavailable")),
            PollAction::Wait(Duration::from_secs(2))
        );
        assert_eq!(
            policy.next(102, &protocol("server_error")),
            PollAction::Wait(Duration::from_secs(4))
        );
    }

    #[test]
    fn desktop_deep_link_is_a_wakeup_seam_not_a_token_channel() {
        let nonce = "abcdefghijklmnopqrstuvwxyz_12345-";
        let request = DeviceAuthorizationRequest::desktop(Provider::Github, nonce).unwrap();
        assert_eq!(
            request.redirect_uri.as_deref(),
            Some("asterism://auth/callback")
        );
        let callback = DesktopCallback::parse(&format!(
            "asterism://auth/callback?state={nonce}&status=complete"
        ))
        .unwrap();
        assert!(callback.complete);
        assert_eq!(callback.state, nonce);
        assert!(DesktopCallback::parse("asterism://auth/callback?access_token=secret").is_err());
    }
}
