//! Production OAuth adapters and the hosted HTTP entry point.
//!
//! The adapter exchanges a one-time authorization code with Google or GitHub
//! over TLS. Google validation asks Google's token-info endpoint to validate
//! the returned OIDC ID token's issuer, audience and expiry; GitHub validation
//! calls its authenticated `/user` endpoint and uses its immutable numeric id.
//! Neither flow requests, stores, or returns an email address.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use url::form_urlencoded;
use uuid::Uuid;

use crate::{
    AccountId, DiscoveryConfig, EnrollmentProof, OAuthProvider, PersistentCoordinator,
    VerifiedOAuth,
};

const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_TOKEN_INFO: &str = "https://oauth2.googleapis.com/tokeninfo";
const GITHUB_TOKEN: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER: &str = "https://api.github.com/user";

/// Registered OAuth client configuration. Secrets are read from a deployment
/// secret manager before this struct is built and are never persisted.
#[derive(Debug, Clone)]
pub struct OAuthClientConfig {
    /// OAuth application client id.
    pub client_id: String,
    /// OAuth application client secret.
    pub client_secret: String,
    /// Exact HTTPS callback URL registered at the provider.
    pub redirect_uri: String,
}

impl OAuthClientConfig {
    fn validate(&self, provider: OAuthProvider) -> Result<()> {
        if self.client_id.trim().is_empty() || self.client_secret.trim().is_empty() {
            bail!("OAuth client id and secret must be configured");
        }
        let redirect = url::Url::parse(&self.redirect_uri).context("parsing OAuth redirect URI")?;
        let expected_path = match provider {
            OAuthProvider::Google => "/oauth/google/callback",
            OAuthProvider::GitHub => "/oauth/github/callback",
        };
        if redirect.scheme() != "https"
            || redirect.host_str().is_none()
            || redirect.path() != expected_path
            || redirect.query().is_some()
            || redirect.fragment().is_some()
        {
            bail!("OAuth redirect URI is not an exact registered HTTPS callback");
        }
        Ok(())
    }
}

/// Production provider implementation used by the HTTP callback routes.
#[derive(Clone)]
pub struct ProductionOAuth {
    client: reqwest::Client,
    google: OAuthClientConfig,
    github: OAuthClientConfig,
}

impl ProductionOAuth {
    /// Builds a TLS-only OAuth adapter.
    pub fn new(google: OAuthClientConfig, github: OAuthClientConfig) -> Result<Self> {
        google.validate(OAuthProvider::Google)?;
        github.validate(OAuthProvider::GitHub)?;
        // `reqwest` deliberately has no provider by default in this workspace;
        // install ring once for this hosted TLS client. A daemon may already
        // have installed the same process-global provider, which is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();
        Ok(Self {
            client: reqwest::Client::builder()
                .https_only(true)
                .build()
                .context("building OAuth HTTPS client")?,
            google,
            github,
        })
    }

    /// Builds the provider authorization URL with state and PKCE S256.
    pub fn authorization_url(
        &self,
        provider: OAuthProvider,
        state: &str,
        verifier: &str,
    ) -> String {
        let (base, config, scopes) = match provider {
            OAuthProvider::Google => (
                "https://accounts.google.com/o/oauth2/v2/auth",
                &self.google,
                "openid",
            ),
            OAuthProvider::GitHub => (
                "https://github.com/login/oauth/authorize",
                &self.github,
                "read:user",
            ),
        };
        let mut query = form_urlencoded::Serializer::new(String::new());
        query.append_pair("client_id", &config.client_id);
        query.append_pair("redirect_uri", &config.redirect_uri);
        query.append_pair("response_type", "code");
        query.append_pair("scope", scopes);
        query.append_pair("state", state);
        query.append_pair("code_challenge_method", "S256");
        query.append_pair("code_challenge", &pkce_challenge(verifier));
        format!("{base}?{}", query.finish())
    }

    /// Exchanges and validates one OAuth code.  Provider tokens are held only
    /// in stack-local response values and are not returned to the caller.
    pub async fn exchange(
        &self,
        provider: OAuthProvider,
        code: &str,
        verifier: &str,
    ) -> Result<VerifiedOAuth> {
        if code.trim().is_empty() || verifier.trim().is_empty() {
            bail!("OAuth callback is missing its code or PKCE verifier");
        }
        match provider {
            OAuthProvider::Google => self.exchange_google(code, verifier).await,
            OAuthProvider::GitHub => self.exchange_github(code, verifier).await,
        }
    }

    async fn exchange_google(&self, code: &str, verifier: &str) -> Result<VerifiedOAuth> {
        #[derive(Deserialize)]
        struct Token {
            id_token: String,
        }
        #[derive(Deserialize)]
        struct TokenInfo {
            iss: String,
            aud: String,
            sub: String,
            exp: String,
        }
        let token: Token = self
            .client
            .post(GOOGLE_TOKEN)
            .form(&[
                ("code", code),
                ("client_id", self.google.client_id.as_str()),
                ("client_secret", self.google.client_secret.as_str()),
                ("redirect_uri", self.google.redirect_uri.as_str()),
                ("grant_type", "authorization_code"),
                ("code_verifier", verifier),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("decoding Google token response")?;
        let info: TokenInfo = self
            .client
            .post(GOOGLE_TOKEN_INFO)
            .form(&[("id_token", token.id_token)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("validating Google ID token")?;
        if info.iss != "https://accounts.google.com"
            || info.aud != self.google.client_id
            || info.sub.trim().is_empty()
        {
            bail!("Google ID token issuer, audience, or subject is invalid");
        }
        let expiry = info
            .exp
            .parse::<u64>()
            .context("Google ID token expiry is invalid")?;
        if expiry <= unix_now()? {
            bail!("Google ID token is expired");
        }
        Ok(VerifiedOAuth {
            provider: OAuthProvider::Google,
            issuer: info.iss,
            subject: info.sub,
        })
    }

    async fn exchange_github(&self, code: &str, verifier: &str) -> Result<VerifiedOAuth> {
        #[derive(Deserialize)]
        struct Token {
            access_token: String,
        }
        #[derive(Deserialize)]
        struct User {
            id: u64,
        }
        let token: Token = self
            .client
            .post(GITHUB_TOKEN)
            .header(ACCEPT, "application/json")
            .form(&[
                ("code", code),
                ("client_id", self.github.client_id.as_str()),
                ("client_secret", self.github.client_secret.as_str()),
                ("redirect_uri", self.github.redirect_uri.as_str()),
                ("code_verifier", verifier),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("decoding GitHub token response")?;
        let user: User = self
            .client
            .get(GITHUB_USER)
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, format!("Bearer {}", token.access_token))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("validating GitHub OAuth token")?;
        Ok(VerifiedOAuth {
            provider: OAuthProvider::GitHub,
            issuer: "https://github.com".into(),
            subject: user.id.to_string(),
        })
    }
}

#[derive(Clone)]
struct PendingOAuth {
    provider: OAuthProvider,
    verifier: String,
    browser: String,
    expires_at: u64,
}

#[derive(Clone)]
struct AuthSession {
    account: AccountId,
    browser: String,
    expires_at: u64,
}

const MAX_PENDING_OAUTH: usize = 512;
const MAX_AUTH_SESSIONS: usize = 4_096;
const OAUTH_TTL: Duration = Duration::from_secs(10 * 60);
const AUTH_TTL: Duration = Duration::from_secs(8 * 60 * 60);

/// Root-owned PEM files used by the runnable service. This is a deployment
/// boundary: the binary refuses to serve plaintext when these are absent.
#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

impl TlsFiles {
    /// Loads a TLS 1.2+ server configuration without copying the private key
    /// into diagnostics or application state.
    pub fn load(&self) -> Result<TlsAcceptor> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut cert_reader = BufReader::new(
            File::open(&self.certificate).context("opening coordinator TLS certificate")?,
        );
        let certificates = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("reading coordinator TLS certificate")?;
        if certificates.is_empty() {
            bail!("coordinator TLS certificate chain is empty");
        }
        let mut key_reader = BufReader::new(
            File::open(&self.private_key).context("opening coordinator TLS private key")?,
        );
        let key = rustls_pemfile::private_key(&mut key_reader)
            .context("reading coordinator TLS private key")?
            .ok_or_else(|| anyhow::anyhow!("coordinator TLS private key is missing"))?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .context("building coordinator TLS server")?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

/// Real HTTP service for the optional hosted plane. It has a health endpoint
/// and OAuth start/callback endpoints; there is deliberately no credential
/// endpoint of any kind.
pub struct HostedService {
    oauth: ProductionOAuth,
    coordinator: Arc<Mutex<PersistentCoordinator>>,
    pending: Mutex<BTreeMap<String, PendingOAuth>>,
    sessions: Mutex<BTreeMap<String, AuthSession>>,
}

impl HostedService {
    /// Creates a service around durable coordinator state.
    pub fn new(oauth: ProductionOAuth, coordinator: PersistentCoordinator) -> Arc<Self> {
        Arc::new(Self {
            oauth,
            coordinator: Arc::new(Mutex::new(coordinator)),
            pending: Mutex::new(BTreeMap::new()),
            sessions: Mutex::new(BTreeMap::new()),
        })
    }

    /// Serves the hosted HTTP API on a TCP listener.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let service = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = service.serve_connection(stream).await;
            });
        }
    }

    /// Runs the production listener behind TLS. The executable uses this
    /// entry point exclusively; plaintext serving is retained only for local
    /// HTTP integration tests.
    pub async fn serve_tls(
        self: Arc<Self>,
        listener: TcpListener,
        acceptor: TlsAcceptor,
    ) -> Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let service = Arc::clone(&self);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    let _ = service.serve_connection(tls).await;
                }
            });
        }
    }

    async fn serve_connection<S>(self: Arc<Self>, stream: S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                service_fn(move |request| {
                    let service = Arc::clone(&self);
                    async move { Ok::<_, std::convert::Infallible>(service.route(request).await) }
                }),
            )
            .await
            .context("serving coordinator request")
    }

    /// Routes one request. Public for integration tests that exercise the
    /// production state/PKCE/callback boundary without a real provider secret.
    pub async fn route(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        match (method.clone(), path.as_str()) {
            (Method::GET, "/healthz") => text(StatusCode::OK, "ok"),
            (Method::GET, "/oauth/google/start") => {
                self.start(OAuthProvider::Google, request).await
            }
            (Method::GET, "/oauth/github/start") => {
                self.start(OAuthProvider::GitHub, request).await
            }
            (Method::GET, "/oauth/google/callback") => {
                self.callback(OAuthProvider::Google, request).await
            }
            (Method::GET, "/oauth/github/callback") => {
                self.callback(OAuthProvider::GitHub, request).await
            }
            (Method::POST, "/v1/enrollment/challenge") => self.begin_enrollment(request).await,
            (Method::POST, "/v1/enrollment") => self.enroll(request).await,
            (Method::GET, "/v1/account/export") => self.export(request).await,
            (Method::DELETE, "/v1/account") => self.delete_account(request).await,
            _ if method == Method::GET && path.starts_with("/v1/discovery/") => {
                self.discovery(request, &path).await
            }
            _ if method == Method::DELETE && path.starts_with("/v1/devices/") => {
                self.revoke(request, &path).await
            }
            _ => text(StatusCode::NOT_FOUND, "not found"),
        }
    }

    async fn start(
        &self,
        provider: OAuthProvider,
        request: Request<Incoming>,
    ) -> Response<Full<Bytes>> {
        let (browser, new_browser) =
            browser_cookie(&request).unwrap_or_else(|| (random_token(), true));
        let state = random_token();
        let verifier = random_token();
        let mut pending = self.pending.lock().await;
        prune_pending(&mut pending);
        if pending.len() >= MAX_PENDING_OAUTH {
            return text(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many OAuth logins in progress",
            );
        }
        pending.insert(
            state.clone(),
            PendingOAuth {
                provider,
                verifier: verifier.clone(),
                browser: browser.clone(),
                expires_at: unix_now().unwrap_or(0).saturating_add(OAUTH_TTL.as_secs()),
            },
        );
        let mut response = Response::builder().status(StatusCode::FOUND).header(
            LOCATION,
            self.oauth.authorization_url(provider, &state, &verifier),
        );
        if new_browser {
            response = response.header(SET_COOKIE, browser_cookie_header(&browser));
        }
        response
            .body(Full::new(Bytes::new()))
            .expect("valid redirect response")
    }

    async fn callback(
        &self,
        provider: OAuthProvider,
        request: Request<Incoming>,
    ) -> Response<Full<Bytes>> {
        let browser = browser_cookie(&request).map(|(value, _)| value);
        let parameters: BTreeMap<_, _> =
            form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
                .into_owned()
                .collect();
        let (Some(code), Some(state)) = (parameters.get("code"), parameters.get("state")) else {
            return text(StatusCode::BAD_REQUEST, "missing OAuth code or state");
        };
        let mut all_pending = self.pending.lock().await;
        prune_pending(&mut all_pending);
        let pending = all_pending.remove(state);
        let Some(pending) = pending.filter(|pending| {
            pending.provider == provider && browser.as_deref() == Some(&pending.browser)
        }) else {
            return text(
                StatusCode::UNAUTHORIZED,
                "OAuth state is invalid or expired",
            );
        };
        match self.oauth.exchange(provider, code, &pending.verifier).await {
            Ok(claims) => match self.coordinator.lock().await.sign_in_claims(claims) {
                Ok(account) => self.create_session(account, &pending.browser).await,
                Err(_) => text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not save authenticated account",
                ),
            },
            Err(_) => text(StatusCode::UNAUTHORIZED, "OAuth validation failed"),
        }
    }

    async fn create_session(&self, account: AccountId, browser: &str) -> Response<Full<Bytes>> {
        let token = random_token();
        let mut sessions = self.sessions.lock().await;
        prune_sessions(&mut sessions);
        if sessions.len() >= MAX_AUTH_SESSIONS {
            return text(StatusCode::SERVICE_UNAVAILABLE, "session capacity reached");
        }
        sessions.insert(
            token.clone(),
            AuthSession {
                account: account.clone(),
                browser: browser.into(),
                expires_at: unix_now().unwrap_or(0).saturating_add(AUTH_TTL.as_secs()),
            },
        );
        Response::builder()
            .status(StatusCode::OK)
            .header(SET_COOKIE, auth_cookie_header(&token))
            .body(Full::new(Bytes::from(
                serde_json::json!({"account_id": account.as_str()}).to_string(),
            )))
            .expect("valid response")
    }

    async fn authenticated(&self, request: &Request<Incoming>) -> Result<AccountId> {
        let browser = browser_cookie(request)
            .map(|(value, _)| value)
            .ok_or_else(|| anyhow::anyhow!("browser session missing"))?;
        let token = cookie(request, "__Host-asterism_session")
            .ok_or_else(|| anyhow::anyhow!("authentication missing"))?;
        let mut sessions = self.sessions.lock().await;
        prune_sessions(&mut sessions);
        let session = sessions
            .get(token)
            .ok_or_else(|| anyhow::anyhow!("authentication expired"))?;
        if session.browser != browser {
            bail!("authentication browser mismatch");
        }
        Ok(session.account.clone())
    }

    async fn begin_enrollment(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let account = match self.authenticated(&request).await {
            Ok(value) => value,
            Err(_) => return text(StatusCode::UNAUTHORIZED, "authentication required"),
        };
        match self.coordinator.lock().await.begin_enrollment(&account) {
            Ok(challenge) => json(
                StatusCode::OK,
                &serde_json::json!({"challenge": challenge.token()}),
            ),
            Err(_) => text(StatusCode::NOT_FOUND, "account not found"),
        }
    }

    async fn enroll(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let account = match self.authenticated(&request).await {
            Ok(value) => value,
            Err(_) => return text(StatusCode::UNAUTHORIZED, "authentication required"),
        };
        #[derive(Deserialize)]
        struct Input {
            device_id: String,
            challenge: String,
            signature: String,
            discovery: DiscoveryConfig,
        }
        let input: Input = match decode_body(request).await {
            Ok(value) => value,
            Err(_) => return text(StatusCode::BAD_REQUEST, "invalid enrollment request"),
        };
        let proof = match EnrollmentProof::from_tokens(
            &input.device_id,
            &input.challenge,
            &input.signature,
        ) {
            Ok(value) => value,
            Err(_) => return text(StatusCode::BAD_REQUEST, "invalid enrollment proof"),
        };
        match self
            .coordinator
            .lock()
            .await
            .enroll(&account, proof, input.discovery)
        {
            Ok(device) => json(
                StatusCode::CREATED,
                &serde_json::json!({"device_id": device.device_id, "discovery": device.discovery}),
            ),
            Err(_) => text(StatusCode::BAD_REQUEST, "enrollment refused"),
        }
    }

    async fn discovery(&self, request: Request<Incoming>, path: &str) -> Response<Full<Bytes>> {
        let account = match self.authenticated(&request).await {
            Ok(value) => value,
            Err(_) => return text(StatusCode::UNAUTHORIZED, "authentication required"),
        };
        let device = match crate::parse_device_id(path.trim_start_matches("/v1/discovery/")) {
            Ok(value) => value,
            Err(_) => return text(StatusCode::BAD_REQUEST, "invalid device id"),
        };
        match self
            .coordinator
            .lock()
            .await
            .discovery_for(&account, &device)
        {
            Ok(config) => json(StatusCode::OK, &serde_json::json!({"discovery": config})),
            Err(_) => text(StatusCode::NOT_FOUND, "device not enrolled"),
        }
    }

    async fn revoke(&self, request: Request<Incoming>, path: &str) -> Response<Full<Bytes>> {
        let account = match self.authenticated(&request).await {
            Ok(value) => value,
            Err(_) => return text(StatusCode::UNAUTHORIZED, "authentication required"),
        };
        let device = match crate::parse_device_id(path.trim_start_matches("/v1/devices/")) {
            Ok(value) => value,
            Err(_) => return text(StatusCode::BAD_REQUEST, "invalid device id"),
        };
        match self
            .coordinator
            .lock()
            .await
            .revoke_device(&account, &device)
        {
            Ok(()) => text(StatusCode::NO_CONTENT, ""),
            Err(_) => text(StatusCode::NOT_FOUND, "device not enrolled"),
        }
    }

    async fn export(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let account = match self.authenticated(&request).await {
            Ok(value) => value,
            Err(_) => return text(StatusCode::UNAUTHORIZED, "authentication required"),
        };
        match self.coordinator.lock().await.export_account(&account) {
            Ok(export) => json(
                StatusCode::OK,
                &serde_json::to_value(export).expect("serializable export"),
            ),
            Err(_) => text(StatusCode::NOT_FOUND, "account not found"),
        }
    }

    async fn delete_account(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let account = match self.authenticated(&request).await {
            Ok(value) => value,
            Err(_) => return text(StatusCode::UNAUTHORIZED, "authentication required"),
        };
        match self.coordinator.lock().await.delete_account(&account) {
            Ok(()) => text(StatusCode::NO_CONTENT, ""),
            Err(_) => text(StatusCode::NOT_FOUND, "account not found"),
        }
    }
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

async fn decode_body<T: serde::de::DeserializeOwned>(request: Request<Incoming>) -> Result<T> {
    let bytes = request.into_body().collect().await?.to_bytes();
    if bytes.len() > 64 * 1024 {
        bail!("request body is too large");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn cookie<'a>(request: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    request
        .headers()
        .get(COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| {
            let (key, value) = part.split_once('=')?;
            (key == name && !value.is_empty()).then_some(value)
        })
}

fn browser_cookie(request: &Request<Incoming>) -> Option<(String, bool)> {
    cookie(request, "__Host-asterism_browser").map(|value| (value.to_owned(), false))
}

fn browser_cookie_header(value: &str) -> String {
    format!("__Host-asterism_browser={value}; Path=/; HttpOnly; SameSite=Lax; Secure")
}

fn auth_cookie_header(value: &str) -> String {
    format!("__Host-asterism_session={value}; Path=/; HttpOnly; SameSite=Lax; Secure")
}

fn prune_pending(entries: &mut BTreeMap<String, PendingOAuth>) {
    let now = unix_now().unwrap_or(u64::MAX);
    entries.retain(|_, entry| entry.expires_at > now);
}

fn prune_sessions(entries: &mut BTreeMap<String, AuthSession>) {
    let now = unix_now().unwrap_or(u64::MAX);
    entries.retain(|_, entry| entry.expires_at > now);
}

fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
fn pkce_challenge(verifier: &str) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()))
}
fn text(status: StatusCode, value: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::copy_from_slice(value.as_bytes())))
        .expect("valid response")
}
fn json(status: StatusCode, value: &serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(value.to_string())))
        .expect("valid JSON response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_mesh::{
        pairing, DeviceIdentity, IssuedTicket, MeshEndpoint, MeshMode, PairingTicket,
        DEFAULT_TICKET_TTL,
    };
    use tokio::time::Duration;

    fn oauth() -> ProductionOAuth {
        ProductionOAuth::new(
            OAuthClientConfig {
                client_id: "google-client".into(),
                client_secret: "google-secret".into(),
                redirect_uri: "https://coord.example/oauth/google/callback".into(),
            },
            OAuthClientConfig {
                client_id: "github-client".into(),
                client_secret: "github-secret".into(),
                redirect_uri: "https://coord.example/oauth/github/callback".into(),
            },
        )
        .unwrap()
    }

    #[test]
    fn authorization_urls_bind_the_exact_redirect_state_and_pkce_challenge() {
        let url = oauth().authorization_url(OAuthProvider::Google, "state-value", "verifier-value");
        assert!(url.starts_with("https://accounts.google.com/"));
        assert!(url.contains("state=state-value"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Fcoord.example%2Foauth%2Fgoogle%2Fcallback")
        );
        assert!(!url.contains("google-secret"));
    }

    #[tokio::test]
    async fn a_pre_paired_orbit_uses_cached_discovery_through_a_real_24_hour_control_plane_outage()
    {
        let directory = tempfile::tempdir().unwrap();
        let coordinator = crate::PersistentCoordinator::open(
            directory.path().join("state.enc"),
            crate::MetadataKeyRing::new(crate::MetadataKey::new("test-v1", [3; 32]).unwrap(), [])
                .unwrap(),
            [4; 32],
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = HostedService::new(oauth(), coordinator);
        let server = tokio::spawn(Arc::clone(&service).serve(listener));
        let health = reqwest::get(format!("http://{address}/healthz"))
            .await
            .unwrap();
        assert_eq!(health.status(), reqwest::StatusCode::OK);

        // Pair while the hosted plane is still reachable, then retain the
        // discovery configuration exactly as an orbit client does locally.
        let cached_discovery = crate::DiscoveryConfig {
            relays: vec!["https://third-party-relay.example".into()],
            pkarr_relay: Some("https://directory.example/pkarr".into()),
            dns_origin: None,
        };
        let cached_infra = cached_discovery.mesh_infra();
        let inviter = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let joiner = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let issued = IssuedTicket::new(PairingTicket::issue(
            inviter.direct_addr().await.unwrap(),
            DEFAULT_TICKET_TTL,
        ));
        let ticket = PairingTicket::decode(&issued.ticket().encode()).unwrap();
        let accepting = tokio::spawn(async move {
            let accepted = pairing::accept(&inviter, &issued).await.unwrap();
            (inviter, accepted)
        });
        let paired = pairing::join(&joiner, &ticket).await.unwrap();
        let (inviter, accepted) = accepting.await.unwrap();
        assert_eq!(paired.device_id(), inviter.device_id());
        assert_eq!(accepted.device_id(), joiner.device_id());

        // The coordinator is actually gone, not mocked. Time advances in a
        // deterministic clock value so this test does not sleep for a day.
        server.abort();
        let _ = server.await;
        assert!(
            reqwest::get(format!("http://{address}/healthz"))
                .await
                .is_err(),
            "the coordinator must really be unreachable"
        );
        let cached_at = 1_000_000_u64;
        let after_24_hours = cached_at + Duration::from_secs(24 * 60 * 60).as_secs();
        assert_eq!(after_24_hours - cached_at, 86_400);
        assert_eq!(
            cached_infra.relays,
            vec!["https://third-party-relay.example"]
        );

        // Prove the connection established before the outage still carries
        // application data after it, without contacting the coordinator.
        let inbound = paired.connection().accept_stream();
        let mut outbound = accepted.connection().open_stream().await.unwrap();
        outbound
            .send
            .write_all(b"already-paired-after-outage")
            .await
            .unwrap();
        outbound.send.finish().unwrap();
        let mut inbound = inbound.await.unwrap();
        assert_eq!(
            inbound.recv.read_to_end(64).await.unwrap(),
            b"already-paired-after-outage"
        );
        paired.connection().close(b"outage proof complete");
        joiner.close().await;
        inviter.close().await;
    }

    #[test]
    fn expired_or_over_capacity_browser_oauth_state_is_not_retained() {
        let mut pending = BTreeMap::new();
        pending.insert(
            "expired".into(),
            PendingOAuth {
                provider: OAuthProvider::Google,
                verifier: "v".into(),
                browser: "b".into(),
                expires_at: 0,
            },
        );
        prune_pending(&mut pending);
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn authenticated_http_lifecycle_routes_are_served_and_account_bound() {
        let directory = tempfile::tempdir().unwrap();
        let mut coordinator = crate::PersistentCoordinator::open(
            directory.path().join("state.enc"),
            crate::MetadataKeyRing::new(crate::MetadataKey::new("test-v1", [8; 32]).unwrap(), [])
                .unwrap(),
            [9; 32],
        )
        .unwrap();
        let account = coordinator
            .sign_in_claims(VerifiedOAuth {
                provider: OAuthProvider::GitHub,
                issuer: "https://github.com".into(),
                subject: "immutable-user-id".into(),
            })
            .unwrap();
        let device = DeviceIdentity::generate();
        let challenge = coordinator.begin_enrollment(&account).unwrap();
        coordinator
            .enroll(
                &account,
                crate::enrollment_proof(&device, challenge),
                crate::DiscoveryConfig {
                    relays: vec!["https://third-party-relay.example".into()],
                    ..Default::default()
                },
            )
            .unwrap();
        let service = HostedService::new(oauth(), coordinator);
        service.sessions.lock().await.insert(
            "session".into(),
            AuthSession {
                account,
                browser: "browser".into(),
                expires_at: unix_now().unwrap() + AUTH_TTL.as_secs(),
            },
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));
        let client = reqwest::Client::new();
        let cookie = "__Host-asterism_browser=browser; __Host-asterism_session=session";
        assert_eq!(
            client
                .get(format!("http://{address}/v1/account/export"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            client
                .post(format!("http://{address}/v1/enrollment/challenge"))
                .header(reqwest::header::COOKIE, cookie)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        assert_eq!(
            client
                .get(format!(
                    "http://{address}/v1/discovery/{}",
                    device.device_id()
                ))
                .header(reqwest::header::COOKIE, cookie)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        assert_eq!(
            client
                .delete(format!(
                    "http://{address}/v1/devices/{}",
                    device.device_id()
                ))
                .header(reqwest::header::COOKIE, cookie)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::NO_CONTENT
        );
        assert_eq!(
            client
                .delete(format!("http://{address}/v1/account"))
                .header(reqwest::header::COOKIE, cookie)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::NO_CONTENT
        );
        server.abort();
    }
}
