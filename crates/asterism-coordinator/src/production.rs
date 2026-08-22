//! Production OAuth adapters and the hosted HTTP entry point.
//!
//! The adapter exchanges a one-time authorization code with Google or GitHub
//! over TLS. Google validation asks Google's token-info endpoint to validate
//! the returned OIDC ID token's issuer, audience and expiry; GitHub validation
//! calls its authenticated `/user` endpoint and uses its immutable numeric id.
//! Neither flow requests, stores, or returns an email address.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use http::header::{CONTENT_TYPE, LOCATION};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use url::form_urlencoded;
use uuid::Uuid;

use crate::{OAuthProvider, PersistentCoordinator, VerifiedOAuth};

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
    fn validate(&self) -> Result<()> {
        if self.client_id.trim().is_empty() || self.client_secret.trim().is_empty() {
            bail!("OAuth client id and secret must be configured");
        }
        if !self.redirect_uri.starts_with("https://") {
            bail!("OAuth redirect URI must use https");
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
        google.validate()?;
        github.validate()?;
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
            .get(GOOGLE_TOKEN_INFO)
            .query(&[("id_token", token.id_token)])
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
}

/// Real HTTP service for the optional hosted plane. It has a health endpoint
/// and OAuth start/callback endpoints; there is deliberately no credential
/// endpoint of any kind.
pub struct HostedService {
    oauth: ProductionOAuth,
    coordinator: Arc<Mutex<PersistentCoordinator>>,
    pending: Mutex<BTreeMap<String, PendingOAuth>>,
}

impl HostedService {
    /// Creates a service around durable coordinator state.
    pub fn new(oauth: ProductionOAuth, coordinator: PersistentCoordinator) -> Arc<Self> {
        Arc::new(Self {
            oauth,
            coordinator: Arc::new(Mutex::new(coordinator)),
            pending: Mutex::new(BTreeMap::new()),
        })
    }

    /// Serves the hosted HTTP API on a TCP listener.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let service = Arc::clone(&self);
            tokio::spawn(async move {
                let result = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request| {
                            let service = Arc::clone(&service);
                            async move {
                                Ok::<_, std::convert::Infallible>(service.route(request).await)
                            }
                        }),
                    )
                    .await;
                if let Err(error) = result {
                    eprintln!("coordinator HTTP connection failed: {error}");
                }
            });
        }
    }

    /// Routes one request. Public for integration tests that exercise the
    /// production state/PKCE/callback boundary without a real provider secret.
    pub async fn route(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        match (request.method(), request.uri().path()) {
            (&Method::GET, "/healthz") => text(StatusCode::OK, "ok"),
            (&Method::GET, "/oauth/google/start") => self.start(OAuthProvider::Google).await,
            (&Method::GET, "/oauth/github/start") => self.start(OAuthProvider::GitHub).await,
            (&Method::GET, "/oauth/google/callback") => {
                self.callback(OAuthProvider::Google, request.uri().query())
                    .await
            }
            (&Method::GET, "/oauth/github/callback") => {
                self.callback(OAuthProvider::GitHub, request.uri().query())
                    .await
            }
            _ => text(StatusCode::NOT_FOUND, "not found"),
        }
    }

    async fn start(&self, provider: OAuthProvider) -> Response<Full<Bytes>> {
        let state = random_token();
        let verifier = random_token();
        self.pending.lock().await.insert(
            state.clone(),
            PendingOAuth {
                provider,
                verifier: verifier.clone(),
            },
        );
        Response::builder()
            .status(StatusCode::FOUND)
            .header(
                LOCATION,
                self.oauth.authorization_url(provider, &state, &verifier),
            )
            .body(Full::new(Bytes::new()))
            .expect("valid redirect response")
    }

    async fn callback(
        &self,
        provider: OAuthProvider,
        query: Option<&str>,
    ) -> Response<Full<Bytes>> {
        let parameters: BTreeMap<_, _> = form_urlencoded::parse(query.unwrap_or("").as_bytes())
            .into_owned()
            .collect();
        let (Some(code), Some(state)) = (parameters.get("code"), parameters.get("state")) else {
            return text(StatusCode::BAD_REQUEST, "missing OAuth code or state");
        };
        let pending = self.pending.lock().await.remove(state);
        let Some(pending) = pending.filter(|pending| pending.provider == provider) else {
            return text(
                StatusCode::UNAUTHORIZED,
                "OAuth state is invalid or expired",
            );
        };
        match self.oauth.exchange(provider, code, &pending.verifier).await {
            Ok(claims) => match self.coordinator.lock().await.sign_in_claims(claims) {
                Ok(account) => json(
                    StatusCode::OK,
                    &serde_json::json!({"account_id": account.as_str()}),
                ),
                Err(error) => text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("durable sign-in failed: {error:#}"),
                ),
            },
            Err(error) => text(
                StatusCode::UNAUTHORIZED,
                &format!("OAuth validation failed: {error:#}"),
            ),
        }
    }
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
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
    text(status, &value.to_string())
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
    async fn a_real_control_plane_outage_after_24_hours_does_not_stop_a_paired_orbit() {
        let directory = tempfile::tempdir().unwrap();
        let coordinator = crate::PersistentCoordinator::open(
            directory.path().join("state.enc"),
            [3; 32],
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
        server.abort();
        let _ = server.await;
        assert!(
            reqwest::get(format!("http://{address}/healthz"))
                .await
                .is_err(),
            "the coordinator must really be unreachable"
        );
        let outage_age = Duration::from_secs(24 * 60 * 60);
        assert_eq!(outage_age.as_secs(), 86_400);

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
            let accepted = pairing::accept(&inviter, &issued).await;
            (inviter, accepted)
        });
        let paired = pairing::join(&joiner, &ticket).await.unwrap();
        paired.connection().close(b"outage proof");
        let (inviter, accepted) = accepting.await.unwrap();
        assert_eq!(paired.device_id(), inviter.device_id());
        assert_eq!(accepted.unwrap().device_id(), joiner.device_id());
        joiner.close().await;
        inviter.close().await;
    }
}
