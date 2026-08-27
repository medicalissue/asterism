//! `astrelay` — Asterism's own iroh relay server.
//!
//! # What a relay is, and what it is not
//!
//! Two devices in an orbit want a direct QUIC path to each other. Most of the
//! time hole punching finds one. When it cannot — symmetric NAT on both ends,
//! a corporate network that drops UDP to anything it has not seen, a carrier
//! CGNAT — the connection falls back to a relay, which forwards packets
//! between the two.
//!
//! A relay forwards **ciphertext**. The QUIC session is terminated on the two
//! devices and nowhere else; its keys are derived from the two device
//! identities during a handshake the relay only carries bytes for. This
//! process holds no orbit key material of any kind — its own TLS certificate
//! authenticates *the relay* to clients, and is unrelated to the keys that
//! encrypt what passes through. Running one gives an operator packet counts,
//! packet sizes and timing between two public keys. It does not give them a
//! single byte of anyone's traffic. That is why the default access policy here
//! is to accept everyone: gating adds operational cost and buys no
//! confidentiality that the transport did not already provide.
//!
//! # Why it exists
//!
//! Two reasons, in this order. First, Asterism shipped Phase 2 on n0's public
//! relay fleet, which is a bootstrap and not a destination: a product cannot
//! put its fallback path on infrastructure it neither runs nor pays for.
//! Second, relayed bytes are the one resource an orbit consumes that costs the
//! operator money per gigabyte, so they are the billing basis — and a billing
//! basis has to be measured on hardware whose counters we can read. See
//! `docs/RELAY.md`.
//!
//! # Self-hosting
//!
//! This binary is dual licensed MIT/Apache-2.0 like the rest of the device
//! software, and running your own is a supported configuration rather than a
//! tolerated one: point `ASTERISM_RELAY_URL` at it and the daemon uses it.
//! `docs/RELAY.md` is the operator's guide.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    path::PathBuf,
    sync::Arc,
};

mod accounting;

use accounting::{Accounting, ClientMetrics, PerClient};
use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use iroh_relay::server::{
    Access, AccessControl, AcmeConfig, CertConfig, ClientRateLimit, ClientRequest, QuicConfig,
    RelayConfig, Server, ServerConfig, TlsConfig,
};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tracing::info;
use tracing_subscriber::{prelude::*, EnvFilter};

/// The plaintext port `--dev` binds. Same number the upstream iroh relay uses
/// in its own dev mode, so a developer who has run one knows this one.
const DEV_PORT: u16 = 3340;

/// The environment variable a token-gated relay reads its shared secret from.
///
/// A token belongs in the environment rather than in a flag because a flag is
/// visible in `ps` output to every user on the host.
const ACCESS_TOKEN_ENV: &str = "ASTRELAY_ACCESS_TOKEN";

/// Asterism's relay server. Forwards ciphertext between devices that cannot
/// reach each other directly.
#[derive(Parser, Debug)]
#[command(name = "astrelay", version, about, long_about = None)]
struct Cli {
    /// Run in plain HTTP on localhost, for development and tests.
    ///
    /// Binds 127.0.0.1:3340 with no TLS and ignores every TLS flag. The URL to
    /// hand a daemon is printed at startup. Never use this on a public
    /// address: without TLS a client cannot tell this relay from an
    /// impersonation of it.
    #[arg(long)]
    dev: bool,

    /// Address for the plain HTTP listener.
    ///
    /// With TLS off this serves the relay itself. With TLS on it serves only
    /// the captive-portal probe, and the relay moves to `--https-bind`.
    #[arg(long, value_name = "ADDR")]
    http_bind: Option<SocketAddr>,

    /// How this relay proves who it is to connecting devices.
    #[arg(long, value_name = "MODE", default_value = "none")]
    tls: TlsMode,

    /// Address for the HTTPS listener, when `--tls` is not `none`.
    #[arg(long, value_name = "ADDR")]
    https_bind: Option<SocketAddr>,

    /// PEM certificate chain, for `--tls manual`.
    #[arg(long, value_name = "PATH")]
    cert: Option<PathBuf>,

    /// PEM private key, for `--tls manual`.
    #[arg(long, value_name = "PATH")]
    key: Option<PathBuf>,

    /// A hostname to obtain a certificate for, for `--tls lets-encrypt`.
    /// Repeatable.
    #[arg(long, value_name = "HOST")]
    acme_domain: Vec<String>,

    /// Contact email for the ACME account, for `--tls lets-encrypt`.
    #[arg(long, value_name = "EMAIL")]
    acme_contact: Option<String>,

    /// Directory to cache issued certificates in, for `--tls lets-encrypt`.
    ///
    /// Without it every restart asks Let's Encrypt for a new certificate,
    /// which their rate limits will eventually refuse.
    #[arg(long, value_name = "DIR")]
    acme_cache: Option<PathBuf>,

    /// Use Let's Encrypt's staging environment rather than production.
    #[arg(long)]
    acme_staging: bool,

    /// Serve QUIC address discovery on this address. Requires TLS.
    ///
    /// This is the probe that tells a device what address the world sees it
    /// on, which is what makes hole punching work. It relays nothing.
    #[arg(long, value_name = "ADDR")]
    quic_bind: Option<SocketAddr>,

    /// Serve Prometheus metrics on this address.
    ///
    /// Bind it to a private interface: the counters name no devices, but they
    /// are operational detail and there is no reason to publish them.
    #[arg(long, value_name = "ADDR")]
    metrics_bind: Option<SocketAddr>,

    /// Who may use this relay.
    #[arg(long, value_name = "MODE", default_value = "open")]
    access: AccessMode,

    /// Throttle each client connection's inbound rate, in bytes per second.
    ///
    /// Unset means unlimited, which is the default: a relay that starts
    /// throttling before anyone has measured what normal looks like is a
    /// mystery outage waiting to happen. This is a *throttle* — iroh-relay
    /// applies it as a token bucket on the read side, so an over-eager client
    /// is slowed down, not disconnected.
    #[arg(long, value_name = "BYTES")]
    client_rx_limit: Option<u32>,

    /// Allow a burst above `--client-rx-limit`, in bytes.
    #[arg(long, value_name = "BYTES", requires = "client_rx_limit")]
    client_rx_burst: Option<u32>,

    /// Break the connection counters out per client public key.
    ///
    /// Off by default: each key becomes a Prometheus label, and a relay open
    /// to strangers meets an unbounded number of them. See
    /// `--per-client-metrics-max`.
    #[arg(long)]
    per_client_metrics: bool,

    /// How many distinct client keys may hold a label of their own.
    ///
    /// Past this, connections are counted only in the aggregates and
    /// `astrelay_clients_untracked` records that it happened.
    #[arg(
        long,
        value_name = "N",
        default_value_t = 1024,
        requires = "per_client_metrics"
    )]
    per_client_metrics_max: usize,
}

/// How the relay authenticates itself to clients.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum TlsMode {
    /// No TLS. Only correct behind a terminating proxy, or under `--dev`.
    None,
    /// A certificate and key supplied on disk, by whatever issued them.
    Manual,
    /// Obtain and renew a certificate from Let's Encrypt over ACME TLS-ALPN.
    LetsEncrypt,
}

/// Who is admitted.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum AccessMode {
    /// Everyone. The default, because a relay forwards ciphertext it cannot
    /// read and refusing a stranger protects nobody's data — only bandwidth.
    Open,
    /// Only clients presenting the bearer token in `ASTRELAY_ACCESS_TOKEN`.
    ///
    /// A shared secret, not an identity: use it to keep a private relay from
    /// being used as free bandwidth, not as an authorisation system.
    Token,
}

/// Admits a client only if it presented the configured bearer token.
#[derive(Debug)]
struct TokenAccess {
    token: String,
}

impl AccessControl for TokenAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        match request.auth_token() {
            // Compared in constant time: a byte-at-a-time comparison of a
            // shared secret is an oracle for guessing it one byte at a time.
            Some(offered) if constant_time_eq(offered.as_bytes(), self.token.as_bytes()) => {
                Access::Allow
            }
            _ => Access::Deny {
                reason: Some("this relay requires an access token".to_owned()),
            },
        }
    }
}

/// Whether two byte strings are equal, in time that does not depend on where
/// they first differ.
///
/// Length is not secret here — the token's length is a property of the
/// operator's configuration, not of any individual guess — so an early return
/// on a length mismatch leaks nothing an attacker did not choose.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The address the plain HTTP listener ends up on.
///
/// Split out from the rest so the defaulting rule — dev is loopback, anything
/// else is every interface — is one testable expression rather than a shape
/// buried in `main`.
fn http_bind_addr(cli: &Cli) -> SocketAddr {
    if let Some(addr) = cli.http_bind {
        return addr;
    }
    if cli.dev {
        return (Ipv4Addr::LOCALHOST, DEV_PORT).into();
    }
    (Ipv6Addr::UNSPECIFIED, 80).into()
}

/// The address the HTTPS listener ends up on.
fn https_bind_addr(cli: &Cli) -> SocketAddr {
    cli.https_bind
        .unwrap_or_else(|| (Ipv6Addr::UNSPECIFIED, 443).into())
}

/// Whether TLS is actually in play, after `--dev` has had its say.
///
/// `--dev` wins over `--tls` deliberately: a developer who exported a TLS
/// configuration once and then asked for a local plaintext relay wants the
/// local plaintext relay, and a half-applied TLS mode is the confusing
/// outcome.
fn effective_tls_mode(cli: &Cli) -> TlsMode {
    if cli.dev {
        TlsMode::None
    } else {
        cli.tls
    }
}

/// The URL a daemon should be pointed at, given where this relay is listening.
///
/// Printed at startup because the alternative is an operator assembling it by
/// hand from a bind address and getting the scheme wrong.
fn advertised_url(tls: TlsMode, addr: SocketAddr) -> String {
    let scheme = if matches!(tls, TlsMode::None) {
        "http"
    } else {
        "https"
    };
    let host = match addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => "<this-host>".to_owned(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => "<this-host>".to_owned(),
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    format!("{scheme}://{host}:{}", addr.port())
}

/// Builds the `rustls` half of a TLS configuration.
fn cert_config(cli: &Cli) -> Result<CertConfig> {
    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default protocol versions")
    .with_no_client_auth();

    match cli.tls {
        TlsMode::None => unreachable!("cert_config is only called when TLS is on"),
        TlsMode::Manual => {
            let cert = cli
                .cert
                .as_ref()
                .context("--tls manual needs --cert <PATH>")?;
            let key = cli
                .key
                .as_ref()
                .context("--tls manual needs --key <PATH>")?;
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
                .with_context(|| format!("opening the certificate at {}", cert.display()))?
                .collect::<Result<_, _>>()
                .with_context(|| format!("reading certificates from {}", cert.display()))?;
            let key = PrivateKeyDer::from_pem_file(key)
                .with_context(|| format!("reading the private key at {}", key.display()))?;
            let server_config = builder
                .with_single_cert(certs, key)
                .context("the certificate and key do not form a usable TLS configuration")?;
            Ok(CertConfig::Manual { server_config })
        }
        TlsMode::LetsEncrypt => {
            if cli.acme_domain.is_empty() {
                bail!("--tls lets-encrypt needs at least one --acme-domain");
            }
            let contact = cli
                .acme_contact
                .as_ref()
                .context("--tls lets-encrypt needs --acme-contact <EMAIL>")?;
            let mut acme = AcmeConfig::letsencrypt(!cli.acme_staging)
                .domains(cli.acme_domain.clone())
                .contact(vec![format!("mailto:{contact}")]);
            if let Some(dir) = &cli.acme_cache {
                acme = acme.cache_path(dir.clone());
            } else {
                // Said rather than logged: the consequence arrives weeks later
                // as a rate-limit refusal from Let's Encrypt, at which point
                // nobody remembers this decision was made.
                tracing::warn!(
                    "no --acme-cache: every restart will request a fresh certificate, \
                     and Let's Encrypt will eventually refuse"
                );
            }
            Ok(CertConfig::LetsEncrypt {
                acme_config: acme,
                server_config_builder: builder,
            })
        }
    }
}

/// Assembles the whole server configuration from the parsed command line.
// `ServerConfig` and `RelayConfig` are `#[non_exhaustive]`, so a struct literal
// is not available to this crate and field assignment after `default()`/`new()`
// is the only way to build them.
#[allow(clippy::field_reassign_with_default)]
fn server_config(cli: &Cli, metrics: Arc<ClientMetrics>) -> Result<ServerConfig> {
    let tls_mode = effective_tls_mode(cli);
    let http = http_bind_addr(cli);

    let mut relay = RelayConfig::new(http);

    if !matches!(tls_mode, TlsMode::None) {
        relay.tls = Some(TlsConfig::new(https_bind_addr(cli), cert_config(cli)?));
    }

    if let Some(bps) = cli.client_rx_limit {
        let bps = NonZeroU32::new(bps).context("--client-rx-limit must not be zero")?;
        let mut limit = ClientRateLimit::new(bps);
        limit.max_burst_bytes = cli
            .client_rx_burst
            .map(|burst| NonZeroU32::new(burst).context("--client-rx-burst must not be zero"))
            .transpose()?;
        relay.limits.client_rx = Some(limit);
    }

    let policy: Arc<dyn iroh_relay::server::DynAccessControl> = match cli.access {
        AccessMode::Open => Arc::new(iroh_relay::server::AllowAll),
        AccessMode::Token => {
            let token = std::env::var(ACCESS_TOKEN_ENV)
                .ok()
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .with_context(|| format!("--access token needs {ACCESS_TOKEN_ENV} to be set"))?;
            Arc::new(TokenAccess { token })
        }
    };
    // Accounting wraps whatever the policy is rather than replacing it, so the
    // counters exist under every access mode and the decision stays in one
    // place. See `accounting` for what a relay can and cannot count.
    let per_client = if cli.per_client_metrics {
        PerClient::Capped(cli.per_client_metrics_max)
    } else {
        PerClient::Off
    };
    relay.access = Arc::new(Accounting::new(policy, metrics, per_client));

    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    // Metrics are served from this binary's own registry rather than the one
    // `Server::spawn` would build, because that one holds only iroh-relay's
    // counters and the per-client ones have to appear on the same endpoint.
    config.metrics_addr = None;

    if let Some(addr) = cli.quic_bind {
        if matches!(tls_mode, TlsMode::None) {
            bail!("--quic-bind needs TLS: QUIC address discovery has no plaintext form");
        }
        config.quic = Some(QuicConfig::new(addr));
    }

    Ok(config)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // iroh-relay is built here on `ring` alone, but rustls still wants a
    // process-wide default provider named before anything asks for one, and a
    // missing default is a panic at first handshake rather than an error here.
    // Already-installed is not a failure: a test harness may have got there
    // first.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let tls_mode = effective_tls_mode(&cli);

    if cli.dev && cli.tls != TlsMode::None {
        info!("--dev overrides --tls: this relay is serving plain HTTP");
    }

    let listen = if matches!(tls_mode, TlsMode::None) {
        http_bind_addr(&cli)
    } else {
        https_bind_addr(&cli)
    };

    let client_metrics = Arc::new(ClientMetrics::default());
    let config = server_config(&cli, client_metrics.clone())?;
    let mut server = Server::spawn(config)
        .await
        .map_err(|error| anyhow::anyhow!("starting the relay server: {error}"))?;

    // One endpoint, both meters: iroh-relay's byte and connection counters,
    // and this binary's per-client accounting.
    let metrics_server = match cli.metrics_bind {
        Some(addr) => {
            let mut registry = iroh_metrics::Registry::default();
            registry.register_all(server.metrics());
            registry.register(client_metrics.clone());
            Some(
                iroh_metrics::service::MetricsServer::spawn(addr, Arc::new(registry))
                    .await
                    .with_context(|| format!("binding the metrics server to {addr}"))?,
            )
        }
        None => None,
    };

    info!(
        url = %advertised_url(tls_mode, listen),
        access = ?cli.access,
        tls = ?tls_mode,
        "astrelay is up — point ASTERISM_RELAY_URL at this url"
    );
    if let Some(server) = &metrics_server {
        info!("metrics on http://{}/metrics", server.local_addr());
    }
    match cli.client_rx_limit {
        Some(bps) => info!("per-client inbound throttle: {bps} bytes/s"),
        None => info!("per-client inbound rate: unlimited"),
    }
    // Said every time, because the reason this is safe to self-host is the one
    // thing an operator most needs to be sure of.
    info!("this relay forwards ciphertext only; it holds no orbit key material");

    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
        _ = server.join() => {}
    }

    if let Some(metrics_server) = metrics_server {
        metrics_server.shutdown().await;
    }
    server
        .shutdown()
        .await
        .map_err(|error| anyhow::anyhow!("shutting the relay server down: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        let mut full = vec!["astrelay"];
        full.extend_from_slice(args);
        Cli::parse_from(full)
    }

    #[test]
    fn the_command_line_is_well_formed() {
        // clap's own audit: duplicated short flags and impossible `requires`
        // graphs are a panic at first parse, which would be a panic in front
        // of an operator rather than in front of us.
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn dev_mode_is_loopback_and_never_public() {
        let addr = http_bind_addr(&cli(&["--dev"]));
        assert!(
            addr.ip().is_loopback(),
            "--dev must not bind an address the network can reach, got {addr}"
        );
        assert_eq!(addr.port(), DEV_PORT);
    }

    #[test]
    fn without_dev_the_relay_listens_everywhere_on_the_well_known_port() {
        let addr = http_bind_addr(&cli(&[]));
        assert!(addr.ip().is_unspecified());
        assert_eq!(addr.port(), 80);
        assert_eq!(https_bind_addr(&cli(&[])).port(), 443);
    }

    #[test]
    fn an_explicit_bind_beats_both_defaults() {
        assert_eq!(
            http_bind_addr(&cli(&["--dev", "--http-bind", "127.0.0.1:19999"])),
            "127.0.0.1:19999".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn dev_mode_refuses_to_be_half_encrypted() {
        // A TLS mode left over from another invocation must not produce a
        // relay that is neither plainly local nor properly authenticated.
        assert_eq!(
            effective_tls_mode(&cli(&["--dev", "--tls", "lets-encrypt"])),
            TlsMode::None
        );
        assert_eq!(effective_tls_mode(&cli(&[])), TlsMode::None);
        assert_eq!(
            effective_tls_mode(&cli(&["--tls", "manual"])),
            TlsMode::Manual
        );
    }

    #[test]
    fn the_url_printed_matches_the_scheme_actually_served() {
        assert_eq!(
            advertised_url(TlsMode::None, "127.0.0.1:3340".parse().unwrap()),
            "http://127.0.0.1:3340"
        );
        assert_eq!(
            advertised_url(TlsMode::Manual, "10.0.0.4:443".parse().unwrap()),
            "https://10.0.0.4:443"
        );
        // A wildcard bind has no host to print, and printing `0.0.0.0` would
        // hand an operator a URL that resolves to their own loopback.
        assert_eq!(
            advertised_url(TlsMode::LetsEncrypt, "[::]:443".parse().unwrap()),
            "https://<this-host>:443"
        );
    }

    #[test]
    fn accepting_everyone_is_the_default() {
        assert_eq!(cli(&[]).access, AccessMode::Open);
        let config = server_config(&cli(&["--dev"]), Arc::new(ClientMetrics::default()))
            .expect("a dev relay configures");
        assert!(config.relay.is_some());
        assert!(config.metrics_addr.is_none());
    }

    #[test]
    fn a_token_relay_without_a_token_refuses_to_start() {
        // Rather than starting wide open, which is the failure an operator
        // would not notice until someone else's traffic showed up in the
        // bandwidth bill.
        let previous = std::env::var(ACCESS_TOKEN_ENV).ok();
        std::env::remove_var(ACCESS_TOKEN_ENV);
        let error = server_config(
            &cli(&["--dev", "--access", "token"]),
            Arc::new(ClientMetrics::default()),
        )
        .expect_err("a token relay with no token is a misconfiguration");
        assert!(
            error.to_string().contains(ACCESS_TOKEN_ENV),
            "the error must name the variable to set, got: {error}"
        );
        if let Some(value) = previous {
            std::env::set_var(ACCESS_TOKEN_ENV, value);
        }
    }

    #[test]
    fn quic_address_discovery_refuses_to_run_unencrypted() {
        let error = server_config(
            &cli(&["--dev", "--quic-bind", "127.0.0.1:7842"]),
            Arc::new(ClientMetrics::default()),
        )
        .expect_err("QUIC address discovery has no plaintext form");
        assert!(error.to_string().contains("TLS"), "got: {error}");
    }

    #[test]
    fn manual_tls_names_the_flag_that_is_missing() {
        let error = server_config(
            &cli(&["--tls", "manual"]),
            Arc::new(ClientMetrics::default()),
        )
        .expect_err("manual TLS without a certificate is a misconfiguration");
        assert!(error.to_string().contains("--cert"), "got: {error}");
    }

    #[test]
    fn a_token_comparison_does_not_short_circuit_on_content() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreu"));
        assert!(!constant_time_eq(b"secret", b"secre"));
        assert!(constant_time_eq(b"", b""));
    }
}
