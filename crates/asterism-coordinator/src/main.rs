//! `asterism-coordinator` production entry point.
//!
//! The service reads a root-owned JSON deployment manifest. OAuth client
//! secrets and KMS key material are referenced by files (or can be supplied by
//! another `MetadataKeyLoader` in an embedding), never printed or accepted on
//! the network. The listener is TLS-only; `HostedService::serve` is a test
//! seam, while this executable always calls `serve_tls`.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use tokio::net::TcpListener;

use asterism_coordinator::production::{
    HostedService, OAuthClientConfig, ProductionOAuth, TlsFiles,
};
use asterism_coordinator::{
    MetadataKey, MetadataKeyLoader, MetadataKeyRing, PersistentCoordinator,
};

#[derive(Parser)]
#[command(
    name = "asterism-coordinator",
    about = "TLS hosted coordination for Google/GitHub OAuth only"
)]
struct Arguments {
    /// Root-owned deployment manifest. It contains file references, not raw secrets.
    #[arg(long)]
    config: PathBuf,
}

#[derive(Deserialize)]
struct Config {
    listen: SocketAddr,
    state_file: PathBuf,
    tls: TlsConfig,
    google: OAuthConfig,
    github: OAuthConfig,
    keys: KeyFiles,
}

#[derive(Deserialize)]
struct TlsConfig {
    certificate: PathBuf,
    private_key: PathBuf,
}

#[derive(Deserialize)]
struct OAuthConfig {
    client_id: String,
    client_secret_file: PathBuf,
    redirect_uri: String,
}

#[derive(Deserialize)]
struct KeyFile {
    version: String,
    material_file: PathBuf,
}

#[derive(Deserialize)]
struct KeyFiles {
    active: KeyFile,
    #[serde(default)]
    previous: Vec<KeyFile>,
    /// Stable account-ID HMAC/BLAKE3 key. This is a separate KMS object so
    /// metadata encryption can rotate without changing account identifiers.
    account_id_file: PathBuf,
}

impl MetadataKeyLoader for KeyFiles {
    fn load_metadata_keys(&self) -> Result<Vec<MetadataKey>> {
        std::iter::once(&self.active)
            .chain(&self.previous)
            .map(|key| MetadataKey::new(key.version.clone(), read_32(&key.material_file)?))
            .collect()
    }
}

fn read_secret(path: &PathBuf) -> Result<String> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("reading configured secret file {}", path.display()))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("configured secret file is empty");
    }
    Ok(value)
}

fn read_32(path: &PathBuf) -> Result<[u8; 32]> {
    let encoded = read_secret(path)?;
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .context("decoding configured KMS key")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("configured KMS key is not 32 bytes"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Arguments::parse();
    let config: Config = serde_json::from_slice(
        &fs::read(&args.config).context("reading coordinator deployment manifest")?,
    )
    .context("parsing coordinator deployment manifest")?;
    let keys = MetadataKeyRing::from_loader(&config.keys)?;
    let account_id_key = read_32(&config.keys.account_id_file)?;
    let coordinator = PersistentCoordinator::open(config.state_file, keys, account_id_key)?;
    let oauth = ProductionOAuth::new(
        OAuthClientConfig {
            client_id: config.google.client_id,
            client_secret: read_secret(&config.google.client_secret_file)?,
            redirect_uri: config.google.redirect_uri,
        },
        OAuthClientConfig {
            client_id: config.github.client_id,
            client_secret: read_secret(&config.github.client_secret_file)?,
            redirect_uri: config.github.redirect_uri,
        },
    )?;
    let tls = TlsFiles {
        certificate: config.tls.certificate,
        private_key: config.tls.private_key,
    }
    .load()?;
    let listener = TcpListener::bind(config.listen)
        .await
        .context("binding coordinator TLS listener")?;
    // Only public bind address and key version names are operationally safe to log.
    println!(
        "asterism-coordinator listening with TLS on {}",
        listener.local_addr()?
    );
    HostedService::new(oauth, coordinator)
        .serve_tls(listener, tls)
        .await
}
