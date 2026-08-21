//! Secrets Layer 0: metadata, platform storage, and source routing.
//!
//! Secret values never enter `$ASTERISM_HOME`.  The JSON file here is only an
//! orbit metadata catalog; material is held by [`SecretStore`] (the login
//! Keychain on macOS, explicitly unavailable elsewhere).  Public operations
//! fan out to independent source devices through the existing authenticated
//! mesh.  There is deliberately no CA, CONNECT proxy, or header injection in
//! this layer.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use asterism_core::instance::now_unix;
use asterism_core::paths;
use asterism_core::protocol::{Request, Response, SecretValue};
use asterism_core::secret::{Binding, Handle, Secret, SecretId, SourceDevice};
use asterism_mesh::DeviceIdentity;

use crate::mesh::Mesh;
use crate::Node;

const CATALOG_VERSION: u32 = 1;
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "dev.asterism.secret";

static PLANE: OnceLock<Arc<SecretPlane>> = OnceLock::new();

/// Platform boundary for material. Implementations must never persist bytes
/// alongside the mesh identity or metadata catalog.
pub(crate) trait SecretStore: Send + Sync {
    fn put(&self, id: &SecretId, value: &[u8]) -> Result<()>;
    fn get(&self, id: &SecretId) -> Result<Vec<u8>>;
    fn remove(&self, id: &SecretId) -> Result<()>;
}

#[cfg(target_os = "macos")]
struct PlatformSecretStore {
    /// One machine may host several independent ASTERISM_HOMEs. Their mesh
    /// identities namespace otherwise-identical orbit secret names.
    namespace: String,
}

#[cfg(target_os = "macos")]
impl PlatformSecretStore {
    fn account(&self, id: &SecretId) -> String {
        format!("{}:{}", self.namespace, id.as_str())
    }
}

#[cfg(target_os = "macos")]
impl SecretStore for PlatformSecretStore {
    fn put(&self, id: &SecretId, value: &[u8]) -> Result<()> {
        let account = self.account(id);
        security_framework::passwords::set_generic_password(KEYCHAIN_SERVICE, &account, value)
            .context("storing secret in the macOS login Keychain")
    }

    fn get(&self, id: &SecretId) -> Result<Vec<u8>> {
        let account = self.account(id);
        security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, &account)
            .context("reading secret from the macOS login Keychain")
    }

    fn remove(&self, id: &SecretId) -> Result<()> {
        let account = self.account(id);
        security_framework::passwords::delete_generic_password(KEYCHAIN_SERVICE, &account)
            .context("removing secret from the macOS login Keychain")
    }
}

#[cfg(not(target_os = "macos"))]
struct PlatformSecretStore {
    #[allow(dead_code)]
    namespace: String,
}

#[cfg(not(target_os = "macos"))]
impl SecretStore for PlatformSecretStore {
    fn put(&self, _: &SecretId, _: &[u8]) -> Result<()> {
        bail!("secret storage is unavailable on this platform; no plaintext fallback is used")
    }

    fn get(&self, _: &SecretId) -> Result<Vec<u8>> {
        bail!("secret storage is unavailable on this platform; no plaintext fallback is used")
    }

    fn remove(&self, _: &SecretId) -> Result<()> {
        bail!("secret storage is unavailable on this platform; no plaintext fallback is used")
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CatalogFile {
    version: u32,
    #[serde(default)]
    secrets: Vec<Secret>,
    #[serde(default)]
    bindings: Vec<Binding>,
}

struct Catalog {
    path: PathBuf,
    secrets: Vec<Secret>,
    bindings: Vec<Binding>,
}

impl Catalog {
    fn load(path: &Path) -> Result<Self> {
        let file = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<CatalogFile>(&bytes)
                .with_context(|| format!("corrupt secret metadata at {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => CatalogFile {
                version: CATALOG_VERSION,
                secrets: Vec::new(),
                bindings: Vec::new(),
            },
            Err(e) => return Err(e).context("reading secret metadata"),
        };
        if file.version != CATALOG_VERSION {
            bail!(
                "{} is secret metadata format {}, but this build speaks {CATALOG_VERSION}",
                path.display(),
                file.version
            );
        }
        Ok(Self {
            path: path.to_owned(),
            secrets: file.secrets,
            bindings: file.bindings,
        })
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = CatalogFile {
            version: CATALOG_VERSION,
            secrets: self.secrets.clone(),
            bindings: self.bindings.clone(),
        };
        let tmp = self.path.with_extension("json.tmp");
        #[cfg(unix)]
        let mut out = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut out = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        out.write_all(&serde_json::to_vec_pretty(&file)?)?;
        out.sync_all()?;
        std::fs::rename(&tmp, &self.path).context("committing secret metadata")?;
        Ok(())
    }
}

struct SecretPlane {
    device_id: String,
    catalog: StdMutex<Catalog>,
    store: Box<dyn SecretStore>,
}

impl SecretPlane {
    fn new(device_id: String, path: PathBuf, store: Box<dyn SecretStore>) -> Result<Self> {
        Ok(Self {
            device_id,
            catalog: StdMutex::new(Catalog::load(&path)?),
            store,
        })
    }

    fn list(&self) -> Vec<Secret> {
        self.catalog
            .lock()
            .expect("secret catalog poisoned")
            .secrets
            .clone()
    }

    fn sync(&self, secret: Secret) -> Result<Secret> {
        let id = secret.id.clone();
        let mut catalog = self.catalog.lock().expect("secret catalog poisoned");
        match catalog.secrets.iter_mut().find(|held| held.id == secret.id) {
            Some(held) => *held = merge([held.clone(), secret]).remove(0),
            None => catalog.secrets.push(secret),
        }
        catalog.secrets.sort_by(|a, b| a.name.cmp(&b.name));
        let synced = catalog
            .secrets
            .iter()
            .find(|held| held.id == id)
            .cloned()
            .ok_or_else(|| anyhow!("secret metadata disappeared while syncing"))?;
        catalog.save()?;
        Ok(synced)
    }

    fn put(&self, secret: Secret, value: &SecretValue) -> Result<Secret> {
        let source = secret
            .sources
            .iter()
            .find(|source| source.device_id == self.device_id)
            .cloned()
            .ok_or_else(|| anyhow!("source metadata does not identify this device"))?;
        let mut catalog = self.catalog.lock().expect("secret catalog poisoned");
        if catalog.secrets.iter().any(|held| {
            held.id == secret.id
                && held
                    .sources
                    .iter()
                    .any(|source| source.device_id == self.device_id)
        }) {
            bail!(
                "secret {:?} already has a source on this device; use `ast secret rotate`",
                secret.name
            );
        }
        self.store.put(&secret.id, value.as_bytes())?;
        debug_assert!(secret
            .sources
            .iter()
            .any(|held| held.device_id == source.device_id));
        let local = match catalog.secrets.iter_mut().find(|held| held.id == secret.id) {
            Some(held) => {
                *held = merge([held.clone(), secret]).remove(0);
                held.clone()
            }
            None => {
                catalog.secrets.push(secret.clone());
                secret
            }
        };
        catalog.secrets.sort_by(|a, b| a.name.cmp(&b.name));
        if let Err(e) = catalog.save() {
            let _ = self.store.remove(&local.id);
            return Err(e);
        }
        Ok(local)
    }

    fn remove(&self, id: &SecretId) -> Result<Secret> {
        let mut catalog = self.catalog.lock().expect("secret catalog poisoned");
        let index = catalog
            .secrets
            .iter()
            .position(|secret| &secret.id == id)
            .ok_or_else(|| anyhow!("this device is not a source for secret {:?}", id.as_str()))?;
        if catalog.secrets[index]
            .sources
            .iter()
            .any(|source| source.device_id == self.device_id)
        {
            self.store.remove(id)?;
        }
        let removed = catalog.secrets.remove(index);
        catalog.save()?;
        Ok(removed)
    }

    fn rotate(
        &self,
        id: &SecretId,
        version: u64,
        updated_at: u64,
        value: &SecretValue,
    ) -> Result<Secret> {
        let mut catalog = self.catalog.lock().expect("secret catalog poisoned");
        let secret = catalog
            .secrets
            .iter_mut()
            .find(|secret| &secret.id == id)
            .ok_or_else(|| anyhow!("this device is not a source for secret {:?}", id.as_str()))?;
        if !secret
            .sources
            .iter()
            .any(|source| source.device_id == self.device_id)
        {
            bail!("this device is not a source for secret {:?}", id.as_str());
        }
        if version <= secret.version {
            bail!(
                "secret {:?} is already at version {}",
                secret.name,
                secret.version
            );
        }
        self.store.put(id, value.as_bytes())?;
        secret.version = version;
        secret.updated_at = updated_at;
        for source in &mut secret.sources {
            if source.device_id == self.device_id {
                source.version = version;
                source.updated_at = updated_at;
            }
        }
        let changed = secret.clone();
        catalog.save()?;
        Ok(changed)
    }

    /// Read material only inside the source-side traffic injector.
    ///
    /// This deliberately has no protocol request or response counterpart:
    /// traffic travels to the source device and plaintext never travels back
    /// to a consumer daemon.
    #[allow(dead_code)]
    fn resolve(&self, handle: &Handle) -> Result<SecretValue> {
        if handle.source.device_id != self.device_id {
            bail!("secret handle is for a different source device");
        }
        let catalog = self.catalog.lock().expect("secret catalog poisoned");
        let secret = catalog
            .secrets
            .iter()
            .find(|secret| secret.id == handle.secret_id)
            .ok_or_else(|| anyhow!("this device is not a source for that secret"))?;
        if secret.version != handle.version || handle.source.version != handle.version {
            bail!(
                "secret {:?} rotated from version {} to {}; select a fresh handle",
                secret.name,
                handle.version,
                secret.version
            );
        }
        Ok(SecretValue::new(self.store.get(&handle.secret_id)?))
    }
}

pub(crate) fn init() -> Result<()> {
    let identity = DeviceIdentity::load_or_create(paths::device_key_path())
        .context("loading the source-device identity for secrets")?;
    let device_id = identity.device_id().to_string();
    let plane = SecretPlane::new(
        device_id.clone(),
        paths::home_dir().join("secrets.json"),
        Box::new(PlatformSecretStore {
            namespace: device_id,
        }),
    )?;
    PLANE
        .set(Arc::new(plane))
        .map_err(|_| anyhow!("secret plane initialized twice"))
}

fn plane() -> Result<&'static Arc<SecretPlane>> {
    PLANE
        .get()
        .ok_or_else(|| anyhow!("secret plane is unavailable"))
}

pub(crate) fn is_orbit_request(req: &Request) -> bool {
    matches!(
        req,
        Request::SecretCreate { .. }
            | Request::SecretList
            | Request::SecretRemove { .. }
            | Request::SecretRotate { .. }
    )
}

pub(crate) fn is_source_request(req: &Request) -> bool {
    matches!(
        req,
        Request::SecretSourceList
            | Request::SecretSourceSync { .. }
            | Request::SecretSourcePut { .. }
            | Request::SecretSourceRemove { .. }
            | Request::SecretSourceRotate { .. }
    )
}

pub(crate) async fn serve(req: Request, node: &Node, mesh: Option<&Arc<Mesh>>) -> Response {
    let result = match req {
        Request::SecretCreate {
            name,
            value,
            source_device,
        } => create(&name, value, source_device.as_deref(), node, mesh).await,
        Request::SecretList => list(node, mesh)
            .await
            .map(|secrets| Response::Secrets { secrets }),
        Request::SecretRemove { name } => remove(&name, node, mesh).await,
        Request::SecretRotate { name, value } => rotate(&name, value, node, mesh).await,
        _ => unreachable!("is_orbit_request and serve disagree"),
    };
    result.unwrap_or_else(|e| Response::Error {
        message: format!("{e:#}"),
    })
}

pub(crate) fn serve_source(req: Request) -> Response {
    let result = (|| -> Result<Response> {
        let plane = plane()?;
        match req {
            Request::SecretSourceList => Ok(Response::Secrets {
                secrets: plane.list(),
            }),
            Request::SecretSourceSync { secret } => Ok(Response::Secrets {
                secrets: vec![plane.sync(secret)?],
            }),
            Request::SecretSourcePut { secret, value } => Ok(Response::Secrets {
                secrets: vec![plane.put(secret, &value)?],
            }),
            Request::SecretSourceRemove { id } => Ok(Response::Secrets {
                secrets: vec![plane.remove(&id)?],
            }),
            Request::SecretSourceRotate {
                id,
                version,
                updated_at,
                value,
            } => Ok(Response::Secrets {
                secrets: vec![plane.rotate(&id, version, updated_at, &value)?],
            }),
            _ => unreachable!("is_source_request and serve_source disagree"),
        }
    })();
    result.unwrap_or_else(|e| Response::Error {
        message: format!("{e:#}"),
    })
}

async fn create(
    name: &str,
    value: SecretValue,
    target: Option<&str>,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<Response> {
    let id = SecretId::from_name(name)?;
    let existing = list(node, mesh)
        .await?
        .into_iter()
        .find(|secret| secret.id == id);
    let now = now_unix();
    let source = source_identity(target, node).await?;
    if existing.as_ref().is_some_and(|secret| {
        secret
            .sources
            .iter()
            .any(|held| held.device_id == source.device_id)
    }) {
        bail!(
            "secret {name:?} already has {} as a source; use `ast secret rotate`",
            source.device
        );
    }
    let (version, created_at) = existing
        .as_ref()
        .map(|secret| (secret.version, secret.created_at))
        .unwrap_or((1, now));
    let mut sources = existing
        .as_ref()
        .map(|secret| secret.sources.clone())
        .unwrap_or_default();
    let target_source = SourceDevice {
        version,
        updated_at: now,
        ..source
    };
    sources.push(target_source.clone());
    let secret = Secret {
        id,
        name: name.to_owned(),
        version,
        created_at,
        updated_at: now,
        sources,
    };
    let response = call_source(
        &target_source,
        Request::SecretSourcePut {
            secret: secret.clone(),
            value,
        },
        node,
        mesh,
    )
    .await?;
    match response {
        Response::Secrets { .. } => {
            sync_metadata(&secret, node, mesh).await;
            Ok(Response::Secrets {
                secrets: list(node, mesh).await?,
            })
        }
        Response::Error { message } => bail!(message),
        other => bail!("secret source answered create with {other:?}"),
    }
}

async fn list(node: &Node, mesh: Option<&Arc<Mesh>>) -> Result<Vec<Secret>> {
    let mut replies = vec![plane()?.list()];
    if let Some(mesh) = mesh {
        let peers = node.orbit.lock().await.devices().to_vec();
        for peer in peers {
            if let Ok(Response::Secrets { secrets }) =
                mesh.proxy(&peer.name, Request::SecretSourceList).await
            {
                replies.push(secrets);
            }
        }
    }
    let secrets = merge(replies.into_iter().flatten());
    for secret in &secrets {
        let _ = plane()?.sync(secret.clone());
    }
    Ok(secrets)
}

/// Best-effort replication of metadata only. Values are sent exclusively to
/// source devices by put/rotate; this keeps an offline source visible from a
/// device that saw it previously without turning metadata peers into sources.
async fn sync_metadata(secret: &Secret, node: &Node, mesh: Option<&Arc<Mesh>>) {
    let _ = plane().and_then(|plane| plane.sync(secret.clone()));
    let Some(mesh) = mesh else {
        return;
    };
    let peers = node.orbit.lock().await.devices().to_vec();
    for peer in peers {
        let _ = mesh
            .proxy(
                &peer.name,
                Request::SecretSourceSync {
                    secret: secret.clone(),
                },
            )
            .await;
    }
}

async fn remove(name: &str, node: &Node, mesh: Option<&Arc<Mesh>>) -> Result<Response> {
    let id = SecretId::from_name(name)?;
    let secret = list(node, mesh)
        .await?
        .into_iter()
        .find(|secret| secret.id == id)
        .ok_or_else(|| anyhow!("no secret named {name:?} in this orbit"))?;
    let local = source_identity(None, node).await?;
    let mut devices = vec![local];
    devices.extend(
        node.orbit
            .lock()
            .await
            .devices()
            .iter()
            .map(|peer| SourceDevice {
                device_id: peer.device_id.clone(),
                device: peer.name.clone(),
                version: 0,
                updated_at: 0,
            }),
    );

    let mut failures = Vec::new();
    for device in &devices {
        let is_source = secret
            .sources
            .iter()
            .any(|source| source.device_id == device.device_id);
        match call_source(
            device,
            Request::SecretSourceRemove { id: id.clone() },
            node,
            mesh,
        )
        .await
        {
            Ok(Response::Secrets { .. }) => {}
            Ok(Response::Error { message }) if is_source => {
                failures.push(format!("{}: {message}", device.device))
            }
            Ok(Response::Error { .. }) => {}
            Ok(other) if is_source => {
                failures.push(format!("{}: unexpected {other:?}", device.device))
            }
            Ok(_) => {}
            Err(e) if is_source => failures.push(format!("{}: {e:#}", device.device)),
            Err(_) => {}
        }
    }
    if !failures.is_empty() {
        bail!(
            "secret {name:?} was not removed from every source: {}",
            failures.join("; ")
        );
    }
    Ok(Response::Secrets {
        secrets: vec![secret],
    })
}

async fn rotate(
    name: &str,
    value: SecretValue,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<Response> {
    let id = SecretId::from_name(name)?;
    let secret = list(node, mesh)
        .await?
        .into_iter()
        .find(|secret| secret.id == id)
        .ok_or_else(|| anyhow!("no secret named {name:?} in this orbit"))?;
    let version = secret.version.saturating_add(1);
    let updated_at = now_unix();
    let mut failures = Vec::new();
    for source in &secret.sources {
        let request = Request::SecretSourceRotate {
            id: id.clone(),
            version,
            updated_at,
            value: value.clone(),
        };
        match call_source(source, request, node, mesh).await {
            Ok(Response::Secrets { .. }) => {}
            Ok(Response::Error { message }) => {
                failures.push(format!("{}: {message}", source.device))
            }
            Ok(other) => failures.push(format!("{}: unexpected {other:?}", source.device)),
            Err(e) => failures.push(format!("{}: {e:#}", source.device)),
        }
    }
    if !failures.is_empty() {
        bail!(
            "secret {name:?} reached version {version} on only some sources: {}",
            failures.join("; ")
        );
    }
    let mut rotated = secret.clone();
    rotated.version = version;
    rotated.updated_at = updated_at;
    for source in &mut rotated.sources {
        source.version = version;
        source.updated_at = updated_at;
    }
    sync_metadata(&rotated, node, mesh).await;
    Ok(Response::Secrets {
        secrets: list(node, mesh).await?,
    })
}

async fn source_identity(target: Option<&str>, node: &Node) -> Result<SourceDevice> {
    let plane = plane()?;
    let orbit = node.orbit.lock().await;
    match target {
        None => Ok(SourceDevice {
            device_id: plane.device_id.clone(),
            device: orbit.self_name().to_owned(),
            version: 0,
            updated_at: 0,
        }),
        Some(name) if name == orbit.self_name() => Ok(SourceDevice {
            device_id: plane.device_id.clone(),
            device: name.to_owned(),
            version: 0,
            updated_at: 0,
        }),
        Some(name) => orbit
            .get(name)
            .map(|peer| SourceDevice {
                device_id: peer.device_id.clone(),
                device: peer.name.clone(),
                version: 0,
                updated_at: 0,
            })
            .ok_or_else(|| anyhow!("no device named {name:?} in this orbit — see: ast devices")),
    }
}

async fn call_source(
    source: &SourceDevice,
    request: Request,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<Response> {
    if source.device_id == plane()?.device_id {
        return Ok(serve_source(request));
    }
    let current_name = node
        .orbit
        .lock()
        .await
        .by_id(&source.device_id)
        .map(|device| device.name.clone())
        .ok_or_else(|| anyhow!("secret source {} is no longer in this orbit", source.device))?;
    let mesh = mesh.ok_or_else(|| {
        anyhow!("the mesh is unavailable, so secret source {current_name:?} cannot be reached")
    })?;
    mesh.proxy(&current_name, request).await
}

fn merge(secrets: impl IntoIterator<Item = Secret>) -> Vec<Secret> {
    let mut merged: BTreeMap<SecretId, Secret> = BTreeMap::new();
    for mut incoming in secrets {
        match merged.get_mut(&incoming.id) {
            None => {
                incoming
                    .sources
                    .sort_by(|a, b| a.device_id.cmp(&b.device_id));
                merged.insert(incoming.id.clone(), incoming);
            }
            Some(secret) => {
                secret.created_at = secret.created_at.min(incoming.created_at);
                secret.updated_at = secret.updated_at.max(incoming.updated_at);
                secret.version = secret.version.max(incoming.version);
                for source in incoming.sources {
                    match secret
                        .sources
                        .iter_mut()
                        .find(|held| held.device_id == source.device_id)
                    {
                        Some(held) if source.version > held.version => *held = source,
                        Some(_) => {}
                        None => secret.sources.push(source),
                    }
                }
                secret.sources.sort_by(|a, b| a.device_id.cmp(&b.device_id));
            }
        }
    }
    let mut out: Vec<_> = merged.into_values().collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryStore(StdMutex<BTreeMap<SecretId, Vec<u8>>>);

    impl SecretStore for MemoryStore {
        fn put(&self, id: &SecretId, value: &[u8]) -> Result<()> {
            self.0.lock().unwrap().insert(id.clone(), value.to_vec());
            Ok(())
        }

        fn get(&self, id: &SecretId) -> Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or_else(|| anyhow!("missing"))
        }

        fn remove(&self, id: &SecretId) -> Result<()> {
            self.0.lock().unwrap().remove(id);
            Ok(())
        }
    }

    fn source(version: u64) -> SourceDevice {
        SourceDevice {
            device_id: "device-public-key".into(),
            device: "laptop".into(),
            version,
            updated_at: version,
        }
    }

    #[test]
    fn plaintext_never_enters_the_metadata_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let plane = SecretPlane::new(
            "device-public-key".into(),
            path.clone(),
            Box::new(MemoryStore::default()),
        )
        .unwrap();
        let sentinel = b"NEVER-WRITE-THIS-PLAINTEXT";
        plane
            .put(
                Secret {
                    id: SecretId::from_name("api").unwrap(),
                    name: "api".into(),
                    version: 1,
                    created_at: 1,
                    updated_at: 1,
                    sources: vec![source(1)],
                },
                &SecretValue::new(sentinel.to_vec()),
            )
            .unwrap();
        let disk = std::fs::read(path).unwrap();
        assert!(!disk
            .windows(sentinel.len())
            .any(|window| window == sentinel));
        assert!(String::from_utf8(disk)
            .unwrap()
            .contains("device-public-key"));
    }

    #[test]
    fn merging_keeps_independent_sources_and_highest_version() {
        let id = SecretId::from_name("api").unwrap();
        let one = Secret {
            id: id.clone(),
            name: "api".into(),
            version: 1,
            created_at: 1,
            updated_at: 1,
            sources: vec![source(1)],
        };
        let mut other_source = source(2);
        other_source.device_id = "other-public-key".into();
        other_source.device = "desktop".into();
        let two = Secret {
            id,
            name: "api".into(),
            version: 2,
            created_at: 1,
            updated_at: 2,
            sources: vec![other_source],
        };
        let merged = merge([one, two]);
        assert_eq!(merged[0].version, 2);
        assert_eq!(merged[0].sources.len(), 2);
    }

    #[test]
    fn orbit_metadata_keeps_remote_sources_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let id = SecretId::from_name("api").unwrap();
        let mut remote = source(4);
        remote.device_id = "remote-public-key".into();
        remote.device = "desktop".into();
        {
            let plane = SecretPlane::new(
                "device-public-key".into(),
                path.clone(),
                Box::new(MemoryStore::default()),
            )
            .unwrap();
            plane
                .sync(Secret {
                    id,
                    name: "api".into(),
                    version: 4,
                    created_at: 1,
                    updated_at: 4,
                    sources: vec![source(4), remote],
                })
                .unwrap();
        }
        let restarted = SecretPlane::new(
            "device-public-key".into(),
            path,
            Box::new(MemoryStore::default()),
        )
        .unwrap();
        assert_eq!(restarted.list()[0].sources.len(), 2);
        assert_eq!(restarted.list()[0].version, 4);
    }

    #[test]
    fn source_resolution_is_version_pinned_across_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let plane = SecretPlane::new(
            "device-public-key".into(),
            dir.path().join("secrets.json"),
            Box::new(MemoryStore::default()),
        )
        .unwrap();
        let id = SecretId::from_name("api").unwrap();
        plane
            .put(
                Secret {
                    id: id.clone(),
                    name: "api".into(),
                    version: 1,
                    created_at: 1,
                    updated_at: 1,
                    sources: vec![source(1)],
                },
                &SecretValue::new(b"old".to_vec()),
            )
            .unwrap();
        let stale = Handle {
            secret_id: id.clone(),
            source: source(1),
            version: 1,
        };
        plane
            .rotate(&id, 2, 2, &SecretValue::new(b"new".to_vec()))
            .unwrap();
        assert!(plane
            .resolve(&stale)
            .unwrap_err()
            .to_string()
            .contains("rotated"));
        let fresh = Handle {
            secret_id: id,
            source: source(2),
            version: 2,
        };
        assert_eq!(plane.resolve(&fresh).unwrap().as_bytes(), b"new");
    }

    #[test]
    fn source_requests_are_distinct_from_orbit_operations() {
        assert!(is_orbit_request(&Request::SecretList));
        assert!(!is_source_request(&Request::SecretList));
        assert!(is_source_request(&Request::SecretSourceList));
        assert!(!is_orbit_request(&Request::SecretSourceList));
    }
}
