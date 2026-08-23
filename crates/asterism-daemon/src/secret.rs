//! Secrets Layer 0: metadata, platform storage, and source routing.
//!
//! Secret values never enter `$ASTERISM_HOME`.  The JSON file here is only an
//! orbit metadata catalog; material is held by [`SecretStore`] (the login
//! Keychain on macOS, FreeDesktop Secret Service on Linux, explicitly
//! unavailable elsewhere).  Public operations
//! fan out to independent source devices through the existing authenticated
//! mesh.
//!
//! This module owns the *policy* half of the secrets data plane: which source
//! device may serve a value, what a binding is allowed to say, and where a
//! request has to be sent to be given one. The transport half — the proxy,
//! the certificates, the two TLS connections — is [`crate::egress`], and it
//! is somebody else's maintained code all the way down.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use asterism_core::durable::{self, Loaded};
use asterism_core::instance::now_unix;
use asterism_core::paths;
use asterism_core::protocol::{EgressRequest, EgressResponse, Request, Response, SecretValue};
use asterism_core::secret::{
    self, Binding, GuestHandle, Handle, HandleShape, Placement, Refreshed, Secret, SecretId,
    SourceDevice, ValueRevision,
};
use asterism_mesh::DeviceIdentity;

use crate::mesh::Mesh;
use crate::Node;

const CATALOG_VERSION: u32 = 1;
#[cfg(any(target_os = "macos", target_os = "linux"))]
const PLATFORM_SERVICE: &str = "dev.asterism.secret";

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
        security_framework::passwords::set_generic_password(PLATFORM_SERVICE, &account, value)
            .context("storing secret in the macOS login Keychain")
    }

    fn get(&self, id: &SecretId) -> Result<Vec<u8>> {
        let account = self.account(id);
        security_framework::passwords::get_generic_password(PLATFORM_SERVICE, &account)
            .context("reading secret from the macOS login Keychain")
    }

    fn remove(&self, id: &SecretId) -> Result<()> {
        let account = self.account(id);
        security_framework::passwords::delete_generic_password(PLATFORM_SERVICE, &account)
            .context("removing secret from the macOS login Keychain")
    }
}

#[cfg(target_os = "linux")]
struct PlatformSecretStore {
    namespace: String,
}

#[cfg(target_os = "linux")]
impl PlatformSecretStore {
    fn entry(&self, id: &SecretId) -> Result<keyring::Entry> {
        let account = format!("{}:{}", self.namespace, id.as_str());
        keyring::Entry::new(PLATFORM_SERVICE, &account).context(
            "opening FreeDesktop Secret Service (org.freedesktop.secrets); \
             no plaintext fallback is used",
        )
    }
}

#[cfg(target_os = "linux")]
impl SecretStore for PlatformSecretStore {
    fn put(&self, id: &SecretId, value: &[u8]) -> Result<()> {
        self.entry(id)?
            .set_secret(value)
            .context("storing secret in FreeDesktop Secret Service")
    }

    fn get(&self, id: &SecretId) -> Result<Vec<u8>> {
        match self.entry(id)?.get_secret() {
            Ok(value) => Ok(value),
            Err(keyring::Error::NoEntry) => {
                bail!("secret {:?} is not in Secret Service", id.as_str())
            }
            Err(error) => Err(error).context("reading secret from FreeDesktop Secret Service"),
        }
    }

    fn remove(&self, id: &SecretId) -> Result<()> {
        match self.entry(id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error).context("removing secret from FreeDesktop Secret Service"),
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
struct PlatformSecretStore {
    #[allow(dead_code)]
    namespace: String,
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
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

/// The on-disk catalog.
///
/// Note what is *not* here: bindings. When they were a bare
/// `(secret, authority)` pair they could plausibly have lived beside the
/// metadata; now that one carries an opaque guest handle, it is a per-instance
/// bearer credential, and this file replicates to every device in the orbit.
/// A binding lives on its instance, in that device's shard, and travels only
/// with the instance.
#[derive(Debug, Serialize, Deserialize)]
struct CatalogFile {
    version: u32,
    #[serde(default)]
    secrets: Vec<Secret>,
}

struct Catalog {
    path: PathBuf,
    secrets: Vec<Secret>,
}

impl Catalog {
    fn load(path: &Path) -> Result<Self> {
        let loaded =
            durable::load_json_versioned::<CatalogFile>(path, "secret metadata", CATALOG_VERSION)?;
        let file = match loaded {
            Some(Loaded { value, repaired }) => {
                if let Some(why) = repaired {
                    // The values themselves are in the platform store and are
                    // untouched by any of this; what a repair can cost is the
                    // *binding* written by the last commit, which is why the
                    // user is told rather than left to find a guest that
                    // cannot see its secret.
                    eprintln!("astd: {why}");
                }
                value
            }
            None => CatalogFile {
                version: CATALOG_VERSION,
                secrets: Vec::new(),
            },
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
        })
    }

    fn save(&self) -> Result<()> {
        let file = CatalogFile {
            version: CATALOG_VERSION,
            secrets: self.secrets.clone(),
        };
        // Private from the first byte: the catalog names authorities and
        // handles, and which instance is bound to which credential is not
        // for a second user on this machine to read.
        durable::commit_json_private(&self.path, &file).context("committing secret metadata")
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

    /// Put the platform store back in the state it had before a metadata
    /// commit was attempted. Secret Service and Keychain are the durable side
    /// of this transaction: a failed compensation must be returned to the
    /// caller, never hidden behind the original catalog error.
    fn restore_material(&self, id: &SecretId, previous: Option<&[u8]>) -> Result<()> {
        match previous {
            Some(bytes) => self
                .store
                .put(id, bytes)
                .context("restoring the previous value in the platform secret store"),
            None => self
                .store
                .remove(id)
                .context("removing the uncommitted value from the platform secret store"),
        }
    }

    fn compensation_error(
        operation: &str,
        commit: anyhow::Error,
        restore: anyhow::Error,
    ) -> anyhow::Error {
        anyhow!(
            "{operation} metadata did not commit: {commit:#}; compensation also failed: \
             {restore:#}. The platform secret store may not match the catalog; retry the \
             operation after repairing Secret Service/Keychain access"
        )
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

    /// Take custody of material for one secret on this device.
    ///
    /// The metadata arriving alongside the bytes names the lineage and the
    /// revision they belong to, which is what makes this the authenticated
    /// copy path: a second source becomes interchangeable with the first only
    /// by receiving both together.  Bytes offered under a lineage this device
    /// already knows the name by are the partitioned create seen from the
    /// source side, and this is the last place able to refuse them.
    fn put(&self, secret: Secret, value: &SecretValue) -> Result<Secret> {
        let source = secret
            .sources
            .iter()
            .find(|source| source.device_id == self.device_id)
            .cloned()
            .ok_or_else(|| anyhow!("source metadata does not identify this device"))?;
        if let Some(conflict) = secret.conflict() {
            bail!(
                "refusing to hold material for secret {:?}: {conflict}",
                secret.name
            );
        }
        let mut catalog = self.catalog.lock().expect("secret catalog poisoned");
        if let Some(held) = catalog.secrets.iter().find(|held| held.id == secret.id) {
            if held
                .sources
                .iter()
                .any(|held| held.device_id == self.device_id)
            {
                bail!(
                    "secret {:?} already has a source on this device; use `ast secret rotate`",
                    secret.name
                );
            }
            if let Some(other) = held
                .sources
                .iter()
                .find(|known| known.origin != source.origin)
            {
                bail!(
                    "secret {:?} is already a different value in this orbit, held by {}; \
                     remove it from every source before creating it again",
                    secret.name,
                    other.device
                );
            }
        }
        self.store.put(&secret.id, value.as_bytes())?;
        let snapshot = catalog.secrets.clone();
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
            catalog.secrets = snapshot;
            if let Err(restore) = self.restore_material(&local.id, None) {
                return Err(Self::compensation_error("creating secret", e, restore));
            }
            return Err(e.context("creating secret metadata"));
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
        let held = catalog.secrets[index].clone();
        let previous_bytes = if held
            .sources
            .iter()
            .any(|source| source.device_id == self.device_id)
        {
            Some(
                self.store
                    .get(id)
                    .context("reading the value before removing its metadata")?,
            )
        } else {
            None
        };
        if previous_bytes.is_some() {
            self.store.remove(id)?;
        }
        let snapshot = catalog.secrets.clone();
        let removed = catalog.secrets.remove(index);
        if let Err(e) = catalog.save() {
            catalog.secrets = snapshot;
            if let Some(bytes) = previous_bytes.as_deref() {
                if let Err(restore) = self.restore_material(id, Some(bytes)) {
                    return Err(Self::compensation_error("removing secret", e, restore));
                }
            }
            return Err(e.context("removing secret metadata"));
        }
        Ok(removed)
    }

    fn rotate(
        &self,
        id: &SecretId,
        version: u64,
        updated_at: u64,
        revision: &ValueRevision,
        value: &SecretValue,
    ) -> Result<Secret> {
        let mut catalog = self.catalog.lock().expect("secret catalog poisoned");
        let index = catalog
            .secrets
            .iter()
            .position(|secret| &secret.id == id)
            .ok_or_else(|| anyhow!("this device is not a source for secret {:?}", id.as_str()))?;
        let secret = &catalog.secrets[index];
        if !secret
            .sources
            .iter()
            .any(|source| source.device_id == self.device_id)
        {
            bail!("this device is not a source for secret {:?}", id.as_str());
        }
        if let Some(conflict) = secret.conflict() {
            bail!(
                "secret {:?} cannot be rotated while it is in conflict: {conflict}",
                secret.name
            );
        }
        if version <= secret.version {
            bail!(
                "secret {:?} is already at version {}",
                secret.name,
                secret.version
            );
        }
        // The orbit mints one revision per rotation and hands the same one to
        // every source.  Reusing a revision already in this secret would claim
        // these bytes are ones some source is known to hold.
        if secret
            .sources
            .iter()
            .any(|source| &source.revision == revision)
        {
            bail!(
                "secret {:?} was handed a value revision one of its sources already holds",
                secret.name
            );
        }
        let previous_bytes = self
            .store
            .get(id)
            .context("reading the current value before rotating it")?;
        let previous_secret = secret.clone();
        self.store.put(id, value.as_bytes())?;
        let changed = {
            let secret = &mut catalog.secrets[index];
            secret.version = version;
            secret.updated_at = updated_at;
            for source in &mut secret.sources {
                if source.device_id == self.device_id {
                    source.version = version;
                    source.updated_at = updated_at;
                    source.revision = revision.clone();
                }
            }
            secret.clone()
        };
        if let Err(e) = catalog.save() {
            catalog.secrets[index] = previous_secret;
            if let Err(restore) = self.restore_material(id, Some(&previous_bytes)) {
                return Err(Self::compensation_error("rotating secret", e, restore));
            }
            return Err(e.context("rotating secret metadata"));
        }
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
        if let Some(conflict) = secret.conflict() {
            bail!(
                "secret {:?} is in conflict — {conflict}; resolve it before use",
                secret.name
            );
        }
        if secret.version != handle.version || handle.source.version != handle.version {
            bail!(
                "secret {:?} rotated from version {} to {}; select a fresh handle",
                secret.name,
                handle.version,
                secret.version
            );
        }
        let local = secret
            .sources
            .iter()
            .find(|source| source.device_id == self.device_id)
            .ok_or_else(|| anyhow!("this device is not a source for that secret"))?;
        // The version alone cannot say which value it meant.  A handle
        // selected from a snapshot taken on the far side of a partition can
        // name this version and still mean the other lineage's bytes.
        if local.origin != handle.source.origin || local.revision != handle.source.revision {
            bail!(
                "secret {:?} does not hold the value this handle selected; select a fresh handle",
                secret.name
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
            | Request::SecretSourceEgress { .. }
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

pub(crate) async fn serve_source(req: Request) -> Response {
    // The one source operation that is not a question about the catalog: it
    // resolves material and then spends a network round trip with it. It is
    // answered before the lock below is taken, because it holds no lock at
    // all while it is waiting on somebody else's server.
    if let Request::SecretSourceEgress { handle, request } = req {
        return crate::egress::serve_source(handle, *request).await;
    }
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
                revision,
                value,
            } => Ok(Response::Secrets {
                secrets: vec![plane.rotate(&id, version, updated_at, &revision, &value)?],
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
    let secret = match existing {
        None => begin_lineage(id, name, &source, value, now, node, mesh).await?,
        Some(existing) => widen_by_rotation(existing, &source, value, now, node, mesh).await?,
    };
    sync_metadata(&secret, node, mesh).await;
    Ok(Response::Secrets {
        secrets: list(node, mesh).await?,
    })
}

/// Create a name nobody in the orbit has used, on one source device.
async fn begin_lineage(
    id: SecretId,
    name: &str,
    source: &SourceRoute,
    value: SecretValue,
    now: u64,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<Secret> {
    // A lineage is named by the first value in it, so origin and first
    // revision are one mint.  Nothing derives either from the bytes.
    let origin = ValueRevision::mint();
    let target_source = SourceDevice {
        device_id: source.device_id.clone(),
        device: source.device.clone(),
        version: 1,
        updated_at: now,
        origin: origin.clone(),
        revision: origin,
    };
    let secret = Secret {
        id,
        name: name.to_owned(),
        version: 1,
        created_at: now,
        updated_at: now,
        sources: vec![target_source.clone()],
    };
    expect_source_ok(
        call_source(
            source,
            Request::SecretSourcePut {
                secret: secret.clone(),
                value,
            },
            node,
            mesh,
        )
        .await,
        &target_source.device,
    )?;
    Ok(secret)
}

/// Add a source to a name the orbit already holds.
///
/// The bytes on stdin cannot be checked against the value the orbit already
/// has: the only check would be a digest, and a digest of a secret in
/// replicated metadata is an offline verifier for every weak value in the
/// orbit.  So this does not pretend the new device is joining at the current
/// version.  It is an explicit rotation that happens to widen the source set:
/// one fresh revision reaches the joining device and every existing source, so
/// they end interchangeable no matter what was typed.  If a source cannot be
/// reached the operation fails rather than leaving two values at one version,
/// which is the state this whole design exists to make unrepresentable.
async fn widen_by_rotation(
    existing: Secret,
    source: &SourceRoute,
    value: SecretValue,
    now: u64,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<Secret> {
    let name = existing.name.clone();
    if let Some(conflict) = existing.conflict() {
        bail!(
            "secret {name:?} is in conflict — {conflict}; remove it from every source with \
             `ast secret rm {name}` and create it once"
        );
    }
    if existing
        .sources
        .iter()
        .any(|held| held.device_id == source.device_id)
    {
        bail!(
            "secret {name:?} already has {} as a source; use `ast secret rotate`",
            source.device
        );
    }
    let origin = existing
        .sources
        .first()
        .map(|held| held.origin.clone())
        .ok_or_else(|| anyhow!("secret {name:?} has no source to join"))?;
    let version = existing.version.saturating_add(1);
    let revision = ValueRevision::mint();
    let joining = SourceDevice {
        device_id: source.device_id.clone(),
        device: source.device.clone(),
        version,
        updated_at: now,
        origin,
        revision: revision.clone(),
    };

    // The joining device is told the truth as it stands: it holds the new
    // revision, and the existing sources are still on the old one.  Announcing
    // them as already rotated would make a value they no longer hold look
    // current if the rotation below then failed.
    let mut sources = existing.sources.clone();
    sources.push(joining.clone());
    let secret = Secret {
        version,
        updated_at: now,
        sources,
        ..existing.clone()
    };
    expect_source_ok(
        call_source(
            source,
            Request::SecretSourcePut {
                secret: secret.clone(),
                value: value.clone(),
            },
            node,
            mesh,
        )
        .await,
        &joining.device,
    )?;

    let mut failures = Vec::new();
    for held in &existing.sources {
        let request = Request::SecretSourceRotate {
            id: existing.id.clone(),
            version,
            updated_at: now,
            revision: revision.clone(),
            value: value.clone(),
        };
        let reply = call_source(&SourceRoute::to(held), request, node, mesh).await;
        if let Err(e) = expect_source_ok(reply, &held.device) {
            failures.push(format!("{e:#}"));
        }
    }
    if !failures.is_empty() {
        bail!(
            "{} joined secret {name:?} at version {version}, but the value did not reach every \
             existing source: {}. Finish with `ast secret rotate {name}`.",
            joining.device,
            failures.join("; ")
        );
    }

    let mut widened = secret;
    for source in &mut widened.sources {
        source.version = version;
        source.updated_at = now;
        source.revision = revision.clone();
    }
    Ok(widened)
}

/// Collapse one source device's reply into a plain success or a named failure.
fn expect_source_ok(reply: Result<Response>, device: &str) -> Result<()> {
    match reply {
        Ok(Response::Secrets { .. }) => Ok(()),
        Ok(Response::Error { message }) => bail!("{device}: {message}"),
        Ok(other) => bail!("{device}: unexpected {other:?}"),
        Err(e) => bail!("{device}: {e:#}"),
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
            .map(|peer| SourceRoute {
                device_id: peer.device_id.clone(),
                device: peer.name.clone(),
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
    if let Some(conflict) = secret.conflict() {
        bail!(
            "secret {name:?} is in conflict — {conflict}; rotating would hand every source one \
             value and silently discard the other, so remove it with `ast secret rm {name}` and \
             create it once"
        );
    }
    let version = secret.version.saturating_add(1);
    let updated_at = now_unix();
    // One mint for the whole orbit.  Every source that accepts these bytes
    // records the same revision, and that shared revision is the only thing
    // that later proves they agree.
    let revision = ValueRevision::mint();
    let mut failures = Vec::new();
    for source in &secret.sources {
        let request = Request::SecretSourceRotate {
            id: id.clone(),
            version,
            updated_at,
            revision: revision.clone(),
            value: value.clone(),
        };
        let reply = call_source(&SourceRoute::to(source), request, node, mesh).await;
        if let Err(e) = expect_source_ok(reply, &source.device) {
            failures.push(format!("{e:#}"));
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
        source.revision = revision.clone();
    }
    sync_metadata(&rotated, node, mesh).await;
    Ok(Response::Secrets {
        secrets: list(node, mesh).await?,
    })
}

/// Where to send a source operation: the mesh identity, plus the name to
/// route by today.
///
/// This is deliberately not a [`SourceDevice`].  A routing target has no
/// version and no revision, and the placeholders it would need are exactly the
/// fields the merge trusts to decide whether two devices hold one value.
#[derive(Clone)]
struct SourceRoute {
    device_id: String,
    device: String,
}

impl SourceRoute {
    fn to(source: &SourceDevice) -> Self {
        Self {
            device_id: source.device_id.clone(),
            device: source.device.clone(),
        }
    }
}

async fn source_identity(target: Option<&str>, node: &Node) -> Result<SourceRoute> {
    let plane = plane()?;
    let orbit = node.orbit.lock().await;
    match target {
        None => Ok(SourceRoute {
            device_id: plane.device_id.clone(),
            device: orbit.self_name().to_owned(),
        }),
        Some(name) if name == orbit.self_name() => Ok(SourceRoute {
            device_id: plane.device_id.clone(),
            device: name.to_owned(),
        }),
        Some(name) => orbit
            .get(name)
            .map(|peer| SourceRoute {
                device_id: peer.device_id.clone(),
                device: peer.name.clone(),
            })
            .ok_or_else(|| anyhow!("no device named {name:?} in this orbit — see: ast devices")),
    }
}

async fn call_source(
    source: &SourceRoute,
    request: Request,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<Response> {
    if source.device_id == plane()?.device_id {
        return Ok(serve_source(request).await);
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

/// Fold every device's view of the orbit's secrets into one catalog.
///
/// Merging is evidence-preserving.  It never decides that two source records
/// describe one value; it only drops a record that some other record provably
/// supersedes, and leaves everything else standing for [`Secret::conflict`] to
/// report.  The bug this replaces did the opposite: it keyed sources by device
/// alone, so two devices that had independently created one name during a
/// partition merged into a single secret with two interchangeable sources, and
/// whichever one a consumer picked was the value it got.
fn merge(secrets: impl IntoIterator<Item = Secret>) -> Vec<Secret> {
    let mut merged: BTreeMap<SecretId, Secret> = BTreeMap::new();
    for incoming in secrets {
        let secret = merged.entry(incoming.id.clone()).or_insert_with(|| Secret {
            sources: Vec::new(),
            ..incoming.clone()
        });
        secret.created_at = secret.created_at.min(incoming.created_at);
        secret.updated_at = secret.updated_at.max(incoming.updated_at);
        secret.version = secret.version.max(incoming.version);
        for source in incoming.sources {
            absorb(&mut secret.sources, source);
        }
        secret.sources.sort_by(|a, b| {
            (&a.device_id, a.version, &a.revision).cmp(&(&b.device_id, b.version, &b.revision))
        });
    }
    let mut out: Vec<_> = merged.into_values().collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Fold one source record into a secret's source list.
///
/// A device supersedes its own earlier record only inside one lineage, only
/// forward in version, and only while it speaks with a single voice.  Every
/// other shape is kept: a second lineage, or two values claimed at one
/// version, is precisely the evidence a conflict is made of, and dropping it
/// here is how a partitioned create used to disappear into a merge.
fn absorb(sources: &mut Vec<SourceDevice>, incoming: SourceDevice) {
    let same_lineage = |held: &SourceDevice| {
        held.device_id == incoming.device_id && held.origin == incoming.origin
    };
    // A record already held, or one this device has moved past, adds nothing.
    if sources.iter().any(|held| {
        same_lineage(held)
            && (held.version > incoming.version
                || (held.version == incoming.version && held.revision == incoming.revision))
    }) {
        return;
    }
    let (first, second) = {
        let mut lineage = sources
            .iter()
            .enumerate()
            .filter(|(_, held)| same_lineage(held))
            .map(|(index, _)| index);
        (lineage.next(), lineage.next())
    };
    match (first, second) {
        (Some(index), None) if incoming.version > sources[index].version => {
            sources[index] = incoming;
        }
        _ => sources.push(incoming),
    }
}

/// Read material for one pinned handle, on the device that holds it.
///
/// The only caller is [`crate::egress::serve_source`], and the only thing it
/// does with the result is put it in a header and open a connection. There is
/// deliberately no protocol frame that returns this: plaintext travels to the
/// upstream, never back to a consumer daemon.
pub(crate) fn resolve(handle: &Handle) -> Result<SecretValue> {
    plane()?.resolve(handle)
}

/// Everything `ast attach --secret` has to decide, on the device that will
/// run the guest.
///
/// This is where a binding is refused, and the refusals are the feature: a
/// secret nobody in the orbit has, a secret in conflict, a source device that
/// does not hold the current version, an authority that cannot be intercepted
/// honestly. Each of them is a sentence here rather than a guest that boots
/// with a handle nothing will ever honour.
pub(crate) async fn plan_binding(
    secret: &str,
    authority: &str,
    placement: Option<Placement>,
    env: Option<String>,
    source_device: Option<&str>,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<Binding> {
    let authority = secret::check_authority(authority)?;
    let id = SecretId::from_name(secret)?;
    let held = list(node, mesh)
        .await?
        .into_iter()
        .find(|held| held.id == id)
        .ok_or_else(|| anyhow!("no secret named {secret:?} in this orbit — see: ast secret ls"))?;
    if let Some(conflict) = held.conflict() {
        bail!(
            "secret {secret:?} is in conflict — {conflict}; a binding has to name one value, \
             so resolve it with `ast secret rm {secret}` and create it once before attaching it"
        );
    }
    // A named device must be a source; an unnamed one picks a source that
    // actually holds the current version, preferring this device because a
    // local resolve is a function call and a remote one is a network.
    let source = match source_device {
        Some(name) => {
            let route = source_identity(Some(name), node).await?;
            held.sources
                .iter()
                .find(|held| held.device_id == route.device_id)
                .cloned()
                .ok_or_else(|| {
                    anyhow!(
                        "{name} is not a source for secret {secret:?} — it is held by {}",
                        named(&held)
                    )
                })?
        }
        None => {
            let here = plane()?.device_id.clone();
            held.sources
                .iter()
                .find(|source| source.device_id == here && source.version == held.version)
                .or_else(|| {
                    held.sources
                        .iter()
                        .find(|source| source.version == held.version)
                })
                .cloned()
                .ok_or_else(|| {
                    anyhow!(
                        "no source for secret {secret:?} holds its current version {} — \
                         finish the rotation with `ast secret rotate {secret}`",
                        held.version
                    )
                })?
        }
    };
    // Proves now, at attach time, that this source can be asked at all.
    held.handle(&source.device_id)?;

    let placement = placement.unwrap_or_else(|| Placement::for_authority(&authority));
    let env = match env {
        Some(env) => {
            secret::check_env_name(&env)?;
            env
        }
        None => secret::default_env_name(secret),
    };
    Ok(Binding {
        id: binding_id(),
        secret_id: held.id.clone(),
        secret: held.name.clone(),
        authority: authority.clone(),
        guest_handle: GuestHandle::mint(HandleShape::for_authority(&authority)),
        placement,
        env,
        source_device_id: source.device_id.clone(),
        source_device: source.device.clone(),
        version: held.version,
        bound_at: now_unix(),
    })
}

/// The devices a secret is held by, for a refusal that has to name them.
fn named(secret: &Secret) -> String {
    let names: Vec<&str> = secret
        .sources
        .iter()
        .map(|source| source.device.as_str())
        .collect();
    match names.is_empty() {
        true => "no device".to_owned(),
        false => names.join(", "),
    }
}

/// A random id for a binding row.
///
/// Spelled through [`ValueRevision::mint`] because `uuid` is a dependency of
/// asterism-core and not of this crate, and one identifier is not worth a
/// second one — the randomness underneath is the same either way. The *type*
/// is a plain string, deliberately: a revision means "which bytes", and a
/// binding is not bytes.
fn binding_id() -> String {
    ValueRevision::mint().to_string()
}

/// The source handle to redeem for a binding, selected fresh.
///
/// Per request, and deliberately: a handle pins a version *and* the revision
/// that version meant, so one written down at attach time is a promise about
/// bytes that a later rotation makes false. Re-selecting means a rotation is
/// picked up by the next request, and a source that has genuinely gone is
/// refused here, in words, rather than as somebody else's 401.
pub(crate) async fn refresh(
    binding: &Binding,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<Refreshed> {
    let held = list(node, mesh)
        .await?
        .into_iter()
        .find(|held| held.id == binding.secret_id)
        .ok_or_else(|| {
            anyhow!(
                "secret {:?} is no longer in this orbit — the binding on this instance \
                 has nothing left to resolve",
                binding.secret
            )
        })?;
    binding.refresh(&held)
}

/// Send one outbound request to the device that holds the value.
///
/// Local when this device is the source, over the authenticated mesh when it
/// is not, and the same code either way — which is the only reason a bound
/// secret can live on a machine that is not the one running the guest.
pub(crate) async fn egress_via_source(
    binding: &Binding,
    handle: Option<Handle>,
    request: EgressRequest,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<EgressResponse> {
    let route = SourceRoute {
        device_id: binding.source_device_id.clone(),
        device: binding.source_device.clone(),
    };
    let frame = Request::SecretSourceEgress {
        handle,
        request: Box::new(request),
    };
    match call_source(&route, frame, node, mesh).await? {
        Response::Egress { response } => Ok(*response),
        Response::Error { message } => bail!("{}: {message}", route.device),
        other => bail!("{}: unexpected {other:?}", route.device),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use asterism_core::secret::SecretConflict;

    /// A store whose contents the test can still see, so a refusal can be
    /// checked to have refused before any material was written.
    #[derive(Clone, Default)]
    struct MemoryStore(Arc<StdMutex<BTreeMap<SecretId, Vec<u8>>>>);

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

    struct RestoreFailStore {
        inner: MemoryStore,
        fail_put_value: Vec<u8>,
    }

    impl SecretStore for RestoreFailStore {
        fn put(&self, id: &SecretId, value: &[u8]) -> Result<()> {
            if value == self.fail_put_value {
                bail!("injected durable restore failure");
            }
            self.inner.put(id, value)
        }

        fn get(&self, id: &SecretId) -> Result<Vec<u8>> {
            self.inner.get(id)
        }

        fn remove(&self, id: &SecretId) -> Result<()> {
            self.inner.remove(id)
        }
    }

    fn id() -> SecretId {
        SecretId::from_name("api").unwrap()
    }

    fn value(bytes: &[u8]) -> SecretValue {
        SecretValue::new(bytes.to_vec())
    }

    /// A source holding the first value of a lineage: origin and revision are
    /// the same mint, exactly as `begin_lineage` produces them.
    fn source(device_id: &str, version: u64, lineage: &ValueRevision) -> SourceDevice {
        holding(device_id, version, lineage, lineage)
    }

    /// A source that has rotated: same lineage, a revision of its own.
    fn holding(
        device_id: &str,
        version: u64,
        lineage: &ValueRevision,
        revision: &ValueRevision,
    ) -> SourceDevice {
        SourceDevice {
            device_id: device_id.into(),
            device: device_id.into(),
            version,
            updated_at: version,
            origin: lineage.clone(),
            revision: revision.clone(),
        }
    }

    fn secret(version: u64, sources: Vec<SourceDevice>) -> Secret {
        Secret {
            id: id(),
            name: "api".into(),
            version,
            created_at: 1,
            updated_at: version,
            sources,
        }
    }

    fn local_plane(path: &Path, device_id: &str, store: MemoryStore) -> SecretPlane {
        SecretPlane::new(device_id.into(), path.to_owned(), Box::new(store)).unwrap()
    }

    /// The catalog is metadata, not material: the values are in the platform
    /// store and a torn catalog cannot reach them. What a repair recovers is
    /// which secret exists and which instance is bound to it, and doing that
    /// beats starting empty — an empty catalog would read as "this device
    /// holds no secrets" while the keychain still held every one of them.
    #[test]
    fn a_torn_catalog_is_repaired_from_the_last_known_good() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let lineage = ValueRevision::mint();
        let plane = local_plane(&path, "laptop", MemoryStore::default());
        plane
            .put(
                secret(1, vec![source("laptop", 1, &lineage)]),
                &value(b"v1"),
            )
            .unwrap();
        // A second secret, so there is a second commit and therefore a
        // last-known-good copy holding only the first.
        let other = Secret {
            id: SecretId::from_name("other").unwrap(),
            name: "other".into(),
            ..secret(1, vec![source("laptop", 1, &ValueRevision::mint())])
        };
        plane.put(other, &value(b"v2")).unwrap();

        let whole = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, &whole[..whole.len() / 2]).unwrap();

        let recovered = Catalog::load(&path).expect("a torn catalog is repaired, not fatal");
        assert_eq!(recovered.secrets.len(), 1);
        assert_eq!(recovered.secrets[0].name, "api");
    }

    /// And the catalog it writes is only readable by its owner, from the
    /// first byte — the commit sets the mode on the open, so there is no
    /// window where a second user could read which authorities this device
    /// holds credentials for.
    #[test]
    fn the_catalog_is_private_from_the_first_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let lineage = ValueRevision::mint();
        let plane = local_plane(&path, "laptop", MemoryStore::default());
        plane
            .put(
                secret(1, vec![source("laptop", 1, &lineage)]),
                &value(b"v1"),
            )
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// The catalog through its own API, with the staging path already
    /// occupied by a world-readable file — a crash leftover, or something a
    /// second user on this machine put there. The metadata names every
    /// authority this device holds a credential for, and it must come out
    /// 0600 whatever was sitting in the way.
    #[cfg(unix)]
    #[test]
    fn a_planted_staging_file_cannot_make_the_catalog_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let tmp = asterism_core::durable::tmp_path(&path);
        std::fs::write(&tmp, b"planted").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).unwrap();

        let lineage = ValueRevision::mint();
        let plane = local_plane(&path, "laptop", MemoryStore::default());
        plane
            .put(
                secret(1, vec![source("laptop", 1, &lineage)]),
                &value(b"v1"),
            )
            .unwrap();

        let mode = std::fs::symlink_metadata(&path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the planted mode was adopted");
        assert!(
            !tmp.exists(),
            "and the planted file is gone, not written into"
        );
    }

    /// The same path with a symlink in the way. Following it would put the
    /// catalog wherever the link pointed, and the rename afterwards would
    /// hide that it happened.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_staging_path_cannot_redirect_the_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"victim").unwrap();
        std::os::unix::fs::symlink(&victim, asterism_core::durable::tmp_path(&path)).unwrap();

        let lineage = ValueRevision::mint();
        let plane = local_plane(&path, "laptop", MemoryStore::default());
        plane
            .put(
                secret(1, vec![source("laptop", 1, &lineage)]),
                &value(b"v1"),
            )
            .unwrap();

        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"victim",
            "the catalog went to the victim"
        );
        let catalog = Catalog::load(&path).unwrap();
        assert_eq!(catalog.secrets.len(), 1);
    }

    #[test]
    fn plaintext_never_enters_the_metadata_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let lineage = ValueRevision::mint();
        let plane = local_plane(&path, "laptop", MemoryStore::default());
        let sentinel = b"NEVER-WRITE-THIS-PLAINTEXT";
        plane
            .put(
                secret(1, vec![source("laptop", 1, &lineage)]),
                &value(sentinel),
            )
            .unwrap();
        let disk = std::fs::read(path).unwrap();
        assert!(!disk
            .windows(sentinel.len())
            .any(|window| window == sentinel));
        let text = String::from_utf8(disk).unwrap();
        assert!(text.contains("laptop"));
        // The commitment that reached the file is a mint, not a digest: it
        // cannot be recomputed from the value, so a reader of this file has no
        // offline oracle against a weak secret.
        assert!(text.contains(&lineage.to_string()));
    }

    #[test]
    fn merging_keeps_independent_sources_and_highest_version() {
        let lineage = ValueRevision::mint();
        let next = ValueRevision::mint();
        let one = secret(1, vec![source("laptop", 1, &lineage)]);
        let two = secret(2, vec![holding("desktop", 2, &lineage, &next)]);
        let merged = merge([one, two]);
        assert_eq!(merged[0].version, 2);
        assert_eq!(merged[0].sources.len(), 2);
        // One source simply has not caught up with a rotation yet, which is
        // not divergence.
        assert!(merged[0].conflict().is_none());
    }

    #[test]
    fn orbit_metadata_keeps_remote_sources_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let lineage = ValueRevision::mint();
        let current = ValueRevision::mint();
        {
            let plane = local_plane(&path, "laptop", MemoryStore::default());
            plane
                .sync(secret(
                    4,
                    vec![
                        holding("laptop", 4, &lineage, &current),
                        holding("desktop", 4, &lineage, &current),
                    ],
                ))
                .unwrap();
        }
        let restarted = local_plane(&path, "laptop", MemoryStore::default());
        assert_eq!(restarted.list()[0].sources.len(), 2);
        assert_eq!(restarted.list()[0].version, 4);
        assert!(restarted.list()[0].conflict().is_none());
    }

    #[test]
    fn source_resolution_is_version_pinned_across_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let lineage = ValueRevision::mint();
        let plane = local_plane(
            &dir.path().join("secrets.json"),
            "laptop",
            MemoryStore::default(),
        );
        plane
            .put(
                secret(1, vec![source("laptop", 1, &lineage)]),
                &value(b"old"),
            )
            .unwrap();
        let stale = plane.list()[0].handle("laptop").unwrap();
        let next = ValueRevision::mint();
        plane.rotate(&id(), 2, 2, &next, &value(b"new")).unwrap();
        assert!(plane
            .resolve(&stale)
            .unwrap_err()
            .to_string()
            .contains("rotated"));
        let fresh = plane.list()[0].handle("laptop").unwrap();
        assert_eq!(fresh.source.revision, next);
        assert_eq!(plane.resolve(&fresh).unwrap().as_bytes(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn rotate_compensates_the_store_when_the_catalog_commit_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let store = MemoryStore::default();
        let plane = local_plane(&path, "laptop", store.clone());
        let lineage = ValueRevision::mint();
        plane
            .put(
                secret(1, vec![source("laptop", 1, &lineage)]),
                &value(b"v1"),
            )
            .unwrap();
        assert_eq!(store.get(&id()).unwrap(), b"v1");

        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        let next = ValueRevision::mint();
        let err = plane.rotate(&id(), 2, 2, &next, &value(b"v2"));
        let mut restore = std::fs::metadata(dir.path()).unwrap().permissions();
        restore.set_mode(0o755);
        std::fs::set_permissions(dir.path(), restore).unwrap();
        assert!(err.is_err(), "a frozen catalog must refuse the rotation");
        assert_eq!(
            store.get(&id()).unwrap(),
            b"v1",
            "Secret Service/store mutation must roll back when metadata does not commit"
        );
        assert_eq!(plane.list()[0].version, 1);
    }

    #[test]
    fn a_failed_platform_restore_is_reported_and_metadata_is_repaired_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let store = MemoryStore::default();
        let plane = SecretPlane::new(
            "laptop".into(),
            path.clone(),
            Box::new(RestoreFailStore {
                inner: store.clone(),
                fail_put_value: b"v1".to_vec(),
            }),
        )
        .unwrap();
        let lineage = ValueRevision::mint();
        plane
            .put(
                secret(1, vec![source("laptop", 1, &lineage)]),
                &value(b"v1-initial"),
            )
            .unwrap();
        // Make the previous value the one the store will refuse only during
        // compensation, after the forward write has succeeded.
        store.put(&id(), b"v1").unwrap();

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let err = plane
            .rotate(&id(), 2, 2, &ValueRevision::mint(), &value(b"v2"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("compensation also failed"), "{err}");
        assert!(
            err.contains("repairing Secret Service/Keychain access"),
            "{err}"
        );
        assert_eq!(
            plane.list()[0].version,
            1,
            "catalog ownership was not repaired"
        );
        assert_eq!(store.get(&id()).unwrap(), b"v2");
    }

    #[test]
    fn a_partitioned_create_of_one_name_survives_the_merge_as_a_conflict() {
        // Two devices, cut off from each other, each ran `ast secret create
        // api` with a value of its own.  Both landed on the same name-derived
        // id and both called it version 1.  Before revisions this merged into
        // one secret with two sources that a consumer could pick between, and
        // it got whichever value it happened to select.
        let here = ValueRevision::mint();
        let there = ValueRevision::mint();
        let merged = merge([
            secret(1, vec![source("laptop", 1, &here)]),
            secret(1, vec![source("desktop", 1, &there)]),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].sources.len(), 2, "neither value may be dropped");
        match merged[0].conflict() {
            Some(SecretConflict::Origin { origins }) => assert_eq!(origins.len(), 2),
            other => panic!("expected an origin conflict, got {other:?}"),
        }
        assert!(merged[0].handle("laptop").is_err());
        assert!(merged[0].handle("desktop").is_err());
    }

    #[test]
    fn sources_that_diverged_at_one_version_do_not_merge_as_interchangeable() {
        // One lineage, rotated on both sides of a partition.  The origins
        // agree, so only the per-version revision separates the two values.
        let lineage = ValueRevision::mint();
        let merged = merge([
            secret(
                2,
                vec![holding("laptop", 2, &lineage, &ValueRevision::mint())],
            ),
            secret(
                2,
                vec![holding("desktop", 2, &lineage, &ValueRevision::mint())],
            ),
        ]);
        match merged[0].conflict() {
            Some(SecretConflict::Revision { version, revisions }) => {
                assert_eq!(version, 2);
                assert_eq!(revisions.len(), 2);
            }
            other => panic!("expected a revision conflict, got {other:?}"),
        }
        assert!(merged[0].handle("laptop").is_err());
    }

    #[test]
    fn one_device_claiming_two_values_at_one_version_keeps_both_records() {
        // A device cannot legitimately reach this, so a peer reporting it is
        // either confused or lying.  Collapsing the two records by device
        // would decide which of the two claims to believe; keeping them lets
        // the conflict be reported instead.
        let lineage = ValueRevision::mint();
        let merged = merge([
            secret(
                1,
                vec![holding("laptop", 1, &lineage, &ValueRevision::mint())],
            ),
            secret(
                1,
                vec![holding("laptop", 1, &lineage, &ValueRevision::mint())],
            ),
        ]);
        assert_eq!(merged[0].sources.len(), 2);
        assert!(matches!(
            merged[0].conflict(),
            Some(SecretConflict::Revision { .. })
        ));
    }

    #[test]
    fn a_conflict_outlives_a_restart_and_refuses_every_ambiguous_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let here = ValueRevision::mint();
        let there = ValueRevision::mint();
        {
            let plane = local_plane(&path, "laptop", MemoryStore::default());
            plane
                .put(secret(1, vec![source("laptop", 1, &here)]), &value(b"mine"))
                .unwrap();
            // The partition heals and the other side's metadata arrives.  A
            // sync records the conflict; refusing the frame would only hide it.
            plane
                .sync(secret(1, vec![source("desktop", 1, &there)]))
                .unwrap();
        }

        let restarted = local_plane(&path, "laptop", MemoryStore::default());
        let held = restarted.list().remove(0);
        assert!(matches!(
            held.conflict(),
            Some(SecretConflict::Origin { .. })
        ));

        // Rotating would hand every source one value and quietly destroy the
        // other, so it is refused until a human resolves the name.
        let refused = restarted
            .rotate(&id(), 2, 2, &ValueRevision::mint(), &value(b"either"))
            .unwrap_err()
            .to_string();
        assert!(refused.contains("conflict"), "{refused}");

        // A handle cannot be obtained for an ambiguous secret, and one built
        // by hand from the pre-partition view does not get around that.
        assert!(held.handle("laptop").is_err());
        let forged = Handle {
            secret_id: id(),
            source: source("laptop", 1, &here),
            version: 1,
        };
        assert!(restarted
            .resolve(&forged)
            .unwrap_err()
            .to_string()
            .contains("conflict"));
    }

    #[test]
    fn a_source_refuses_material_offered_under_a_foreign_lineage() {
        // The partitioned create seen from the joining device: it already
        // knows this name as another value, so the bytes on offer are not a
        // copy of anything, whatever the version says.
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::default();
        let plane = local_plane(&dir.path().join("secrets.json"), "desktop", store.clone());
        let here = ValueRevision::mint();
        let there = ValueRevision::mint();
        plane
            .sync(secret(1, vec![source("laptop", 1, &here)]))
            .unwrap();
        let refused = plane
            .put(
                secret(1, vec![source("desktop", 1, &there)]),
                &value(b"a different value"),
            )
            .unwrap_err()
            .to_string();
        assert!(refused.contains("different value"), "{refused}");
        assert!(
            store.0.lock().unwrap().is_empty(),
            "material must not be stored by a refused put"
        );
    }

    #[test]
    fn copying_one_revision_to_a_second_source_keeps_both_usable() {
        // The valid way to widen a source set: the bytes travel on the
        // authenticated source path together with the lineage and revision
        // they belong to, so the second device becomes interchangeable with
        // the first instead of merely claiming the same version.
        let dir = tempfile::tempdir().unwrap();
        let lineage = ValueRevision::mint();
        let holder = local_plane(
            &dir.path().join("laptop.json"),
            "laptop",
            MemoryStore::default(),
        );
        holder
            .put(
                secret(1, vec![source("laptop", 1, &lineage)]),
                &value(b"token"),
            )
            .unwrap();

        let joining = local_plane(
            &dir.path().join("desktop.json"),
            "desktop",
            MemoryStore::default(),
        );
        joining
            .put(
                secret(
                    1,
                    vec![
                        source("laptop", 1, &lineage),
                        source("desktop", 1, &lineage),
                    ],
                ),
                &value(b"token"),
            )
            .unwrap();

        let merged = merge([holder.list(), joining.list()].concat());
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].sources.len(), 2);
        assert!(merged[0].conflict().is_none());
        assert!(merged[0].handle("laptop").is_ok());
        let handle = merged[0].handle("desktop").unwrap();
        assert_eq!(handle.source.revision, lineage);
        assert_eq!(joining.resolve(&handle).unwrap().as_bytes(), b"token");
    }

    #[test]
    fn one_rotation_reaches_every_source_as_the_same_revision() {
        // The counterpart of the divergence test: a rotation that the orbit
        // drove from one mint leaves the sources agreeing, so the conflict
        // check must stay quiet or it would fire on every ordinary rotation.
        let dir = tempfile::tempdir().unwrap();
        let lineage = ValueRevision::mint();
        let both = secret(
            1,
            vec![
                source("laptop", 1, &lineage),
                source("desktop", 1, &lineage),
            ],
        );
        let laptop = local_plane(
            &dir.path().join("laptop.json"),
            "laptop",
            MemoryStore::default(),
        );
        let desktop = local_plane(
            &dir.path().join("desktop.json"),
            "desktop",
            MemoryStore::default(),
        );
        laptop.put(both.clone(), &value(b"one")).unwrap();
        desktop.put(both, &value(b"one")).unwrap();

        let next = ValueRevision::mint();
        laptop.rotate(&id(), 2, 2, &next, &value(b"two")).unwrap();
        desktop.rotate(&id(), 2, 2, &next, &value(b"two")).unwrap();

        let merged = merge([laptop.list(), desktop.list()].concat());
        assert_eq!(merged[0].version, 2);
        assert_eq!(merged[0].sources.len(), 2);
        assert!(merged[0].conflict().is_none());
        assert_eq!(merged[0].handle("laptop").unwrap().source.revision, next);

        // Replaying a revision would tell the other sources they still hold
        // bytes that have since been replaced.
        assert!(laptop.rotate(&id(), 3, 3, &next, &value(b"three")).is_err());
    }

    #[test]
    fn source_requests_are_distinct_from_orbit_operations() {
        assert!(is_orbit_request(&Request::SecretList));
        assert!(!is_source_request(&Request::SecretList));
        assert!(is_source_request(&Request::SecretSourceList));
        assert!(!is_orbit_request(&Request::SecretSourceList));
    }
}
