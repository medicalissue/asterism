//! `ast ssh` — where to point ssh at, and what has to stay alive for that
//! address to keep working.
//!
//! Not part of [`crate::instance`], because this is the one instance command
//! whose answer outlives its own reply. When the guest's cpu is on another
//! device the address handed back is a listener *this* daemon just bound and
//! spliced over the mesh, and the [`Splice`] that keeps it up belongs to the
//! connection that asked — so this is answered in [`crate::serve`], where a
//! connection's lifetime is, and not in the shard dispatch, where there is
//! nothing to hang it on.
//!
//! The two cases produce the same shape on purpose: a loopback host and a
//! port. Nothing below the reply knows which case it was, and neither does
//! the user.

use std::sync::Arc;

use anyhow::{Context, Result};

use asterism_core::instance::Instance;
use asterism_core::paths;
use asterism_core::protocol::Response;
use asterism_core::registry;

use crate::mesh::{Mesh, Splice};
use crate::{instance, Node};

/// Where `ssh` should be pointed to reach `name`'s guest, and whatever has to
/// stay alive for that address to keep working.
///
/// When this device supplies the guest's cpu the address is the hypervisor's
/// own forwarded port and nothing needs holding open. When another device
/// does, the mesh puts a listener here and splices it there, and the returned
/// [`Splice`] is what the caller must keep to keep it.
pub(crate) async fn endpoint(
    name: &str,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> (Response, Option<Splice>) {
    let local = {
        let mut reg = node.shard.lock().await;
        instance::reconcile(&mut reg);
        reg.get(name).ok().cloned()
    };

    if let Some(inst) = local {
        if let Some(conflict) = &inst.conflict {
            return (
                Response::Error { message: registry::conflicted(&inst, conflict) },
                None,
            );
        }
        let Some(endpoint) = inst.endpoint() else {
            return (not_running(name), None);
        };
        let (host, port) = endpoint.ssh_target();
        let identity = match guest_identity(&inst, node, mesh).await {
            Ok(identity) => identity,
            Err(e) => return (Response::Error { message: format!("{e:#}") }, None),
        };
        return (Response::SshEndpoint { host, port, identity }, None);
    }

    let Some(mesh) = mesh else {
        return (
            Response::Error {
                message: format!("no instance named {name:?} in this orbit"),
            },
            None,
        );
    };
    match mesh.ssh_splice(name).await {
        Ok(Some((port, identity, splice))) => (
            Response::SshEndpoint { host: "127.0.0.1".into(), port, identity },
            Some(splice),
        ),
        Ok(None) => (
            Response::Error {
                message: format!("no instance named {name:?} in this orbit"),
            },
            None,
        ),
        Err(e) => (Response::Error { message: format!("{e:#}") }, None),
    }
}

/// The key file that opens a guest, from this device.
///
/// Usually this device's own: the guest was seeded here. After a cpu-part
/// swap it is the *seeding* device's, because the seed travelled with the
/// instance and a guest trusts the key that is in its seed — which is a
/// property of the instance, not of whoever is running it today.
async fn guest_identity(
    inst: &Instance,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<String> {
    // Reached only for a row this device holds, so an instance with nothing
    // recorded was seeded here — that was the invariant before instances
    // could move. Falling back to *this device* rather than to the recorded
    // cpu device also survives a device rename, which leaves old rows naming
    // a device by a name it no longer answers to.
    let here = node.device_name().await;
    let seeder = inst.seed_device.as_deref().unwrap_or(&here);
    if seeder == here {
        asterism_core::seed::ensure_asterism_key()
            .context("preparing this device's guest key")?;
        return Ok(paths::ssh_key_path().display().to_string());
    }
    let mesh = mesh.ok_or_else(|| {
        anyhow::anyhow!(
            "instance {:?} was seeded by {seeder}, whose guest key opens it, and this \
             daemon has no mesh endpoint to ask for it",
            inst.name
        )
    })?;
    mesh.guest_key_of(seeder).await
}

fn not_running(name: &str) -> Response {
    Response::Error {
        message: format!("instance {name:?} is not running — `ast up {name}` first"),
    }
}
