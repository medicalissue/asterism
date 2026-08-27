//! Which device in the orbit holds an instance, answered in one call, with
//! the refusals already worded.
//!
//! Instance names are unique across an orbit and every command addresses one
//! by its bare name — `ast open bot:3000`, `ast ssh bot`, and eventually
//! anything else that has to reach a guest. None of them should mention a
//! device, so each of them needs the same question answered: *is this one
//! here, is it somewhere else, or is it nowhere I can reach?*
//!
//! That question has three answers and two of them are refusals, which is why
//! it lives here rather than being re-derived by each caller. A caller that
//! wrote its own would get the easy answer right and the two hard ones
//! subtly differently:
//!
//! * **Local first.** An instance this device holds needs no mesh at all.
//!   Asking peers about it would make the common case — the agent and the
//!   browser on one machine — depend on the orbit being reachable, which it
//!   is not required to be.
//! * **"No such instance" and "its device is not answering" are different
//!   sentences**, and telling them apart needs the *assembled* orbit rather
//!   than a name lookup: [`Mesh::orbit_registry`] keeps the rows of a device
//!   that did not answer, from the shard cache, and marks them not live. A
//!   plain lookup would report a sleeping laptop's instance as a typo.
//! * **A refusal names the orbit it looked in.** An unknown name comes back
//!   with the names that *are* there, because that is the next thing the user
//!   would ask for.
//!
//! [`Mesh::orbit_registry`]: crate::mesh::Mesh::orbit_registry

use std::sync::Arc;

use anyhow::{bail, Result};

use asterism_core::names;
use asterism_core::open;
use asterism_core::protocol::Response;
use asterism_core::registry::OrbitRow;

use crate::mesh::Mesh;
use crate::{instance, Node};

/// Where an instance's compute is, seen from the device the user is at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Located {
    /// This device holds the row, and therefore the guest.
    Here,
    /// Another device does, and it is answering right now.
    On(String),
    /// The name is a *device* in this orbit rather than an instance.
    ///
    /// Only [`resolve`] ever returns this. The instance-addressed commands
    /// call [`locate`], which refuses a device name rather than pretending
    /// there is a guest behind it.
    Device(String),
}

/// What one bare name means in this orbit — the whole namespace, in one call.
///
/// [`locate`] answers "where is this instance"; this answers the question in
/// front of it, "what is this". They are separate because most commands are
/// only ever about instances and should refuse a device name with the same
/// sentence as any other name that is not an instance. `ast ssh` is the
/// exception that motivates this one: it is two entirely different
/// operations, chosen by what the name turns out to be.
///
/// Instances are looked up first, and that ordering is free rather than a
/// tie-break: a name cannot be both. `claim` refuses an instance named after
/// a device and pairing refuses a device named after an instance, so by the
/// time anything is asked here the namespace has one entry per name.
pub(crate) async fn resolve(name: &str, node: &Node, mesh: Option<&Arc<Mesh>>) -> Result<Located> {
    let local = {
        let mut reg = node.shard.lock().await;
        instance::reconcile(&mut reg);
        reg.get(name).ok().cloned()
    };
    if local.is_some() {
        return Ok(Located::Here);
    }
    let myself = node.device_name().await;
    if myself == name {
        return Ok(Located::Device(name.to_owned()));
    }

    // No mesh: this device is the whole orbit, so the only device name there
    // is is its own, and the only instances are the ones it holds.
    let Some(mesh) = mesh else {
        let mine = {
            let reg = node.shard.lock().await;
            let mut names: Vec<String> = reg.list().into_iter().map(|held| held.name).collect();
            names.sort();
            names
        };
        bail!(names::unknown_name(name, &[myself], &mine));
    };
    let devices = mesh.device_names().await;
    if devices.iter().any(|device| device == name) {
        return Ok(Located::Device(name.to_owned()));
    }

    let rows = orbit_rows(node, mesh).await?;
    let Some(row) = rows.iter().find(|row| row.instance.name == name) else {
        bail!(names::unknown_name(name, &devices, &names_of(&rows)));
    };
    let device = row.instance.cpu_device.clone();
    if !row.live {
        let seen = mesh.last_seen(&device).await.map(age_of);
        bail!(open::device_offline(&device, seen, name));
    }
    Ok(Located::On(device))
}

/// Find `name` anywhere in this orbit: this device first, then every peer.
///
/// `subject` is what the user asked for, as they would recognise it —
/// `bot:3000` for `ast open`, `bot` for a command that names only the
/// instance. It appears in the offline refusal, which is a sentence about the
/// *device* with the thing that became unreachable named at the end of it.
///
/// Errors are the two refusals, already worded, and are meant to be shown
/// verbatim.
pub(crate) async fn locate(
    name: &str,
    subject: &str,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<Located> {
    let local = {
        let mut reg = node.shard.lock().await;
        instance::reconcile(&mut reg);
        reg.get(name).ok().cloned()
    };
    if local.is_some() {
        return Ok(Located::Here);
    }

    // No mesh at all: this device's shard *is* the orbit, and it does not
    // have it.
    let Some(mesh) = mesh else {
        bail!(open::unknown_instance(name, &[]));
    };

    let rows = orbit_rows(node, mesh).await?;
    let Some(row) = rows.iter().find(|row| row.instance.name == name) else {
        bail!(open::unknown_instance(name, &names_of(&rows)));
    };
    let device = row.instance.cpu_device.clone();
    if !row.live {
        let seen = mesh.last_seen(&device).await.map(age_of);
        bail!(open::device_offline(&device, seen, subject));
    }
    Ok(Located::On(device))
}

/// The assembled orbit registry, or the refusal that assembling it produced.
async fn orbit_rows(node: &Node, mesh: &Arc<Mesh>) -> Result<Vec<OrbitRow>> {
    match mesh.orbit_registry(node).await? {
        Response::Orbit { rows } => Ok(rows),
        Response::Error { message } => bail!(message),
        other => bail!("the orbit registry answered with {other:?}"),
    }
}

/// Every instance name in the orbit, sorted and deduplicated, for the
/// "unknown instance" refusal to list.
fn names_of(rows: &[OrbitRow]) -> Vec<String> {
    let mut names: Vec<String> = rows.iter().map(|row| row.instance.name.clone()).collect();
    names.sort();
    names.dedup();
    names
}

/// How long ago a Unix timestamp was, in seconds, saturating at zero.
///
/// Clocks on two devices disagree, and a "last seen" from four seconds in the
/// future is a clock skew rather than a fact worth reporting as one.
fn age_of(seen_at: u64) -> u64 {
    asterism_core::instance::now_unix().saturating_sub(seen_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::instance::Instance;

    fn row(name: &str, live: bool) -> OrbitRow {
        let instance = Instance::new(
            name,
            "dev5",
            "debian:13",
            asterism_core::instance::Shape::default(),
            asterism_core::hv::Machine {
                backend: "qemu".into(),
                machine_type: "virt".into(),
                cpu: "host".into(),
                hv_version: "test".into(),
            },
        );
        OrbitRow { instance, live }
    }

    #[test]
    fn the_orbits_names_are_sorted_and_unique() {
        let rows = vec![row("web", true), row("bot", true), row("web", false)];
        assert_eq!(names_of(&rows), vec!["bot".to_owned(), "web".to_owned()]);
    }

    #[test]
    fn a_last_seen_from_the_future_is_zero_rather_than_a_huge_number() {
        let now = asterism_core::instance::now_unix();
        assert_eq!(age_of(now + 3_600), 0);
        assert!(age_of(now.saturating_sub(120)) >= 120);
    }

    /// The offline refusal is about the device, and names whatever the caller
    /// was after — a `NAME:PORT` for `ast open`, a bare name for a command
    /// that has no port in it.
    #[test]
    fn the_offline_refusal_takes_the_callers_words_for_the_subject() {
        assert_eq!(
            open::device_offline("dev5", Some(252), "bot:3000"),
            "dev5 is offline (last seen 4 min ago) — bot:3000 is unreachable"
        );
        assert_eq!(
            open::device_offline("dev5", Some(252), "bot"),
            "dev5 is offline (last seen 4 min ago) — bot is unreachable"
        );
    }
}
