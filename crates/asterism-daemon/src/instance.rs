//! Everything this device answers out of its own shard of the orbit
//! registry: defining an instance, booting it, stopping it, renaming it,
//! deleting it, and hanging volumes off it.
//!
//! This is the last stop in [`crate::handle`]'s chain and therefore the one
//! that owns the refusal at the end of it. A request that no area claimed is
//! one this device's shard cannot answer, and saying so here — once, in one
//! place — is what lets every other area be a short list of frames it does
//! know rather than a long list of frames it does not.
//!
//! The split exists so that six branches adding six commands are six edits to
//! six files. Adding an instance command means a variant in
//! [`asterism_core::protocol`] and an arm in [`serve`]; nothing in `main.rs`
//! moves, because `main.rs` no longer knows what an instance command is.
//!
//! # What the shard is not
//!
//! Nothing here consults the orbit. By the time a request reaches this module
//! its name has already been resolved (or claimed) against every device, so
//! this is deliberately the shard-local end of the world — which is also what
//! stops a forwarded request from fanning out again on arrival.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use asterism_core::durable;
use asterism_core::hv::{GuestHealth, ImageKind, RunState, STOP_DEADLINE};
use asterism_core::instance::{local_host, Instance, Policy, Restart, Status};
use asterism_core::profile;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::{self, Shard};
use asterism_core::volume::{AttachIntent, AttachIntents, ReleaseIntent, ReleaseIntents};
use asterism_core::{backup, compat};
use asterism_core::{paths, VERSION};

use crate::mesh::Mesh;
use crate::{backend, egress, persist, swap, volume, Node};

/// A startup recovery attempt may span more than one provider round trip,
/// but it may not keep daemon startup hostage indefinitely. Cancellation is
/// safe because the durable intent remains and the next startup retries it.
const STORAGE_RECOVERY_DEADLINE: Duration = Duration::from_secs(30);

/// Answer one request against this device's shard.
///
/// Reached from the unix socket and from a mesh stream alike — a forwarded
/// request is not a different kind of request, it just arrived by a different
/// door, and that is the whole reason no command needed a second
/// implementation to be answerable from anywhere in the orbit.
pub(crate) async fn serve(req: Request, reg: &mut Shard, cpu_device: &str) -> Response {
    // Reads answer straight from memory; mutations persist before replying.
    let mutation = match req {
        // The version handshake, answered here rather than earlier on purpose:
        // `ast` sends it before every command, and a daemon that has just
        // noticed a dead guest should have reconciled that before it says it
        // is well.
        Request::Ping { .. } => {
            let ours = compat::ours();
            return Response::Pong {
                version: VERSION.to_owned(),
                build_id: Some(asterism_core::BUILD_ID.to_owned()),
                protocol: ours.max,
                min_protocol: ours.min,
            };
        }
        Request::Compat => {
            return Response::Compat {
                compat: Box::new(compat::Compat::current()),
            }
        }
        Request::List => {
            return Response::Instances {
                instances: reg.list(),
            }
        }
        Request::Status { name } => {
            return match reg.get(&name) {
                Ok(instance) => {
                    let mut instance = instance.clone();
                    volume::annotate_runtime(&mut instance).await;
                    status_response(instance)
                }
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        // The backend is chosen once, here, and recorded on the instance. An
        // explicit choice is forced; the default probes VZ first and falls
        // back to QEMU when VZ is unavailable or lacks a required capability.
        Request::Create {
            name,
            image,
            shape,
            backend: requested,
            publish,
            profiles,
        } => {
            // `_recording` rather than plain `image_ref`: a local file is
            // never adopted into the store, so the moment the user names it
            // is the only chance to write down what it was.
            backend::image_ref_recording(&image).and_then(|r| {
                let requirements = backend::CreateRequirements::new(&r, &publish);
                let machine = backend::select_for(requested.as_deref(), requirements)?;
                // Resolved before the row exists, so a mistyped profile is a
                // refusal rather than an instance that cannot boot. Nothing
                // is applied here: profiles reach a guest through its seed.
                check_profiles(&profiles)?;
                reg.create(&name, cpu_device, &r.name, shape, machine)?;
                if r.kind == ImageKind::OciRootfs {
                    // A container that has finished is not a crash; see
                    // `Policy::never`.
                    reg.set_policy(&name, Policy::never())?;
                }
                if !profiles.is_empty() {
                    reg.set_profiles(&name, profiles)?;
                }
                reg.set_source(&name, r.kind, publish)
            })
        }
        // Recorded now, applied at the next boot. Saying so is the CLI's
        // job; refusing a name the catalog does not know is this one's.
        Request::SetProfiles { name, profiles } => reg
            .get(&name)
            .map(|_| ())
            .and_then(|_| check_profiles(&profiles))
            .and_then(|_| reg.set_profiles(&name, profiles)),
        // `--restart` is recorded before the boot, so an instance that comes
        // up and immediately dies is already carrying the policy the user
        // asked for when the supervisor looks at the corpse.
        Request::Up { name, restart } => return attach_response(up(reg, &name, restart)),
        // A guest being asked to shut down cleanly keeps its disks until the
        // backend proves it stopped. Only then do its local bridges and egress
        // proxy go away. A failed stop, including an unresolved launch with no
        // handle, must preserve every side effect behind that authority row.
        Request::Down { name } => match down(reg, &name) {
            Ok(stopped) => {
                volume::take_down(&name).await;
                // The port is remembered, so the next boot puts it back where
                // the seed already says it is.
                egress::stop(&name);
                Ok(stopped)
            }
            Err(error) => Err(error),
        },
        Request::Remove { name } => {
            // Leases are handed back while the immutable instance identity
            // still exists. A sleeping or refusing provider leaves the row
            // intact; deleting it would strand a lease no same-name
            // replacement is authorised to release.
            if let Ok(inst) = reg.get(&name).cloned() {
                if inst.status == Status::Running {
                    return attach_response(Err(anyhow::anyhow!(
                        "instance {name:?} is running — `ast down {name}` first"
                    )));
                }
                if let Some(intent) = &inst.boot_intent_id {
                    return attach_response(Err(anyhow::anyhow!(
                        "instance {name:?} has unresolved boot intent {intent}; refusing to remove its authority row"
                    )));
                }
                volume::take_down(&name).await;
                if let Err(e) = volume::release_all(&inst).await {
                    return attach_response(Err(e).context(
                        "instance removal refused until every block-volume lease is released",
                    ));
                }
                // The instance directory goes below, and this instance's CA
                // private key is in it.
                egress::stop(&inst.name);
            }
            reg.remove(&name).inspect(|inst| {
                persist::forget(&inst.name);
                let _ = std::fs::remove_dir_all(paths::instance_dir(&inst.name));
            })
        }
        // The instance's directory is named after the instance, so the rename
        // is not done until the bytes have moved too.
        Request::Rename { name, new_name } => reg.rename(&name, &new_name).inspect(|_| {
            let (from, to) = (paths::instance_dir(&name), paths::instance_dir(&new_name));
            if from.exists() {
                // The rename is published like any other: the row committed
                // above names the new directory, so a crash between the two
                // with the rename still in the page cache would leave a row
                // pointing at a directory that is not there.
                if let Err(e) = durable::publish_rename(&from, &to) {
                    eprintln!(
                        "astd: renaming {} to {}: {e:#}",
                        from.display(),
                        to.display()
                    );
                }
            }
        }),
        Request::MarkConflicted {
            name,
            other_cpu_device,
        } => reg.mark_conflicted(&name, &other_cpu_device),
        Request::AttachVolume {
            name,
            path,
            host,
            mount_point,
        } => {
            let host = host.unwrap_or_else(local_host);
            // Recording a volume the instance's backend could never show
            // the guest would leave something that looks configured and is
            // not, so the capability is checked before the registry moves.
            reg.get(&name)
                .cloned()
                .and_then(|inst| backend::check_can_share(&inst))
                .and_then(|()| resolve_volume_path(&path, &host))
                .and_then(|path| reg.attach_volume(&name, &path, &host, mount_point.as_deref()))
        }
        // A block volume is taken, not merely recorded: the lease is asked
        // for now, from the device that holds the bytes, so that "somebody
        // else has it" is a refusal at attach time rather than a boot that
        // fails later for reasons the user has to go and read about.
        Request::AttachBlock {
            name,
            volume: vol,
            device,
        } => {
            let provider_id = match volume::provider_identity(&device).await {
                Ok(id) => id,
                Err(e) => return attach_response(Err(e)),
            };
            return attach_response(
                attach_block_owned(reg, &name, &vol, &device, &provider_id, false).await,
            );
        }
        // Catalog placement is deliberately a separate frame from the
        // device-qualified legacy attach. It resolves every eligibility
        // requirement before taking a lease or changing the instance row;
        // the provider's lease remains the race-safe final fence.
        Request::AttachStorage {
            name,
            volume: vol,
            owner_device,
            max_latency_ms,
        } => {
            return attach_response(
                attach_storage(reg, &name, &vol, owner_device.as_deref(), max_latency_ms).await,
            )
        }
        Request::Detach {
            name,
            volume: vol,
            host,
        } => return attach_response(detach(reg, &name, &vol, host.as_deref()).await),
        // A secret is taken, not merely recorded: the orbit is asked which
        // devices hold it, and a source that cannot serve its current version
        // is a refusal here rather than a guest that boots holding a handle
        // nothing will ever honour.
        Request::AttachSecret {
            name,
            secret,
            authority,
            placement,
            env,
            source_device,
        } => {
            attach_secret(
                reg,
                &name,
                &secret,
                &authority,
                placement,
                env,
                source_device.as_deref(),
            )
            .await
        }
        Request::DetachSecret { name, secret } => detach_secret(reg, &name, &secret),
        Request::BackupExport { name, destination } => {
            let exported = reg.get(&name).cloned().and_then(|inst| {
                let provenance = backup::image_provenance(&inst)?;
                backup::export(
                    &inst,
                    &paths::instance_dir(&name),
                    Path::new(&destination),
                    provenance,
                )
            });
            return match exported {
                Ok(report) => Response::BackupExported { report },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            };
        }
        Request::BackupImport { source, name } => {
            return tokio::task::block_in_place(|| {
                restore_backup(reg, Path::new(&source), &name, cpu_device)
            });
        }
        // A file on this device's disk, read here rather than by the CLI, so
        // that the answer is the same whoever asked and from wherever.
        Request::Logs { name, lines } => {
            return match reg.get(&name).map(|i| i.name.clone()) {
                Ok(name) => match console_tail(&name, lines) {
                    Ok((text, truncated)) => Response::Log { text, truncated },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        _ => return not_a_shard_request(),
    };
    match mutation {
        Ok(instance) => {
            if let Err(e) = reg.save() {
                return Response::Error {
                    message: format!("saving registry: {e:#}"),
                };
            }
            Response::Instance {
                instance,
                guest_health: None,
            }
        }
        Err(e) => Response::Error {
            message: format!("{e:#}"),
        },
    }
}

/// Attach owns its persistence boundary instead of falling through the
/// generic mutation save below. Its provider lease and consumer row are a
/// cross-device saga; another unconditional save after the intent was
/// cleared could turn an already-committed attach into an error response.
fn attach_response(result: Result<Instance>) -> Response {
    match result {
        Ok(instance) => Response::Instance {
            instance,
            guest_health: None,
        },
        Err(e) => Response::Error {
            message: format!("{e:#}"),
        },
    }
}

/// Make a status response from the recorded row plus a fresh, optional guest
/// observation. The registry is deliberately not changed: agent health is a
/// sample, while its rows are durable instance configuration and lifecycle.
fn status_response(instance: Instance) -> Response {
    let guest_health = instance
        .handle
        .as_ref()
        .and_then(guest_health)
        .map(Box::new);
    Response::Instance {
        instance,
        guest_health,
    }
}

/// Ask the backend that owns this handle, rather than selecting on a host or
/// backend name here. A failed status poll is absence of a guest observation,
/// not evidence that a still-running instance has died.
fn guest_health(handle: &asterism_core::hv::Handle) -> Option<GuestHealth> {
    backend::for_handle(&handle.backend)
        .ok()?
        .guest_health(handle)
        .ok()
        .flatten()
}

/// What a request that no area of this daemon claims is told.
///
/// Four families end up here, and each of them was already answered
/// somewhere else: `ssh` and `set cpu` on the connection that asked, because
/// they report as they go; the orbit views and the pairing frames in
/// [`crate::dispatch`], because they are about the orbit rather than about a
/// shard; the wake frames in [`crate::wake`] and `mesh::serve_stream`,
/// because they are about this device's NIC; the volume frames in
/// [`crate::volume`], before the shard was ever locked. Arriving here means
/// one of them came in by a door that does not lead anywhere, which is worth
/// a sentence rather than a panic.
fn not_a_shard_request() -> Response {
    Response::Error {
        message: "that request is not answered by a single device's shard".into(),
    }
}

// ---- the fences ------------------------------------------------------------

/// The refusal an instance owes this request before any area gets to run it,
/// or `None` if there is none.
///
/// Two states put an instance out of reach, and both are about the orbit
/// rather than about the guest: a name that turned out not to be unique, and
/// bytes that are in flight to another device. They are checked here, once,
/// ahead of the per-area dispatch, because they hold for every command an
/// instance has — a snapshot of an instance whose disk is being copied away
/// is exactly as wrong as a boot of it.
pub(crate) fn refusal(req: &Request, reg: &Shard) -> Option<Response> {
    let name = req.subject()?;

    // An instance whose name turned out not to be unique answers exactly the
    // commands that can end that, and tells everything else what to do.
    if !req.survives_a_conflict() {
        if let Ok(inst) = reg.get(name) {
            if let Some(conflict) = &inst.conflict {
                return Some(Response::Error {
                    message: registry::conflicted(inst, conflict),
                });
            }
        }
    }

    // An instance whose bytes are in flight to another device answers only
    // what cannot change them. This is the half of "never two bootable
    // copies" that lives on the source: the target's half is that its copy is
    // not called anything an instance could be called until it commits.
    if !req.survives_a_move() {
        if let Ok(inst) = reg.get(name) {
            if let Some(moving) = &inst.moving {
                return Some(Response::Error {
                    message: format!(
                        "instance {name:?} is moving to {} — its bytes are in \
                         flight, so this device will not touch them. Wait for the \
                         move to finish, or run it again if it was interrupted.",
                        moving.to_device
                    ),
                });
            }
        }
    }

    // What a device says about an instance that used to be here. Only ever
    // reached by a request aimed at this device directly; the ordinary path
    // resolves the name across the orbit and lands on whoever holds the row
    // now.
    if !reg.holds(name) {
        if let Some(note) = swap::moved_note(name) {
            return Some(Response::Error { message: note });
        }
    }
    None
}

// ---- claiming a name -------------------------------------------------------

/// The refusal a request owes the orbit's one flat instance namespace before
/// it is routed anywhere, or `None` if it claims no name.
///
/// Two commands claim rather than resolve, and they are here together because
/// they are the same question asked twice: `create` claims the name it is
/// given, `rename` claims the name it is moving to. Renaming claims first and
/// resolves second, in that order — an instance that fails the claim must
/// keep the name it has.
pub(crate) async fn claim_name(
    req: &Request,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Option<Response> {
    let name = claimed_name(req)?;
    claim(name, node, mesh)
        .await
        .err()
        .map(|e| Response::Error {
            message: format!("{e:#}"),
        })
}

/// The name a request claims outright, as opposed to the name it resolves.
///
/// A rename claims the name it is moving *to*: the one it already has is
/// taken by definition, and claiming that would refuse every rename there is.
fn claimed_name(req: &Request) -> Option<&str> {
    match req {
        Request::Create { name, .. } => Some(name),
        Request::Rename { new_name, .. } => Some(new_name),
        Request::BackupImport { name, .. } => Some(name),
        _ => None,
    }
}

/// Verify and stage the whole backup before one live path or registry row is
/// touched, then publish the directory and row as one recoverable operation.
fn restore_backup(reg: &mut Shard, source: &Path, name: &str, cpu_device: &str) -> Response {
    if let Ok(existing) = reg.get(name) {
        return Response::Error {
            message: registry::taken(existing),
        };
    }
    let live = paths::instance_dir(name);
    // The same backup gets the same staging directory and resumes there; a
    // different backup of the same name gets a different one, so files that
    // were present in an older export can never leak into this restore.
    let preview = match backup::inspect(source) {
        Ok(manifest) => manifest,
        Err(e) => {
            return Response::Error {
                message: format!("{e:#}"),
            }
        }
    };
    let restore_key =
        blake3::hash(format!("{}:{}", preview.instance.id, preview.created_at).as_bytes()).to_hex();
    let staging = paths::home_dir()
        .join("instances")
        .join(format!(".{name}.restoring-{}", &restore_key[..12]));

    // A power cut after publishing the directory but before saving the row
    // leaves one distinctive state: a live directory with our restore
    // receipt and no registry entry. Retrying the same import verifies those
    // files again and finishes the row instead of stranding the instance.
    let receipt = live.join(".restore-receipt.json");
    let recovering_publication = if live.exists() {
        match std::fs::read(&receipt)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<backup::RestoreReport>(&bytes).ok())
        {
            Some(report) if report.instance == name && report.id == preview.instance.id => true,
            _ => {
                return Response::Error {
                    message: format!(
                        "{} already exists without a matching restore receipt — refusing to overwrite possible instance bytes",
                        live.display()
                    ),
                }
            }
        }
    } else {
        false
    };
    let restore_at = if recovering_publication {
        &live
    } else {
        &staging
    };
    let (mut instance, report) = match backup::restore_to(source, restore_at, name) {
        Ok(restored) => restored,
        Err(e) => {
            return Response::Error {
                message: format!("{e:#}"),
            }
        }
    };
    if reg.list().iter().any(|held| held.id == instance.id) {
        return Response::Error {
            message: format!(
                "instance identity {} already exists on this device — refusing to create a second writer",
                instance.id
            ),
        };
    }
    instance.cpu_device = cpu_device.to_owned();
    if !recovering_publication {
        if let Err(e) = durable::publish_dir(&staging, &live) {
            return Response::Error {
                message: format!("publishing restored instance: {e:#}"),
            };
        }
    }
    let adopted = reg.adopt(instance).and_then(|_| reg.save());
    if let Err(e) = adopted {
        let _ = reg.remove(name);
        if !recovering_publication {
            let _ = durable::publish_rename(&live, &staging);
        }
        return Response::Error {
            message: format!("saving restored instance: {e:#}"),
        };
    }
    let _ = std::fs::remove_file(live.join(".restore-receipt.json"));
    Response::BackupRestored { report }
}

/// Refuse an unknown profile before anything is written.
///
/// [`profile::Bootstrap::resolve`] answers with the catalog when a name is
/// unknown. Both cloud images and OCI rootfs images consume the resolved
/// bootstrap at boot: cloud images through their seed and OCI images through
/// Asterism's generated init.
fn check_profiles(profiles: &[String]) -> Result<()> {
    profile::Bootstrap::resolve(profiles).map(|_| ())
}

/// Claims a name in the orbit's one flat instance namespace.
///
/// This device's shard first, then every peer it can reach. A peer it cannot
/// reach is not a veto — see `Shard::mark_conflicted` for why, and for what
/// happens instead when the two devices can see each other again.
async fn claim(name: &str, node: &Node, mesh: Option<&Arc<Mesh>>) -> Result<()> {
    registry::check_name(name)?;
    if let Ok(existing) = node.shard.lock().await.get(name) {
        anyhow::bail!("{}", registry::taken(existing));
    }
    let Some(mesh) = mesh else { return Ok(()) };
    if let Some(existing) = mesh.claim(name).await? {
        anyhow::bail!("{}", registry::taken(&existing));
    }
    Ok(())
}

// ---- booting and stopping --------------------------------------------------

pub(crate) fn up(reg: &mut Shard, name: &str, restart: Option<Restart>) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    if let Some(intent) = &inst.boot_intent_id {
        anyhow::bail!(
            "instance {name:?} has unresolved boot intent {intent}; refusing a second guest"
        );
    }
    if inst.status == Status::Running {
        anyhow::bail!("instance {name:?} is already running");
    }
    refuse_pending_release(&inst)?;

    // Fence this launch before it can renew one provider epoch or create one
    // guest process. The marker survives every ambiguous save and makes a
    // daemon restart refuse a second guest even in the narrow window before
    // the first one's handle can be recorded.
    let mut fenced = reg.clone();
    if let Some(restart) = restart {
        fenced.set_restart(name, restart)?;
    }
    let (_, boot_intent_id) = fenced.begin_boot(name)?;
    if let Err(first) = fenced.save_confirmed() {
        let durable = Shard::load(&paths::state_path()).with_context(|| {
            format!("reloading the launch fence after its commit failed: {first:#}")
        })?;
        if durable.get(name)?.boot_intent_id.as_deref() != Some(boot_intent_id.as_str()) {
            *reg = durable;
            return Err(first).context("committing the durable guest-launch fence");
        }
        durable
            .save_confirmed()
            .context("confirming an ambiguously committed guest-launch fence")?;
        fenced = durable;
    }
    *reg = fenced;
    let inst = reg.get(name)?.clone();

    // A cloud-init seed bakes in the guest key of the device that builds it,
    // so whoever builds one is whose key opens that guest from then on.
    // Normally that is settled at the first boot and never moves again; it
    // moves when the seed is rebuilt, which is why the stamp is compared
    // rather than assumed. `up` only ever runs on the device holding the row,
    // so that device is this instance's own cpu device.
    let stamp = paths::instance_dir(name).join("seed.stamp");
    let before = std::fs::read(&stamp).ok();
    let raised = match tokio::task::block_in_place(|| -> Result<_> {
        let hv = backend::for_instance(&inst)?;
        // Every boot renews the lease on every block volume this instance
        // holds, at a higher epoch, and raises the local socket the guest's
        // disk arrives on. A volume somebody else has taken in the meantime
        // stops the boot here, saying who has it — which is the whole point
        // of doing it before the hypervisor is asked for anything.
        volume::bring_up(&inst, &*hv, &boot_intent_id)
    }) {
        Ok(raised) => raised,
        Err(error) => {
            compensate_boot(reg, &inst, &boot_intent_id)
                .with_context(|| format!("raising storage for the guest failed ({error:#})"))?;
            return Err(error);
        }
    };

    // The epoch this boot was granted, written back onto the instance. The
    // one recorded before was the attach's, and it stopped being true the
    // moment this boot renewed it — which matters to `ast status`, and
    // matters more to the next daemon that has to reconnect this guest's
    // disks without disturbing the guest (`volume::reattach`).
    let mut leased = reg.clone();
    for lease in &raised.leases {
        leased.attach_block(
            name,
            &lease.volume,
            &lease.device,
            lease.epoch,
            lease.size_bytes,
        )?;
    }
    if let Err(first) = leased.save_confirmed() {
        let durable = match Shard::load(&paths::state_path()) {
            Ok(durable) => durable,
            Err(reload) => {
                compensate_boot(reg, &inst, &boot_intent_id).with_context(|| {
                    format!(
                        "renewed storage epochs failed to commit and the shard failed to reload ({first:#}; {reload:#})"
                    )
                })?;
                return Err(first).context("committing renewed storage epochs before guest launch");
            }
        };
        if !boot_epochs_match(&durable, name, &boot_intent_id, &raised.leases) {
            *reg = durable;
            compensate_boot(reg, &inst, &boot_intent_id).with_context(|| {
                format!("renewed storage epochs were not durably committed ({first:#})")
            })?;
            return Err(first).context("committing renewed storage epochs before guest launch");
        }
        if let Err(confirm) = durable.save_confirmed() {
            *reg = durable;
            compensate_boot(reg, &inst, &boot_intent_id).with_context(|| {
                format!("confirming renewed storage epochs failed ({confirm:#})")
            })?;
            return Err(confirm).context("confirming renewed storage epochs before guest launch");
        }
        leased = durable;
    }
    *reg = leased;

    // Only now, with the launch fence and every storage epoch confirmed in
    // both durable shard copies, may the backend create a guest.
    let boot_inst = reg.get(name)?.clone();
    let (hv, req, prep) = match tokio::task::block_in_place(|| -> Result<_> {
        let hv = backend::for_instance(&boot_inst)?;
        let mut req = backend::boot_req(&boot_inst, &*hv)?;
        req.extra_disks = raised.disks;
        let prep = hv.prepare(&req)?;
        Ok((hv, req, prep))
    }) {
        Ok(prepared) => prepared,
        Err(error) => {
            compensate_boot(reg, &boot_inst, &boot_intent_id)
                .with_context(|| format!("preparing the backend launch failed ({error:#})"))?;
            return Err(error);
        }
    };
    let handle = match tokio::task::block_in_place(|| hv.boot(&req, &prep)) {
        Ok(handle) => handle,
        Err(error) => {
            // Crossing into `boot` crosses the process-creation boundary.
            // QEMU may daemonize successfully and then leave no readable
            // pidfile; VZ may spawn a helper and then fail to capture its
            // identity or endpoint. With no exact Handle there is nothing we
            // can safely signal or use to prove death, so releasing leases or
            // publishing stopped authority here could admit a second guest.
            return Err(error).context(format!(
                "backend launch outcome is ambiguous; durable boot intent {boot_intent_id} remains fenced"
            ));
        }
    };

    let mut running = reg.clone();
    if boot_inst.seed_device.is_none() || std::fs::read(&stamp).ok() != before {
        running.set_seed_device(name, &boot_inst.cpu_device)?;
    }
    let answer = running.set_running(name, handle.clone())?;
    if let Err(first) = running.save_confirmed() {
        let durable = match Shard::load(&paths::state_path()) {
            Ok(durable) => durable,
            Err(reload) => {
                if let Err(stop) = kill_and_prove(&*hv, &handle) {
                    return Err(first).context(format!(
                        "committing the running guest handle; the shard also failed to reload ({reload:#}) and shutdown is not proven: {stop:#}"
                    ));
                }
                compensate_boot(reg, &boot_inst, &boot_intent_id).with_context(|| {
                    format!(
                        "the uncommitted guest was stopped, but the shard failed to reload ({reload:#})"
                    )
                })?;
                return Err(first)
                    .context("committing the running guest handle; guest was stopped");
            }
        };
        let exact_running = durable.get(name).is_ok_and(|candidate| {
            candidate.status == Status::Running
                && candidate.handle.as_ref() == Some(&handle)
                && candidate.boot_intent_id.is_none()
        });
        if exact_running && durable.save_confirmed().is_ok() {
            let answer = durable.get(name)?.clone();
            *reg = durable;
            return Ok(answer);
        }

        // Rollback order is the same safety boundary as provider release:
        // prove process death first, then publish stopped/free authority.
        if let Err(stop) = kill_and_prove(&*hv, &handle) {
            *reg = durable;
            return Err(first).context(format!(
                "committing the running guest handle; shutdown is not proven and the durable launch fence remains: {stop:#}"
            ));
        }
        *reg = durable;
        compensate_boot(reg, &boot_inst, &boot_intent_id).with_context(|| {
            format!("the uncommitted guest was stopped after registry failure ({first:#})")
        })?;
        return Err(first).context("committing the running guest handle; guest was stopped");
    }
    *reg = running;
    Ok(answer)
}

fn boot_epochs_match(reg: &Shard, name: &str, intent_id: &str, leases: &[volume::Leased]) -> bool {
    reg.get(name).is_ok_and(|instance| {
        instance.boot_intent_id.as_deref() == Some(intent_id)
            && leases.iter().all(|leased| {
                instance.volumes.iter().any(|volume| {
                    volume.is_block()
                        && volume.host == leased.device
                        && volume.path == leased.volume
                        && volume.epoch == Some(leased.epoch)
                })
            })
    })
}

fn compensate_boot(reg: &mut Shard, instance: &Instance, boot_intent_id: &str) -> Result<()> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(volume::compensate_boot_leases(instance, boot_intent_id))
    })?;
    let mut durable = Shard::load(&paths::state_path())?;
    durable.clear_boot(&instance.name, boot_intent_id)?;
    durable.set_stopped(&instance.name)?;
    durable
        .save_confirmed()
        .context("clearing the compensated guest-launch fence")?;
    *reg = durable;
    Ok(())
}

fn kill_and_prove(
    hv: &dyn asterism_core::hv::Hypervisor,
    handle: &asterism_core::hv::Handle,
) -> Result<()> {
    let kill = hv.kill(handle);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if matches!(hv.state(handle), Ok(RunState::Stopped)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return match kill {
                Ok(()) => anyhow::bail!("backend still reports the guest running after SIGKILL"),
                Err(error) => Err(error).context("asking the backend to kill the guest"),
            };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn down(reg: &mut Shard, name: &str) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    let Some(handle) = inst.handle.clone() else {
        anyhow::bail!("instance {name:?} is not running");
    };
    // A deliberate stop is not a crash: it cancels any restart owed.
    persist::forget(name);
    tokio::task::block_in_place(|| -> Result<()> {
        // The handle names its own backend, so a guest booted by one
        // backend is always stopped by that same one — even if the
        // instance has since been redefined, or the device's default has
        // moved on since it booted.
        backend::for_handle(&handle.backend)?.stop(&handle, STOP_DEADLINE)
    })?;
    reg.set_stopped(name)
}

/// Instances marked running whose guest died (host reboot, crash) get
/// flipped back to stopped so the state file tracks reality.
pub(crate) fn reconcile(reg: &mut Shard) {
    let stale: Vec<String> = reg
        .list()
        .into_iter()
        .filter(|i| i.status == Status::Running && i.boot_intent_id.is_none() && !is_running(i))
        .map(|i| i.name)
        .collect();
    if stale.is_empty() {
        return;
    }
    for name in stale {
        // Stopped is the truth right now; the supervisor decides whether it
        // stays that way.
        persist::note_died(&name);
        let _ = reg.set_stopped(&name);
    }
    let _ = reg.save();
}

/// A handle reloaded from the registry is never assumed valid — and it is
/// asked about by the backend that booted it, which the handle names. A
/// device running both backends has both kinds of guest to reconcile, and
/// "is it alive" means something different for each.
fn is_running(inst: &Instance) -> bool {
    let Some(h) = &inst.handle else { return false };
    let Ok(hv) = backend::for_handle(&h.backend) else {
        return false;
    };
    matches!(hv.state(h), Ok(RunState::Running))
}

// ---- volumes on an instance ------------------------------------------------

/// Durably attach a block volume across the provider and consumer.
///
/// Read-only admission comes first. Before the provider may grant anything,
/// an independent consumer journal records enough to release an ambiguous
/// grant. The instance row is then committed twice (live and recovery copy),
/// and only then is the journal cleared. A registry-save error is resolved by
/// reloading the durable row: visible means roll forward and acknowledge;
/// absent means release the provider and roll back before returning failure.
async fn attach_block_owned(
    reg: &mut Shard,
    name: &str,
    vol: &str,
    device: &str,
    provider_device_id: &str,
    auto_placed: bool,
) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    refuse_running_block_attach(name, inst.status)?;
    refuse_pending_release(&inst)?;
    if auto_placed
        && inst
            .volumes
            .iter()
            .any(|candidate| candidate.is_block() && candidate.path == vol)
    {
        anyhow::bail!(
            "{name:?} already has a block volume called {vol:?}; name its provider explicitly \
             instead of auto-placing another one"
        );
    }
    if let Some(existing) = existing_block(&inst, vol, device, provider_device_id)? {
        return Ok(existing);
    }
    let hv = backend::for_instance(&inst)?;
    volume::check_backend(&*hv)?;
    // Admission precedes the provider-side lease bump and the local registry
    // write.  A relay-only or high-latency placement therefore leaves neither
    // device half-mutated.
    volume::preflight_remote_volume(device).await?;

    let holder_device_id = volume::consumer_device_id()?;
    let intent = AttachIntent::new(
        name,
        &inst.id,
        vol,
        device,
        provider_device_id,
        &holder_device_id,
    );
    let mut intents = AttachIntents::load(&paths::volume_attach_intents_path())?;
    if let Some(pending) = intents.get(&intent).cloned() {
        reconcile_one_attach(reg, &mut intents, &pending).await?;
        if let Some(existing) = existing_block(reg.get(name)?, vol, device, provider_device_id)? {
            return Ok(existing);
        }
    }
    intents.begin_durable(intent.clone())?;

    let (epoch, _export, size) = match volume::take_lease(
        vol,
        device,
        Some(provider_device_id),
        name,
        &inst.id,
        Some(&intent.intent_id),
    )
    .await
    {
        Ok(grant) => grant,
        Err(grant_error) => {
            let compensated = abort_attach(reg, &mut intents, &intent).await;
            return match compensated {
                Ok(()) => Err(grant_error).context("taking the provider lease"),
                Err(compensation) => Err(grant_error).context(format!(
                    "taking the provider lease; compensation remains pending: {compensation:#}"
                )),
            };
        }
    };

    let mut next = reg.clone();
    let attached = match next.attach_block_owned(
        name,
        vol,
        device,
        registry::BlockAuthority {
            provider_device_id: Some(provider_device_id.to_owned()),
            attach_intent_id: Some(intent.intent_id.clone()),
        },
        epoch,
        size,
    ) {
        Ok(instance) => instance,
        Err(e) => {
            abort_attach(reg, &mut intents, &intent).await?;
            return Err(e);
        }
    };

    if let Err(first) = next.save_confirmed() {
        // A trailing directory sync can report failure after the rename is
        // visible. Reload decides that ambiguity from durable state rather
        // than from the mutated in-memory row.
        match Shard::load(&paths::state_path()) {
            Ok(reloaded) => {
                *reg = reloaded;
                if let Some(committed) = exact_block(reg, &intent, epoch) {
                    // Confirm both the live shard and its recovery copy before
                    // the independent intent is allowed to disappear.
                    if reg.save_confirmed().is_ok() {
                        if let Err(e) = intents.complete_durable(&intent) {
                            eprintln!(
                                "astd: volume attach committed, but its intent remains for startup \
                                 reconciliation: {e:#}"
                            );
                        }
                        return Ok(committed);
                    }
                }
            }
            Err(e) => {
                eprintln!("astd: reloading the registry after its attach commit failed: {e:#}")
            }
        }

        let compensation = abort_attach(reg, &mut intents, &intent).await;
        return match compensation {
            Ok(()) => Err(first).context("committing the consumer volume attachment"),
            Err(e) => Err(first).context(format!(
                "committing the consumer volume attachment; compensation remains pending: {e:#}"
            )),
        };
    }

    *reg = next;

    if let Err(e) = intents.complete_durable(&intent) {
        // The row and provider lease are already mutually consistent and
        // confirmed in both recovery copies. Returning success is truthful;
        // startup sees row+intent and idempotently clears the journal.
        eprintln!(
            "astd: volume attach committed, but its intent remains for startup \
             reconciliation: {e:#}"
        );
    }
    Ok(attached)
}

fn refuse_running_block_attach(name: &str, status: Status) -> Result<()> {
    if status == Status::Running {
        anyhow::bail!(
            "instance {name:?} is running; stop it before attaching block storage so its live \
             disk cannot be fenced"
        );
    }
    Ok(())
}

/// A release intent is a durable decision to roll a detach forward. Until it
/// settles, booting could renew the provider lease between its release and
/// the consumer-row commit, and another attach could obscure which row the
/// recovery record owns. Keep both mutations behind the same local fence.
fn refuse_pending_release(inst: &Instance) -> Result<()> {
    let pending = ReleaseIntents::load(&paths::volume_release_intents_path())?
        .list()
        .into_iter()
        .find(|intent| intent.instance_id == inst.id);
    if let Some(intent) = pending {
        anyhow::bail!(
            "instance {:?} has a pending detach of {}:{}; retry that detach or restart astd to \
             reconcile it before booting or attaching storage",
            inst.name,
            intent.device,
            intent.volume
        );
    }
    Ok(())
}

fn existing_block(
    inst: &Instance,
    vol: &str,
    device: &str,
    provider_device_id: &str,
) -> Result<Option<Instance>> {
    let Some(existing) = inst
        .volumes
        .iter()
        .find(|candidate| candidate.path == vol && candidate.host == device)
    else {
        return Ok(None);
    };
    if !existing.is_block() {
        anyhow::bail!(
            "{device}:{vol} is already attached to {:?} as a directory",
            inst.name
        );
    }
    match existing.host_id.as_deref() {
        Some(recorded) if recorded != provider_device_id => anyhow::bail!(
            "{device}:{vol} now resolves to device id {provider_device_id}, but the attached \
             storage authority is {recorded}; restore that provider mapping or repair the \
             authority explicitly"
        ),
        None => anyhow::bail!(
            "{device}:{vol} was attached before immutable storage identities; refusing to bind \
             the current provider until the original authority is explicitly repaired"
        ),
        Some(_) => {}
    }
    Ok(Some(inst.clone()))
}

fn exact_block(reg: &Shard, intent: &AttachIntent, epoch: u64) -> Option<Instance> {
    let inst = reg.get(&intent.instance).ok()?;
    if inst.id != intent.instance_id {
        return None;
    }
    inst.volumes
        .iter()
        .any(|candidate| {
            candidate.is_block()
                && candidate.path == intent.volume
                && candidate.host == intent.device
                && candidate.host_id.as_deref() == Some(intent.provider_device_id.as_str())
                && candidate.attach_intent_id.as_deref() == Some(intent.intent_id.as_str())
                && candidate.epoch == Some(epoch)
        })
        .then(|| inst.clone())
}

/// Settle an intent left by a crash or a failed cleanup. A matching consumer
/// row means the registry commit landed, so recovery rolls forward. Without
/// that row the provider grant is compensated before the intent is cleared.
async fn reconcile_one_attach(
    reg: &mut Shard,
    intents: &mut AttachIntents,
    intent: &AttachIntent,
) -> Result<()> {
    if intent.aborting {
        return abort_attach(reg, intents, intent).await;
    }
    let committed = reg.get(&intent.instance).ok().is_some_and(|inst| {
        inst.id == intent.instance_id
            && inst.volumes.iter().any(|candidate| {
                candidate.is_block()
                    && candidate.path == intent.volume
                    && candidate.host == intent.device
                    && candidate.host_id.as_deref() == Some(intent.provider_device_id.as_str())
                    && candidate.attach_intent_id.as_deref() == Some(intent.intent_id.as_str())
            })
    });
    if committed {
        reg.save_confirmed()
            .context("confirming a recovered consumer volume attachment")?;
        intents.complete_durable(intent)?;
        return Ok(());
    }

    abort_attach(reg, intents, intent).await
}

async fn abort_attach(
    reg: &mut Shard,
    intents: &mut AttachIntents,
    intent: &AttachIntent,
) -> Result<()> {
    // This durable phase is the rollback commit point. If it cannot be
    // recorded, leave both authorities untouched: startup may still see a
    // committed consumer row and must then roll forward, which remains safe
    // only while the provider lease is intact.
    intents
        .mark_aborting_durable(intent)
        .context("recording volume-attach compensation")?;
    if reg.get(&intent.instance).ok().is_some_and(|inst| {
        inst.id == intent.instance_id
            && inst.volumes.iter().any(|candidate| {
                candidate.is_block()
                    && candidate.path == intent.volume
                    && candidate.host == intent.device
                    && candidate.host_id.as_deref() == Some(intent.provider_device_id.as_str())
                    && candidate.attach_intent_id.as_deref() == Some(intent.intent_id.as_str())
            })
    }) {
        let mut next = reg.clone();
        next.detach_volume(&intent.instance, &intent.volume, &intent.device)
            .context("rolling back the consumer row")?;
        if let Err(e) = next.save_confirmed() {
            match Shard::load(&paths::state_path()) {
                Ok(reloaded) => *reg = reloaded,
                Err(reload) => anyhow::bail!(
                    "persisting the compensated consumer registry: {e:#}; reloading it: {reload:#}"
                ),
            }
            if reg.get(&intent.instance).ok().is_some_and(|inst| {
                inst.id == intent.instance_id
                    && inst.volumes.iter().any(|candidate| {
                        candidate.is_block()
                            && candidate.path == intent.volume
                            && candidate.host == intent.device
                            && candidate.attach_intent_id.as_deref()
                                == Some(intent.intent_id.as_str())
                    })
            }) {
                return Err(e).context(
                    "consumer rollback is not durably absent; provider lease remains fenced",
                );
            }
        } else {
            *reg = next;
        }
    }
    volume::compensate_lease(intent)
        .await
        .context("releasing the provider lease")?;
    intents.complete_durable(intent)
}

/// Reconcile every attach which crossed only part of its two-device saga.
/// Called after the volume plane exists and before guest resurrection, so an
/// uncommitted disk can never reach a hypervisor after daemon restart.
pub(crate) async fn reconcile_pending_attaches(node: &Node) {
    let mut intents = match AttachIntents::load(&paths::volume_attach_intents_path()) {
        Ok(intents) => intents,
        Err(e) => {
            eprintln!("astd: pending volume attaches are unavailable: {e:#}");
            return;
        }
    };
    for intent in intents.list() {
        // Startup has not begun accepting requests yet, but still never hold
        // the shard mutex over a peer dial: a dead provider must not pin the
        // registry lock or turn its network timeout into a daemon-wide stall.
        let mut reg = node.shard.lock().await.clone();
        match tokio::time::timeout(
            STORAGE_RECOVERY_DEADLINE,
            reconcile_one_attach(&mut reg, &mut intents, &intent),
        )
        .await
        {
            Ok(Ok(())) => eprintln!(
                "astd: reconciled pending attach of {}:{} to {:?}",
                intent.device, intent.volume, intent.instance
            ),
            Ok(Err(e)) => eprintln!(
                "astd: pending attach of {}:{} to {:?} remains fenced: {e:#}",
                intent.device, intent.volume, intent.instance
            ),
            Err(_) => eprintln!(
                "astd: pending attach of {}:{} to {:?} exceeded the {}s recovery deadline and remains fenced",
                intent.device,
                intent.volume,
                intent.instance,
                STORAGE_RECOVERY_DEADLINE.as_secs()
            ),
        }
        *node.shard.lock().await = reg;
    }
}

/// Catalog-driven block attachment. Every read-only placement check precedes
/// the provider lease, and the instance row is still the final mutation.
async fn attach_storage(
    reg: &mut Shard,
    name: &str,
    vol: &str,
    owner_device: Option<&str>,
    max_latency_ms: Option<u64>,
) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    let hv = backend::for_instance(&inst)?;
    volume::check_backend(&*hv)?;
    let (device, provider_device_id) =
        volume::place(vol, owner_device, name, max_latency_ms).await?;
    attach_block_owned(
        reg,
        name,
        vol,
        &device,
        &provider_device_id,
        owner_device.is_none(),
    )
    .await
}

/// Complete catalog placement after the caller has performed the orbit-wide
/// read without holding the instance shard lock.
pub(crate) async fn attach_storage_placed(
    reg: &mut Shard,
    name: &str,
    vol: &str,
    device: &str,
    provider_device_id: &str,
    auto_placed: bool,
) -> Response {
    attach_response(
        attach_block_owned(reg, name, vol, device, provider_device_id, auto_placed).await,
    )
}

/// Bind an orbit secret to one authority this instance may reach.
///
/// Everything that could make the binding a lie is checked before the shard
/// moves: a backend with no guest-only door, an OCI guest with nothing to
/// install a trust root into, a secret in conflict, a source device that does
/// not hold the current version. What is written down afterwards is a policy
/// and an opaque handle, and the proxy is restarted so that the handle is
/// honoured from this moment rather than from the next boot.
async fn attach_secret(
    reg: &mut Shard,
    name: &str,
    secret: &str,
    authority: &str,
    placement: Option<asterism_core::secret::Placement>,
    env: Option<String>,
    source_device: Option<&str>,
) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    egress::check_can_bind(&inst)?;
    let (node, mesh) = egress::orbit()?;
    let binding = crate::secret::plan_binding(
        secret,
        authority,
        placement,
        env,
        source_device,
        &node,
        mesh.as_ref(),
    )
    .await?;
    let inst = reg.attach_secret(name, binding)?;
    egress::refresh_bindings(&inst);
    Ok(inst)
}

/// Revoke a binding.
///
/// The proxy is torn down and restarted against what is left, which is what
/// makes this a revocation rather than a note: the old proxy held the
/// bindings it started with and is marked revoked as it goes, so a request
/// already inside it is refused and no new one is accepted against the old
/// policy. The handle the guest still has in its environment stops being
/// honoured the moment this returns; the guest keeps a string that now means
/// nothing, until its next boot reissues the seed without it.
fn detach_secret(reg: &mut Shard, name: &str, secret: &str) -> Result<Instance> {
    let (inst, _revoked) = reg.detach_secret(name, secret)?;
    egress::refresh_bindings(&inst);
    Ok(inst)
}

/// Take a volume off an instance, handing back a block volume's lease.
///
/// Refused while the guest is running: neither backend offers disk hotplug
/// (`Caps::disk_hotplug` is false on both), so pulling the bytes out from
/// under a live guest would be a yanked cable rather than a detach.
async fn detach(reg: &mut Shard, name: &str, vol: &str, host: Option<&str>) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    if inst.status == Status::Running {
        anyhow::bail!(
            "instance {name:?} is running and its guest has this volume — \
             `ast down {name}` first"
        );
    }
    // `--host` is optional because most of the time there is only one volume
    // by that name on the instance, and making the user name a device to
    // remove a part they can see in `ast status` would be a riddle.
    let matches: Vec<&asterism_core::instance::Volume> =
        inst.volumes.iter().filter(|v| v.path == vol).collect();
    let host = match host {
        Some(host) => host.to_owned(),
        None => match matches.as_slice() {
            [only] => only.host.clone(),
            [] => anyhow::bail!("{name:?} has no volume called {vol:?} — see: ast status {name}"),
            many => anyhow::bail!(
                "{name:?} has {vol:?} from {} devices — say which: {}",
                many.len(),
                many.iter()
                    .map(|v| format!("--volume {}:{}", v.host, v.path))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        },
    };

    let record = inst
        .volumes
        .iter()
        .find(|v| v.path == vol && v.host == host)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{host}:{vol} is not attached to {name:?}"))?;

    if !record.is_block() {
        let mut next = reg.clone();
        let (detached, _) = next.detach_volume(name, vol, &host)?;
        next.save()
            .context("committing the consumer directory detachment")?;
        *reg = next;
        return Ok(detached);
    }

    // A human device name is not authority. Rows written before immutable
    // provider ids cannot be rebound during detach: the name may now belong
    // to a replacement device while the original still holds this lease.
    let provider_device_id = recorded_provider_id(&record, "detach")?.to_owned();
    let epoch = record
        .epoch
        .context("the attached block volume has no lease epoch to release safely")?;
    let holder_device_id = volume::consumer_device_id()?;
    let proposed = ReleaseIntent::new(
        name,
        &inst.id,
        vol,
        &host,
        &provider_device_id,
        &holder_device_id,
        epoch,
    );
    let mut intents = ReleaseIntents::load(&paths::volume_release_intents_path())?;
    let intent = intents.get(&proposed).cloned().unwrap_or(proposed);
    if intents.contains(&intent) {
        reconcile_one_release(reg, &mut intents, &intent).await?;
        if !release_row_matches(reg, &intent) {
            return reg
                .get(name)
                .cloned()
                .context("the instance disappeared while replaying its volume detach");
        }
    }

    intents.begin_durable(intent.clone())?;
    complete_release(reg, &mut intents, &intent).await?;
    reg.get(name)
        .cloned()
        .context("the instance disappeared while committing its volume detach")
}

fn release_row_matches(reg: &Shard, intent: &ReleaseIntent) -> bool {
    reg.get(&intent.instance).ok().is_some_and(|inst| {
        inst.id == intent.instance_id
            && inst.volumes.iter().any(|candidate| {
                candidate.is_block()
                    && candidate.path == intent.volume
                    && candidate.host == intent.device
                    && candidate.host_id.as_deref() == Some(intent.provider_device_id.as_str())
                    && candidate.epoch == Some(intent.epoch)
            })
    })
}

/// Whether the row otherwise owned by this release lacks or disagrees with
/// its immutable provider authority. Absence cannot mean "already detached":
/// a pre-v6 row may still name a lease on the original, now-unreachable
/// device. Recovery must preserve both row and intent for explicit repair.
fn release_row_has_ambiguous_authority(reg: &Shard, intent: &ReleaseIntent) -> bool {
    reg.get(&intent.instance).ok().is_some_and(|inst| {
        inst.id == intent.instance_id
            && inst.volumes.iter().any(|candidate| {
                candidate.is_block()
                    && candidate.path == intent.volume
                    && candidate.host == intent.device
                    && candidate.epoch == Some(intent.epoch)
                    && candidate.host_id.as_deref() != Some(intent.provider_device_id.as_str())
            })
    })
}

/// Roll a durable detach forward. The provider is released first; only then
/// may the consumer forget the row. A failed or ambiguous shard commit is
/// reloaded before returning so in-memory state always follows disk.
async fn complete_release(
    reg: &mut Shard,
    intents: &mut ReleaseIntents,
    intent: &ReleaseIntent,
) -> Result<()> {
    if release_row_has_ambiguous_authority(reg, intent) {
        anyhow::bail!(
            "attached volume {}:{} has no matching immutable provider identity; refusing to \
             forget its consumer row or release intent after possible device-name reuse",
            intent.device,
            intent.volume
        );
    }
    if !release_row_matches(reg, intent) {
        // The live row may be the first half of a confirming write while its
        // backup still names the released disk. Confirm absence before the
        // independent journal is allowed to disappear.
        reg.save_confirmed()
            .context("confirming a recovered consumer volume detachment")?;
        intents.complete_durable(intent)?;
        return Ok(());
    }

    volume::release_lease(intent)
        .await
        .context("releasing the provider lease")?;

    let mut next = reg.clone();
    next.detach_volume(&intent.instance, &intent.volume, &intent.device)
        .context("removing the released consumer volume row")?;
    if let Err(first) = next.save_confirmed() {
        *reg = Shard::load(&paths::state_path()).with_context(|| {
            format!("reloading the registry after its detach commit failed: {first:#}")
        })?;
        if release_row_has_ambiguous_authority(reg, intent) {
            return Err(first).context(
                "the detach commit reloaded a row without the exact provider identity; \
                 release intent remains pending",
            );
        }
        if release_row_matches(reg, intent) {
            return Err(first).context(
                "committing the consumer volume detachment; release intent remains pending",
            );
        }
        reg.save_confirmed()
            .context("confirming an ambiguously committed volume detachment")?;
    } else {
        *reg = next;
    }

    if let Err(e) = intents.complete_durable(intent) {
        eprintln!(
            "astd: volume detach committed, but its intent remains for startup reconciliation: \
             {e:#}"
        );
    }
    Ok(())
}

fn recorded_provider_id<'a>(
    record: &'a asterism_core::instance::Volume,
    action: &str,
) -> Result<&'a str> {
    record.host_id.as_deref().with_context(|| {
        format!(
            "cannot {action} legacy block volume {}:{}: it has no immutable provider identity, \
             so its device name may have been reused; preserving the consumer row and lease authority",
            record.host, record.path
        )
    })
}

async fn reconcile_one_release(
    reg: &mut Shard,
    intents: &mut ReleaseIntents,
    intent: &ReleaseIntent,
) -> Result<()> {
    complete_release(reg, intents, intent).await
}

/// Re-drive every detach whose provider acknowledgement or consumer commit
/// was interrupted. This runs before guest resurrection, so a row whose
/// writer fence was released is removed before it can reach a hypervisor.
pub(crate) async fn reconcile_pending_releases(node: &Node) {
    let mut intents = match ReleaseIntents::load(&paths::volume_release_intents_path()) {
        Ok(intents) => intents,
        Err(e) => {
            eprintln!("astd: pending volume releases are unavailable: {e:#}");
            return;
        }
    };
    for intent in intents.list() {
        let mut reg = node.shard.lock().await.clone();
        match tokio::time::timeout(
            STORAGE_RECOVERY_DEADLINE,
            reconcile_one_release(&mut reg, &mut intents, &intent),
        )
        .await
        {
            Ok(Ok(())) => eprintln!(
                "astd: reconciled pending detach of {}:{} from {:?}",
                intent.device, intent.volume, intent.instance
            ),
            Ok(Err(e)) => eprintln!(
                "astd: pending detach of {}:{} from {:?} remains fenced: {e:#}",
                intent.device, intent.volume, intent.instance
            ),
            Err(_) => eprintln!(
                "astd: pending detach of {}:{} from {:?} exceeded the {}s recovery deadline and remains fenced",
                intent.device,
                intent.volume,
                intent.instance,
                STORAGE_RECOVERY_DEADLINE.as_secs()
            ),
        }
        *node.shard.lock().await = reg;
    }
}

/// A volume on this device is about to be handed to a hypervisor, so it has
/// to be a real directory and it has to be named absolutely — the CLI may
/// have been run from anywhere, and the daemon's cwd is not the user's.
/// Volumes on other devices are taken on faith; we cannot see their disks.
fn resolve_volume_path(path: &str, host: &str) -> Result<String> {
    if host != local_host() {
        return Ok(path.to_owned());
    }
    let canonical =
        std::fs::canonicalize(path).with_context(|| format!("cannot use {path} as a volume"))?;
    if !canonical.is_dir() {
        anyhow::bail!("{path} is not a directory — volumes are directories");
    }
    Ok(canonical.display().to_string())
}

// ---- the console -----------------------------------------------------------

/// The last `lines` lines of a guest's console, and whether older ones were
/// left behind. `lines` of 0 means all of it.
/// The most of a console log that will ever be put in one reply.
///
/// A console is the one thing in this protocol whose size the guest chooses,
/// and it chooses it over months: an agent that logs a line a second leaves
/// gigabytes behind. Reading all of that to answer `ast logs` made the reply
/// frame, and the daemon's memory alongside it, something a guest could grow
/// without limit — so the file is read from its end, and only this much of
/// it. Well inside [`ipc::MAX_RESPONSE_FRAME`] even after JSON escaping
/// doubles every newline in it.
const CONSOLE_TAIL_BYTES: u64 = 4 * 1024 * 1024;

/// The end of an instance's console log, and whether anything was left out.
///
/// Two things can leave something out and both report it the same way,
/// because from the reader's side they are the same fact: `--lines` asked for
/// fewer lines than there are, or the file is longer than
/// [`CONSOLE_TAIL_BYTES`]. `ast` turns either into the same offer of
/// `--lines`, and `ast logs -f` — which reads the file directly — is the
/// answer for anyone who wants all of it.
fn console_tail(name: &str, lines: u32) -> Result<(String, bool)> {
    let path = paths::instance_dir(name).join("console.log");
    tail_of(&path, lines).map_err(|_| {
        anyhow::anyhow!("no console log for {name:?} yet — `ast up {name}` starts one")
    })
}

fn tail_of(path: &Path, lines: u32) -> Result<(String, bool)> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path)?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let from = size.saturating_sub(CONSOLE_TAIL_BYTES);
    let mut clipped = from > 0;
    if clipped {
        file.seek(SeekFrom::Start(from))
            .with_context(|| format!("reading the end of {}", path.display()))?;
    }
    let mut bytes = Vec::new();
    file.take(CONSOLE_TAIL_BYTES)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    // Lossy, not strict: a console carries whatever the guest's firmware put
    // on the serial line, which is not always utf-8 and is never a reason to
    // tell the user there is no log. Starting mid-file makes that certain
    // rather than merely likely, since the seek lands wherever it lands.
    let text = String::from_utf8_lossy(&bytes).into_owned();
    // The first line of a clipped read is half a line. Dropping it is what
    // makes "the rest of this is real" true.
    let text = match clipped {
        true => text
            .split_once('\n')
            .map(|(_, rest)| rest.to_owned())
            .unwrap_or_default(),
        false => text,
    };
    if lines == 0 {
        return Ok((text, clipped));
    }
    let all: Vec<&str> = text.lines().collect();
    let keep = all.len().min(lines as usize);
    clipped |= keep < all.len();
    let tail = all[all.len() - keep..].join("\n");
    Ok((tail, clipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_machine() -> asterism_core::hv::Machine {
        asterism_core::hv::Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "test".into(),
        }
    }

    /// The normal dead-handle reconciliation path must not turn the missing
    /// handle inside an ambiguous boot window into stopped authority.
    #[test]
    fn reconcile_preserves_a_pending_boot_fence() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = Shard::load(&dir.path().join("state.json")).unwrap();
        reg.create(
            "pending",
            "laptop",
            "debian:13",
            asterism_core::instance::Shape::default(),
            test_machine(),
        )
        .unwrap();
        let (_, intent) = reg.begin_boot("pending").unwrap();

        reconcile(&mut reg);

        let pending = reg.get("pending").unwrap();
        assert_eq!(pending.status, Status::Running);
        assert_eq!(pending.boot_intent_id.as_deref(), Some(intent.as_str()));
    }

    /// A pre-v6 row cannot acquire authority merely because a new device now
    /// answers to the old provider's human name. Recovery must keep both the
    /// consumer row and its intent instead of accepting the replacement's
    /// missing lease as proof that the original writer fence is gone.
    #[tokio::test]
    async fn legacy_provider_name_reuse_preserves_release_row_and_intent() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        let intents_path = dir.path().join("release.json");
        let mut reg = Shard::load(&state).unwrap();
        reg.create(
            "dev",
            "laptop",
            "debian:13",
            asterism_core::instance::Shape::default(),
            test_machine(),
        )
        .unwrap();
        reg.attach_block("dev", "tank", "nas", 7, 1 << 30).unwrap();
        reg.save_confirmed().unwrap();
        let instance_id = reg.get("dev").unwrap().id.clone();
        let intent = ReleaseIntent::new(
            "dev",
            &instance_id,
            "tank",
            "nas",
            "replacement-device-id",
            "laptop-id",
            7,
        );
        let mut intents = ReleaseIntents::load(&intents_path).unwrap();
        intents.begin_durable(intent.clone()).unwrap();

        let error = complete_release(&mut reg, &mut intents, &intent)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("possible device-name reuse"), "{error}");
        let row = reg.get("dev").unwrap();
        assert_eq!(row.volumes.len(), 1, "the legacy row was forgotten");
        assert!(row.volumes[0].host_id.is_none());
        assert!(
            ReleaseIntents::load(&intents_path)
                .unwrap()
                .contains(&intent),
            "the ambiguous release intent was cleared"
        );
    }

    #[test]
    fn detach_refuses_a_legacy_provider_before_rebinding_its_name() {
        let legacy = asterism_core::instance::Volume::block("tank", "nas", 7, 1 << 30);
        let error = recorded_provider_id(&legacy, "detach")
            .unwrap_err()
            .to_string();
        assert!(error.contains("no immutable provider identity"), "{error}");
        assert!(error.contains("preserving the consumer row"), "{error}");
    }

    /// A console is the one thing in this protocol whose size the guest
    /// chooses, and it chooses it over months. Reading all of it to answer
    /// `ast logs` put the size of a reply frame — and of the daemon's own
    /// allocation — in the hands of whatever is running in the guest.
    #[test]
    fn a_console_longer_than_the_cap_is_answered_from_its_end() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("console.log");
        let line = "the guest said something\n";
        let mut written = String::new();
        while written.len() < (CONSOLE_TAIL_BYTES as usize) + (1 << 20) {
            written.push_str(line);
        }
        written.push_str("this is the last thing it said\n");
        std::fs::write(&log, &written).unwrap();

        let (text, clipped) = tail_of(&log, 0).unwrap();
        assert!(clipped, "a clipped read did not say so");
        assert!(
            text.len() as u64 <= CONSOLE_TAIL_BYTES,
            "answered with {} bytes, cap is {CONSOLE_TAIL_BYTES}",
            text.len()
        );
        assert!(
            text.ends_with("this is the last thing it said\n"),
            "it is not the end"
        );
        // Starting mid-file lands mid-line; the half-line is dropped rather
        // than presented as something the guest wrote.
        assert!(
            text.starts_with(line),
            "a partial first line was kept: {:?}",
            &text[..40]
        );
    }

    /// The ordinary case still reads the whole file and says nothing was
    /// left out, and `--lines` still means what it meant.
    #[test]
    fn a_short_console_is_answered_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("console.log");
        std::fs::write(&log, "one\ntwo\nthree\n").unwrap();

        assert_eq!(
            tail_of(&log, 0).unwrap(),
            ("one\ntwo\nthree\n".to_owned(), false)
        );
        assert_eq!(tail_of(&log, 2).unwrap(), ("two\nthree".to_owned(), true));
        assert_eq!(
            tail_of(&log, 9).unwrap(),
            ("one\ntwo\nthree".to_owned(), false)
        );
    }

    #[test]
    fn attaching_block_storage_to_a_running_guest_is_refused_before_a_lease() {
        let error = refuse_running_block_attach("dev", Status::Running)
            .unwrap_err()
            .to_string();
        assert!(error.contains("stop it before attaching"), "{error}");
        assert!(error.contains("cannot be fenced"), "{error}");
        assert!(refuse_running_block_attach("dev", Status::Stopped).is_ok());
    }

    /// Firmware puts whatever it likes on a serial line, and a stray byte
    /// that is not utf-8 is not a reason to tell the user there is no log —
    /// which is what `read_to_string` made it, since both failures came back
    /// as the same error.
    #[test]
    fn a_console_that_is_not_utf8_is_still_a_console() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("console.log");
        std::fs::write(&log, b"before\n\xff\xfe\nafter\n").unwrap();
        let (text, _) = tail_of(&log, 0).unwrap();
        assert!(
            text.contains("before") && text.contains("after"),
            "{text:?}"
        );
    }

    /// An unknown profile is refused before the row exists.
    #[test]
    fn an_unknown_profile_is_refused_at_create() {
        assert!(check_profiles(&["claude".to_owned()]).is_ok());
        assert!(check_profiles(&[]).is_ok());

        let err = check_profiles(&["cladue".to_owned()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no bootstrap profile called"), "{err}");
    }

    /// Claiming and resolving are different questions, and a rename asks
    /// both — the old name is resolved, the new one is claimed. Getting that
    /// round the wrong way would refuse every rename ever typed, because the
    /// name an instance already has is taken by that instance.
    #[test]
    fn a_rename_claims_the_name_it_is_moving_to_and_not_the_one_it_has() {
        assert_eq!(
            claimed_name(&Request::Rename {
                name: "dev".into(),
                new_name: "dev2".into()
            }),
            Some("dev2")
        );
        assert_eq!(
            claimed_name(&Request::Create {
                name: "dev".into(),
                image: "debian:13".into(),
                shape: Default::default(),
                backend: None,
                publish: Vec::new(),
                profiles: Vec::new(),
            }),
            Some("dev")
        );
        // Everything else resolves a name it did not invent, so it claims
        // nothing and must not be made to wait on every peer in the orbit.
        assert_eq!(
            claimed_name(&Request::Up {
                name: "dev".into(),
                restart: None
            }),
            None
        );
        assert_eq!(claimed_name(&Request::Status { name: "dev".into() }), None);
        assert_eq!(claimed_name(&Request::List), None);
    }

    /// The refusal the chain ends on is a sentence, not a panic: a frame that
    /// arrived by the wrong door is a bug in a daemon, and the daemon on the
    /// other end has to be able to print something.
    #[test]
    fn a_frame_no_area_claims_is_refused_in_words() {
        let Response::Error { message } = not_a_shard_request() else {
            panic!("a refusal");
        };
        assert!(message.contains("single device's shard"), "{message}");
    }
}
