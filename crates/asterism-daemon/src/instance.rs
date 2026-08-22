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

use anyhow::{Context, Result};

use asterism_core::durable;
use asterism_core::hv::{ImageKind, RunState, STOP_DEADLINE};
use asterism_core::instance::{local_host, Instance, Policy, Status};
use asterism_core::profile;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::{self, Shard};
use asterism_core::{backup, compat};
use asterism_core::{paths, VERSION};

use crate::mesh::Mesh;
use crate::{backend, egress, persist, swap, volume, Node};

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
                    Response::Instance { instance }
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
                check_profiles(&r.kind, &profiles)?;
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
        Request::SetProfiles { name, profiles } => {
            let kind = reg.get(&name).map(|i| i.image_kind);
            kind.and_then(|kind| check_profiles(&kind, &profiles))
                .and_then(|_| reg.set_profiles(&name, profiles))
        }
        // `--restart` is recorded before the boot, so an instance that comes
        // up and immediately dies is already carrying the policy the user
        // asked for when the supervisor looks at the corpse.
        Request::Up { name, restart } => match restart {
            Some(restart) => reg.set_restart(&name, restart).and_then(|_| up(reg, &name)),
            None => up(reg, &name),
        },
        // The bridges go before the guest does: a QEMU that is being asked to
        // shut down cleanly should find its disks still there, and the local
        // sockets should be gone by the time it is.
        Request::Down { name } => {
            let stopped = down(reg, &name);
            volume::take_down(&name).await;
            // The egress proxy exists for a guest, so it goes when the guest
            // does. Its port is remembered, so the next boot puts it back
            // where the seed already says it is.
            egress::stop(&name);
            stopped
        }
        Request::Remove { name } => {
            // Leases are handed back while we still know what they were.
            // A device that will not answer does not block the removal — its
            // volume stays leased to an instance that no longer exists, which
            // `ast detach` on that device's side is the remedy for, and which
            // is a great deal better than an instance that cannot be deleted
            // because a NAS is asleep.
            if let Ok(inst) = reg.get(&name).cloned() {
                volume::take_down(&name).await;
                volume::release_all(&inst).await;
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
        } => attach_block(reg, &name, &vol, &device).await,
        Request::Detach {
            name,
            volume: vol,
            host,
        } => detach(reg, &name, &vol, host.as_deref()).await,
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
            Response::Instance { instance }
        }
        Err(e) => Response::Error {
            message: format!("{e:#}"),
        },
    }
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

/// Refuse a profile set that cannot be applied, before anything is written.
///
/// Two ways it cannot be. The name may not be in the catalog, which
/// [`profile::Bootstrap::resolve`] answers with the catalog itself. Or the
/// instance may be an OCI one, which has no cloud-init and therefore no way
/// to be told anything: a container image's whole configuration was written
/// into its filesystem at pull time, so a profile silently doing nothing is
/// the alternative to saying this.
fn check_profiles(kind: &ImageKind, profiles: &[String]) -> Result<()> {
    if profiles.is_empty() {
        return Ok(());
    }
    if *kind == ImageKind::OciRootfs {
        anyhow::bail!(
            "a container image has no cloud-init to apply a bootstrap profile with — \
             its configuration is the image. Boot a cloud image (ast images) \
             to use profiles"
        );
    }
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

pub(crate) fn up(reg: &mut Shard, name: &str) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    if inst.status == Status::Running {
        anyhow::bail!("instance {name:?} is already running");
    }
    // A cloud-init seed bakes in the guest key of the device that builds it,
    // so whoever builds one is whose key opens that guest from then on.
    // Normally that is settled at the first boot and never moves again; it
    // moves when the seed is rebuilt, which is why the stamp is compared
    // rather than assumed. `up` only ever runs on the device holding the row,
    // so that device is this instance's own cpu device.
    let stamp = paths::instance_dir(name).join("seed.stamp");
    let before = std::fs::read(&stamp).ok();
    let (handle, leases) = tokio::task::block_in_place(|| -> Result<_> {
        let hv = backend::for_instance(&inst)?;
        let mut req = backend::boot_req(&inst, &*hv)?;
        // Every boot renews the lease on every block volume this instance
        // holds, at a higher epoch, and raises the local socket the guest's
        // disk arrives on. A volume somebody else has taken in the meantime
        // stops the boot here, saying who has it — which is the whole point
        // of doing it before the hypervisor is asked for anything.
        let raised = volume::bring_up(&inst, &*hv)?;
        req.extra_disks = raised.disks;
        let prep = hv.prepare(&req)?;
        Ok((hv.boot(&req, &prep)?, raised.leases))
    })?;
    // The epoch this boot was granted, written back onto the instance. The
    // one recorded before was the attach's, and it stopped being true the
    // moment this boot renewed it — which matters to `ast status`, and
    // matters more to the next daemon that has to reconnect this guest's
    // disks without disturbing the guest (`volume::reattach`).
    for lease in leases {
        let _ = reg.attach_block(
            name,
            &lease.volume,
            &lease.device,
            lease.epoch,
            lease.size_bytes,
        );
    }
    if inst.seed_device.is_none() || std::fs::read(&stamp).ok() != before {
        let _ = reg.set_seed_device(name, &inst.cpu_device);
    }
    reg.set_running(name, handle)
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
        .filter(|i| i.status == Status::Running && !is_running(i))
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

/// Take a block volume's lease from the device that holds it, and record it
/// on the instance.
///
/// The lease first, the registry second: a record written against a lease we
/// were refused would be an instance that looks configured and cannot boot,
/// which is the failure `check_can_share` exists to prevent for directories.
async fn attach_block(reg: &mut Shard, name: &str, vol: &str, device: &str) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    let hv = backend::for_instance(&inst)?;
    volume::check_backend(&*hv)?;
    // Admission precedes the provider-side lease bump and the local registry
    // write.  A relay-only or high-latency placement therefore leaves neither
    // device half-mutated.
    volume::preflight_remote_volume(device).await?;
    let (epoch, _export, size) = volume::take_lease(vol, device, name).await?;
    reg.attach_block(name, vol, device, epoch, size)
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

    // The lease goes back before the record does. A provider that will not
    // answer fails the detach rather than leaving a volume this device has
    // forgotten and that device still thinks is spoken for.
    if record.is_block() {
        volume::give_lease_back(vol, &host, name).await?;
    }
    reg.detach_volume(name, vol, &host).map(|(inst, _)| inst)
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

    /// A profile that cannot be applied is refused before the row exists.
    ///
    /// Both refusals are about the same thing: an instance whose record
    /// promises work that will never happen. One is a name nothing answers
    /// to; the other is a guest with no cloud-init to be told anything by,
    /// which is every OCI instance and is not a thing a message can fix.
    #[test]
    fn a_profile_that_cannot_be_applied_is_refused_at_create() {
        assert!(check_profiles(&ImageKind::Disk, &["claude".to_owned()]).is_ok());
        // Nothing asked for is nothing to refuse, whatever the image is.
        assert!(check_profiles(&ImageKind::OciRootfs, &[]).is_ok());

        let err = check_profiles(&ImageKind::Disk, &["cladue".to_owned()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no bootstrap profile called"), "{err}");

        let err = check_profiles(&ImageKind::OciRootfs, &["claude".to_owned()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("container image has no cloud-init"), "{err}");
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
