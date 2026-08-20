//! astd — the Asterism device daemon.
//!
//! The orbit is a pool of parts; an instance is a computer assembled from
//! them. This daemon is one device's contribution to that pool: it holds this
//! device's shard of the orbit registry, boots the guests whose cpu and ram it
//! supplies, and serves the `ast` CLI over a unix socket (one JSON request per
//! line, one JSON response per line). Guests are booted through the
//! [`Hypervisor`] boundary: this file never names a hypervisor concept, and
//! gates optional behaviour on `Caps`.
//!
//! It also holds this device's presence in its orbit — see [`mesh`]. The
//! daemon, not the CLI, is what other devices talk to and what dials them.
//! That is what makes the instance namespace flat: `ast up dev` typed anywhere
//! arrives at the nearest daemon, which resolves `dev` across the orbit and,
//! if some other device holds that row, sends it the very same [`Request`]
//! frame over a mesh stream. The user never names a device, because in a pool
//! of parts there is nothing for them to name.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use asterism_core::hv::{ImageKind, RunState, SnapshotId, STOP_DEADLINE};
use asterism_core::instance::{local_host, Instance, Policy, Status};
use asterism_core::orbit::Orbit;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::{self, Shard};
use asterism_core::{paths, VERSION};

mod backend;
mod mesh;
mod persist;
mod swap;
mod volume;
mod wake;

use mesh::{ClientIo, Mesh, Splice};

/// This device's own state: its shard of the orbit registry, and the name the
/// orbit knows it by.
///
/// The two travel together because almost everything needs both — a row is
/// written with the device that supplies its cpu, and that device is named by
/// the orbit, not by its hostname. Two daemons on one machine with different
/// orbit names are two distinct suppliers of parts, and the tests depend on
/// that being true.
#[derive(Clone)]
pub(crate) struct Node {
    pub shard: Arc<Mutex<Shard>>,
    pub orbit: Arc<Mutex<Orbit>>,
}

impl Node {
    /// What this device is called in its orbit.
    pub async fn device_name(&self) -> String {
        self.orbit.lock().await.self_name().to_owned()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let home = paths::home_dir();
    std::fs::create_dir_all(&home).with_context(|| format!("creating {}", home.display()))?;

    // Before anything is served: a cpu-part swap this device was receiving
    // when it died left a staging directory, and this is the "next contact"
    // that clears it. It was never bootable and no shard row ever pointed at
    // it, so there is nothing to consult first.
    swap::sweep_staging();

    let node = Node {
        shard: Arc::new(Mutex::new(Shard::load(&paths::state_path())?)),
        orbit: Arc::new(Mutex::new(Orbit::load(&paths::orbit_path())?)),
    };

    let sock = paths::socket_path();
    // A leftover socket file from a dead daemon blocks bind; a live daemon
    // would still be accepting, so probe before unlinking.
    if sock.exists() {
        if UnixStream::connect(&sock).await.is_ok() {
            anyhow::bail!("another astd is already running on {}", sock.display());
        }
        std::fs::remove_file(&sock)?;
    }
    let listener =
        UnixListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))?;

    // The pid file is how an `ast` newer than this daemon retires it: the
    // socket says something is listening, but only a pid can be acted on.
    let pidfile = paths::daemon_pid_path();
    std::fs::write(&pidfile, std::process::id().to_string())
        .with_context(|| format!("writing {}", pidfile.display()))?;

    eprintln!("astd {VERSION}: listening on {}", sock.display());

    // The mesh is presence, not plumbing the local commands need: a device
    // whose endpoint will not bind should still run its own instances, and
    // say clearly why the orbit is out of reach.
    let mesh = match Mesh::start(node.clone()).await {
        Ok(mesh) => {
            eprintln!(
                "astd: device {} on the mesh as {:?}",
                mesh.device_id().short(),
                mesh.self_name().await
            );
            Some(mesh)
        }
        Err(e) => {
            eprintln!("astd: the mesh is unavailable: {e:#}");
            None
        }
    };

    // The volume plane, before anything can be resurrected onto it: an
    // instance coming back up may need a lease taken and a bridge raised
    // before its guest has a disk to boot with.
    if let Err(e) = volume::init(node.clone(), mesh.clone()) {
        eprintln!("astd: block volumes are unavailable: {e:#}");
    }

    // Moving an instance's cpu part needs the mesh, and the target's half of
    // a move is reached from a mesh stream — so, like the volume plane, it
    // holds a process-wide handle rather than taking one as an argument.
    swap::init(mesh.clone());

    // What this device was running, it runs again — before the first
    // request is served, and then continuously (see `persist`).
    persist::resurrect(&node.shard).await;
    persist::supervise(node.shard.clone());

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let node = node.clone();
                let mesh = mesh.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(stream, node, mesh).await {
                        eprintln!("astd: connection error: {e:#}");
                    }
                });
            }
            _ = shutdown_signal() => {
                let _ = std::fs::remove_file(&sock);
                let _ = std::fs::remove_file(&pidfile);
                eprintln!("astd: shutting down");
                return Ok(());
            }
        }
    }
}

/// Ctrl-C, or the SIGTERM the CLI sends when it retires a stale daemon.
/// Both have to clean up the socket and pid file, or the replacement
/// daemon refuses to bind.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

async fn serve(stream: UnixStream, node: Node, mesh: Option<Arc<Mesh>>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();

    // Anything this connection asked us to hold open on its behalf. Today
    // that is the loopback listener behind `ast ssh` on a guest whose cpu is
    // elsewhere: `ast` keeps this socket open for exactly as long as ssh is
    // running, so dropping these when the loop ends *is* the teardown.
    let mut splices: Vec<Splice> = Vec::new();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<Request>(&line) {
            Ok(req) => req,
            // A CLI newer than this daemon lands here, on a variant we have
            // never heard of. The wording matters: `ast` classifies it and
            // restarts us rather than showing the user a serde error.
            Err(e) => {
                send(&mut write, &Response::Error { message: format!("bad request: {e}") }).await?;
                continue;
            }
        };

        // Pairing is a conversation, not a question — a ticket to print, a
        // code to compare, a verdict to take — so it borrows the connection
        // for as many frames as it needs.
        if let Request::DeviceInvite { .. } | Request::DeviceAdd { .. } = request {
            let mut io = ClientIo { lines: &mut lines, write: &mut write };
            if let Err(e) = pair(request, mesh.as_ref(), &mut io).await {
                io.send(&Response::Error { message: format!("{e:#}") }).await?;
            }
            continue;
        }

        // A wake is a job rather than a question — who is going to send the
        // packet, that it went, and then up to a minute later whether the
        // machine turned up — so it reports as it goes, which needs the
        // connection the same way pairing does.
        if let Request::DeviceWake { name } = &request {
            let mut io = ClientIo { lines: &mut lines, write: &mut write };
            let woken = match mesh.as_ref() {
                Some(mesh) => mesh.wake(name, &mut io).await,
                None => Err(anyhow::anyhow!("{NO_MESH}")),
            };
            if let Err(e) = woken {
                io.send(&Response::Error { message: format!("{e:#}") }).await?;
            }
            continue;
        }

        // A cpu-part swap is a job rather than a question — a preflight, a
        // fence, a disk crossing a network, two commits — so it reports as it
        // goes, on the connection that asked, exactly as a wake does.
        if let Request::SetCpu { name, device, down } = &request {
            let mut io = ClientIo { lines: &mut lines, write: &mut write };
            let moved = swap::run(name, device, *down, &node, mesh.as_ref(), &mut io).await;
            if let Err(e) = moved {
                io.send(&Response::Error { message: format!("{e:#}") }).await?;
            }
            continue;
        }

        // `ast ssh` needs something to outlive its own reply — a listener the
        // CLI is about to point ssh at — so it is answered here, where the
        // connection's lifetime is.
        if let Request::SshEndpoint { name } = &request {
            let (response, splice) = ssh_endpoint(name, &node, mesh.as_ref()).await;
            splices.extend(splice);
            send(&mut write, &response).await?;
            continue;
        }

        let response = dispatch(request, &node, mesh.as_ref()).await;
        send(&mut write, &response).await?;
    }
    Ok(())
}

async fn send(
    write: &mut tokio::net::unix::OwnedWriteHalf,
    response: &Response,
) -> Result<()> {
    let mut out = serde_json::to_vec(response)?;
    out.push(b'\n');
    write.write_all(&out).await?;
    Ok(())
}

/// Routes one request that came off the unix socket.
///
/// Three kinds arrive here. Requests about the orbit itself go to the mesh.
/// Requests about one instance are resolved across the orbit and forwarded to
/// whichever device holds that row — this is where `--device` stops being
/// necessary. Everything else is about this device and is answered from its
/// shard.
async fn dispatch(request: Request, node: &Node, mesh: Option<&Arc<Mesh>>) -> Response {
    match request {
        Request::Proxy { device, inner } => match mesh {
            Some(mesh) => reply_or_error(mesh.proxy(&device, *inner).await),
            None => no_mesh(),
        },
        Request::Devices => match mesh {
            Some(mesh) => Response::Devices { devices: mesh.devices().await },
            None => no_mesh(),
        },
        // Two questions about this device and nothing else: where it sits on
        // the wire, and what it can honestly promise about being woken.
        // Neither consults the shard or the orbit.
        Request::DeviceFacts => Response::WakeFacts { facts: wake::facts() },
        Request::DeviceCheck => Response::WakeCheck {
            device: node.device_name().await,
            rows: wake::check(),
        },
        // Sent by a peer that wants a packet put on *this* device's LAN, and
        // the reason wake is an orbit operation at all. Membership was
        // established by the accept loop before the frame was read, exactly
        // as for every other forwarded request; the lan-id inside it is then
        // checked against this device's own, so a device that has moved
        // declines rather than broadcasting somebody's MAC at strangers.
        Request::WakeBroadcast { mac, lan_id } => {
            match wake::broadcast(&mac, lan_id.as_deref()) {
                Ok(sent) => Response::Wake { text: sent.join(", "), done: true },
                Err(e) => Response::Error { message: format!("{e:#}") },
            }
        }
        // Answered on the connection that asked, in `serve`, because it
        // reports as it goes rather than once at the end.
        Request::DeviceWake { name } => Response::Error {
            message: format!("ast device wake {name} needs a connection of its own"),
        },
        Request::DevicePing { device } => match mesh {
            Some(mesh) => reply_or_error(mesh.ping(&device).await),
            None => no_mesh(),
        },
        Request::DeviceRemove { name } => match mesh {
            Some(mesh) => match mesh.remove_device(&name).await {
                Ok(_) => Response::Ok,
                Err(e) => Response::Error { message: format!("{e:#}") },
            },
            None => no_mesh(),
        },
        // Only ever arrives inside a pairing conversation, which handles it
        // there; on its own it is a CLI that lost its place.
        Request::PairConfirm { .. } => Response::Error {
            message: "there is no pairing in progress on this connection".into(),
        },
        // The whole registry, not this device's slice of it. `ast ls`.
        Request::ListOrbit => match mesh {
            Some(mesh) => reply_or_error(mesh.orbit_registry(node).await),
            // With no mesh there is no orbit to assemble, but there is still a
            // shard, and it is the honest whole of what this device can see.
            None => local_rows(node).await,
        },
        Request::Create { name, image, shape, backend, publish } => {
            match claim(&name, node, mesh).await {
                Ok(()) => {
                    handle(Request::Create { name, image, shape, backend, publish }, node).await
                }
                Err(e) => Response::Error { message: format!("{e:#}") },
            }
        }
        // Renaming claims the new name and resolves the old one, in that
        // order: an instance that fails the claim must keep the name it has.
        Request::Rename { name, new_name } => {
            if let Err(e) = claim(&new_name, node, mesh).await {
                return Response::Error { message: format!("{e:#}") };
            }
            route(Request::Rename { name, new_name }, node, mesh).await
        }
        request => route(request, node, mesh).await,
    }
}

/// Answers a request about one instance from wherever that instance is.
///
/// The name is looked up in this device's shard first — the common case, and
/// the one that must not pay for the mesh — and then across the orbit. A hit
/// elsewhere is forwarded verbatim in a [`Request::Proxy`] envelope, so the
/// far daemon runs the identical frame its own CLI would have handed it.
async fn route(request: Request, node: &Node, mesh: Option<&Arc<Mesh>>) -> Response {
    let Some(name) = request.subject() else {
        return handle(request, node).await;
    };
    if node.shard.lock().await.holds(name) {
        return handle(request, node).await;
    }
    let Some(mesh) = mesh else {
        return handle(request, node).await;
    };
    match mesh.locate(name).await {
        Ok(Some(device)) => reply_or_error(mesh.proxy(&device, request).await),
        // Nowhere in the orbit answers to it, so the local shard's "no such
        // instance" is both true and the message the user should see.
        Ok(None) => handle(request, node).await,
        Err(e) => Response::Error { message: format!("{e:#}") },
    }
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

/// The orbit view a daemon with no mesh can honestly produce: its own shard.
async fn local_rows(node: &Node) -> Response {
    let mut shard = node.shard.lock().await;
    reconcile(&mut shard);
    Response::Orbit {
        rows: shard
            .list()
            .into_iter()
            .map(|instance| asterism_core::registry::OrbitRow { instance, live: true })
            .collect(),
    }
}

/// Drives `ast device invite` / `ast device add`, which need the connection
/// rather than a single reply.
async fn pair(request: Request, mesh: Option<&Arc<Mesh>>, io: &mut ClientIo<'_>) -> Result<()> {
    let Some(mesh) = mesh else {
        anyhow::bail!("{NO_MESH}");
    };
    match request {
        Request::DeviceInvite { name, ttl_secs } => mesh.invite(name, ttl_secs, io).await,
        Request::DeviceAdd { ticket, name } => mesh.add(&ticket, name, io).await,
        other => anyhow::bail!("{other:?} is not a pairing request"),
    }
}

/// What a daemon whose endpoint never came up has to say about the orbit.
const NO_MESH: &str = "this daemon has no mesh endpoint — see the astd log for why";

fn no_mesh() -> Response {
    Response::Error { message: NO_MESH.into() }
}

fn reply_or_error(result: Result<Response>) -> Response {
    match result {
        Ok(response) => response,
        Err(e) => Response::Error { message: format!("{e:#}") },
    }
}

/// Runs a request against this device's shard of the orbit registry.
///
/// Reached from the unix socket and from a mesh stream alike — a forwarded
/// request is not a different kind of request, it just arrived by a different
/// door, and that is the whole reason no command needed a second
/// implementation to be answerable from anywhere in the orbit.
///
/// Nothing here consults the orbit. By the time a request gets this far its
/// name has already been resolved (or claimed) against every device, so this
/// is deliberately the shard-local end of the world: it is also what stops a
/// forwarded request from fanning out again on arrival.
pub(crate) async fn handle(req: Request, node: &Node) -> Response {
    // Volumes are this device's own part of the pool, not a row in its shard,
    // and they are answered before the shard is touched. That is not only
    // tidiness: `up` holds the shard while it boots, and an instance whose
    // volume is on the very device running it would otherwise ask itself for
    // a lease and wait forever on its own lock.
    if volume::is_plane_request(&req) {
        return volume::serve(req).await;
    }

    let cpu_device = node.device_name().await;
    let mut reg = node.shard.lock().await;
    reconcile(&mut reg);

    // An instance whose name turned out not to be unique answers exactly the
    // commands that can end that, and tells everything else what to do.
    if let Some(name) = req.subject() {
        if !req.survives_a_conflict() {
            if let Ok(inst) = reg.get(name) {
                if let Some(conflict) = &inst.conflict {
                    return Response::Error {
                        message: registry::conflicted(inst, conflict),
                    };
                }
            }
        }

        // An instance whose bytes are in flight to another device answers
        // only what cannot change them. This is the half of "never two
        // bootable copies" that lives on the source: the target's half is
        // that its copy is not called anything an instance could be called
        // until it commits.
        if !req.survives_a_move() {
            if let Ok(inst) = reg.get(name) {
                if let Some(moving) = &inst.moving {
                    return Response::Error {
                        message: format!(
                            "instance {name:?} is moving to {} — its bytes are in \
                             flight, so this device will not touch them. Wait for the \
                             move to finish, or run it again if it was interrupted.",
                            moving.to_device
                        ),
                    };
                }
            }
        }

        // What a device says about an instance that used to be here. Only
        // ever reached by a request aimed at this device directly; the
        // ordinary path resolves the name across the orbit and lands on
        // whoever holds the row now.
        if !reg.holds(name) {
            if let Some(note) = swap::moved_note(name) {
                return Response::Error { message: note };
            }
        }
    }

    // Reads answer straight from memory; mutations persist before replying.
    let mutation = match req {
        Request::Ping => return Response::Pong { version: VERSION.to_owned() },
        Request::List => return Response::Instances { instances: reg.list() },
        Request::Status { name } => {
            return match reg.get(&name) {
                Ok(instance) => Response::Instance { instance: instance.clone() },
                Err(e) => Response::Error { message: format!("{e:#}") },
            }
        }
        // The backend is chosen once, here, and recorded on the instance:
        // `--backend vz` is opt-in until vz has survived a release
        // (BACKENDS.md §7), and an explicit choice this device cannot honour
        // fails now rather than at the first `ast up`.
        Request::Create { name, image, shape, backend: requested, publish } => {
            backend::select_for(requested.as_deref()).and_then(|hv| {
                let r = backend::image_ref(&image)?;
                // What the image turned out to be is checked against the
                // backend before the registry moves: an instance defined
                // against a backend that could never boot it is worse than
                // a create that says no.
                backend::check_can_boot(&*hv, &r, &publish)?;
                reg.create(&name, &cpu_device, &r.name, shape, backend::machine_identity(&*hv))?;
                if r.kind == ImageKind::OciRootfs {
                    // A container that has finished is not a crash; see
                    // `Policy::never`.
                    reg.set_policy(&name, Policy::never())?;
                }
                reg.set_source(&name, r.kind, publish)
            })
        }
        // `--restart` is recorded before the boot, so an instance that comes
        // up and immediately dies is already carrying the policy the user
        // asked for when the supervisor looks at the corpse.
        Request::Up { name, restart } => match restart {
            Some(restart) => {
                reg.set_restart(&name, restart).and_then(|_| up(&mut reg, &name))
            }
            None => up(&mut reg, &name),
        },
        // The bridges go before the guest does: a QEMU that is being asked to
        // shut down cleanly should find its disks still there, and the local
        // sockets should be gone by the time it is.
        Request::Down { name } => {
            let stopped = down(&mut reg, &name);
            volume::take_down(&name).await;
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
                let _ = std::fs::rename(&from, &to);
            }
        }),
        Request::MarkConflicted { name, other_cpu_device } => {
            reg.mark_conflicted(&name, &other_cpu_device)
        }
        Request::AttachVolume { name, path, host, mount_point } => {
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
        Request::AttachBlock { name, volume: vol, device } => {
            attach_block(&mut reg, &name, &vol, &device).await
        }
        Request::Detach { name, volume: vol, host } => {
            detach(&mut reg, &name, &vol, host.as_deref()).await
        }
        // ---- swapping the cpu part -----------------------------------------
        //
        // Each of these is one step of a move, aimed at one named device and
        // answered by its shard. They save (or refuse) themselves, so they
        // return rather than falling through to the mutation path.
        Request::MoveOffer { name } => {
            return tokio::task::block_in_place(|| swap::offer(&reg, &name))
        }
        Request::MoveProbe { manifest } => {
            let already_here = reg.holds(&manifest.instance.name);
            return tokio::task::block_in_place(|| {
                swap::probe(&manifest, &cpu_device, already_here)
            });
        }
        Request::MovePrepare { name, to_device, epoch } => {
            return tokio::task::block_in_place(|| {
                swap::prepare(&mut reg, &name, &to_device, epoch)
            })
        }
        Request::MoveCommitTarget { manifest, epoch } => {
            return tokio::task::block_in_place(|| {
                swap::commit_target(&mut reg, &manifest, epoch, &cpu_device)
            })
        }
        Request::MoveCommitSource { name, epoch } => {
            return tokio::task::block_in_place(|| swap::commit_source(&mut reg, &name, epoch))
        }
        Request::MoveAbortSource { name, epoch } => {
            return swap::abort_source(&mut reg, &name, epoch)
        }
        Request::MoveAbortTarget { name, epoch } => return swap::abort_target(&name, epoch),

        // Snapshots live in the instance's disk, not in the registry, so
        // these answer without a save.
        Request::Snapshot { name, tag } => {
            return reply(stopped(&reg, &name).and_then(|inst| {
                tokio::task::block_in_place(|| snapshot_create(&inst, &tag))
            }))
        }
        Request::SnapshotList { name } => {
            let listed = reg
                .get(&name)
                .cloned()
                .and_then(|inst| tokio::task::block_in_place(|| snapshot_list(&inst)));
            return match listed {
                Ok(snapshots) => Response::Snapshots { snapshots },
                Err(e) => Response::Error { message: format!("{e:#}") },
            };
        }
        Request::SnapshotRestore { name, tag } => {
            return reply(stopped(&reg, &name).and_then(|inst| {
                tokio::task::block_in_place(|| snapshot_restore(&inst, &tag))
            }))
        }
        // Stopped, like taking one and rolling one back. For a raw instance
        // the file being unlinked is not the one the guest has open, but a
        // legacy `disk.qcow2` keeps its snapshots *inside* the disk, and
        // rewriting that table under a live guest is not a thing to offer on
        // one disk layout and refuse on the other.
        Request::SnapshotRemove { name, tag } => {
            return reply(stopped(&reg, &name).and_then(|inst| {
                tokio::task::block_in_place(|| snapshot_remove(&inst, &tag))
            }))
        }
        // A file on this device's disk, read here rather than by the CLI, so
        // that the answer is the same whoever asked and from wherever.
        Request::Logs { name, lines } => {
            return match reg.get(&name).map(|i| i.name.clone()) {
                Ok(name) => match console_tail(&name, lines) {
                    Ok((text, truncated)) => Response::Log { text, truncated },
                    Err(e) => Response::Error { message: format!("{e:#}") },
                },
                Err(e) => Response::Error { message: format!("{e:#}") },
            }
        }
        // Answered on the connection that asked, in `serve`, because the reply
        // is only useful for as long as the listener behind it is alive.
        Request::SshEndpoint { .. }
        // Assembled by `dispatch` out of many shards, this one included.
        | Request::ListOrbit
        // Routed by `dispatch` before they get here; a mesh stream that
        // carries one anyway is talking to the wrong half of the daemon.
        | Request::Proxy { .. }
        | Request::Devices
        | Request::DeviceInvite { .. }
        | Request::DeviceAdd { .. }
        | Request::PairConfirm { .. }
        | Request::DeviceRemove { .. }
        | Request::DevicePing { .. }
        // Answered before they get here on both doors — by `dispatch` off the
        // unix socket, by `mesh::serve_stream` off a mesh stream — because
        // they are about this device's NIC and not about its shard.
        | Request::DeviceWake { .. }
        | Request::WakeBroadcast { .. }
        | Request::DeviceFacts
        | Request::DeviceCheck
        // Answered by the volume plane at the top of this function, before
        // the shard was ever locked.
        | Request::VolumeCreate { .. }
        | Request::VolumeReconnect { .. }
        | Request::VolumeList
        | Request::VolumeRemove { .. }
        | Request::VolumeLease { .. }
        | Request::VolumeRelease { .. }
        // Answered on the connection that asked, in `serve`: a move reports
        // as it goes, because it is minutes of a disk crossing a network.
        | Request::SetCpu { .. } => {
            return Response::Error {
                message: "that request is not answered by a single device's shard".into(),
            }
        }
    };
    match mutation {
        Ok(instance) => {
            if let Err(e) = reg.save() {
                return Response::Error { message: format!("saving registry: {e:#}") };
            }
            Response::Instance { instance }
        }
        Err(e) => Response::Error { message: format!("{e:#}") },
    }
}

/// The last `lines` lines of a guest's console, and whether older ones were
/// left behind. `lines` of 0 means all of it.
fn console_tail(name: &str, lines: u32) -> Result<(String, bool)> {
    let path = paths::instance_dir(name).join("console.log");
    let text = std::fs::read_to_string(&path).map_err(|_| {
        anyhow::anyhow!("no console log for {name:?} yet — `ast up {name}` starts one")
    })?;
    if lines == 0 {
        return Ok((text, false));
    }
    let all: Vec<&str> = text.lines().collect();
    let keep = all.len().min(lines as usize);
    let tail = all[all.len() - keep..].join("\n");
    Ok((tail, keep < all.len()))
}

/// Where `ssh` should be pointed to reach `name`'s guest, and whatever has to
/// stay alive for that address to keep working.
///
/// One answer for both cases, which is the point: a loopback host and port.
/// When this device supplies the guest's cpu that is the hypervisor's own
/// forwarded port and nothing needs holding open. When another device does,
/// the mesh puts a listener here and splices it there, and the returned
/// [`Splice`] is what the caller must keep to keep it.
async fn ssh_endpoint(
    name: &str,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> (Response, Option<Splice>) {
    let local = {
        let mut reg = node.shard.lock().await;
        reconcile(&mut reg);
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

/// For requests whose whole answer is "it worked" or why it didn't.
fn reply(result: Result<()>) -> Response {
    match result {
        Ok(()) => Response::Ok,
        Err(e) => Response::Error { message: format!("{e:#}") },
    }
}

/// The instance, refused if a guest is currently running on its disk.
fn stopped(reg: &Shard, name: &str) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    if inst.status == Status::Running {
        anyhow::bail!("instance {name:?} is running — `ast down {name}` first");
    }
    Ok(inst)
}

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
        let _ = reg.attach_block(name, &lease.volume, &lease.device, lease.epoch, lease.size_bytes);
    }
    if inst.seed_device.is_none() || std::fs::read(&stamp).ok() != before {
        let _ = reg.set_seed_device(name, &inst.cpu_device);
    }
    reg.set_running(name, handle)
}

/// Take a block volume's lease from the device that holds it, and record it
/// on the instance.
///
/// The lease first, the registry second: a record written against a lease we
/// were refused would be an instance that looks configured and cannot boot,
/// which is the failure `check_can_share` exists to prevent for directories.
async fn attach_block(
    reg: &mut Shard,
    name: &str,
    vol: &str,
    device: &str,
) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    let hv = backend::for_instance(&inst)?;
    volume::check_backend(&*hv)?;
    let (epoch, _export, size) = volume::take_lease(vol, device, name).await?;
    reg.attach_block(name, vol, device, epoch, size)
}

/// Take a volume off an instance, handing back a block volume's lease.
///
/// Refused while the guest is running: neither backend offers disk hotplug
/// (`Caps::disk_hotplug` is false on both), so pulling the bytes out from
/// under a live guest would be a yanked cable rather than a detach.
async fn detach(
    reg: &mut Shard,
    name: &str,
    vol: &str,
    host: Option<&str>,
) -> Result<Instance> {
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
            [] => anyhow::bail!(
                "{name:?} has no volume called {vol:?} — see: ast status {name}"
            ),
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

// ---- snapshots -------------------------------------------------------------
//
// Capability-gated: a backend without `disk_snapshot` says so here rather
// than failing somewhere deeper with a hypervisor's own error.

fn snapshot_create(inst: &Instance, tag: &str) -> Result<()> {
    let hv = backend::for_instance(inst)?;
    let caps = hv.caps();
    if !caps.disk_snapshot {
        anyhow::bail!(
            "the {} backend cannot snapshot {:?}'s disk",
            hv.id(),
            inst.name
        );
    }
    let req = backend::disk_req(inst)?;
    let prep = hv.prepare(&req)?;
    hv.disk_snapshot(&prep, tag)
        .map(|_| ())
        .with_context(|| format!("snapshotting {:?}", inst.name))
}

fn snapshot_list(inst: &Instance) -> Result<Vec<asterism_core::snapshot::Snapshot>> {
    let hv = backend::for_instance(inst)?;
    if !hv.caps().disk_snapshot {
        return Ok(Vec::new());
    }
    let req = backend::disk_req(inst)?;
    let prep = hv.prepare(&req)?;
    hv.disk_snapshot_list(&prep)
}

fn snapshot_restore(inst: &Instance, tag: &str) -> Result<()> {
    let hv = backend::for_instance(inst)?;
    if !hv.caps().disk_snapshot {
        anyhow::bail!("the {} backend cannot roll {:?}'s disk back", hv.id(), inst.name);
    }
    let req = backend::disk_req(inst)?;
    let prep = hv.prepare(&req)?;
    hv.disk_restore(&prep, &SnapshotId(tag.to_owned()))
        .with_context(|| format!("restoring {:?} — see: ast snapshots {}", inst.name, inst.name))
}

fn snapshot_remove(inst: &Instance, tag: &str) -> Result<()> {
    let hv = backend::for_instance(inst)?;
    if !hv.caps().disk_snapshot {
        anyhow::bail!("the {} backend keeps no disk snapshots to delete", hv.id());
    }
    let req = backend::disk_req(inst)?;
    let prep = hv.prepare(&req)?;
    hv.disk_snapshot_remove(&prep, &SnapshotId(tag.to_owned()))
        .with_context(|| format!("deleting a snapshot of {:?} — see: ast snapshots {}", inst.name, inst.name))
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
    let Ok(hv) = backend::for_handle(&h.backend) else { return false };
    matches!(hv.state(h), Ok(RunState::Running))
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
