//! astd — the Asterism device daemon.
//!
//! The orbit is a pool of parts; an instance is a computer assembled from
//! them. This daemon is one device's contribution to that pool: it holds this
//! device's shard of the orbit registry, boots the guests whose compute it
//! supplies, and serves the `ast` CLI over a unix socket (one JSON request per
//! line, one JSON response per line). Guests are booted through the
//! [`Hypervisor`] boundary: nothing in this daemon names a hypervisor concept
//! outside [`backend`], and optional behaviour is gated on `Caps`.
//!
//! It also holds this device's presence in its orbit — see [`mesh`]. The
//! daemon, not the CLI, is what other devices talk to and what dials them.
//! That is what makes the instance namespace flat: `ast up dev` typed anywhere
//! arrives at the nearest daemon, which resolves `dev` across the orbit and,
//! if some other device holds that row, sends it the very same [`Request`]
//! frame over a mesh stream. The user never names a device, because in a pool
//! of parts there is nothing for them to name.
//!
//! # The door, and what is behind it
//!
//! Everything local arrives through one unix socket, and the rules that
//! socket is behind are not in this file: they are in
//! [`asterism_core::ipc`] (who may connect, where the socket lives, what
//! makes this process the only daemon on its home) and in [`transport`] (how
//! a frame is bounded, how long one may take, how many peers may be inside at
//! once). Both are seams rather than checks, on purpose — a limit enforced
//! per command is a limit whichever command was added last does not have.
//! A connection reaches this file only as an [`Admitted`], and an `Admitted`
//! hands out nothing but a bounded reader and a deadlined writer.
//!
//! # What this file is, and what it is not
//!
//! This file is the doors and the routing between them, and nothing else. It
//! knows that a request may have to be forwarded, claimed, or answered on the
//! connection that asked; it does not know what any command *does*. Each area
//! owns its own frames in its own module — [`instance`], [`snapshot`],
//! [`volume`], [`swap`], [`orbit`], [`ssh`], [`wake`] — and each offers the
//! same two things: a `claims` predicate and a `serve`. Routing is then a
//! short chain of "is this yours?", which is the shape that lets two branches
//! add two commands to two areas without touching the same lines. The one
//! rule the chain rests on is that each area's predicate and match agree;
//! each module tests its own.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Mutex;

use asterism_core::compat;
use asterism_core::ipc;
use asterism_core::orbit::Orbit;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::Shard;
use asterism_core::{paths, VERSION};

use transport::{Admitted, Framing};

mod backend;
mod device_shell;
mod egress;
mod images;
mod instance;
mod mesh;
mod orbit;
mod persist;
mod secret;
mod snapshot;
mod ssh;
mod swap;
mod transport;
mod volume;
mod wake;

use mesh::{ClientIo, Mesh, Splice};

#[cfg(windows)]
fn apply_service_home_from_args() {
    // ImagePath is `astd.exe --service --home <dir>`. SCM starts with almost
    // no environment, so the home has to be on the command line rather than
    // inherited from the installing shell.
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--home" {
            if let Some(home) = args.next() {
                std::env::set_var("ASTERISM_HOME", home);
            }
            return;
        }
        if let Some(home) = arg.strip_prefix("--home=") {
            std::env::set_var("ASTERISM_HOME", home);
            return;
        }
    }
}

/// This device's own state: its shard of the orbit registry, and the name the
/// orbit knows it by.
///
/// The two travel together because almost everything needs both — a row is
/// written with the device that supplies its compute, and that device is named by
/// the orbit, not by its hostname. Two daemons on one machine with different
/// orbit names are two distinct suppliers of parts, and the tests depend on
/// that being true.
#[derive(Clone)]
pub(crate) struct Node {
    pub shard: Arc<Mutex<Shard>>,
    pub orbit: Arc<Mutex<Orbit>>,
    pub shell: Arc<device_shell::Manager>,
}

impl Node {
    /// What this device is called in its orbit.
    pub async fn device_name(&self) -> String {
        self.orbit.lock().await.self_name().to_owned()
    }
}

fn main() -> Result<()> {
    // Release activation has to prove the staged daemon before it replaces a
    // running one. This path touches no state and binds no socket, so a
    // downgrade refusal remains a refusal before mutation.
    if matches!(std::env::args().nth(1).as_deref(), Some("-V")) {
        println!("version   {}", asterism_core::VERSION);
        println!("build     {}", asterism_core::BUILD_ID);
        return Ok(());
    }
    if print_early_exit() {
        return Ok(());
    }
    if std::env::args().any(|arg| arg == "--service") {
        #[cfg(windows)]
        {
            apply_service_home_from_args();
            return asterism_core::windows_host::dispatch_service(
                asterism_core::windows_host::SERVICE_NAME,
                || runtime().block_on(run_daemon(StopSource::Service)),
            );
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!(
                "astd --service is the Windows Service dispatcher; this build is {}",
                std::env::consts::OS
            );
        }
    }
    runtime().block_on(run_daemon(StopSource::Console))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

async fn run_daemon(stop_source: StopSource) -> Result<()> {
    // Before anything: the signals that mean "stop". Registering one is what
    // makes it ours — until then the default disposition applies, and for
    // both of these that is death with nothing tidied up. The socket is
    // bound early and the mesh takes a moment to come up after it, so a
    // daemon that only registered when it reached its accept loop had a
    // window in which a `SIGTERM` left the socket and the pid file behind
    // for the next daemon to trip over. `ast` sends exactly that `SIGTERM`
    // when it retires a daemon across an upgrade, and it sends it as soon as
    // the socket answers — which is inside the window.
    let mut stop = Stop::listen(stop_source);

    let home = paths::home_dir();
    // Everything this daemon remembers is in here, and until now it was
    // created `0777 & !umask` — which on a default login means every other
    // user on the machine can list the instance names, watch for a staging
    // path, and see the socket. `0700`, and tightened if an older astd left
    // it open. See `asterism_core::ipc`.
    private_state(&home)?;

    // First, and before every line below it. Each of them changes something
    // — a staging directory is swept, a store is read and written back
    // migrated, a restore is converged — and each would meet a newer build's
    // state one file at a time, part-way through a startup that had already
    // begun. This is the last moment at which refusing a downgrade costs
    // nothing, so it is where the refusal is. See `asterism_core::compat`.
    if let Some(note) = compat::stamp_home(&home)? {
        eprintln!("astd: {note}");
    }

    // Now that this build has been established as one that may touch this
    // home: a compute move this device was receiving when it died left a
    // staging directory, and this is the "next contact" that clears it. It
    // was never bootable and no shard row ever pointed at it, so there is
    // nothing to consult first.
    swap::sweep_staging();

    let node = Node {
        shard: Arc::new(Mutex::new(Shard::load(&paths::state_path())?)),
        orbit: Arc::new(Mutex::new(Orbit::load(&paths::orbit_path())?)),
        shell: device_shell::Manager::load(),
    };

    // The election, the stale-socket sweep and the bind, in that order and
    // behind one `flock(2)`. What used to be here — probe the socket, unlink
    // it if nobody answered, bind — could not tell a dead daemon from one
    // that was about to answer, so ten `ast` commands typed at once started
    // ten daemons that each unlinked the last one's socket. See
    // `asterism_core::ipc::Door`.
    let door = transport::Door::open(&home, &paths::socket_path())?;
    let sock = door.socket().to_path_buf();

    // Now, and not before, this process has proved it is the only daemon on
    // this home — the election is the mutex, so nothing here can be tidying
    // up after a daemon that is still running. Both of these are crash
    // cleanup: the staging file of a commit that never published, and the
    // marker of a disk restore that never finished.
    sweep_interrupted_commits();
    converge_restores(&node).await;

    // The pid file is how an `ast` newer than this daemon retires it: the
    // socket says something is listening, but only a pid can be acted on.
    let pidfile = paths::daemon_pid_path();
    write_private(&pidfile, std::process::id().to_string().as_bytes())
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

    // Metadata lives in ASTERISM_HOME; values live behind the platform store
    // (the macOS login Keychain). There is intentionally no file fallback.
    if let Err(e) = secret::init() {
        eprintln!("astd: secrets are unavailable: {e:#}");
    }

    // The volume plane, before anything can be resurrected onto it: an
    // instance coming back up may need a lease taken and a bridge raised
    // before its guest has a disk to boot with.
    if let Err(e) = volume::init(node.clone(), mesh.clone()) {
        eprintln!("astd: block volumes are unavailable: {e:#}");
    }

    // An attach spans the provider's lease book and this consumer's instance
    // shard. Settle its independent journal before resurrection can hand any
    // ambiguously recorded disk to a hypervisor.
    instance::reconcile_pending_storage(&node).await;

    // The egress plane, for the same reason and in the same shape: a bound
    // guest's proxy is put up by the boot that builds its seed, and the
    // source half of a bound request arrives from a mesh stream.
    if let Err(e) = egress::init(node.clone(), mesh.clone()) {
        eprintln!("astd: secret egress is unavailable: {e:#}");
    }

    // Moving an instance's compute needs the mesh, and the target's half of
    // a move is reached from a mesh stream — so, like the volume plane, it
    // holds a process-wide handle rather than taking one as an argument.
    swap::init(mesh.clone());

    // Records written before a process could be identified only carry a pid,
    // and a pid is not evidence. This gives the ones whose process can still
    // be proven a real identity, and everything after it — resurrection, the
    // supervisor, every stop — deals only in proof. Before `resurrect`,
    // because resurrect is the first thing that acts on liveness.
    {
        let mut reg = node.shard.lock().await;
        if backend::adopt_identities(&mut reg) {
            if let Err(e) = reg.save() {
                eprintln!("astd: saving the registry after adopting process identities: {e:#}");
            }
        }
    }
    volume::adopt_export_identities().await;

    // What this device was running, it runs again — before the first
    // request is served, and then continuously (see `persist`).
    persist::resurrect(&node.shard).await;
    persist::supervise(node.shard.clone());

    let slots = door.slots();
    loop {
        tokio::select! {
            accepted = door.accept() => {
                let stream = accepted?;
                let node = node.clone();
                let mesh = mesh.clone();
                let slots = slots.clone();
                tokio::spawn(async move {
                    // Who the peer is and whether there is room for it are
                    // settled here rather than in the accept loop: both can
                    // wait, and an accept loop that waits stops draining the
                    // backlog.
                    match transport::admit(stream, slots).await {
                        Ok(Some(conn)) => {
                            if let Err(e) = serve(conn, node, mesh).await {
                                eprintln!("astd: connection error: {e:#}");
                            }
                        }
                        // Turned away, and told why on the way out.
                        Ok(None) => {}
                        Err(e) => eprintln!("astd: {e:#}"),
                    }
                });
            }
            _ = stop.next() => {
                node.shell.revoke_all("astd is shutting down");
                let _ = std::fs::remove_file(&sock);
                let _ = std::fs::remove_file(&pidfile);
                eprintln!("astd: shutting down");
                return Ok(());
            }
        }
    }
}

/// Print the daemon's identity without starting it.
///
/// This deliberately runs before even registering signal handlers: asking a
/// shipped binary what it is must not create state or claim its unix socket.
fn print_early_exit() -> bool {
    match std::env::args().nth(1).as_deref() {
        Some("--version") => {
            println!("astd {VERSION}");
            true
        }
        Some("--help") => {
            println!(
                "astd — the Asterism device daemon\n\n\
                 Usage: astd\n\n\
                 Options:\n\
                   --help     Print help\n\
                   --version  Print version\n\
                   --service  Windows Service dispatcher (SCM ImagePath)"
            );
            true
        }
        _ => false,
    }
}

/// Write a small file `0600`, replacing whatever was there.
///
/// `std::fs::write` would leave it `0644`, which is how the pid file used to
/// come out — a small thing, but the home is private now and a file in it
/// that is not is a question somebody has to answer later.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)
}

/// Make every directory this daemon keeps state in reachable only by the
/// user running it.
///
/// The home, the per-instance directories under it, the volume directory and
/// the cached guest keys, plus the runtime directory a socket falls back to
/// when its own path is too long to bind — that last one because it is under
/// the system temp directory, which on Linux is writable by everybody, and a
/// socket path derived from a hash is a path anybody can compute.
///
/// A directory that was left open is tightened and the fact is logged: an
/// `$ASTERISM_HOME` from any earlier astd is exactly that, and a daemon that
/// refused to start until the user ran `chmod` by hand would be a worse
/// answer to a problem it can simply fix.
fn private_state(home: &std::path::Path) -> Result<()> {
    for dir in [
        home.to_path_buf(),
        home.join("instances"),
        home.join("volumes"),
        home.join("guest-keys"),
        paths::runtime_dir(),
    ] {
        match ipc::private_dir(&dir)? {
            ipc::Privacy::Tightened { was } => eprintln!(
                "astd: {} was mode {was:04o} — other users on this machine could read                  it; it is 0700 now",
                dir.display()
            ),
            ipc::Privacy::Already | ipc::Privacy::Created => {}
        }
    }
    Ok(())
}

/// Settle every instance whose disk restore was interrupted.
///
/// A restore is the one state change that is not a file this daemon commits:
/// it is a clone of a snapshot renamed over a running instance's disk. A
/// crash in the middle leaves a marker, and until it is settled the snapshot
/// it was reading from cannot be deleted. Which side of the rename it stopped
/// on is readable from the directory, so this converges rather than guesses —
/// see [`asterism_core::snapshot::converge`].
async fn converge_restores(node: &Node) {
    let names: Vec<String> = node
        .shard
        .lock()
        .await
        .list()
        .into_iter()
        .map(|i| i.name)
        .collect();
    for name in names {
        let dir = paths::instance_dir(&name);
        if let Some(what) = asterism_core::snapshot::converge(&dir) {
            eprintln!("astd: {name}: {what}");
        }
    }
}

/// Remove what a commit killed halfway through left behind.
///
/// The directories that hold committed state, and only those: everything
/// `durable` writes is a sibling of the file it commits, so a sweep of the
/// home and of the one subdirectory that holds per-device files is the whole
/// of it. Each staging file is a value that either landed — in which case it
/// is a duplicate — or did not, in which case it was never committed and
/// nothing has ever read it. The `.bak` files beside them are the safety net
/// and stay.
///
/// Anything found is logged: an interrupted commit came to nothing, but it is
/// the fingerprint of a crash and worth a line.
fn sweep_interrupted_commits() {
    let home = paths::home_dir();
    let dirs = [home.clone(), home.join("guest-keys")];
    for dir in dirs {
        for swept in asterism_core::durable::sweep_temporaries(&dir) {
            eprintln!(
                "astd: swept {} — a commit was interrupted before it published",
                swept.display()
            );
        }
    }
}

/// Ctrl-C, or the SIGTERM the CLI sends when it retires a stale daemon.
///
/// Both have to clean up the socket and pid file, or the replacement daemon
/// trips over what this one left. The handlers are installed at the very top
/// of `main`, before the socket exists, because a signal that arrives before
/// its handler does is not a shutdown — it is the default disposition, which
/// is death, and a daemon killed that way leaves both files behind.
#[derive(Clone, Copy)]
enum StopSource {
    Console,
    #[cfg(windows)]
    Service,
}

struct Stop {
    #[cfg(windows)]
    source: WindowsStop,
    #[cfg(unix)]
    term: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    int: Option<tokio::signal::unix::Signal>,
}

#[cfg(windows)]
enum WindowsStop {
    Console(Option<tokio::signal::windows::CtrlC>),
    Service,
}

impl Stop {
    fn listen(source: StopSource) -> Stop {
        #[cfg(unix)]
        {
            let StopSource::Console = source;
            use tokio::signal::unix::{signal, SignalKind};
            Stop {
                term: signal(SignalKind::terminate()).ok(),
                int: signal(SignalKind::interrupt()).ok(),
            }
        }
        #[cfg(windows)]
        {
            let source = match source {
                // Constructing the listener here registers the console handler
                // before startup mutates state, matching the Unix contract.
                StopSource::Console => {
                    WindowsStop::Console(tokio::signal::windows::ctrl_c().ok())
                }
                StopSource::Service => WindowsStop::Service,
            };
            Stop { source }
        }
    }

    /// Wait only for the source that owns this process. A console daemon must
    /// never start the blocking SCM waiter: dropping its join handle after
    /// Ctrl-C does not cancel it, and Tokio waits for blocking tasks while
    /// dropping the runtime. Conversely, an SCM worker has no console signal
    /// to race and waits only for STOP/SHUTDOWN.
    async fn next(&mut self) {
        #[cfg(unix)]
        {
            self.unix_signal().await;
        }

        #[cfg(windows)]
        match &mut self.source {
            WindowsStop::Console(Some(ctrl_c)) => {
                let _ = ctrl_c.recv().await;
            }
            WindowsStop::Console(None) => std::future::pending().await,
            WindowsStop::Service => {
                let _ = tokio::task::spawn_blocking(
                    asterism_core::windows_host::wait_service_stop,
                )
                .await;
            }
        }
    }

    /// Wait for either unix signal. A signal this process could not register
    /// for never arrives here, which is correct: it was never ours to catch.
    #[cfg(unix)]
    async fn unix_signal(&mut self) {
        match (&mut self.term, &mut self.int) {
            (Some(term), Some(int)) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = int.recv() => {}
                }
            }
            (Some(one), None) | (None, Some(one)) => {
                one.recv().await;
            }
            (None, None) => std::future::pending().await,
        }
    }
}

/// One connection from the unix socket, for as long as it stays open.
///
/// Most requests are a question and an answer and go straight to
/// [`dispatch`]. The four below are not, and each of them is here for the
/// same reason: it needs something this connection has. Three report as they
/// go and so need somewhere to send progress; the fourth needs to leave a
/// listener standing that dies when this socket does.
async fn serve(conn: Admitted, node: Node, mesh: Option<Arc<Mesh>>) -> Result<()> {
    let Admitted {
        mut frames,
        mut write,
        ..
    } = conn;

    // Anything this connection asked us to hold open on its behalf. Today
    // that is the loopback listener behind `ast ssh` on a guest whose cpu is
    // elsewhere: `ast` keeps this socket open for exactly as long as ssh is
    // running, so dropping these when the loop ends *is* the teardown.
    let mut splices: Vec<Splice> = Vec::new();

    // The version this connection is being spoken at.
    //
    // Per connection rather than per process, because a connection is the
    // only thing that has one peer: `ast` opens one per command and hands
    // over its range on the first frame, and a daemon replaced mid-session
    // would otherwise inherit the last client's answer. Until a `Ping`
    // arrives it is the wire that predates the number — the conservative
    // reading, and the true one for the only clients that never send a range.
    let mut spoken = compat::FIRST_PROTOCOL;

    loop {
        let line = match frames.next().await? {
            Framing::Frame(line) => line,
            Framing::Eof => break,
            // Not a frame this protocol has room for — too long, too slow,
            // not utf-8. The peer is told which, once, and the connection
            // ends: a peer that cannot produce a frame will not produce a
            // better one by being asked again.
            Framing::Refused(message) => {
                write.refuse(&message).await;
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<Request>(&line) {
            Ok(req) => req,
            // A CLI newer than this daemon lands here, on a variant we have
            // never heard of. With a negotiated version this is the race
            // rather than the mechanism — the client knew what we speak
            // before it sent anything — but the race is real, and the wording
            // still matters: `ast` classifies it and restarts us rather than
            // showing the user a serde error.
            Err(e) => {
                write
                    .send(&Response::Error {
                        message: format!("bad request: {e}"),
                    })
                    .await?;
                continue;
            }
        };

        // The first frame of the conversation settles what the rest of it is
        // spoken in. Both ends run the same rule on the same pair of ranges,
        // so neither has to be told the answer.
        if let Request::Ping {
            protocol,
            min_protocol,
        } = &request
        {
            let theirs = compat::Speaks::claimed(*protocol, *min_protocol);
            match compat::select(theirs) {
                compat::Selection::Common(version) => spoken = version,
                // No version in common. The refusal is a sentence rather than
                // a dropped connection, because this is the one frame whose
                // whole job is to be answerable by a build that cannot answer
                // anything else.
                // Both halves are on this device, so the refusal is written
                // for a half-finished local upgrade rather than for a skew
                // between two machines — and from the reader's side, which is
                // the terminal that ran `ast`.
                compat::Selection::TooOld { theirs, ours } => {
                    let why = compat::client_too_old(theirs, ours, VERSION);
                    write.refuse(&format!("{why:#}")).await;
                    break;
                }
                compat::Selection::TooNew { theirs, ours } => {
                    let why = compat::client_too_new(theirs, ours, VERSION);
                    write.refuse(&format!("{why:#}")).await;
                    break;
                }
            }
        }

        // A frame from after the version in force. A well-behaved `ast` never
        // sends one — it holds the same table — so this is the daemon that
        // was replaced between a client's handshake and its command. Named,
        // because "unknown variant" is what this exists to stop being the
        // answer.
        if !request.speakable_at(spoken) {
            let what = request
                .versioned_name()
                .map(|name| format!("the {name} frame"))
                .unwrap_or_else(|| "that request".to_owned());
            let refusal = compat::frame_too_new(&what, request.since(), spoken, "this daemon");
            write
                .send(&Response::Error {
                    message: format!("{refusal:#}"),
                })
                .await?;
            continue;
        }

        // A device shell is a framed conversation for the life of one
        // process. It borrows this private unix-socket connection and either
        // enters the local target through the same policy path or bridges it
        // to one dedicated authenticated mesh stream.
        if let Request::DeviceShellOpen { device, open } = &request {
            let mut io = ClientIo {
                frames: &mut frames,
                write: &mut write,
            };
            let served = match mesh.as_ref() {
                Some(mesh) => {
                    mesh.device_shell(device, open.clone(), &node, &mut io)
                        .await
                }
                None => Err(anyhow::anyhow!("{}", orbit::NO_MESH)),
            };
            if let Err(e) = served {
                io.send(&Response::DeviceShellRefused {
                    code: "unreachable".into(),
                    message: format!("{e:#}"),
                })
                .await?;
            }
            continue;
        }

        // Pairing is a conversation, not a question — a ticket to print, a
        // code to compare, a verdict to take — so it borrows the connection
        // for as many frames as it needs.
        if let Request::DeviceInvite { .. } | Request::DeviceAdd { .. } = request {
            let mut io = ClientIo {
                frames: &mut frames,
                write: &mut write,
            };
            if let Err(e) = orbit::pair(request, mesh.as_ref(), &mut io).await {
                io.send(&Response::Error {
                    message: format!("{e:#}"),
                })
                .await?;
            }
            continue;
        }

        // A wake is a job rather than a question — who is going to send the
        // packet, that it went, and then up to a minute later whether the
        // machine turned up — so it reports as it goes, which needs the
        // connection the same way pairing does.
        if let Request::DeviceWake { name } = &request {
            let mut io = ClientIo {
                frames: &mut frames,
                write: &mut write,
            };
            let woken = match mesh.as_ref() {
                Some(mesh) => mesh.wake(name, &mut io).await,
                None => Err(anyhow::anyhow!("{}", orbit::NO_MESH)),
            };
            if let Err(e) = woken {
                io.send(&Response::Error {
                    message: format!("{e:#}"),
                })
                .await?;
            }
            continue;
        }

        // A compute move is a job rather than a question — a preflight, a
        // fence, a disk crossing a network, two commits — so it reports as it
        // goes, on the connection that asked, exactly as a wake does.
        if let Request::SetCpu { name, device, down } = &request {
            let mut io = ClientIo {
                frames: &mut frames,
                write: &mut write,
            };
            let moved = swap::run(name, device, *down, &node, mesh.as_ref(), &mut io).await;
            if let Err(e) = moved {
                io.send(&Response::Error {
                    message: format!("{e:#}"),
                })
                .await?;
            }
            continue;
        }

        // `ast ssh` needs something to outlive its own reply — a listener the
        // CLI is about to point ssh at — so it is answered here, where the
        // connection's lifetime is.
        if let Request::SshEndpoint { name } = &request {
            let (response, splice) = ssh::endpoint(name, &node, mesh.as_ref()).await;
            splices.extend(splice);
            write.send(&response).await?;
            continue;
        }

        let response = dispatch(request, &node, mesh.as_ref()).await;
        write.send(&at_most(response, spoken)).await?;
    }
    Ok(())
}

/// A reply this connection's peer can read, or a sentence saying why there
/// isn't one.
///
/// The mirror of the check on the way in, and it is not redundant with it: a
/// request old enough to send is not automatically a request whose *answer*
/// is, once a later version adds a richer reply to an existing command. A
/// peer that gets a variant it has never heard of sees a parse error on a
/// command that worked, which is the worst of both.
fn at_most(response: Response, spoken: u32) -> Response {
    if response.speakable_at(spoken) {
        return response;
    }
    let refusal = compat::frame_too_new("that reply", response.since(), spoken, "this client");
    Response::Error {
        message: format!("{refusal:#}"),
    }
}

/// Routes one request that came off the unix socket.
///
/// Three kinds arrive here, and this is the order they are asked about in.
/// Requests about the orbit itself are answered by [`orbit`] — before
/// anything else, because they are the ones that must never be resolved
/// against the instance namespace. Requests that claim a name have that claim
/// put to every device. Everything left is about one instance, so it is
/// resolved across the orbit and forwarded to whichever device holds that
/// row — which is where `--device` stops being necessary.
async fn dispatch(request: Request, node: &Node, mesh: Option<&Arc<Mesh>>) -> Response {
    if secret::is_orbit_request(&request) {
        return secret::serve(request, node, mesh).await;
    }
    if volume::is_orbit_request(&request) {
        return volume::serve_orbit(request, node, mesh).await;
    }
    if orbit::claims(&request) {
        return orbit::serve(request, node, mesh).await;
    }
    // A name is claimed before anything is written down, and a claim that
    // fails ends the request here: an instance that could not have the name
    // it asked for must not be created, and one that could not have the name
    // it is being renamed to must keep the one it has.
    if let Some(refusal) = instance::claim_name(&request, node, mesh).await {
        return refusal;
    }
    route(request, node, mesh).await
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
        Ok(Some(device)) => orbit::reply_or_error(mesh.proxy(&device, request).await),
        // Nowhere in the orbit answers to it, so the local shard's "no such
        // instance" is both true and the message the user should see.
        Ok(None) => handle(request, node).await,
        Err(e) => Response::Error {
            message: format!("{e:#}"),
        },
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
/// forwarded request from fanning out again on arrival, which is why
/// [`orbit`] is asked in [`dispatch`] and never here.
///
/// The body is a chain of one question — "is this yours?" — asked of each
/// area in turn, ending at [`instance`], which owns both the shard's own
/// commands and the refusal for a frame nobody claimed.
pub(crate) async fn handle(req: Request, node: &Node) -> Response {
    // The version handshake, before anything that can wait.
    //
    // `ast` sends `Ping` in front of every command, so whatever this answer
    // waits on, every command waits on. The shard is held for the whole of a
    // boot — `hv.prepare` converting a gigabyte, `hv.boot` on a backend that
    // has stopped answering — so answering the handshake from behind it made
    // one stuck guest into a CLI that hangs with nothing on the screen, for
    // every command, including the ones that would have said what was wrong.
    //
    // Nothing in the reply comes from the registry: it is this binary's
    // version, which is a constant. Reconciling first was a courtesy — a
    // daemon that has just noticed a dead guest writing that down before it
    // says it is well — and a courtesy is exactly what `try_lock` is for. It
    // happens when the registry is free and is skipped when it is not.
    if let Request::Ping { .. } = req {
        if let Ok(mut reg) = node.shard.try_lock() {
            instance::reconcile(&mut reg);
        }
        let ours = compat::ours();
        return Response::Pong {
            version: VERSION.to_owned(),
            build_id: Some(asterism_core::BUILD_ID.to_owned()),
            protocol: ours.max,
            min_protocol: ours.min,
        };
    }
    // What this build speaks, answered from the constants rather than from
    // anything on disk, so it is the one command that still works when the
    // registry is wedged. `ast` merges it with its own view.
    if let Request::Compat = req {
        return Response::Compat {
            compat: Box::new(compat::Compat::current()),
        };
    }
    if secret::is_source_request(&req) {
        return secret::serve_source(req).await;
    }
    // Volumes are this device's own part of the pool, not a row in its shard,
    // and they are answered before the shard is touched. That is not only
    // tidiness: `up` holds the shard while it boots, and an instance whose
    // volume is on the very device running it would otherwise ask itself for
    // a lease and wait forever on its own lock.
    if volume::is_plane_request(&req) {
        return volume::serve(req).await;
    }
    if images::is_plane_request(&req) {
        return images::serve(req).await;
    }

    // Catalog fan-out can wait on every peer. Resolve it before taking the
    // shard lock so one partitioned storage device cannot stall unrelated
    // instance commands. The selected authority is revalidated by immutable
    // device id and by its lease once the shard is locked below.
    let storage_placement = if let Request::AttachStorage {
        name,
        volume: volume_name,
        owner_device,
        max_latency_ms,
    } = &req
    {
        match volume::place(volume_name, owner_device.as_deref(), name, *max_latency_ms).await {
            Ok((device, device_id)) => Some((
                name.clone(),
                volume_name.clone(),
                device,
                device_id,
                owner_device.is_none(),
            )),
            Err(e) => {
                return Response::Error {
                    message: format!("{e:#}"),
                }
            }
        }
    } else {
        None
    };

    let cpu_device = node.device_name().await;
    let mut reg = node.shard.lock().await;
    instance::reconcile(&mut reg);

    // Two states put an instance out of reach whatever is being asked of it —
    // a name that is not unique, and bytes in flight to another device — so
    // they are checked once, here, ahead of every area.
    if let Some(refusal) = instance::refusal(&req, &reg) {
        return refusal;
    }

    if let Some((name, volume_name, device, device_id, auto_placed)) = storage_placement {
        return instance::attach_storage_placed(
            &mut reg,
            &name,
            &volume_name,
            &device,
            &device_id,
            auto_placed,
        )
        .await;
    }

    if swap::is_step(&req) {
        return swap::serve(req, &mut reg, &cpu_device);
    }
    if snapshot::claims(&req) {
        return snapshot::serve(req, &reg);
    }
    instance::serve(req, &mut reg, &cpu_device).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_on(home: &std::path::Path) -> Node {
        Node {
            shard: Arc::new(Mutex::new(Shard::load(&home.join("state.json")).unwrap())),
            orbit: Arc::new(Mutex::new(Orbit::load(&home.join("orbit.json")).unwrap())),
            shell: device_shell::Manager::load_at(home),
        }
    }

    /// A stalled backend is a held registry, and the handshake must not be
    /// behind it.
    ///
    /// `up` holds the shard for the whole of a boot — a gigabyte being
    /// converted, or a hypervisor that has stopped answering — and `ast`
    /// sends `Ping` in front of every single command. Answering the
    /// handshake from behind that lock therefore turned one stuck guest into
    /// a CLI that hangs, with nothing printed, for every command a user could
    /// try next, including the ones that would have told them what was wrong.
    ///
    /// Holding the lock here is exactly what a stalled boot does to it, and
    /// is the only part of a stall a test needs to reproduce.
    #[tokio::test]
    async fn the_handshake_is_answered_while_the_registry_is_held() {
        let tmp = tempfile::tempdir().unwrap();
        let node = node_on(tmp.path());
        let stalled = node.shard.clone().lock_owned().await;

        let answered = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle(
                Request::Ping {
                    protocol: 0,
                    min_protocol: 0,
                },
                &node,
            ),
        )
        .await
        .expect("the handshake waited on the registry");
        assert!(matches!(
            answered,
            Response::Pong {
                version,
                build_id: Some(build_id),
                ..
            } if version == VERSION && build_id == asterism_core::BUILD_ID
        ));

        drop(stalled);
    }

    /// And the courtesy the handshake used to perform still happens when
    /// there is nothing in the way: a daemon that has just noticed a dead
    /// guest writes that down before it says it is well. It is a `try_lock`,
    /// so it is skipped rather than waited for.
    #[tokio::test]
    async fn a_free_registry_is_still_reconciled_by_the_handshake() {
        let tmp = tempfile::tempdir().unwrap();
        let node = node_on(tmp.path());
        let answered = handle(
            Request::Ping {
                protocol: 0,
                min_protocol: 0,
            },
            &node,
        )
        .await;
        assert!(matches!(answered, Response::Pong { .. }));
        assert!(
            node.shard.try_lock().is_ok(),
            "the handshake kept the registry after answering"
        );
    }
}
