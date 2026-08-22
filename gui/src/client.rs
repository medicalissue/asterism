//! The daemon client.
//!
//! Same wire as `ast`: one JSON [`Request`] per line over the unix socket
//! at [`paths::socket_path`], one JSON [`Response`] line back. The types
//! come from `asterism-core`, so the app cannot drift from the CLI.
//!
//! Three things differ from the CLI, all because this runs in a polling
//! loop rather than as a one-shot command:
//!
//! * every socket read and write has a timeout, so a wedged daemon stalls
//!   one refresh instead of the poll thread forever;
//! * spawning `astd` is rate-limited. The CLI spawns on any failed
//!   connect, which is right for a command the user just typed; a GUI that
//!   did that would fork a daemon every few seconds for as long as the
//!   daemon stays broken;
//! * snapshot listings are cached, because they are the one request that
//!   costs the daemon a process spawn per instance.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use asterism_core::backup::{ExportReport, RestoreReport};
use asterism_core::compat;
use asterism_core::device_shell::{ShellPolicyAction, ShellPolicyStatus};
use asterism_core::instance::{Instance, Shape};
use asterism_core::orbit::DeviceStatus;
use asterism_core::paths;
use asterism_core::protocol::{self, Request, Response};
use asterism_core::registry::OrbitRow;
use asterism_core::snapshot::Snapshot;
use asterism_core::volume::BlockVolume;

/// How long to wait for a freshly spawned daemon to start answering.
const STARTUP_ATTEMPTS: u32 = 20;
const STARTUP_DELAY: Duration = Duration::from_millis(100);
/// How long the read and write halves may block on a question the daemon
/// can answer out of its own memory.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long they may block on one it cannot.
///
/// `ListOrbit` and `Devices` are answered by asking every other device in
/// the orbit, so the deadline that matters is not this daemon's — it is a
/// peer's, over the mesh, and a peer that has gone to sleep takes as long to
/// give up on as the daemon's own mesh timeout. Five seconds is right for a
/// `List`; on an orbit view it is a stopwatch that goes off before the
/// answer arrives and reports a working daemon as unreachable.
const ORBIT_TIMEOUT: Duration = Duration::from_secs(30);
/// Backups legitimately read and hash gigabytes. The operation itself is
/// resumable; the UI should keep listening rather than manufacture a timeout.
const BACKUP_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
/// Minimum gap between two attempts to start `astd` ourselves.
const SPAWN_COOLDOWN: Duration = Duration::from_secs(15);

static LAST_SPAWN: Mutex<Option<Instant>> = Mutex::new(None);

/// This device's shard: the instances whose cpu and ram it supplies. What
/// the tray menu lists, and what the New Instance window checks a name
/// against.
pub fn list() -> Result<Vec<Instance>> {
    match send(&Request::List)? {
        Response::Instances { instances } => Ok(instances),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// The whole orbit registry, assembled: every shard the daemon could reach,
/// plus the last-seen rows of the devices it could not. The same frame
/// `ast ls` sends, and what the window's Instances table shows — a menu is
/// a list of what is on this machine, a window is a view of the fleet.
pub fn list_orbit() -> Result<Vec<OrbitRow>> {
    match send_with(&Request::ListOrbit, ORBIT_TIMEOUT)? {
        Response::Orbit { rows } => Ok(rows),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// Every device in this orbit, with liveness probed as the request is
/// served. The frame `ast devices` sends.
pub fn devices() -> Result<Vec<DeviceStatus>> {
    match send_with(&Request::Devices, ORBIT_TIMEOUT)? {
        Response::Devices { devices } => Ok(devices),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// Read one target's device-shell offer. The inner frame is read-only and
/// may cross the authenticated mesh; policy mutation has no corresponding
/// remote helper.
pub fn device_shell_status(device: Option<&str>) -> Result<ShellPolicyStatus> {
    let request = device_shell_status_request(device);
    let mut response = send_with(&request, ORBIT_TIMEOUT)?;
    // Protocol 4 exposed local status through the policy frame. Preserve
    // that read during a rolling upgrade, but never use the local-only frame
    // as a fallback for a remote target.
    if device.is_none()
        && matches!(&response, Response::Error { message } if protocol::is_unknown_variant_error(message))
    {
        response = send(&Request::DeviceShellPolicy {
            action: ShellPolicyAction::Status,
        })?;
    }
    match response {
        Response::DeviceShellStatus { status, .. } => Ok(status),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

fn device_shell_status_request(device: Option<&str>) -> Request {
    match device {
        Some(device) => Request::Proxy {
            device: device.to_owned(),
            inner: Box::new(Request::DeviceShellStatus),
        },
        None => Request::DeviceShellStatus,
    }
}

/// Change only the daemon behind this app's private local socket. Keeping
/// the target out of this API makes remote enable structurally impossible.
pub fn set_device_shell(enabled: bool) -> Result<ShellPolicyStatus> {
    match send(&device_shell_policy_request(enabled))? {
        Response::DeviceShellStatus { status, .. } => Ok(status),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

fn device_shell_policy_request(enabled: bool) -> Request {
    Request::DeviceShellPolicy {
        action: if enabled {
            ShellPolicyAction::Enable
        } else {
            ShellPolicyAction::Disable
        },
    }
}

/// The running daemon's version, and the build it was compiled from.
///
/// A daemon older than the `Pong` variant answers `Ping` with a plain `Ok`,
/// so the absence of a version is itself the answer: it is old, and saying
/// so beats printing nothing. The build id arrived later than `Pong` did, so
/// `None` there says the same thing about a narrower gap — the daemon is
/// running and cannot tell us which build it is.
pub fn daemon_build() -> Result<(String, Option<String>)> {
    let ours = compat::ours();
    match send(&Request::Ping {
        protocol: ours.max,
        min_protocol: ours.min,
    })? {
        Response::Pong {
            version, build_id, ..
        } => Ok((version, build_id)),
        Response::Ok => Ok(("older than 0.0.2".to_owned(), None)),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// Define an instance, exactly as `ast create` does.
///
/// `backend` of `None` is what an `ast create` with no `--backend` sends,
/// and means "this device's default". Naming one instead makes the daemon
/// probe it here, at create, so a device that cannot run it says why now
/// rather than at the first boot.
pub fn create(name: &str, image: &str, shape: Shape, backend: Option<&str>) -> Result<()> {
    expect_done(&create_request(name, image, shape, backend))
}

/// The frame [`create`] puts on the wire. Split out from the sending so a
/// test can check it against the one `ast create` sends without needing a
/// daemon to send it to. The New Instance model has no profile picker, so
/// its intentional default is the same as `ast create` without `--profile`:
/// a stock image with no bootstrap profiles.
fn create_request(name: &str, image: &str, shape: Shape, backend: Option<&str>) -> Request {
    Request::Create {
        name: name.to_owned(),
        image: image.to_owned(),
        shape,
        backend: backend.map(str::to_owned),
        publish: Vec::new(),
        profiles: Vec::new(),
    }
}

/// Boot an instance.
pub fn up(name: &str) -> Result<()> {
    expect_done(&Request::Up {
        name: name.to_owned(),
        restart: None,
    })
}

/// Shut an instance down.
pub fn down(name: &str) -> Result<()> {
    expect_done(&Request::Down {
        name: name.to_owned(),
    })
}

/// Take a disk snapshot. The daemon refuses this on a running instance;
/// the menu greys the item out for the same reason, but the daemon is the
/// one that decides.
pub fn snapshot(name: &str, tag: &str) -> Result<()> {
    let done = expect_done(&Request::Snapshot {
        name: name.to_owned(),
        tag: tag.to_owned(),
    });
    forget_snapshots();
    done
}

/// Roll a stopped instance's disk back to a snapshot.
pub fn snapshot_restore(name: &str, tag: &str) -> Result<()> {
    let done = expect_done(&Request::SnapshotRestore {
        name: name.to_owned(),
        tag: tag.to_owned(),
    });
    forget_snapshots();
    done
}

/// The tail of an instance's guest console, routed across the orbit by astd.
pub fn logs(name: &str, lines: u32) -> Result<(String, bool)> {
    match send(&Request::Logs {
        name: name.to_owned(),
        lines,
    })? {
        Response::Log { text, truncated } => Ok((text, truncated)),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

pub fn backup(name: &str) -> Result<ExportReport> {
    let destination = paths::home_dir().join("backups").join(format!(
        "{}-{}",
        name,
        asterism_core::instance::now_unix()
    ));
    match send_with(
        &Request::BackupExport {
            name: name.to_owned(),
            destination: destination.display().to_string(),
        },
        BACKUP_TIMEOUT,
    )? {
        Response::BackupExported { report } => Ok(report),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

pub fn restore_backup(source: &str, name: Option<&str>) -> Result<RestoreReport> {
    let source = std::path::PathBuf::from(source);
    let source = if source.is_absolute() {
        source
    } else {
        std::env::current_dir()?.join(source)
    };
    let manifest = asterism_core::backup::inspect(&source)?;
    let name = name
        .filter(|name| !name.is_empty())
        .unwrap_or(&manifest.instance.name);
    match send_with(
        &Request::BackupImport {
            source: source.display().to_string(),
            name: name.to_owned(),
        },
        BACKUP_TIMEOUT,
    )? {
        Response::BackupRestored { report } => Ok(report),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// Block volumes whose bytes are supplied by this device.
///
/// Volumes are device parts, not orbit-global objects, so this deliberately
/// asks the local daemon without pretending to assemble a global inventory.
pub fn volumes() -> Result<Vec<BlockVolume>> {
    match send(&Request::VolumeList)? {
        Response::Volumes { volumes } => Ok(volumes),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// Every snapshot on one instance's disk. Private because the menu wants
/// tags rather than rows, and wants them cached — [`snapshot_tags`] is the
/// way in.
fn snapshots(name: &str) -> Result<Vec<Snapshot>> {
    match send(&Request::SnapshotList {
        name: name.to_owned(),
    })? {
        Response::Snapshots { snapshots } => Ok(snapshots),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

// ---- the snapshot cache ----------------------------------------------------
//
// Listing snapshots costs the daemon a `qemu-img snapshot -l` per instance:
// a process spawn and a disk read. `List` costs it a lock on a map. Paying
// the first on the three-second status poll would turn a menu bar app into
// a background job, so snapshot tags run on their own slower clock, and are
// dropped outright whenever we change them ourselves — the only case where
// the user is owed an instant answer.

/// How long a listing is allowed to be believed.
const SNAPSHOT_TTL: Duration = Duration::from_secs(30);

/// The tags on one instance's disk, or why we could not find out. The
/// failure is kept rather than swallowed: "snapshots unavailable" is a
/// truthful menu line, an empty list is a lie.
pub type Tags = std::result::Result<Vec<String>, String>;

struct SnapshotCache {
    at: Instant,
    tags: HashMap<String, Tags>,
}

static SNAPSHOTS: Mutex<Option<SnapshotCache>> = Mutex::new(None);

/// Snapshot tags for each of `names`, refreshing the cache when it has
/// aged out or when it has never heard of one of the instances (an
/// instance that just appeared must not show an empty Snapshots menu).
pub fn snapshot_tags(names: &[String]) -> HashMap<String, Tags> {
    // The lock is held across the requests on purpose: two poll ticks
    // racing to refresh the same listing would double the cost of the
    // thing this cache exists to make cheap.
    let mut cache = SNAPSHOTS.lock().unwrap_or_else(|e| e.into_inner());
    let stale = match cache.as_ref() {
        Some(c) => c.at.elapsed() >= SNAPSHOT_TTL || names.iter().any(|n| !c.tags.contains_key(n)),
        None => true,
    };
    if stale {
        let tags = names.iter().map(|n| (n.clone(), list_tags(n))).collect();
        *cache = Some(SnapshotCache {
            at: Instant::now(),
            tags,
        });
    }
    let fresh = cache.as_ref().expect("filled just above");
    names
        .iter()
        .filter_map(|n| fresh.tags.get(n).map(|t| (n.clone(), t.clone())))
        .collect()
}

/// Force the next [`snapshot_tags`] to ask the daemon again.
fn forget_snapshots() {
    *SNAPSHOTS.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn list_tags(name: &str) -> Tags {
    snapshots(name)
        .map(|snaps| snaps.into_iter().map(|s| s.tag).collect())
        .map_err(|e| format!("{e:#}"))
}

/// Requests whose whole answer is "it worked", or why it did not. `Up` and
/// `Down` answer with the changed instance; the next poll picks the new
/// state up, so the body is not needed here.
fn expect_done(request: &Request) -> Result<()> {
    match send(request)? {
        Response::Ok | Response::Instance { .. } => Ok(()),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// One request, one response, on this daemon's own clock.
fn send(request: &Request) -> Result<Response> {
    send_with(request, IO_TIMEOUT)
}

/// One request, one response, with a deadline the caller picks — because how
/// long an answer is worth waiting for depends on how many machines have to
/// be asked for it.
fn send_with(request: &Request, timeout: Duration) -> Result<Response> {
    let sock = paths::socket_path();
    let stream = connect(&sock)?;
    if matches!(request, Request::Proxy { .. }) {
        send_on(stream, request, timeout)
    } else {
        send_raw_on(stream, request, timeout)
    }
}

/// Speak one request on an already-open local daemon connection.
///
/// A `Proxy` carries the inner frame verbatim, so its floor is the inner
/// frame's floor. The connection must therefore settle a protocol before the
/// proxy (or any other versioned request) is written.
fn send_on(stream: UnixStream, request: &Request, timeout: Duration) -> Result<Response> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let mut writer = stream.try_clone()?;
    let spoken = handshake(&mut writer, &stream)?;
    refuse_unspeakable(request, spoken)?;
    write_request(&mut writer, request)?;

    read_response(&stream)
}

/// Send a direct request unchanged. The GUI has legacy direct-frame
/// fallbacks, so only the transparent Proxy envelope needs the negotiated
/// pre-write gate above.
fn send_raw_on(stream: UnixStream, request: &Request, timeout: Duration) -> Result<Response> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut writer = stream.try_clone()?;
    write_request(&mut writer, request)?;
    read_response(&stream)
}

/// Exchange protocol ranges before writing an application request.
///
/// The old `Ping` and `Pong` shapes still establish the original wire, so an
/// old daemon can be refused locally before a newer proxy is put on the wire.
fn handshake(writer: &mut UnixStream, stream: &UnixStream) -> Result<u32> {
    let ours = compat::ours();
    write_request(
        writer,
        &Request::Ping {
            protocol: ours.max,
            min_protocol: ours.min,
        },
    )?;

    let peer = match read_response(stream)? {
        Response::Pong {
            protocol,
            min_protocol,
            ..
        } => compat::Speaks::claimed(protocol, min_protocol),
        Response::Ok => compat::Speaks::unversioned(),
        Response::Error { message } if protocol::is_unknown_variant_error(&message) => {
            compat::Speaks::unversioned()
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply to ping from astd: {other:?}"),
    };
    match compat::select(peer) {
        compat::Selection::Common(spoken) => Ok(spoken),
        compat::Selection::TooOld { theirs, ours } => {
            Err(compat::too_old("astd on this device", theirs, ours))
        }
        compat::Selection::TooNew { theirs, ours } => {
            Err(compat::too_new("astd on this device", theirs, ours))
        }
    }
}

/// Stop a request that the negotiated daemon cannot parse before it is sent.
fn refuse_unspeakable(request: &Request, spoken: u32) -> Result<()> {
    if request.speakable_at(spoken) {
        return Ok(());
    }
    let what = request
        .versioned_name()
        .map(|name| format!("`ast {name}`"))
        .unwrap_or_else(|| "that command".to_owned());
    Err(compat::frame_too_new(
        &what,
        request.since(),
        spoken,
        "astd on this device",
    ))
}

fn write_request(writer: &mut UnixStream, request: &Request) -> Result<()> {
    let mut line = serde_json::to_string(request)?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .context("writing to astd")?;
    Ok(())
}

fn read_response(stream: &UnixStream) -> Result<Response> {
    let mut reply = String::new();
    BufReader::new(stream.try_clone()?)
        .read_line(&mut reply)
        .context("reading from astd")?;
    if reply.trim().is_empty() {
        bail!("astd closed the connection without answering");
    }
    serde_json::from_str(&reply).context("astd sent something we could not parse")
}

// ---- conversations ---------------------------------------------------------

/// A request the daemon answers with more than one line, on a connection
/// nobody else is using.
///
/// Pairing and waking are the two: the daemon has a ticket to print, then a
/// code, and it will not write anything down until a human has answered —
/// and a wake is a packet, then a minute of waiting, then a machine that
/// either turned up or did not. The socket is line-delimited JSON in both
/// directions already, so this is the same wire as [`send`], held open.
///
/// It gets its own connection for a reason the CLI never has to think
/// about: this app has a poll loop on the same socket, and a three-second
/// `List` landing in the middle of a pairing would read the peer's SAS as
/// its own answer.
pub struct Conversation {
    write: UnixStream,
    read: BufReader<UnixStream>,
}

impl Conversation {
    /// Open a connection and put `request` on it.
    pub fn open(request: &Request) -> Result<Conversation> {
        let stream = connect(&paths::socket_path())?;
        // No read timeout, unlike [`send`]. What this waits for is a person
        // at another machine typing a ticket in, and five seconds is not a
        // measure of how long that takes. The window's Cancel button is the
        // way out, and it works by dropping this.
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut conn = Conversation {
            write: stream.try_clone()?,
            read: BufReader::new(stream),
        };
        conn.send(request)?;
        Ok(conn)
    }

    /// Say something else on the same connection. This is how a
    /// `PairConfirm` reaches the daemon that is holding the half-made
    /// pairing: on a fresh connection it would arrive at a daemon with no
    /// pairing in progress.
    pub fn send(&mut self, request: &Request) -> Result<()> {
        let mut line = serde_json::to_string(request)?;
        line.push('\n');
        self.write
            .write_all(line.as_bytes())
            .context("writing to astd")?;
        Ok(())
    }

    /// A handle that ends this conversation from another thread.
    ///
    /// An invite waits for a person at another machine, which is a wait
    /// with no deadline worth choosing. Cancel therefore has to interrupt a
    /// blocking read rather than time it out: shutting the socket down makes
    /// the read return nothing, which [`Conversation::next`] already reports
    /// as a daemon that hung up.
    pub fn hangup(&self) -> Result<Hangup> {
        Ok(Hangup(self.write.try_clone()?))
    }

    /// The next line the daemon has to say.
    pub fn next(&mut self) -> Result<Response> {
        let mut line = String::new();
        self.read
            .read_line(&mut line)
            .context("reading from astd")?;
        if line.trim().is_empty() {
            bail!("astd closed the connection without answering");
        }
        serde_json::from_str(&line).context("astd sent something we could not parse")
    }
}

/// The far end of a [`Conversation`], for whoever has to end it.
pub struct Hangup(UnixStream);

impl Hangup {
    /// Stop the conversation. Safe to call twice, and safe to call on one
    /// that has already finished: a shutdown of a closed socket is an error
    /// nobody needs told about.
    pub fn end(&self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

/// Connect to the daemon, starting it if it is not answering and we have
/// not just tried that.
fn connect(sock: &Path) -> Result<UnixStream> {
    if let Ok(stream) = UnixStream::connect(sock) {
        return Ok(stream);
    }
    if !claim_spawn_slot() {
        bail!("astd is not answering on {}", sock.display());
    }

    spawn_daemon()?;
    for attempt in 0.. {
        match UnixStream::connect(sock) {
            Ok(stream) => return Ok(stream),
            Err(e) if attempt >= STARTUP_ATTEMPTS => {
                return Err(e).context("astd did not come up");
            }
            Err(_) => std::thread::sleep(STARTUP_DELAY),
        }
    }
    unreachable!("the loop above returns")
}

/// True at most once per [`SPAWN_COOLDOWN`], so a daemon that cannot start
/// is retried occasionally instead of on every poll.
fn claim_spawn_slot() -> bool {
    let mut last = LAST_SPAWN.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if last.is_some_and(|t| now.duration_since(t) < SPAWN_COOLDOWN) {
        return false;
    }
    *last = Some(now);
    true
}

fn spawn_daemon() -> Result<()> {
    let astd = daemon_path();
    std::process::Command::new(&astd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {}", astd.display()))?;
    Ok(())
}

/// Where `astd` lives. Public because the vz check has to look next to the
/// *daemon*, not next to us: the helper the daemon would launch is the one
/// that decides whether vz works, and it sits beside the daemon binary.
pub fn daemon_path() -> PathBuf {
    tool_path("astd", "ASTERISM_ASTD")
}

/// Where `ast` lives. Used to hand a command to Terminal.app, which needs
/// an absolute path for the same reason we do.
pub fn ast_path() -> PathBuf {
    tool_path("ast", "ASTERISM_AST")
}

/// Find one of our binaries. An installed .app has no CLI inside it, so
/// the useful answers are, in order: an explicit override, the copy
/// sitting next to us (a `cargo build` tree, or a bundle that ships one),
/// and finally the usual install prefixes.
///
/// A macOS app launched from Finder inherits a bare `PATH` that contains
/// none of those prefixes, so they are tried by hand before falling back
/// to the bare name and hoping `PATH` is better than we think.
fn tool_path(tool: &str, override_var: &str) -> PathBuf {
    if let Some(explicit) = std::env::var_os(override_var) {
        return PathBuf::from(explicit);
    }
    if let Ok(me) = std::env::current_exe() {
        let sibling = me.with_file_name(tool);
        if sibling.exists() {
            return sibling;
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let candidates = [
        format!("{home}/.cargo/bin/{tool}"),
        format!("/opt/homebrew/bin/{tool}"),
        format!("/usr/local/bin/{tool}"),
    ];
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    PathBuf::from(tool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn machine() -> asterism_core::hv::Machine {
        asterism_core::hv::Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "test".into(),
        }
    }

    /// The window is a second surface, not a second backend: what it sends
    /// to define an instance has to be the frame `ast create` sends, field
    /// for field. This is what catches a window that grew its own idea of a
    /// request.
    #[test]
    fn the_window_creates_with_the_frame_the_cli_sends() {
        let shape = Shape {
            cpus: 2,
            mem_mib: 2048,
            disk_gib: 20,
        };
        let wire = serde_json::to_string(&create_request("dev", "debian:13", shape, None)).unwrap();
        assert_eq!(
            wire,
            r#"{"cmd":"create","name":"dev","image":"debian:13","#.to_owned()
                + r#""shape":{"cpus":2,"mem_mib":2048,"disk_gib":20},"backend":null,"publish":[],"profiles":[]}"#
        );
    }

    /// The form intentionally has no bootstrap-profile control. Its create
    /// frame must therefore retain the CLI's no-`--profile` semantics rather
    /// than acquiring a profile merely to satisfy the protocol shape.
    #[test]
    fn a_new_instance_form_asks_for_no_bootstrap_profiles() {
        let Request::Create { profiles, .. } =
            create_request("dev", "debian:13", Shape::default(), None)
        else {
            panic!("should be a create");
        };
        assert!(profiles.is_empty());
    }

    /// No backend chosen means "this device's default", which is `None`
    /// rather than the string "qemu": the daemon reads `None` as "take the
    /// default, do not probe" and a literal id as "probe this one now".
    #[test]
    fn an_unchosen_backend_is_absent_and_a_chosen_one_is_named() {
        let Request::Create { backend, .. } =
            create_request("dev", "debian:13", Shape::default(), None)
        else {
            panic!("should be a create");
        };
        assert_eq!(backend, None);

        let Request::Create { backend, .. } =
            create_request("dev", "debian:13", Shape::default(), Some("vz"))
        else {
            panic!("should be a create");
        };
        assert_eq!(backend.as_deref(), Some("vz"));
    }

    /// `Create` claims a name rather than resolving one, so it must not be
    /// routed to whichever device already answers to it. The rule lives in
    /// `asterism-core`; this pins the window's frame to it.
    #[test]
    fn a_create_from_the_window_is_not_routed_by_name() {
        let req = create_request("dev", "debian:13", Shape::default(), None);
        assert_eq!(req.subject(), None);
    }

    /// The half of [`expect_done`] that does not need a socket: which
    /// replies the window may treat as "it worked".
    fn reply_to_done(line: &str) -> Result<()> {
        match serde_json::from_str(line)? {
            Response::Ok | Response::Instance { .. } => Ok(()),
            Response::Error { message } => bail!(message),
            other => bail!("unexpected reply from astd: {other:?}"),
        }
    }

    #[test]
    fn a_refusal_reaches_the_caller_with_the_daemons_own_words() {
        assert!(reply_to_done(r#"{"result":"ok"}"#).is_ok());

        let boom = reply_to_done(r#"{"result":"error","message":"name taken"}"#).unwrap_err();
        assert_eq!(format!("{boom:#}"), "name taken");

        // `Create` answers with the instance it defined; the poll picks the
        // new row up, so the body is not needed here and not an error.
        let inst = serde_json::to_string(&Response::Instance {
            instance: Instance::new("dev", "here", "debian:13", Shape::default(), machine()),
            guest_health: None,
        })
        .unwrap();
        assert!(reply_to_done(&inst).is_ok());

        // Anything else is a daemon we do not understand, and saying so
        // beats reporting success we did not get.
        assert!(reply_to_done(r#"{"result":"pong","version":"0.0.2"}"#).is_err());
    }

    #[test]
    fn gui_shell_mutation_has_no_remote_target() {
        assert_eq!(
            serde_json::to_string(&device_shell_policy_request(true)).unwrap(),
            r#"{"cmd":"device_shell_policy","action":"enable"}"#
        );
        assert_eq!(
            serde_json::to_string(&device_shell_policy_request(false)).unwrap(),
            r#"{"cmd":"device_shell_policy","action":"disable"}"#
        );
    }

    fn proxy(inner: Request) -> Request {
        Request::Proxy {
            device: "other".into(),
            inner: Box::new(inner),
        }
    }

    /// A protocol-1 daemon may read the handshake, but must never receive a
    /// newer proxy as a second frame. This covers both current proxy floors:
    /// device-shell status at v5 and image inventory at v6.
    fn old_daemon_receives_only_the_handshake(request: Request) {
        let (client, mut daemon) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let mut reader = BufReader::new(daemon.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(matches!(
                serde_json::from_str::<Request>(&line).unwrap(),
                Request::Ping { .. }
            ));
            daemon.write_all(b"{\"result\":\"ok\"}\n").unwrap();

            daemon
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            line.clear();
            let second = reader.read_line(&mut line);
            assert!(
                matches!(second, Ok(0) | Err(_)),
                "wrote an unsupported second frame"
            );
        });

        assert!(send_on(client, &request, IO_TIMEOUT).is_err());
        server.join().unwrap();
    }

    #[test]
    fn an_old_daemon_never_receives_a_newer_proxied_frame() {
        old_daemon_receives_only_the_handshake(proxy(Request::DeviceShellStatus));
        old_daemon_receives_only_the_handshake(proxy(Request::ImageList));
    }

    /// The GUI's remote device-shell caller goes through the same negotiated
    /// door as every other GUI request, so the daemon sees Ping before Proxy.
    #[test]
    fn gui_remote_shell_status_handshakes_before_its_proxy() {
        let request = device_shell_status_request(Some("other"));
        let (client, mut daemon) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let mut reader = BufReader::new(daemon.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(matches!(
                serde_json::from_str::<Request>(&line).unwrap(),
                Request::Ping { .. }
            ));
            daemon
                .write_all(b"{\"result\":\"pong\",\"version\":\"test\",\"protocol\":5,\"min_protocol\":1}\n")
                .unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert!(matches!(
                serde_json::from_str::<Request>(&line).unwrap(),
                Request::Proxy { device, inner }
                    if device == "other" && matches!(*inner, Request::DeviceShellStatus)
            ));
            daemon.write_all(b"{\"result\":\"ok\"}\n").unwrap();
        });

        assert!(matches!(
            send_on(client, &request, IO_TIMEOUT).unwrap(),
            Response::Ok
        ));
        server.join().unwrap();
    }
}
