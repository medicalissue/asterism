//! The opt-in shell one device may offer to authenticated orbit peers.
//!
//! Policy, authorization, process lifetime and audit are deliberately one
//! seam. A mesh connection being authenticated is necessary but not enough:
//! every open is checked again against current membership and the peer-key
//! snapshot captured by the most recent local enable.

use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use uuid::Uuid;

use asterism_core::device_shell::{
    ShellData, ShellExit, ShellFrame, ShellOpen, ShellOutput, ShellPolicyState, ShellPolicyStatus,
    ShellSessionStatus, MAX_DATA_BYTES, MAX_FRAME_BYTES, MAX_TERMINAL_DIMENSION, POLICY_VERSION,
};
use asterism_core::durable;
use asterism_core::instance::now_unix;
use asterism_core::orbit::Device;
use asterism_core::paths;
use asterism_core::protocol::{Request, Response};
use asterism_mesh::iroh_types::{RecvStream, SendStream};
use asterism_mesh::{DeviceId, MeshStream};

use crate::mesh::ClientIo;
use crate::Node;

const GLOBAL_SESSION_LIMIT: usize = 4;
const PEER_SESSION_LIMIT: usize = 2;
const FRAME_DEADLINE: Duration = Duration::from_secs(5);
const KILL_GRACE: Duration = Duration::from_secs(1);

/// Frames that must never execute through generic mesh RPC. Policy is local
/// control only; open and subsequent controls belong to a dedicated shell
/// stream with an authenticated peer identity attached.
pub(crate) fn local_only_request(request: &Request) -> bool {
    matches!(
        request,
        Request::DeviceShellPolicy { .. }
            | Request::DeviceShellOpen { .. }
            | Request::DeviceShellInput { .. }
            | Request::DeviceShellEof
            | Request::DeviceShellResize { .. }
            | Request::DeviceShellSignal { .. }
            | Request::DeviceShellClose
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyFile {
    version: u32,
    enabled: bool,
    #[serde(default)]
    enabled_at: u64,
    #[serde(default)]
    changed_at: u64,
    #[serde(default)]
    epoch: u64,
    /// Full Ed25519 public keys. Names and short ids are never authority.
    #[serde(default)]
    allowed_device_ids: Vec<String>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            version: POLICY_VERSION,
            enabled: false,
            enabled_at: 0,
            changed_at: 0,
            epoch: 0,
            allowed_device_ids: Vec::new(),
        }
    }
}

struct LiveSession {
    status: ShellSessionStatus,
    epoch: u64,
    revoke: watch::Sender<Option<String>>,
}

struct State {
    policy: PolicyFile,
    unavailable: Option<String>,
    sessions: HashMap<String, LiveSession>,
}

/// Process-wide shell policy and live-session registry.
pub(crate) struct Manager {
    policy_path: PathBuf,
    audit_path: PathBuf,
    state: Mutex<State>,
    audit_lock: Mutex<()>,
}

impl Manager {
    /// Missing state is disabled. Corrupt or future state is unavailable and
    /// fail-closed, but does not stop the rest of the daemon from starting.
    pub(crate) fn load() -> Arc<Self> {
        Self::load_from(
            paths::device_shell_policy_path(),
            paths::device_shell_audit_path(),
        )
    }

    #[cfg(test)]
    pub(crate) fn load_at(home: &std::path::Path) -> Arc<Self> {
        Self::load_from(home.join("shell.json"), home.join("shell-audit.jsonl"))
    }

    fn load_from(policy_path: PathBuf, audit_path: PathBuf) -> Arc<Self> {
        let (policy, mut unavailable) = match std::fs::read(&policy_path) {
            Ok(bytes) => match serde_json::from_slice::<PolicyFile>(&bytes) {
                Ok(policy) if policy.version == POLICY_VERSION => (policy, None),
                Ok(policy) => (
                    PolicyFile::default(),
                    Some(format!(
                        "{} is device-shell policy version {}, but this daemon reads {} — shell access is disabled",
                        policy_path.display(), policy.version, POLICY_VERSION
                    )),
                ),
                Err(e) => (
                    PolicyFile::default(),
                    Some(format!(
                        "{} is not readable as device-shell policy ({e}) — shell access is disabled",
                        policy_path.display()
                    )),
                ),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (PolicyFile::default(), None),
            Err(e) => (
                PolicyFile::default(),
                Some(format!(
                    "{} cannot be read ({e}) — shell access is disabled",
                    policy_path.display()
                )),
            ),
        };
        if let Some(why) = privilege_refusal() {
            unavailable = Some(why);
        }
        Arc::new(Self {
            policy_path,
            audit_path,
            state: Mutex::new(State {
                policy,
                unavailable,
                sessions: HashMap::new(),
            }),
            audit_lock: Mutex::new(()),
        })
    }

    pub(crate) fn status(&self, mesh_available: bool) -> ShellPolicyStatus {
        let state = self
            .state
            .lock()
            .expect("device-shell policy lock poisoned");
        let unavailable = state.unavailable.clone().or_else(|| {
            (!mesh_available).then(|| {
                "the mesh endpoint is unavailable, so no authenticated device-shell stream can be served".to_owned()
            })
        });
        let mut active: Vec<_> = state.sessions.values().map(|s| s.status.clone()).collect();
        active.sort_by(|a, b| {
            a.started_at
                .cmp(&b.started_at)
                .then_with(|| a.session_id.cmp(&b.session_id))
        });
        let policy_state = if unavailable.is_some() {
            ShellPolicyState::Unavailable
        } else if state.policy.enabled && !active.is_empty() {
            ShellPolicyState::Active
        } else if state.policy.enabled {
            ShellPolicyState::EnabledOrbit
        } else {
            ShellPolicyState::Disabled
        };
        ShellPolicyStatus {
            state: policy_state,
            epoch: state.policy.epoch,
            changed_at: (state.policy.changed_at != 0)
                .then_some(state.policy.changed_at)
                .or_else(|| (state.policy.enabled_at != 0).then_some(state.policy.enabled_at)),
            enabled_at: (state.policy.enabled_at != 0).then_some(state.policy.enabled_at),
            active,
            unavailable_reason: unavailable,
        }
    }

    /// Enable for exactly the device ids present now. A later pairing does
    /// not inherit authority; the local user must enable again to approve it.
    pub(crate) fn enable(&self, mut allowed_device_ids: Vec<String>) -> Result<ShellPolicyStatus> {
        allowed_device_ids.sort();
        allowed_device_ids.dedup();
        let mut state = self
            .state
            .lock()
            .expect("device-shell policy lock poisoned");
        if let Some(why) = &state.unavailable {
            bail!(why.clone());
        }
        let changed_at = now_unix();
        let next = PolicyFile {
            version: POLICY_VERSION,
            enabled: true,
            enabled_at: changed_at,
            changed_at,
            epoch: state.policy.epoch.saturating_add(1),
            allowed_device_ids,
        };
        self.audit(AuditRecord::policy("allow", next.epoch))?;
        durable::commit_json_private(&self.policy_path, &next)
            .context("committing the device-shell policy")?;
        state.policy = next;
        drop(state);
        Ok(self.status(true))
    }

    /// Publish disabled before draining sessions. An open serialized after
    /// this point observes the new epoch and cannot enter the registry.
    pub(crate) fn disable(&self) -> Result<(ShellPolicyStatus, usize)> {
        let mut state = self
            .state
            .lock()
            .expect("device-shell policy lock poisoned");
        let next = PolicyFile {
            version: POLICY_VERSION,
            enabled: false,
            enabled_at: 0,
            changed_at: now_unix(),
            epoch: state.policy.epoch.saturating_add(1),
            allowed_device_ids: Vec::new(),
        };
        durable::commit_json_private(&self.policy_path, &next)
            .context("committing the disabled device-shell policy")?;
        state.policy = next;
        let epoch = state.policy.epoch;
        let sessions: Vec<_> = state
            .sessions
            .values()
            .map(|session| {
                (
                    session.status.clone(),
                    session.epoch,
                    session.revoke.clone(),
                )
            })
            .collect();
        drop(state);
        self.audit_best_effort(AuditRecord::policy("deny", epoch));
        for (status, epoch, revoke) in &sessions {
            let reason = "device shell disabled locally".to_owned();
            self.audit_best_effort(AuditRecord::session(
                "revoke",
                &status.session_id,
                &status.peer_device_id,
                &status.peer_name,
                *epoch,
                status.pty,
                Some(reason.clone()),
            ));
            let _ = revoke.send(Some(reason));
        }
        let status = self.status(true);
        Ok((status, sessions.len()))
    }

    /// A membership removal is the other real-time revocation path.
    pub(crate) fn revoke_peer(&self, peer_device_id: &str, reason: &str) -> usize {
        let state = self
            .state
            .lock()
            .expect("device-shell policy lock poisoned");
        let sessions: Vec<_> = state
            .sessions
            .values()
            .filter(|session| session.status.peer_device_id == peer_device_id)
            .map(|session| {
                (
                    session.status.clone(),
                    session.epoch,
                    session.revoke.clone(),
                )
            })
            .collect();
        drop(state);
        for (status, epoch, revoke) in &sessions {
            self.audit_best_effort(AuditRecord::session(
                "revoke",
                &status.session_id,
                &status.peer_device_id,
                &status.peer_name,
                *epoch,
                status.pty,
                Some(reason.to_owned()),
            ));
            let _ = revoke.send(Some(reason.to_owned()));
        }
        sessions.len()
    }

    pub(crate) fn revoke_all(&self, reason: &str) {
        let mut peers: Vec<String> = self
            .state
            .lock()
            .expect("device-shell policy lock poisoned")
            .sessions
            .values()
            .map(|s| s.status.peer_device_id.clone())
            .collect();
        peers.sort();
        peers.dedup();
        for peer in peers {
            self.revoke_peer(&peer, reason);
        }
    }

    /// Called while the caller still holds the orbit lock that proved current
    /// membership. Device removal takes that lock before revoking, so an open
    /// cannot slip between the membership check and session registration.
    fn reserve(
        self: &Arc<Self>,
        peer_device_id: &str,
        peer_name: &str,
        pty: bool,
    ) -> Result<Lease> {
        let mut state = self
            .state
            .lock()
            .expect("device-shell policy lock poisoned");
        let refusal = if let Some(why) = &state.unavailable {
            Some(("unavailable", why.clone()))
        } else if !state.policy.enabled {
            Some((
                "disabled",
                "device shell is disabled on the target — run `ast device shell enable` there"
                    .to_owned(),
            ))
        } else if !state
            .policy
            .allowed_device_ids
            .iter()
            .any(|id| id == peer_device_id)
        {
            Some((
                "not_approved",
                "this peer was not present at the target's last local approval — run `ast device shell enable` there again".to_owned(),
            ))
        } else if state.sessions.len() >= GLOBAL_SESSION_LIMIT {
            Some((
                "busy",
                "the target is already serving four device-shell sessions".to_owned(),
            ))
        } else if state
            .sessions
            .values()
            .filter(|session| session.status.peer_device_id == peer_device_id)
            .count()
            >= PEER_SESSION_LIMIT
        {
            Some((
                "busy",
                "this peer already has two device-shell sessions on the target".to_owned(),
            ))
        } else {
            None
        };
        if let Some((code, message)) = refusal {
            let epoch = state.policy.epoch;
            drop(state);
            self.audit_best_effort(AuditRecord::deny(
                peer_device_id,
                peer_name,
                epoch,
                code,
                &message,
                pty,
            ));
            bail!("{code}: {message}");
        }

        let session_id = Uuid::new_v4().to_string();
        let status = ShellSessionStatus {
            session_id: session_id.clone(),
            peer_device_id: peer_device_id.to_owned(),
            peer_name: peer_name.to_owned(),
            started_at: now_unix(),
            pty,
        };
        state.policy.changed_at = status.started_at;
        let (revoke, revoked) = watch::channel(None);
        let epoch = state.policy.epoch;
        state.sessions.insert(
            session_id.clone(),
            LiveSession {
                status: status.clone(),
                epoch,
                revoke,
            },
        );
        Ok(Lease {
            manager: Arc::downgrade(self),
            status,
            epoch,
            revoked,
            finished: false,
        })
    }

    fn audit(&self, record: AuditRecord) -> Result<()> {
        let _audit = self
            .audit_lock
            .lock()
            .expect("device-shell audit lock poisoned");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.audit_path)
            .with_context(|| format!("opening {}", self.audit_path.display()))?;
        // Tighten a file created by an older build. The containing directory
        // is already 0700, but the audit contract is explicit 0600.
        let mut permissions = file.metadata()?.permissions();
        if permissions.mode() & 0o777 != 0o600 {
            permissions.set_mode(0o600);
            file.set_permissions(permissions)?;
        }
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }

    fn audit_best_effort(&self, record: AuditRecord) {
        let event = record.event.clone();
        if let Err(e) = self.audit(record) {
            eprintln!("astd: device-shell {event} audit failed: {e:#}");
        }
    }

    fn audit_denial(
        &self,
        peer_device_id: &str,
        peer_name: &str,
        code: &str,
        message: &str,
        pty: bool,
    ) {
        let epoch = self
            .state
            .lock()
            .expect("device-shell policy lock poisoned")
            .policy
            .epoch;
        self.audit_best_effort(AuditRecord::deny(
            peer_device_id,
            peer_name,
            epoch,
            code,
            message,
            pty,
        ));
    }
}

struct Lease {
    manager: Weak<Manager>,
    status: ShellSessionStatus,
    epoch: u64,
    revoked: watch::Receiver<Option<String>>,
    finished: bool,
}

impl Lease {
    fn start(&self) -> Result<()> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| anyhow!("device-shell policy went away"))?;
        manager.audit(AuditRecord::session(
            "start",
            &self.status.session_id,
            &self.status.peer_device_id,
            &self.status.peer_name,
            self.epoch,
            self.status.pty,
            None,
        ))
    }

    fn finish(&mut self, exit: &ShellExit) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(manager) = self.manager.upgrade() {
            let result = exit
                .reason
                .clone()
                .or_else(|| exit.code.map(|code| format!("exit {code}")))
                .or_else(|| exit.signal.map(|signal| format!("signal {signal}")));
            manager.audit_best_effort(AuditRecord::session(
                "end",
                &self.status.session_id,
                &self.status.peer_device_id,
                &self.status.peer_name,
                self.epoch,
                self.status.pty,
                result,
            ));
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            let mut state = manager
                .state
                .lock()
                .expect("device-shell policy lock poisoned");
            if state.sessions.remove(&self.status.session_id).is_some() {
                state.policy.changed_at = now_unix();
            }
            drop(state);
            if !self.finished {
                manager.audit_best_effort(AuditRecord::session(
                    "end",
                    &self.status.session_id,
                    &self.status.peer_device_id,
                    &self.status.peer_name,
                    self.epoch,
                    self.status.pty,
                    Some("disconnect".to_owned()),
                ));
            }
        }
    }
}

#[derive(Serialize)]
struct AuditRecord {
    timestamp_utc: u64,
    event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_name: Option<String>,
    policy_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal_code: Option<String>,
}

impl AuditRecord {
    fn policy(event: &str, epoch: u64) -> Self {
        Self {
            timestamp_utc: now_unix(),
            event: event.to_owned(),
            session_id: None,
            peer_device_id: None,
            peer_name: None,
            policy_epoch: epoch,
            mode: None,
            result: None,
            refusal_code: None,
        }
    }

    fn deny(peer: &str, name: &str, epoch: u64, code: &str, result: &str, pty: bool) -> Self {
        Self {
            timestamp_utc: now_unix(),
            event: "deny".to_owned(),
            session_id: None,
            peer_device_id: Some(peer.to_owned()),
            peer_name: Some(name.to_owned()),
            policy_epoch: epoch,
            mode: Some(if pty { "pty" } else { "command" }),
            result: Some(result.to_owned()),
            refusal_code: Some(code.to_owned()),
        }
    }

    fn session(
        event: &str,
        session_id: &str,
        peer: &str,
        name: &str,
        epoch: u64,
        pty: bool,
        result: Option<String>,
    ) -> Self {
        Self {
            timestamp_utc: now_unix(),
            event: event.to_owned(),
            session_id: Some(session_id.to_owned()),
            peer_device_id: Some(peer.to_owned()),
            peer_name: Some(name.to_owned()),
            policy_epoch: epoch,
            mode: Some(if pty { "pty" } else { "command" }),
            result,
            refusal_code: None,
        }
    }
}

// ---- account and process boundary -----------------------------------------

struct Account {
    uid: libc::uid_t,
    gid: libc::gid_t,
    user: String,
    home: PathBuf,
    shell: PathBuf,
}

fn privilege_refusal() -> Option<String> {
    // SAFETY: getuid/geteuid take no pointers and have no failure case.
    let (real, effective) = unsafe { (libc::getuid(), libc::geteuid()) };
    if effective == 0 {
        return Some(
            "device shell is unavailable because astd is running as root; it only serves an unprivileged user's account"
                .to_owned(),
        );
    }
    (real != effective).then(|| {
        format!(
            "device shell is unavailable because astd's real uid ({real}) and effective uid ({effective}) differ"
        )
    })
}

fn local_account() -> Result<Account> {
    // SAFETY: getuid takes no pointers and has no failure case.
    let uid = unsafe { libc::getuid() };
    // A bounded buffer avoids trusting a surprising sysconf answer. User and
    // path records larger than 64 KiB are not an account this daemon should
    // try to execute as.
    let hinted = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let size = if hinted <= 0 {
        16 * 1024
    } else {
        (hinted as usize).clamp(1024, 64 * 1024)
    };
    let mut buf = vec![0u8; size];
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut found = std::ptr::null_mut();
    // SAFETY: pwd and buf are writable for the lengths passed, and found is
    // checked before any field is read.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut found,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc)).context("looking up the daemon user");
    }
    if found.is_null() {
        bail!("the daemon uid {uid} has no local account record");
    }
    // SAFETY: getpwuid_r succeeded and returned pwd through found; its string
    // pointers refer into buf until this function returns.
    let pwd = unsafe { pwd.assume_init() };
    let field = |ptr: *const libc::c_char, what: &str| -> Result<String> {
        if ptr.is_null() {
            bail!("the local account has no {what}");
        }
        // SAFETY: successful getpwuid_r returns NUL-terminated fields.
        Ok(unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .with_context(|| format!("the local account's {what} is not utf-8"))?
            .to_owned())
    };
    let user = field(pwd.pw_name, "user name")?;
    let home = std::fs::canonicalize(field(pwd.pw_dir, "home directory")?)
        .context("resolving the local account's home directory")?;
    if !home.is_dir() {
        bail!(
            "the local account home {} is not a directory",
            home.display()
        );
    }
    let shell = PathBuf::from(field(pwd.pw_shell, "login shell")?);
    let shell_meta = std::fs::metadata(&shell)
        .with_context(|| format!("reading the local account shell {}", shell.display()))?;
    if !shell_meta.is_file() || shell_meta.mode() & 0o111 == 0 {
        bail!(
            "the local account shell {} is not an executable file",
            shell.display()
        );
    }
    Ok(Account {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        user,
        home,
        shell,
    })
}

enum ProcessInput {
    Data(Vec<u8>),
    Eof,
}

struct Running {
    pid: i32,
    input: mpsc::Sender<ProcessInput>,
    output: mpsc::Receiver<ShellFrame>,
    exit: oneshot::Receiver<ShellExit>,
    pty_master: Option<File>,
}

fn spawn(open: &ShellOpen) -> Result<Running> {
    open.validate().map_err(anyhow::Error::msg)?;
    let account = local_account()?;
    if open.pty {
        spawn_pty(open, &account)
    } else {
        spawn_command(open, &account)
    }
}

fn command_base(account: &Account, open: &ShellOpen) -> Command {
    let mut command = if let Some(body) = &open.command {
        // A watchdog in the same process group closes the macOS gap where
        // Linux's PR_SET_PDEATHSIG is unavailable. Every caller-controlled
        // value is a positional argument, never text in the wrapper.
        const WATCHDOG: &str = r#"
parent=$PPID
group=$$
(
  while kill -0 "$parent" 2>/dev/null; do sleep 1; done
  kill -HUP -- "-$group" 2>/dev/null
) &
watchdog=$!
"$1" -lc "$2"
status=$?
kill "$watchdog" 2>/dev/null
wait "$watchdog" 2>/dev/null
exit "$status"
"#;
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(WATCHDOG)
            .arg("asterism-device-shell")
            .arg(&account.shell)
            .arg(body);
        command
    } else {
        let mut command = Command::new(&account.shell);
        command.arg("-l");
        command
    };
    command
        .current_dir(&account.home)
        .env_clear()
        .env("HOME", &account.home)
        .env("USER", &account.user)
        .env("LOGNAME", &account.user)
        .env("SHELL", &account.shell)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .uid(account.uid)
        .gid(account.gid);
    for entry in &open.env {
        command.env(&entry.name, &entry.value);
    }
    command
}

fn spawn_command(open: &ShellOpen, account: &Account) -> Result<Running> {
    let mut command = command_base(account, open);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe syscalls run after fork. The closure
    // creates a fresh process group and asks Linux to HUP it if astd dies;
    // the portable watchdog above supplies the same lifetime on macOS.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGHUP) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .context("starting the local account shell")?;
    let pid = child.id() as i32;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("the shell has no stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("the shell has no stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("the shell has no stderr"))?;
    let (input, input_rx) = mpsc::channel(8);
    std::thread::spawn(move || write_pipe(stdin, input_rx));
    let (output, output_rx) = mpsc::channel(8);
    read_pipe(stdout, ShellOutput::Stdout, output.clone());
    read_pipe(stderr, ShellOutput::Stderr, output);
    let exit = wait_child(child);
    Ok(Running {
        pid,
        input,
        output: output_rx,
        exit,
        pty_master: None,
    })
}

fn spawn_pty(open: &ShellOpen, account: &Account) -> Result<Running> {
    let mut master = -1;
    let mut slave = -1;
    #[cfg(target_os = "linux")]
    let size = libc::winsize {
        ws_row: open.rows,
        ws_col: open.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    #[cfg(not(target_os = "linux"))]
    let mut size = libc::winsize {
        ws_row: open.rows,
        ws_col: open.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty initializes both fds or returns an error. The termios
    // pointer is null to request the platform default; size is initialized.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            #[cfg(target_os = "linux")]
            &size,
            #[cfg(not(target_os = "linux"))]
            &mut size,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("opening a pseudo-terminal");
    }
    // SAFETY: successful openpty returned owned descriptors.
    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    set_cloexec(&master)?;
    set_cloexec(&slave)?;

    let mut command = command_base(account, open);
    command
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    // SAFETY: only async-signal-safe syscalls; stdio has been installed when
    // pre_exec runs, so fd 0 is the slave used as controlling terminal.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGHUP) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command
        .spawn()
        .context("starting the local account shell on a pty")?;
    let pid = child.id() as i32;
    let writer = master.try_clone()?;
    let reader = master.try_clone()?;
    let (input, input_rx) = mpsc::channel(8);
    std::thread::spawn(move || write_file(writer, input_rx));
    let (output, output_rx) = mpsc::channel(8);
    read_pipe(reader, ShellOutput::Pty, output);
    let exit = wait_child(child);
    Ok(Running {
        pid,
        input,
        output: output_rx,
        exit,
        pty_master: Some(master),
    })
}

fn set_cloexec(file: &File) -> Result<()> {
    // SAFETY: fcntl operates on an owned, live descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(std::io::Error::last_os_error()).context("marking a pty close-on-exec");
    }
    Ok(())
}

fn write_pipe(mut pipe: ChildStdin, mut input: mpsc::Receiver<ProcessInput>) {
    while let Some(frame) = input.blocking_recv() {
        match frame {
            ProcessInput::Data(data) => {
                if pipe.write_all(&data).is_err() || pipe.flush().is_err() {
                    break;
                }
            }
            ProcessInput::Eof => break,
        }
    }
}

fn write_file(mut file: File, mut input: mpsc::Receiver<ProcessInput>) {
    while let Some(frame) = input.blocking_recv() {
        match frame {
            ProcessInput::Data(data) => {
                if file.write_all(&data).is_err() || file.flush().is_err() {
                    break;
                }
            }
            // A PTY has one bidirectional descriptor and no half-close. EOF
            // is represented by the terminal's VEOF byte (Ctrl-D).
            ProcessInput::Eof => {
                let _ = file.write_all(&[4]);
                let _ = file.flush();
            }
        }
    }
}

fn read_pipe<R: Read + Send + 'static>(
    mut pipe: R,
    stream: ShellOutput,
    output: mpsc::Sender<ShellFrame>,
) {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; MAX_DATA_BYTES];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    let data = ShellData::new(buf[..n].to_vec()).expect("reader obeyed frame cap");
                    if output
                        .blocking_send(ShellFrame::Output { stream, data })
                        .is_err()
                    {
                        return;
                    }
                }
                // PTY masters report EIO after the slave closes on Linux.
                Err(e) if e.raw_os_error() == Some(libc::EIO) => return,
                Err(_) => return,
            }
        }
    });
}

fn wait_child(mut child: std::process::Child) -> oneshot::Receiver<ShellExit> {
    let (send, recv) = oneshot::channel();
    std::thread::spawn(move || {
        let exit = match child.wait() {
            Ok(status) => ShellExit {
                code: status.code(),
                signal: status.signal(),
                core_dumped: status.core_dumped(),
                reason: None,
            },
            Err(e) => ShellExit {
                code: None,
                signal: None,
                core_dumped: false,
                reason: Some(format!("waiting for the shell failed: {e}")),
            },
        };
        let _ = send.send(exit);
    });
    recv
}

fn signal_group(pid: i32, signal: i32) {
    // SAFETY: negative pid targets the fresh group created before exec.
    unsafe {
        libc::kill(-pid, signal);
    }
}

fn resize(master: &File, cols: u16, rows: u16) -> Result<()> {
    if !(1..=MAX_TERMINAL_DIMENSION).contains(&cols)
        || !(1..=MAX_TERMINAL_DIMENSION).contains(&rows)
    {
        bail!("terminal rows and columns must each be between 1 and 1000");
    }
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: master is an owned PTY descriptor and size is initialized.
    if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &size) } != 0 {
        return Err(std::io::Error::last_os_error()).context("resizing the pseudo-terminal");
    }
    Ok(())
}

// ---- the explicit session state machine -----------------------------------

enum Wire<'a, 'b> {
    Mesh(MeshStream),
    Local(&'a mut ClientIo<'b>),
}

impl Wire<'_, '_> {
    async fn send(&mut self, frame: &ShellFrame) -> Result<()> {
        match self {
            Wire::Mesh(stream) => write_shell_frame(&mut stream.send, frame).await,
            Wire::Local(io) => {
                let response = match frame {
                    ShellFrame::Accepted { session_id } => Response::DeviceShellAccepted {
                        session_id: session_id.clone(),
                    },
                    ShellFrame::Refused { code, message } => Response::DeviceShellRefused {
                        code: code.clone(),
                        message: message.clone(),
                    },
                    ShellFrame::Output { stream, data } => Response::DeviceShellOutput {
                        stream: *stream,
                        data: data.clone(),
                    },
                    ShellFrame::Exit { exit } => Response::DeviceShellExit { exit: exit.clone() },
                    other => bail!(
                        "cannot send a {} control frame to ast",
                        shell_frame_name(other)
                    ),
                };
                io.send(&response).await
            }
        }
    }

    async fn recv(&mut self) -> Result<ShellFrame> {
        match self {
            Wire::Mesh(stream) => read_shell_frame(&mut stream.recv).await,
            Wire::Local(io) => match io.next_request().await? {
                Request::DeviceShellInput { data } => Ok(ShellFrame::Stdin { data }),
                Request::DeviceShellEof => Ok(ShellFrame::StdinEof),
                Request::DeviceShellResize { cols, rows } => Ok(ShellFrame::Resize { cols, rows }),
                Request::DeviceShellSignal { signal } => Ok(ShellFrame::Signal { signal }),
                Request::DeviceShellClose => Ok(ShellFrame::Close),
                _ => bail!("unexpected non-session request during a device-shell session"),
            },
        }
    }
}

/// Serve one authenticated mesh stream. Membership is checked here again,
/// immediately before policy authorization; accepting the QUIC connection is
/// not cached authority for a later stream.
pub(crate) async fn serve_mesh(
    stream: MeshStream,
    peer: DeviceId,
    node: &Node,
    open: ShellOpen,
) -> Result<()> {
    let peer_id = peer.to_string();
    let mut wire = Wire::Mesh(stream);
    let member = {
        let orbit = node.orbit.lock().await;
        let member = orbit.by_id(&peer_id).cloned();
        let Some(member) = member else {
            drop(orbit);
            node.shell.audit_denial(
                &peer_id,
                "<not in orbit>",
                "not_in_orbit",
                "the authenticated peer is not in this orbit",
                open.pty,
            );
            send_refusal(
                &mut wire,
                "not_in_orbit",
                "the authenticated peer is not in this orbit",
            )
            .await?;
            return Ok(());
        };
        if let Err(why) = open.validate() {
            drop(orbit);
            node.shell
                .audit_denial(&peer_id, &member.name, "malformed", why, open.pty);
            send_refusal(&mut wire, "malformed", why).await?;
            return Ok(());
        }
        // reserve is synchronous and occurs while membership's lock is held.
        // Device removal takes the same lock before it can revoke.
        let lease = node.shell.reserve(&peer_id, &member.name, open.pty);
        (member, lease)
    };
    let (member, lease) = member;
    let lease = match lease {
        Ok(lease) => lease,
        Err(e) => {
            let rendered = format!("{e:#}");
            let (code, message) = split_refusal(&rendered);
            send_refusal(&mut wire, code, message).await?;
            return Ok(());
        }
    };
    run(open, member, lease, wire).await
}

/// Serve `ast ssh --host` when the target name is this device. It deliberately
/// enters the same policy/session path as a remote peer.
pub(crate) async fn serve_self<'a, 'b>(
    open: ShellOpen,
    peer: DeviceId,
    peer_name: String,
    node: &Node,
    io: &'a mut ClientIo<'b>,
) -> Result<()> {
    let peer_id = peer.to_string();
    if let Err(why) = open.validate() {
        node.shell
            .audit_denial(&peer_id, &peer_name, "malformed", why, open.pty);
        let mut wire = Wire::Local(io);
        send_refusal(&mut wire, "malformed", why).await?;
        return Ok(());
    }
    let lease = node.shell.reserve(&peer_id, &peer_name, open.pty);
    let mut wire = Wire::Local(io);
    let lease = match lease {
        Ok(lease) => lease,
        Err(e) => {
            let rendered = format!("{e:#}");
            let (code, message) = split_refusal(&rendered);
            send_refusal(&mut wire, code, message).await?;
            return Ok(());
        }
    };
    let member = Device {
        name: peer_name,
        device_id: peer_id,
        addrs: vec![],
        relays: vec![],
        addrs_seen_at: 0,
        added_at: now_unix(),
        wake: Default::default(),
    };
    run(open, member, lease, wire).await
}

/// Bridge the local unix-socket conversation to an already-open remote mesh
/// shell stream. Both sides retain their own bounded/deadlined framing; this
/// function only translates the enum used on each door.
pub(crate) async fn bridge_client<'a, 'b>(
    mut stream: MeshStream,
    io: &'a mut ClientIo<'b>,
) -> Result<()> {
    loop {
        tokio::select! {
            remote = read_shell_frame(&mut stream.recv) => {
                let remote = remote?;
                let terminal = matches!(remote, ShellFrame::Refused { .. } | ShellFrame::Exit { .. });
                let response = match remote {
                    ShellFrame::Accepted { session_id } => Response::DeviceShellAccepted { session_id },
                    ShellFrame::Refused { code, message } => Response::DeviceShellRefused { code, message },
                    ShellFrame::Output { stream, data } => Response::DeviceShellOutput { stream, data },
                    ShellFrame::Exit { exit } => Response::DeviceShellExit { exit },
                    other => bail!(
                        "the target sent a {} control frame to the client",
                        shell_frame_name(&other)
                    ),
                };
                io.send(&response).await?;
                if terminal {
                    let _ = stream.send.finish();
                    return Ok(());
                }
            }
            local = io.next_request() => {
                let frame = match local? {
                    Request::DeviceShellInput { data } => ShellFrame::Stdin { data },
                    Request::DeviceShellEof => ShellFrame::StdinEof,
                    Request::DeviceShellResize { cols, rows } => ShellFrame::Resize { cols, rows },
                    Request::DeviceShellSignal { signal } => ShellFrame::Signal { signal },
                    Request::DeviceShellClose => ShellFrame::Close,
                    _ => bail!("unexpected non-session request during a device-shell session"),
                };
                write_shell_frame(&mut stream.send, &frame).await?;
            }
        }
    }
}

async fn run(
    open: ShellOpen,
    member: Device,
    mut lease: Lease,
    mut wire: Wire<'_, '_>,
) -> Result<()> {
    debug_assert!(open.validate().is_ok());
    // The audit write is before spawn and failure is a refusal. There is no
    // session whose start cannot be accounted for.
    if let Err(e) = lease.start() {
        send_refusal(
            &mut wire,
            "audit_unavailable",
            &format!("the target cannot write its device-shell audit: {e:#}"),
        )
        .await?;
        return Ok(());
    }
    let mut running = match spawn(&open) {
        Ok(running) => running,
        Err(e) => {
            let exit = ShellExit {
                code: None,
                signal: None,
                core_dumped: false,
                reason: Some(format!("spawn refused: {e:#}")),
            };
            lease.finish(&exit);
            send_refusal(&mut wire, "spawn_failed", &format!("{e:#}")).await?;
            return Ok(());
        }
    };
    if let Err(e) = send_bounded(
        &mut wire,
        &ShellFrame::Accepted {
            session_id: lease.status.session_id.clone(),
        },
    )
    .await
    {
        let exit = terminate(
            &mut running.exit,
            running.pid,
            format!("client disconnected before accepting the shell: {e:#}"),
        )
        .await;
        lease.finish(&exit);
        return Err(e);
    }

    let mut exit = loop {
        tokio::select! {
            changed = lease.revoked.changed() => {
                let reason = match changed {
                    Ok(()) => lease.revoked.borrow().clone().unwrap_or_else(|| "device-shell access was revoked".to_owned()),
                    Err(_) => "device-shell policy went away".to_owned(),
                };
                break terminate(&mut running.exit, running.pid, reason).await;
            }
            result = &mut running.exit => {
                break result.unwrap_or(ShellExit {
                    code: None,
                    signal: None,
                    core_dumped: false,
                    reason: Some("the shell waiter ended without a result".to_owned()),
                });
            }
            output = running.output.recv() => {
                if let Some(output) = output {
                    if let Err(e) = send_bounded(&mut wire, &output).await {
                        break terminate(
                            &mut running.exit,
                            running.pid,
                            format!("client stopped reading shell output: {e:#}"),
                        ).await;
                    }
                }
            }
            input = wire.recv() => {
                match input {
                    Ok(ShellFrame::Stdin { data }) => {
                        if running.input.try_send(ProcessInput::Data(data.into_bytes())).is_err() {
                            break terminate(
                                &mut running.exit,
                                running.pid,
                                "shell input exceeded the bounded queue".to_owned(),
                            ).await;
                        }
                    }
                    Ok(ShellFrame::StdinEof) => {
                        let _ = running.input.try_send(ProcessInput::Eof);
                    }
                    Ok(ShellFrame::Resize { cols, rows }) if open.pty => {
                        let resized = running
                            .pty_master
                            .as_ref()
                            .ok_or_else(|| anyhow!("the accepted pty has no master"))
                            .and_then(|master| resize(master, cols, rows));
                        if let Err(e) = resized {
                            break terminate(
                                &mut running.exit,
                                running.pid,
                                format!("invalid resize frame: {e:#}"),
                            ).await;
                        }
                    }
                    Ok(ShellFrame::Signal { signal }) if matches!(signal, libc::SIGHUP | libc::SIGINT | libc::SIGTERM) => {
                        signal_group(running.pid, signal);
                    }
                    Ok(ShellFrame::Close) => {
                        break terminate(&mut running.exit, running.pid, "client closed the session".to_owned()).await;
                    }
                    Ok(other) => {
                        break terminate(
                            &mut running.exit,
                            running.pid,
                            format!(
                                "protocol error after open: unexpected {} frame",
                                shell_frame_name(&other)
                            ),
                        ).await;
                    }
                    Err(e) => {
                        break terminate(
                            &mut running.exit,
                            running.pid,
                            format!("transport disconnected: {e:#}"),
                        ).await;
                    }
                }
            }
        }
    };

    // The waiter can win the race with its stdout reader. Drain the bounded
    // queue briefly so a command's final line is not lost behind its status.
    while let Ok(Some(output)) =
        tokio::time::timeout(Duration::from_millis(50), running.output.recv()).await
    {
        if send_bounded(&mut wire, &output).await.is_err() {
            exit.reason
                .get_or_insert_with(|| "client disconnected before final output".to_owned());
            break;
        }
    }
    lease.finish(&exit);
    let _ = send_bounded(&mut wire, &ShellFrame::Exit { exit }).await;
    let _ = member; // retained through the session for its authenticated display name
    Ok(())
}

fn shell_frame_name(frame: &ShellFrame) -> &'static str {
    match frame {
        ShellFrame::Accepted { .. } => "accepted",
        ShellFrame::Refused { .. } => "refused",
        ShellFrame::Stdin { .. } => "stdin",
        ShellFrame::StdinEof => "stdin_eof",
        ShellFrame::Resize { .. } => "resize",
        ShellFrame::Signal { .. } => "signal",
        ShellFrame::Close => "close",
        ShellFrame::Output { .. } => "output",
        ShellFrame::Exit { .. } => "exit",
    }
}

async fn terminate(exit: &mut oneshot::Receiver<ShellExit>, pid: i32, reason: String) -> ShellExit {
    signal_group(pid, libc::SIGHUP);
    let mut result = match tokio::time::timeout(KILL_GRACE, &mut *exit).await {
        Ok(Ok(exit)) => exit,
        _ => {
            signal_group(pid, libc::SIGKILL);
            match (&mut *exit).await {
                Ok(exit) => exit,
                Err(_) => ShellExit {
                    code: None,
                    signal: Some(libc::SIGKILL),
                    core_dumped: false,
                    reason: None,
                },
            }
        }
    };
    result.reason = Some(reason);
    result
}

async fn send_refusal(wire: &mut Wire<'_, '_>, code: &str, message: &str) -> Result<()> {
    send_bounded(
        wire,
        &ShellFrame::Refused {
            code: code.to_owned(),
            message: message.to_owned(),
        },
    )
    .await
}

async fn send_bounded(wire: &mut Wire<'_, '_>, frame: &ShellFrame) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), wire.send(frame))
        .await
        .context("writing a shell frame timed out")?
}

fn split_refusal(rendered: &str) -> (&str, &str) {
    rendered.split_once(": ").unwrap_or(("refused", rendered))
}

pub(crate) async fn write_shell_frame(send: &mut SendStream, frame: &ShellFrame) -> Result<()> {
    let bytes = serde_json::to_vec(frame)?;
    if bytes.len() > MAX_FRAME_BYTES {
        bail!("a device-shell frame is larger than its bounded payload permits");
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

pub(crate) async fn read_shell_frame(recv: &mut RecvStream) -> Result<ShellFrame> {
    let mut len = [0u8; 4];
    // Idle has no timeout. Once a peer starts a frame, the rest must arrive
    // promptly and its length is checked before allocation.
    recv.read_exact(&mut len[..1]).await?;
    tokio::time::timeout(FRAME_DEADLINE, recv.read_exact(&mut len[1..]))
        .await
        .context("a device-shell frame header was still arriving after 5s")??;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_BYTES {
        bail!("a device-shell frame of {len} bytes exceeds its bounded payload");
    }
    let mut bytes = vec![0u8; len];
    tokio::time::timeout(FRAME_DEADLINE, recv.read_exact(&mut bytes))
        .await
        .context("a device-shell frame body was still arriving after 5s")??;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager(tmp: &std::path::Path) -> Arc<Manager> {
        Manager::load_from(tmp.join("shell.json"), tmp.join("audit.jsonl"))
    }

    #[test]
    fn missing_policy_is_disabled_and_new_pairings_do_not_inherit_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let manager = manager(tmp.path());
        let missing = manager.status(true);
        assert_eq!(missing.state, ShellPolicyState::Disabled);
        assert_eq!(missing.changed_at, None);
        let enabled = manager.enable(vec!["peer-a".into()]).unwrap();
        assert_eq!(enabled.changed_at, enabled.enabled_at);
        let approved = manager.reserve("peer-a", "laptop", false).unwrap();
        let active = manager.status(true);
        assert_eq!(active.state, ShellPolicyState::Active);
        assert_eq!(active.active_sessions(), 1);
        assert!(active.changed_at.is_some());
        assert!(manager.reserve("peer-b", "new-laptop", false).is_err());
        drop(approved);
        assert!(manager.status(true).changed_at.is_some());
        let mode = std::fs::metadata(tmp.path().join("shell.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn disable_publishes_a_new_epoch_and_revokes_live_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let manager = manager(tmp.path());
        let enabled = manager.enable(vec!["peer-a".into()]).unwrap();
        let lease = manager.reserve("peer-a", "laptop", false).unwrap();
        let (disabled, count) = manager.disable().unwrap();
        assert_eq!(count, 1);
        assert_eq!(disabled.state, ShellPolicyState::Disabled);
        assert!(disabled.epoch > enabled.epoch);
        assert!(lease
            .revoked
            .borrow()
            .as_deref()
            .unwrap()
            .contains("disabled"));
        assert!(manager.reserve("peer-a", "laptop", false).is_err());
    }

    #[test]
    fn corrupt_policy_is_unavailable_and_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("shell.json"), b"not json").unwrap();
        let manager = manager(tmp.path());
        let status = manager.status(true);
        assert_eq!(status.state, ShellPolicyState::Unavailable);
        assert!(status.unavailable_reason.unwrap().contains("not readable"));
        assert!(manager.reserve("peer-a", "laptop", false).is_err());
        assert!(manager.enable(vec!["peer-a".into()]).is_err());
    }

    #[test]
    fn session_limits_are_enforced_per_peer_and_globally() {
        let tmp = tempfile::tempdir().unwrap();
        let manager = manager(tmp.path());
        manager
            .enable(vec!["a".into(), "b".into(), "c".into()])
            .unwrap();
        let _a1 = manager.reserve("a", "one", false).unwrap();
        let _a2 = manager.reserve("a", "one", false).unwrap();
        assert!(manager.reserve("a", "one", false).is_err());
        let _b1 = manager.reserve("b", "two", false).unwrap();
        let _b2 = manager.reserve("b", "two", false).unwrap();
        assert!(manager.reserve("c", "three", false).is_err());
    }

    #[test]
    fn audit_never_contains_a_command_or_transcript() {
        let tmp = tempfile::tempdir().unwrap();
        let manager = manager(tmp.path());
        manager.enable(vec!["peer-a".into()]).unwrap();
        let lease = manager.reserve("peer-a", "laptop", false).unwrap();
        lease.start().unwrap();
        drop(lease);
        let audit = std::fs::read_to_string(tmp.path().join("audit.jsonl")).unwrap();
        assert!(audit.contains("peer-a"));
        assert!(!audit.contains("\"command\":"));
        assert!(!audit.contains("\"transcript\":"));
    }

    #[test]
    fn denials_and_revocations_record_the_policy_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let manager = manager(tmp.path());
        let enabled = manager.enable(vec!["peer-a".into()]).unwrap();
        let lease = manager.reserve("peer-a", "laptop", false).unwrap();
        assert!(manager.reserve("peer-b", "stranger", false).is_err());
        let (disabled, count) = manager.disable().unwrap();
        assert_eq!(count, 1);

        let records: Vec<serde_json::Value> =
            std::fs::read_to_string(tmp.path().join("audit.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
        assert!(records.iter().any(|record| {
            record["event"] == "deny"
                && record["peer_device_id"] == "peer-b"
                && record["policy_epoch"] == enabled.epoch
        }));
        assert!(records.iter().any(|record| {
            record["event"] == "deny"
                && record.get("session_id").is_none()
                && record.get("refusal_code").is_none()
                && record["policy_epoch"] == disabled.epoch
        }));
        assert!(records.iter().any(|record| {
            record["event"] == "revoke"
                && record["session_id"] == lease.status.session_id
                && record["policy_epoch"] == enabled.epoch
        }));
    }

    #[test]
    fn concurrent_audit_records_remain_one_json_object_per_line() {
        let tmp = tempfile::tempdir().unwrap();
        let manager = manager(tmp.path());
        let mut writers = Vec::new();
        for writer in 0..8 {
            let manager = manager.clone();
            writers.push(std::thread::spawn(move || {
                for record in 0..32 {
                    manager
                        .audit(AuditRecord::policy("allow", writer * 32 + record))
                        .unwrap();
                }
            }));
        }
        for writer in writers {
            writer.join().unwrap();
        }
        let audit = std::fs::read_to_string(tmp.path().join("audit.jsonl")).unwrap();
        let lines: Vec<_> = audit.lines().collect();
        assert_eq!(lines.len(), 8 * 32);
        assert!(lines
            .iter()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok()));
    }

    #[test]
    fn policy_and_session_frames_cannot_use_generic_mesh_rpc() {
        assert!(local_only_request(&Request::DeviceShellPolicy {
            action: asterism_core::device_shell::ShellPolicyAction::Enable,
        }));
        assert!(local_only_request(&Request::DeviceShellOpen {
            device: "desktop".into(),
            open: ShellOpen {
                command: None,
                pty: true,
                cols: 80,
                rows: 24,
                env: vec![],
            },
        }));
        assert!(local_only_request(&Request::DeviceShellEof));
        assert!(!local_only_request(&Request::DeviceShellStatus));
        assert!(!local_only_request(&Request::List));
    }

    #[tokio::test]
    async fn pty_resize_and_exit_status_are_real_kernel_behaviour() {
        if privilege_refusal().is_some() {
            return;
        }
        let open = ShellOpen {
            command: Some("stty size; exit 37".into()),
            pty: true,
            cols: 93,
            rows: 41,
            env: vec![],
        };
        let mut running = spawn(&open).unwrap();
        resize(running.pty_master.as_ref().unwrap(), 94, 42).unwrap();
        let mut bytes = Vec::new();
        let exit = loop {
            tokio::select! {
                frame = running.output.recv() => {
                    if let Some(ShellFrame::Output { data, .. }) = frame {
                        bytes.extend_from_slice(data.as_bytes());
                    }
                }
                exit = &mut running.exit => break exit.unwrap(),
            }
        };
        assert_eq!(exit.code, Some(37));
        let output = String::from_utf8_lossy(&bytes);
        assert!(
            output.contains("42 94") || output.contains("41 93"),
            "{output:?}"
        );
    }
}
