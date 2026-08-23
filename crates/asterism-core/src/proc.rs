//! Process identity: the difference between "pid 4242" and "the process we
//! started".
//!
//! Everything Asterism runs a guest on is a process that outlives the daemon
//! — that is the whole point of the vz helper (BACKENDS.md §4) and of
//! `qemu -daemonize`. So the daemon writes the process down and picks it up
//! again later: after a restart, after an upgrade, after a host reboot.
//!
//! A pid alone does not survive that trip. It is a small integer the kernel
//! hands back out, and by the time a daemon reads one off disk the number may
//! belong to a browser tab. Every path in this tree that used to ask
//! `kill -0 <pid>` was really asking "is *anything* alive there", getting an
//! answer to a different question, and then acting on it — with SIGKILL.
//!
//! What this module adds is the rest of the identity:
//!
//! * **When the process started**, straight from the kernel. Two processes
//!   can share a pid; they cannot share a pid *and* a start instant, because
//!   the second one only got the number after the first one died.
//! * **What it is running.** Start time survives `exec`, so a process that
//!   replaced its own binary keeps it. The executable path is what catches
//!   that.
//!
//! A [`ProcId`] is captured when the process is spawned and stored beside the
//! pid. Every later question — is it alive, stop it, kill it — goes through
//! [`ProcId::check`] first, and anything that is not [`Ownership::Ours`]
//! refuses to signal. That is the invariant this module exists to hold:
//! **no signal leaves this process without proven ownership of its target.**
//!
//! ## Zombies
//!
//! A process that has exited and not been waited for still answers
//! `kill -0`. It is not running anything; it is a slot in the process table
//! holding an exit status. [`ProcId::check`] reads the kernel's process state
//! and calls that [`Ownership::Gone`], which is what it is — so a backend no
//! longer has to reap a child merely to keep liveness honest.
//!
//! ## The window that is left
//!
//! `check()` then `kill()` is two syscalls, and a pid could in principle be
//! recycled between them. Closing that needs a handle type POSIX does not
//! have on this platform (no `pidfd`, no `process_madvise`), so what is left
//! is the same window systemd and every supervisor written against
//! `/proc/<pid>/stat` lives with: microseconds wide, and requiring the kernel
//! to wrap the entire pid space inside it. [`ProcId::signal`] re-checks
//! afterwards and says so loudly if the identity changed, which turns a
//! silent misfire into a log line.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Proof that a pid is the process we started and not a later one wearing
/// its number.
///
/// Recorded on a [`Handle`](crate::hv::Handle) and on a volume
/// [`Lease`](crate::volume::Lease), which is to say: everywhere a process
/// outlives the daemon that spawned it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcId {
    pub pid: u32,
    /// When the kernel says this process started, in microseconds since the
    /// unix epoch.
    ///
    /// Absolute rather than boot-relative on purpose: a boot-relative stamp
    /// would compare equal across a reboot, which is exactly the case a
    /// resurrecting daemon is in.
    pub started_us: u64,
    /// Linux's stable boot identity. Paired with `started_ticks` because
    /// `/proc/stat`'s wall-clock `btime` can move when the host clock steps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    /// Linux clock ticks since boot at process start. This, plus `boot_id`,
    /// is authoritative when present; `started_us` remains for compatibility
    /// and the adoption time-window check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_ticks: Option<u64>,
    /// Absolute path of the executable the process was running when this was
    /// captured. `None` where the platform would not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<PathBuf>,
}

/// What is at a recorded pid now.
///
/// Four answers rather than two, because the two questions a caller asks —
/// "may I signal this?" and "is my guest still running?" — do not have the
/// same safe default. [`Ownership::Unknown`] is the one that makes that
/// visible: it authorises nothing and it kills nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// The process is there and it is the one we recorded.
    Ours,
    /// Nothing is there, or what is there is a zombie: an exit status, not a
    /// running program.
    Gone,
    /// Something else is there. The pid was recycled, or the process
    /// replaced its own executable. Never signalled.
    Foreign(String),
    /// The process exists and the kernel would not say what it is.
    ///
    /// Rare, and deliberately not folded into either neighbour. Folding it
    /// into `Gone` would let a hiccup in one `proc_pidinfo` call declare a
    /// perfectly healthy guest dead — and everything downstream acts on
    /// that: `reconcile` rewrites the registry, the supervisor boots a
    /// second guest onto the first one's disk. Folding it into `Ours` would
    /// let the same hiccup authorise a SIGKILL at a process nothing has
    /// identified. So it does neither: [`ProcId::alive`] counts it as
    /// running, [`ProcId::signal`] refuses it.
    Unknown(String),
}

impl Ownership {
    /// Proven to be the process we recorded. The only answer that
    /// authorises a signal.
    pub fn is_ours(&self) -> bool {
        matches!(self, Ownership::Ours)
    }

    /// Known not to be our running process — gone, or somebody else's.
    /// [`Ownership::Unknown`] is deliberately not this.
    pub fn is_ended(&self) -> bool {
        matches!(self, Ownership::Gone | Ownership::Foreign(_))
    }
}

/// The signals Asterism sends. A closed set because every one of them is a
/// decision someone has to be able to find in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Ask the process to exit.
    Term,
    /// Take it out.
    Kill,
}

impl Signal {
    fn as_libc(self) -> i32 {
        match self {
            Signal::Term => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Signal::Term => "SIGTERM",
            Signal::Kill => "SIGKILL",
        }
    }
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What ties a running process to the instance whose handle names it.
///
/// The thing [`ProcId::adopt`] rests on, and the reason it can rest on
/// anything at all. Every other test adoption makes is satisfiable by
/// coincidence: pids repeat, `qemu-system-aarch64` is a program many things
/// start, and "began at roughly the right time" is a window, not a
/// fingerprint. This is not satisfiable by coincidence, because these paths
/// belong to one instance on one device — its own control socket, its own
/// pidfile, its own config — and a process that did not exist to serve that
/// instance has no reason to be carrying one on its command line.
///
/// `names` is where the authority comes from; `exec` only narrows what may
/// be considered. Supplying no names is not a lax adoption, it is a refused
/// one.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    /// Executable file names a candidate may be running. A family rather
    /// than a path — `qemu-system-*` — so upgrading qemu under a running
    /// guest does not orphan it.
    pub exec: &'a [&'a str],
    /// Paths that belong to this instance alone. At least one must appear on
    /// the candidate's own command line.
    pub names: &'a [&'a Path],
}

impl Evidence<'_> {
    /// The path this command line was carrying, if it was carrying one.
    ///
    /// Substring rather than equality because the paths arrive decorated:
    /// qemu is given `unix:/…/qmp.sock,server,nowait` and `file:/…/console.log`,
    /// and the decoration is qemu's business rather than something to
    /// enumerate here. What makes that safe is that these are full paths to
    /// named files — `/…/instances/dev/qmp.sock` is not a prefix of
    /// `/…/instances/dev2/qmp.sock`, which a bare directory would have been.
    fn found_in<'a>(&'a self, argv: &[String]) -> Option<&'a Path> {
        self.names.iter().copied().find(|name| {
            name.to_str()
                .is_some_and(|name| argv.iter().any(|arg| arg.contains(name)))
        })
    }

    fn describe(&self) -> String {
        self.names
            .iter()
            .map(|n| n.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// How far after a recorded `started_at` a process may have started and
/// still be *considered* for adoption.
///
/// A refusal, never a reason. Nothing is ever adopted because it passed
/// this — see [`Evidence`] for what adoption actually rests on. It is here
/// only to throw out the obvious impostor early: a handle's `started_at` is
/// written after the process is up (for vz, after the guest has booted,
/// which can be minutes), so a genuine process may have started well before
/// it, and one that started well *after* it cannot be the process the
/// handle was written about. The slack absorbs clock jitter between the
/// kernel's stamp and `now_unix()`, nothing more.
const ADOPT_SLACK_SECS: u64 = 60;

impl ProcId {
    /// Capture the identity of a running process the caller already knows
    /// is the right one.
    ///
    /// The contract is in that sentence and it is not checkable here: this
    /// takes a pid and writes down what the kernel says about it, so the
    /// authority it creates is exactly the authority the caller already had.
    /// Every use in this tree is one of two things — a process this daemon
    /// has just spawned and is holding the child handle for, or the one
    /// process holding a unix socket that only this device's daemon binds.
    /// Anything less than that is [`ProcId::adopt`]'s job, and adopt asks
    /// for evidence for a reason.
    ///
    /// Fails if there is no such process, or if it is a zombie — neither is
    /// something worth writing down as a running guest.
    pub fn capture(pid: u32) -> Result<ProcId> {
        let probe = match look(pid) {
            Look::Found(probe) => probe,
            Look::NoSuchProcess => bail!("there is no process {pid} to record"),
            Look::Unreadable(why) => {
                bail!("this host will not say what process {pid} is: {why}")
            }
        };
        if probe.zombie {
            bail!("process {pid} has already exited");
        }
        Ok(ProcId {
            pid,
            started_us: probe.started_us,
            boot_id: probe.boot_id,
            started_ticks: probe.started_ticks,
            exec: probe.exec,
        })
    }

    /// Mint an identity for a pid recorded before identities existed.
    ///
    /// The explicit half of the migration, and the one place in this module
    /// where authority is created out of something other than having started
    /// the process. What it is created out of matters enormously, so it is
    /// worth being precise about what does *not* count.
    ///
    /// A pid does not. Nor does a pid that is alive, nor one running a
    /// program of the right family, nor one whose start time falls in a
    /// plausible window — nor all three together. Every one of those is
    /// satisfied by an unrelated `qemu-system-aarch64` that some other tool
    /// started thirty seconds after this handle was written, and adopting
    /// that would hand `stop` and `kill` a stranger to aim at. They are
    /// refusals: each can throw a candidate out, none can let one in.
    ///
    /// What lets one in is [`Evidence`]: something only this instance's own
    /// process could be carrying. A refusal to supply any is a refusal to
    /// adopt — there is no argument list that mints authority from a number.
    pub fn adopt(
        pid: u32,
        started_at: u64,
        evidence: &Evidence,
    ) -> std::result::Result<ProcId, String> {
        // First, because it is a bug in the caller rather than a fact about
        // the process, and because the whole point of this function is that
        // it cannot be reached without evidence.
        if evidence.names.is_empty() {
            return Err(format!(
                "refusing to adopt pid {pid}: nothing was offered that only this \
                 instance's own process could be carrying"
            ));
        }

        let probe = match look(pid) {
            Look::Found(probe) => probe,
            Look::NoSuchProcess => return Err(format!("no process {pid}")),
            Look::Unreadable(why) => {
                return Err(format!(
                    "this host will not say what process {pid} is: {why}"
                ))
            }
        };
        if probe.zombie {
            return Err(format!("process {pid} has already exited"));
        }
        let started_secs = probe.started_us / 1_000_000;
        if started_secs > started_at.saturating_add(ADOPT_SLACK_SECS) {
            return Err(format!(
                "process {pid} started {}s after the handle that names it, so it is a \
                 different process wearing the same number",
                started_secs.saturating_sub(started_at)
            ));
        }
        // The evidence itself, and the only line here that can answer yes.
        let Some(argv) = argv(pid) else {
            return Err(format!(
                "this host will not say what pid {pid} was started with, so nothing \
                 ties it to this instance"
            ));
        };
        // Linux deliberately hides /proc/<pid>/exe for a file-capability
        // process from its unprivileged parent. In that case argv[0] still
        // has to name the expected executable family, and adoption still
        // rests on the instance-exclusive path below. An argv name alone is
        // never authority.
        let argv_exec = argv.first().map(PathBuf::from);
        let Some(described_exec) = probe.exec.as_ref().or(argv_exec.as_ref()) else {
            return Err(format!(
                "this host will not say what process {pid} is running, so it cannot be adopted"
            ));
        };
        if !matches_any(described_exec, evidence.exec) {
            return Err(format!(
                "process {pid} is running {}, not {}",
                described_exec.display(),
                evidence.exec.join(" or ")
            ));
        }
        if evidence.found_in(&argv).is_none() {
            return Err(format!(
                "pid {pid} is a {} that was not started for this instance — its command \
                 line names none of {}",
                described_exec
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("process"),
                evidence.describe()
            ));
        }

        Ok(ProcId {
            pid,
            started_us: probe.started_us,
            boot_id: probe.boot_id,
            started_ticks: probe.started_ticks,
            exec: probe.exec,
        })
    }

    /// What is at this pid right now.
    pub fn check(&self) -> Ownership {
        self.against(look(self.pid))
    }

    /// The verdict, given what the kernel said. Split out from
    /// [`ProcId::check`] so each answer can be tested for what it authorises
    /// without having to make the kernel produce it.
    fn against(&self, seen: Look) -> Ownership {
        let probe = match seen {
            Look::Found(probe) => probe,
            Look::NoSuchProcess => return Ownership::Gone,
            Look::Unreadable(why) => return Ownership::Unknown(why),
        };
        if probe.zombie {
            return Ownership::Gone;
        }
        match (
            self.boot_id.as_deref(),
            self.started_ticks,
            probe.boot_id.as_deref(),
            probe.started_ticks,
        ) {
            (Some(was_boot), Some(was_ticks), Some(now_boot), Some(now_ticks)) => {
                if was_boot != now_boot || was_ticks != now_ticks {
                    return Ownership::Foreign(format!(
                        "pid {} began at boot {now_boot} tick {now_ticks}, not boot {was_boot} tick {was_ticks} — the number was recycled",
                        self.pid
                    ));
                }
            }
            (Some(_), _, _, _) | (_, Some(_), _, _) => {
                return Ownership::Unknown(format!(
                    "the kernel did not return the Linux boot identity recorded for pid {}",
                    self.pid
                ));
            }
            _ if probe.started_us != self.started_us => {
                return Ownership::Foreign(format!(
                    "pid {} started at {}, not at {} — the number was recycled",
                    self.pid, probe.started_us, self.started_us
                ));
            }
            _ => {}
        }
        // Start time survives exec, so a process that swapped its own binary
        // still matches on the stamp above. Only the path catches it.
        match (&self.exec, &probe.exec) {
            (Some(was), Some(now)) if was != now => Ownership::Foreign(format!(
                "pid {} is running {} now, and was running {} when it was recorded",
                self.pid,
                now.display(),
                was.display()
            )),
            _ => Ownership::Ours,
        }
    }

    /// Is the process we recorded still running?
    ///
    /// False for a pid that is gone, a zombie, and — the case a bare
    /// `kill -0` gets wrong — a pid that now belongs to somebody else.
    ///
    /// True for [`Ownership::Unknown`], which is not the same test as
    /// [`Ownership::is_ours`] and must not be: this answer is what decides
    /// whether a guest gets declared dead, restarted, and eventually booted
    /// a second time onto its own disk. A momentary failure to read the
    /// process table is not evidence that a guest died, and is never worth
    /// acting on as though it were.
    pub fn alive(&self) -> bool {
        !self.check().is_ended()
    }

    /// Send a signal, but only to the process this identity names.
    ///
    /// `Ok(true)` when it was delivered, `Ok(false)` when there was nothing
    /// of ours left to signal (which every caller wants to treat as success:
    /// the process is gone, which is what they were asking for). `Err` only
    /// when the pid is alive and demonstrably somebody else's, because that
    /// is the one outcome a caller must not paper over.
    pub fn signal(&self, sig: Signal) -> Result<bool> {
        match self.check() {
            Ownership::Gone => return Ok(false),
            Ownership::Foreign(why) | Ownership::Unknown(why) => {
                bail!("refusing to send {sig} to pid {}: {why}", self.pid)
            }
            Ownership::Ours => {}
        }
        // SAFETY: a plain kill(2) with a pid we have just proven is ours.
        let rc = unsafe { libc::kill(self.pid as libc::pid_t, sig.as_libc()) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // ESRCH between the check and the kill is the process exiting
            // underneath us, which is not a failure of anything.
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(false);
            }
            bail!("sending {sig} to pid {}: {err}", self.pid);
        }
        // The window this closes is not the one it opens: if the identity
        // changed between the check and the kill, the signal has already
        // gone. Saying so turns an invisible misfire into something a human
        // can find in the log.
        if let Ownership::Foreign(why) = self.check() {
            if sig == Signal::Kill {
                eprintln!(
                    "astd: {sig} to pid {} may have reached another process — {why}",
                    self.pid
                );
            }
        }
        Ok(true)
    }

    /// Poll until this process is gone, or the budget runs out.
    ///
    /// "Gone" includes a pid that has become somebody else's: whatever is
    /// there, what we were waiting for has ended.
    pub fn wait_gone(&self, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            if !self.alive() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl std::fmt::Display for ProcId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pid {} started {}us", self.pid, self.started_us)
    }
}

fn matches_any(exec: &Path, expect: &[&str]) -> bool {
    let Some(name) = exec.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    expect.iter().any(|want| match want.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == *want,
    })
}

// ---- the platform half -----------------------------------------------------

/// What the kernel had to say about a pid.
enum Look {
    Found(Probe),
    /// The kernel is certain there is no such process.
    NoSuchProcess,
    /// There is a process and this host would not describe it. Never the
    /// same answer as `NoSuchProcess` — see [`Ownership::Unknown`].
    Unreadable(String),
}

/// What the kernel will say about a pid.
struct Probe {
    /// Process start, microseconds since the unix epoch.
    started_us: u64,
    boot_id: Option<String>,
    started_ticks: Option<u64>,
    /// Exited and not yet reaped: a slot in the process table, not a program.
    zombie: bool,
    exec: Option<PathBuf>,
}

/// Does a process with this pid exist at all, whatever it is?
///
/// The fallback question, asked only when the descriptive one has failed. It
/// is what tells "the process is gone" apart from "the kernel would not
/// say", which are the same syscall failure from the caller's side and very
/// different facts.
///
/// macOS only: on Linux the absence of `/proc/<pid>` answers it already.
#[cfg(target_os = "macos")]
fn exists(pid: u32) -> bool {
    // SAFETY: signal 0 delivers nothing; it only reports whether the pid
    // could be signalled.
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return true;
    }
    // EPERM means it exists and belongs to somebody else.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// The command line a process was started with.
///
/// `None` where the host would not say, which is a refusal to adopt rather
/// than a licence to skip the check.
#[cfg(target_os = "macos")]
fn argv(pid: u32) -> Option<Vec<String>> {
    // The buffer has to be big enough for the whole block in one call —
    // `KERN_PROCARGS2` will not report the size it needs — and the kernel
    // publishes its own ceiling for exactly this.
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut argmax: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the out-pointer and its length describe the same `c_int`.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            &mut argmax as *mut _ as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || argmax <= 0
    {
        return None;
    }

    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    let mut buf = vec![0u8; argmax as usize];
    let mut size = buf.len();
    // SAFETY: the out-pointer and its length describe the same allocation,
    // and `size` is updated to what was written.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    buf.truncate(size);
    procargs2(&buf)
}

/// Pull the argument vector out of a `KERN_PROCARGS2` block.
///
/// The layout is `argc`, then the executable path, then padding, then `argc`
/// NUL-terminated arguments, then the environment. Split out from the
/// syscall so the parsing can be tested against a block this process did not
/// have to arrange to exist — and so the environment, which follows the
/// arguments in the same block, is provably not searched: a variable a user
/// exported is not evidence of anything.
#[cfg(target_os = "macos")]
fn procargs2(buf: &[u8]) -> Option<Vec<String>> {
    let argc = u32::from_ne_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    let rest = buf.get(4..)?;
    // The executable path, then however many NULs pad it out to alignment.
    let mut at = rest.iter().position(|b| *b == 0)?;
    while rest.get(at) == Some(&0) {
        at += 1;
    }
    let mut args = Vec::with_capacity(argc.min(64));
    for _ in 0..argc {
        let Some(tail) = rest.get(at..) else { break };
        let end = at + tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
        args.push(String::from_utf8_lossy(&rest[at..end]).into_owned());
        at = end + 1;
    }
    Some(args)
}

#[cfg(target_os = "macos")]
fn look(pid: u32) -> Look {
    use std::os::unix::ffi::OsStringExt;

    if pid == 0 {
        return Look::NoSuchProcess;
    }
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let want = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is the struct PROC_PIDTBSDINFO is documented to fill,
    // and its size is passed by value.
    let got = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            want,
        )
    };
    if got != want {
        // Read before anything else can overwrite it: `errno` is what tells
        // the two failures apart, and they are opposite answers.
        let why = std::io::Error::last_os_error();
        if !exists(pid) {
            return Look::NoSuchProcess;
        }
        // A pid that answers `kill -0` and that `proc_pidinfo` says does not
        // exist is a zombie: the process table has the entry, there is no
        // process behind it. XNU refuses to describe one at all — the short
        // form declines too — so this is the only way to know, and it has to
        // be known: an exit status waiting to be collected is not a running
        // guest.
        if why.raw_os_error() == Some(libc::ESRCH) {
            return Look::Found(Probe {
                started_us: 0,
                boot_id: None,
                started_ticks: None,
                zombie: true,
                exec: None,
            });
        }
        // Anything else (EPERM, for a process belonging to another user) is
        // a live process this host will not describe. Its own answer, and
        // deliberately neither of the other two — see `Ownership::Unknown`.
        return Look::Unreadable(format!("proc_pidinfo on pid {pid}: {why}"));
    }

    let started_us = info
        .pbi_start_tvsec
        .saturating_mul(1_000_000)
        .saturating_add(info.pbi_start_tvusec);

    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buffer and length describe the same allocation.
    let len = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };
    let exec = (len > 0).then(|| {
        buf.truncate(len as usize);
        PathBuf::from(std::ffi::OsString::from_vec(buf))
    });

    Look::Found(Probe {
        started_us,
        boot_id: None,
        started_ticks: None,
        zombie: info.pbi_status == libc::SZOMB,
        exec,
    })
}

/// The command line a process was started with. See the macOS twin.
#[cfg(not(target_os = "macos"))]
fn argv(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    Some(
        raw.split(|b| *b == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8_lossy(arg).into_owned())
            .collect(),
    )
}

#[cfg(not(target_os = "macos"))]
fn look(pid: u32) -> Look {
    if pid == 0 {
        return Look::NoSuchProcess;
    }
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Look::NoSuchProcess,
        Err(e) => return Look::Unreadable(format!("reading /proc/{pid}/stat: {e}")),
    };
    let unreadable = || Look::Unreadable(format!("/proc/{pid}/stat is not in the shape expected"));
    // The second field is the executable name in parentheses and may contain
    // both spaces and parentheses, so everything is counted from the last
    // `)` rather than by splitting the whole line.
    let Some(close) = stat.rfind(')') else {
        return unreadable();
    };
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // `fields[0]` is field 3 (state), so field N is `fields[N - 3]`.
    let (Some(state), Some(ticks)) = (fields.first(), fields.get(19)) else {
        return unreadable();
    };
    let (Ok(started_ticks), Some(boot_us), Some(boot_id)) =
        (ticks.parse::<u64>(), boot_time_us(), linux_boot_id())
    else {
        return unreadable();
    };
    Look::Found(Probe {
        started_us: boot_us.saturating_add(started_ticks.saturating_mul(1_000_000) / hz()),
        boot_id: Some(boot_id),
        started_ticks: Some(started_ticks),
        zombie: *state == "Z",
        exec: std::fs::read_link(format!("/proc/{pid}/exe")).ok(),
    })
}

#[cfg(not(target_os = "macos"))]
fn linux_boot_id() -> Option<String> {
    Some(
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()?
            .trim()
            .to_owned(),
    )
}

/// Clock ticks per second, which is what `/proc/<pid>/stat` counts start
/// times in.
#[cfg(not(target_os = "macos"))]
fn hz() -> u64 {
    // SAFETY: a plain sysconf query with no arguments to get wrong.
    match unsafe { libc::sysconf(libc::_SC_CLK_TCK) } {
        n if n > 0 => n as u64,
        // The value POSIX has effectively frozen on Linux; better than a
        // division by zero if sysconf ever declines to answer.
        _ => 100,
    }
}

/// When this host booted, in microseconds since the epoch, so a start time
/// counted from boot can be turned into an absolute one.
#[cfg(not(target_os = "macos"))]
fn boot_time_us() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let btime: u64 = stat
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    Some(btime.saturating_mul(1_000_000))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    /// A process that has exec'd `sleep` and will stay there for the test.
    ///
    /// `Command::spawn` returns after the fork, before the child is
    /// necessarily past `exec`. Capturing its identity in that gap can record
    /// the test binary as the executable; once the child becomes `sleep`, the
    /// identity check correctly calls that a replacement. Wait for the
    /// fixture's actual executable before handing its pid to a test.
    fn sleeper() -> std::process::Child {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let deadline = Instant::now() + Duration::from_secs(5);

        let failure = loop {
            if let Ok(id) = ProcId::capture(pid) {
                let is_sleep = id
                    .exec
                    .as_deref()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == "sleep");
                if is_sleep && id.check().is_ours() {
                    return child;
                }
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    break format!("sleep fixture exited before readiness: {status}")
                }
                Ok(None) => {}
                Err(error) => break format!("checking sleep fixture {pid}: {error}"),
            }
            if Instant::now() >= deadline {
                break format!("sleep fixture {pid} did not exec within five seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        let _ = child.kill();
        let _ = child.wait();
        panic!("{failure}");
    }

    /// Wait for a child to exit while deliberately leaving its exit status in
    /// the process table.  `waitid` with `WNOWAIT` gives this test its needed
    /// ordering edge without consuming the very zombie it is about to
    /// inspect.
    fn wait_for_exit_without_reaping(child: &Child) {
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        loop {
            // SAFETY: `info` is valid writable storage, and `child.id()` is
            // the id of our direct child. `WNOWAIT` promises not to reap it.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if rc == 0 {
                return;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            panic!(
                "waiting for child {} to exit without reaping it: {error}",
                child.id()
            );
        }
    }

    #[test]
    fn our_own_process_is_ours() {
        let me = ProcId::capture(std::process::id()).unwrap();
        assert_eq!(me.check(), Ownership::Ours);
        assert!(me.alive());
        // The test binary is a real file, and this is how the platform half
        // is proven to have answered at all.
        assert!(me.exec.is_some(), "the executable path should be readable");
    }

    #[test]
    fn a_pid_that_was_never_there_is_gone() {
        // Pid 0 is the kernel's, and nothing Asterism spawns can be it.
        let nobody = ProcId {
            pid: 0,
            started_us: 1,
            boot_id: None,
            started_ticks: None,
            exec: None,
        };
        assert_eq!(nobody.check(), Ownership::Gone);
        assert!(!nobody.alive());
        assert!(!nobody.signal(Signal::Kill).unwrap(), "nothing to signal");
    }

    /// The defect this module exists for: a handle that outlived its process
    /// and now names somebody else's. `kill -0` answers *running* here.
    #[test]
    fn a_recycled_pid_is_foreign_and_is_never_signalled() {
        let mut child = sleeper();
        let real = ProcId::capture(child.id()).unwrap();

        // Same pid, a start instant it never had: what a stale handle looks
        // like once the number has been handed out again.
        let mut stale = real.clone();
        if let Some(ticks) = stale.started_ticks.as_mut() {
            *ticks -= 1;
        } else {
            stale.started_us -= 1;
        }
        assert!(matches!(stale.check(), Ownership::Foreign(_)));
        assert!(!stale.alive());

        let refused = stale.signal(Signal::Kill).unwrap_err().to_string();
        assert!(refused.contains("refusing"), "{refused}");
        assert!(refused.contains("recycled"), "{refused}");
        // And the process is still there, which is the whole point.
        assert!(real.alive());

        let _ = child.kill();
        let _ = child.wait();
    }

    /// Start time survives `exec`, so a process that replaced its binary
    /// keeps it. The path is what catches that.
    #[test]
    fn a_replaced_executable_is_foreign() {
        let me = ProcId::capture(std::process::id()).unwrap();
        let swapped = ProcId {
            exec: Some(PathBuf::from("/bin/somebody-else")),
            ..me
        };
        assert!(matches!(swapped.check(), Ownership::Foreign(_)));
        assert!(swapped.signal(Signal::Term).is_err());
    }

    #[test]
    fn a_process_that_exits_stops_being_ours() {
        let mut child = sleeper();
        let id = ProcId::capture(child.id()).unwrap();
        assert!(id.alive());

        assert!(id.signal(Signal::Kill).unwrap(), "delivered");
        // Reaped, so the pid is not a zombie holding an exit status.
        let _ = child.wait();
        assert!(id.wait_gone(Duration::from_secs(5)));
        assert_eq!(id.check(), Ownership::Gone);
        assert!(!id.signal(Signal::Kill).unwrap(), "nothing left to signal");
    }

    /// An unreaped child answers `kill -0`, which is why the vz backend had
    /// to reap one merely to keep liveness honest. The kernel's own process
    /// state says what it is.
    #[test]
    fn a_zombie_is_gone_not_running() {
        let mut child = sleeper();
        let id = ProcId::capture(child.id()).unwrap();
        assert!(id.signal(Signal::Kill).unwrap(), "delivered");
        wait_for_exit_without_reaping(&child);
        // Deliberately not waited for: the pid is now an exit status.
        assert_eq!(
            id.check(),
            Ownership::Gone,
            "an unreaped exit is not a running guest"
        );
        // `kill -0`, the old test, would have said this was alive.
        let answers_kill_zero = unsafe { libc::kill(id.pid as libc::pid_t, 0) } == 0;
        assert!(
            answers_kill_zero,
            "and this is exactly what used to be believed"
        );
        let _ = child.wait();
    }

    #[test]
    fn capture_refuses_a_pid_with_nothing_behind_it() {
        assert!(ProcId::capture(0).is_err());
    }

    // ---- what each answer authorises ---------------------------------------
    //
    // `Unknown` is the one worth pinning down, because the two questions a
    // caller asks it have opposite safe defaults and the kernel is not going
    // to produce the answer on demand. `against` takes what the kernel said,
    // so each verdict can be asserted on directly.

    fn found(started_us: u64) -> Look {
        Look::Found(Probe {
            started_us,
            boot_id: None,
            started_ticks: None,
            zombie: false,
            exec: None,
        })
    }

    #[test]
    fn a_process_the_kernel_will_not_describe_is_neither_dead_nor_ours() {
        let id = ProcId {
            pid: 4242,
            started_us: 7,
            boot_id: None,
            started_ticks: None,
            exec: None,
        };
        let unknown = id.against(Look::Unreadable("no answer".into()));

        assert!(matches!(unknown, Ownership::Unknown(_)));
        // Not proof of ownership: nothing may be signalled on this.
        assert!(!unknown.is_ours());
        // And not proof of death either: a guest is not declared dead, and
        // therefore not restarted onto its own disk, because one call to the
        // process table came back empty-handed.
        assert!(!unknown.is_ended());
    }

    #[test]
    fn every_other_answer_is_settled_one_way_or_the_other() {
        let id = ProcId {
            pid: 4242,
            started_us: 7,
            boot_id: None,
            started_ticks: None,
            exec: None,
        };

        assert_eq!(id.against(found(7)), Ownership::Ours);
        assert!(id.against(found(7)).is_ours());

        assert_eq!(id.against(Look::NoSuchProcess), Ownership::Gone);
        assert!(id.against(Look::NoSuchProcess).is_ended());

        // A recycled number: settled, and settled as *not ours*.
        let recycled = id.against(found(8));
        assert!(matches!(recycled, Ownership::Foreign(_)));
        assert!(!recycled.is_ours());
        assert!(recycled.is_ended());

        // A zombie is an exit status, not a running program.
        let zombie = id.against(Look::Found(Probe {
            started_us: 7,
            boot_id: None,
            started_ticks: None,
            zombie: true,
            exec: None,
        }));
        assert_eq!(zombie, Ownership::Gone);
    }

    #[test]
    fn linux_identity_does_not_move_when_the_wall_clock_steps() {
        let id = ProcId {
            pid: 4242,
            started_us: 100,
            boot_id: Some("this-boot".into()),
            started_ticks: Some(700),
            exec: None,
        };
        let after_clock_step = Look::Found(Probe {
            started_us: 3_000_100,
            boot_id: Some("this-boot".into()),
            started_ticks: Some(700),
            zombie: false,
            exec: None,
        });

        assert_eq!(id.against(after_clock_step), Ownership::Ours);
        assert!(matches!(
            id.against(Look::Found(Probe {
                started_us: 100,
                boot_id: Some("another-boot".into()),
                started_ticks: Some(700),
                zombie: false,
                exec: None,
            })),
            Ownership::Foreign(_)
        ));
    }

    /// An identity that names no executable matches whatever is running —
    /// there is nothing to compare — and one that does is held to it.
    #[test]
    fn the_executable_is_compared_only_when_both_sides_name_one() {
        let bare = ProcId {
            pid: 1,
            started_us: 7,
            boot_id: None,
            started_ticks: None,
            exec: None,
        };
        let running = Look::Found(Probe {
            started_us: 7,
            boot_id: None,
            started_ticks: None,
            zombie: false,
            exec: Some(PathBuf::from("/usr/bin/anything")),
        });
        assert_eq!(bare.against(running), Ownership::Ours);

        let named = ProcId {
            exec: Some(PathBuf::from("/bin/qemu")),
            ..bare
        };
        assert!(matches!(
            named.against(Look::Found(Probe {
                started_us: 7,
                boot_id: None,
                started_ticks: None,
                zombie: false,
                exec: Some(PathBuf::from("/bin/something-else")),
            })),
            Ownership::Foreign(_)
        ));
    }

    /// Neither `capture` nor `adopt` will invent an identity out of a
    /// process the kernel would not describe.
    #[test]
    fn an_undescribable_process_is_never_written_down() {
        // The real path: pid 0 is not a process any of this can name.
        assert!(ProcId::capture(0).is_err());
        let ctl = PathBuf::from("/tmp/asterism-adopt-test/instances/dev/qmp.sock");
        assert!(ProcId::adopt(
            0,
            crate::instance::now_unix(),
            &Evidence {
                exec: &["anything"],
                names: &[&ctl]
            }
        )
        .is_err());
    }

    // ---- adoption ----------------------------------------------------------
    //
    // Adoption is the one place authority is minted from something other
    // than having started the process, so these are about what is and is not
    // allowed to mint it.

    /// A process holding a path, the way a guest's qemu holds its monitor:
    /// on its own command line, where the kernel recorded it.
    ///
    /// `sleep 30 <path>` is not a fixture: GNU sleep treats the path as an
    /// invalid second duration and exits immediately, while other sleep
    /// implementations disagree about extra operands. The shell keeps the
    /// path as its own argument while its short-lived `sleep` child receives
    /// only a valid duration, which works with BSD and GNU `sleep`.
    ///
    /// `Command::spawn` returns before its child has necessarily exec'd. Do
    /// not capture the fixture until the kernel reports both the resolved
    /// shell executable and the instance-owned marker in its argv.
    fn holder(path: &Path) -> (Child, String) {
        // Use the concrete shell binary rather than /bin/sh: on macOS the
        // latter can hand off to bash after the first process-table sample,
        // which would correctly look like an executable replacement.
        let mut child = Command::new("/bin/bash")
            .args(["-c", "while :; do sleep 1; done", "asterism-proc-fixture"])
            .arg(path)
            .spawn()
            .unwrap();
        let pid = child.id();
        let shell = std::fs::canonicalize("/bin/bash")
            .expect("the portable shell fixture should resolve its executable");
        let marker = path.to_string_lossy().into_owned();
        let deadline = Instant::now() + Duration::from_secs(5);

        let failure = loop {
            if let Ok(id) = ProcId::capture(pid) {
                let is_shell = id.exec.as_deref() == Some(shell.as_path());
                let holds_marker =
                    argv(pid).is_some_and(|args| args.iter().any(|arg| arg == &marker));
                if is_shell && holds_marker && id.check().is_ours() {
                    let exec = id
                        .exec
                        .as_deref()
                        .and_then(Path::file_name)
                        .and_then(|name| name.to_str())
                        .expect("the fixture executable should have a UTF-8 name")
                        .to_owned();
                    return (child, exec);
                }
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    break format!("adoption fixture exited before readiness: {status}")
                }
                Ok(None) => {}
                Err(error) => break format!("checking adoption fixture {pid}: {error}"),
            }
            if Instant::now() >= deadline {
                break format!(
                    "adoption fixture {pid} did not exec with its instance-owned argv marker within five seconds"
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        let _ = child.kill();
        let _ = child.wait();
        panic!("{failure}");
    }

    fn evidence<'a>(exec: &'a [&'a str], names: &'a [&'a Path]) -> Evidence<'a> {
        Evidence { exec, names }
    }

    #[test]
    fn adoption_takes_a_process_carrying_something_only_this_instance_owns() {
        let ctl = PathBuf::from("/tmp/asterism-adopt-test/instances/dev/qmp.sock");
        let (mut child, exec) = holder(&ctl);
        let now = crate::instance::now_unix();

        let adopted = ProcId::adopt(child.id(), now, &evidence(&[exec.as_str()], &[&ctl])).unwrap();
        assert_eq!(adopted.pid, child.id());
        assert!(adopted.alive());

        let _ = child.kill();
        let _ = child.wait();
    }

    /// The regression this whole gate exists for.
    ///
    /// Everything a pre-identity handle can say about its guest is satisfied
    /// here by a process that is not it: the pid matches (it is the pid we
    /// are adopting), the executable is the right family, and it started
    /// half a minute after the handle was written — inside any slack a
    /// timestamp comparison could reasonably allow. Before instance-bound
    /// evidence, that was enough to adopt, and adopting it is what would
    /// have pointed `stop` and `kill` at somebody else's VM.
    #[test]
    fn a_foreign_qemu_started_after_the_handle_is_neither_adopted_nor_killable() {
        // What the handle recorded, and where its guest's monitor was.
        let ours = PathBuf::from("/tmp/asterism-adopt-test/instances/ours/qmp.sock");
        let legacy_started_at = crate::instance::now_unix();

        // Somebody else's qemu, started 30s later, serving its own instance.
        // The shell stands in for the binary; the executable family is checked
        // separately and is not what this test turns on.
        let theirs = PathBuf::from("/tmp/asterism-adopt-test/instances/theirs/qmp.sock");
        let (mut foreign, exec) = holder(&theirs);
        let started_30s_later = legacy_started_at + 30;

        let why = ProcId::adopt(
            foreign.id(),
            started_30s_later,
            &evidence(&[exec.as_str()], &[&ours]),
        )
        .unwrap_err();
        assert!(
            why.contains("not started for this instance"),
            "the timestamp window must not be what decides this: {why}"
        );

        // ...and having refused to adopt it, there is no identity to signal
        // it with. The only way to reach `signal` is to have been handed a
        // `ProcId`, and adoption is the only way a migration can produce one.
        let real = ProcId::capture(foreign.id()).unwrap();
        assert!(real.alive(), "the foreign qemu is untouched");

        // Even a hand-built identity naming that pid does not help if it is
        // not the process that was recorded: the number is the only thing it
        // shares, and that is not what `signal` checks.
        let mut forged = real.clone();
        if let Some(ticks) = forged.started_ticks.as_mut() {
            *ticks -= 1;
        } else {
            forged.started_us -= 1;
        }
        assert!(forged.signal(Signal::Kill).is_err());
        assert!(real.alive(), "still untouched");

        let _ = foreign.kill();
        let _ = foreign.wait();
    }

    /// The same shape for the vz helper: a second helper, started for
    /// another instance, half a minute after this handle was written.
    #[test]
    fn a_foreign_vz_helper_started_after_the_handle_is_not_adopted() {
        let ours = PathBuf::from("/tmp/asterism-adopt-test/instances/ours/vz.json");
        let theirs = PathBuf::from("/tmp/asterism-adopt-test/instances/theirs/vz.json");
        let (mut foreign, exec) = holder(&theirs);

        let why = ProcId::adopt(
            foreign.id(),
            crate::instance::now_unix() + 30,
            &evidence(&[exec.as_str()], &[&ours]),
        )
        .unwrap_err();
        assert!(why.contains("not started for this instance"), "{why}");

        let _ = foreign.kill();
        let _ = foreign.wait();
    }

    /// One instance's name being a prefix of another's is the trap a
    /// directory-shaped needle would fall into. These are files.
    #[test]
    fn a_neighbouring_instance_is_not_this_one() {
        let ours = PathBuf::from("/tmp/asterism-adopt-test/instances/dev/qmp.sock");
        let neighbour = PathBuf::from("/tmp/asterism-adopt-test/instances/dev2/qmp.sock");
        let (mut foreign, exec) = holder(&neighbour);

        assert!(ProcId::adopt(
            foreign.id(),
            crate::instance::now_unix(),
            &evidence(&[exec.as_str()], &[&ours])
        )
        .is_err());

        let _ = foreign.kill();
        let _ = foreign.wait();
    }

    /// Offering no evidence is not a lax adoption. It is a refused one, and
    /// it is refused before the process is even looked at — so no caller can
    /// reach authority by having nothing to say.
    #[test]
    fn adoption_without_evidence_is_refused_outright() {
        let mut child = sleeper();
        let why = ProcId::adopt(
            child.id(),
            crate::instance::now_unix(),
            &evidence(&["sleep"], &[]),
        )
        .unwrap_err();
        assert!(why.contains("refusing to adopt"), "{why}");
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn adoption_refuses_a_process_running_something_else() {
        let ctl = PathBuf::from("/tmp/asterism-adopt-test/instances/dev/qmp.sock");
        let (mut child, _exec) = holder(&ctl);
        let now = crate::instance::now_unix();
        let why =
            ProcId::adopt(child.id(), now, &evidence(&["qemu-system-*"], &[&ctl])).unwrap_err();
        assert!(why.contains("not qemu-system-*"), "{why}");
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The recycled-pid case as it actually arrives: the handle is old, the
    /// process at that number is new. Refused early, and refused for a
    /// reason that is a refusal rather than a licence.
    #[test]
    fn adoption_refuses_a_process_that_started_after_the_handle() {
        let ctl = PathBuf::from("/tmp/asterism-adopt-test/instances/dev/qmp.sock");
        let (mut child, exec) = holder(&ctl);
        let long_ago = crate::instance::now_unix() - 3600;
        let why =
            ProcId::adopt(child.id(), long_ago, &evidence(&[exec.as_str()], &[&ctl])).unwrap_err();
        assert!(why.contains("different process"), "{why}");
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn adoption_refuses_a_pid_with_nothing_behind_it() {
        let ctl = PathBuf::from("/tmp/asterism-adopt-test/instances/dev/qmp.sock");
        assert!(ProcId::adopt(
            0,
            crate::instance::now_unix(),
            &evidence(&["sleep"], &[&ctl])
        )
        .is_err());
    }

    /// The command line is read from the kernel, and only the arguments are
    /// read: the environment sits in the same block on macOS, and a variable
    /// somebody exported is not evidence of anything.
    #[test]
    fn a_command_line_is_read_from_the_kernel_and_the_environment_is_not() {
        let me = argv(std::process::id()).expect("this host names its own command line");
        assert!(!me.is_empty(), "argv is never empty");
        assert!(
            me[0].contains("asterism_core"),
            "the first argument is this test binary: {me:?}"
        );

        let marker = "ASTERISM_PROC_TEST_MARKER";
        std::env::set_var(marker, "/tmp/asterism-adopt-test/instances/dev/qmp.sock");
        let mine = argv(std::process::id()).unwrap();
        std::env::remove_var(marker);
        assert!(
            !mine.iter().any(|arg| arg.contains(marker)),
            "the environment must not reach the argument list: {mine:?}"
        );
    }

    #[test]
    fn a_trailing_star_matches_a_family_of_binaries() {
        assert!(matches_any(
            Path::new("/opt/homebrew/bin/qemu-system-aarch64"),
            &["qemu-system-*"]
        ));
        assert!(matches_any(
            Path::new("/usr/local/bin/qemu-system-x86_64"),
            &["qemu-system-*"]
        ));
        assert!(!matches_any(
            Path::new("/usr/bin/qemu-img"),
            &["qemu-system-*"]
        ));
        assert!(matches_any(Path::new("/x/astd-vz"), &["astd-vz"]));
        assert!(!matches_any(Path::new("/x/astd-vz-old"), &["astd-vz"]));
    }

    #[test]
    fn an_identity_round_trips_through_the_registry_format() {
        let id = ProcId {
            pid: 4242,
            started_us: 1_700_000_000_123_456,
            boot_id: Some("boot-a".into()),
            started_ticks: Some(1234),
            exec: Some(PathBuf::from("/opt/homebrew/bin/qemu-system-aarch64")),
        };
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(id, serde_json::from_str::<ProcId>(&json).unwrap());
        // An identity from a platform that would not name the executable is
        // still readable, and matches anything on that field.
        let bare: ProcId = serde_json::from_str(r#"{"pid":1,"started_us":2}"#).unwrap();
        assert_eq!(bare.exec, None);
    }
}
