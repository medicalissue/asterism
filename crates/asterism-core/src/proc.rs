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

/// How far after a recorded `started_at` a process may have started and
/// still be believed to be the one that was recorded.
///
/// One-directional, and that is the point. A handle's `started_at` is
/// written *after* the process is up — for vz, after the guest has booted,
/// which can be minutes — so a genuine process may have started well before
/// it. A recycled pid cannot: it belongs to a process that started after the
/// original died, which is after the handle was written. The slack absorbs
/// clock jitter between the kernel's stamp and `now_unix()`, nothing more.
const ADOPT_SLACK_SECS: u64 = 60;

impl ProcId {
    /// Capture the identity of a running process.
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
            exec: probe.exec,
        })
    }

    /// Mint an identity for a pid recorded before identities existed.
    ///
    /// The explicit half of the migration: a `pid` on disk is not evidence,
    /// so it is only believed when the process at that number passes three
    /// tests — it is not a zombie, it did not start after the handle that
    /// names it was written, and it is running a program the caller expects.
    /// Anything else reads as gone, which is the safe direction: a guest
    /// wrongly believed dead is restarted, a guest wrongly believed alive is
    /// a SIGKILL aimed at a stranger.
    ///
    /// `expect` is matched against the executable's file name, not its full
    /// path, so upgrading qemu under a running guest does not orphan it.
    pub fn adopt(pid: u32, started_at: u64, expect: &[&str]) -> std::result::Result<ProcId, String> {
        let probe = match look(pid) {
            Look::Found(probe) => probe,
            Look::NoSuchProcess => return Err(format!("no process {pid}")),
            Look::Unreadable(why) => {
                return Err(format!("this host will not say what process {pid} is: {why}"))
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
        let Some(exec) = &probe.exec else {
            return Err(format!(
                "this platform will not say what process {pid} is running, so it cannot \
                 be adopted"
            ));
        };
        if !matches_any(exec, expect) {
            return Err(format!(
                "process {pid} is running {}, not {}",
                exec.display(),
                expect.join(" or ")
            ));
        }
        Ok(ProcId {
            pid,
            started_us: probe.started_us,
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
        if probe.started_us != self.started_us {
            return Ownership::Foreign(format!(
                "pid {} started at {}, not at {} — the number was recycled",
                self.pid, probe.started_us, self.started_us
            ));
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
            return Look::Found(Probe { started_us: 0, zombie: true, exec: None });
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
        zombie: info.pbi_status == libc::SZOMB,
        exec,
    })
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
    let Some(close) = stat.rfind(')') else { return unreadable() };
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // `fields[0]` is field 3 (state), so field N is `fields[N - 3]`.
    let (Some(state), Some(ticks)) = (fields.first(), fields.get(19)) else {
        return unreadable();
    };
    let (Ok(started_ticks), Some(boot_us)) = (ticks.parse::<u64>(), boot_time_us()) else {
        return unreadable();
    };
    Look::Found(Probe {
        started_us: boot_us.saturating_add(started_ticks.saturating_mul(1_000_000) / hz()),
        zombie: *state == "Z",
        exec: std::fs::read_link(format!("/proc/{pid}/exe")).ok(),
    })
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
    use std::process::Command;

    /// A process that is definitely there for the length of the test.
    fn sleeper() -> std::process::Child {
        Command::new("sleep").arg("30").spawn().unwrap()
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
        let nobody = ProcId { pid: 0, started_us: 1, exec: None };
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
        let stale = ProcId { started_us: real.started_us - 1, ..real.clone() };
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
        let swapped = ProcId { exec: Some(PathBuf::from("/bin/somebody-else")), ..me };
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
        let mut child = Command::new("true").spawn().unwrap();
        let id = ProcId::capture(child.id()).unwrap();
        // Deliberately not waited for: the pid is now an exit status.
        let deadline = Instant::now() + Duration::from_secs(5);
        while id.check() != Ownership::Gone && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(id.check(), Ownership::Gone, "an unreaped exit is not a running guest");
        // `kill -0`, the old test, would have said this was alive.
        let answers_kill_zero = unsafe { libc::kill(id.pid as libc::pid_t, 0) } == 0;
        assert!(answers_kill_zero, "and this is exactly what used to be believed");
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
        Look::Found(Probe { started_us, zombie: false, exec: None })
    }

    #[test]
    fn a_process_the_kernel_will_not_describe_is_neither_dead_nor_ours() {
        let id = ProcId { pid: 4242, started_us: 7, exec: None };
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
        let id = ProcId { pid: 4242, started_us: 7, exec: None };

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
            zombie: true,
            exec: None,
        }));
        assert_eq!(zombie, Ownership::Gone);
    }

    /// An identity that names no executable matches whatever is running —
    /// there is nothing to compare — and one that does is held to it.
    #[test]
    fn the_executable_is_compared_only_when_both_sides_name_one() {
        let bare = ProcId { pid: 1, started_us: 7, exec: None };
        let running = Look::Found(Probe {
            started_us: 7,
            zombie: false,
            exec: Some(PathBuf::from("/usr/bin/anything")),
        });
        assert_eq!(bare.against(running), Ownership::Ours);

        let named = ProcId { exec: Some(PathBuf::from("/bin/qemu")), ..bare };
        assert!(matches!(
            named.against(Look::Found(Probe {
                started_us: 7,
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
        assert!(ProcId::adopt(0, crate::instance::now_unix(), &["anything"]).is_err());
    }

    // ---- adoption ----------------------------------------------------------

    #[test]
    fn adoption_takes_a_live_process_running_what_was_expected() {
        let mut child = sleeper();
        let now = crate::instance::now_unix();
        let adopted = ProcId::adopt(child.id(), now, &["sleep"]).unwrap();
        assert_eq!(adopted.pid, child.id());
        assert!(adopted.alive());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn adoption_refuses_a_process_running_something_else() {
        let mut child = sleeper();
        let now = crate::instance::now_unix();
        let why = ProcId::adopt(child.id(), now, &["qemu-system-*"]).unwrap_err();
        assert!(why.contains("sleep"), "{why}");
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The recycled-pid case as it actually arrives: the handle is old, the
    /// process at that number is new.
    #[test]
    fn adoption_refuses_a_process_that_started_after_the_handle() {
        let mut child = sleeper();
        let long_ago = crate::instance::now_unix() - 3600;
        let why = ProcId::adopt(child.id(), long_ago, &["sleep"]).unwrap_err();
        assert!(why.contains("different process"), "{why}");
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn adoption_refuses_a_pid_with_nothing_behind_it() {
        assert!(ProcId::adopt(0, crate::instance::now_unix(), &["sleep"]).is_err());
    }

    #[test]
    fn a_trailing_star_matches_a_family_of_binaries() {
        assert!(matches_any(Path::new("/opt/homebrew/bin/qemu-system-aarch64"), &["qemu-system-*"]));
        assert!(matches_any(Path::new("/usr/local/bin/qemu-system-x86_64"), &["qemu-system-*"]));
        assert!(!matches_any(Path::new("/usr/bin/qemu-img"), &["qemu-system-*"]));
        assert!(matches_any(Path::new("/x/astd-vz"), &["astd-vz"]));
        assert!(!matches_any(Path::new("/x/astd-vz-old"), &["astd-vz"]));
    }

    #[test]
    fn an_identity_round_trips_through_the_registry_format() {
        let id = ProcId {
            pid: 4242,
            started_us: 1_700_000_000_123_456,
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
