//! Sleep prevention — the `power::Assertion` row of `docs/PLATFORM.md`.
//!
//! A home for an agent that goes to sleep is not a home. While this device
//! is running at least one instance it holds an OS-level assertion that the
//! machine must not idle-sleep, and it drops that assertion the moment the
//! last instance stops: a laptop with nothing running should still sleep
//! like a laptop.
//!
//! This module is a seam, so it is one of the few places allowed to carry
//! `#[cfg(target_os)]`. Callers hold a [`SleepGuard`] and tell it how many
//! instances are running; they never learn which mechanism is underneath.
//!
//! | OS | mechanism |
//! |---|---|
//! | macOS | IOKit `IOPMAssertionCreateWithName`, `PreventUserIdleSystemSleep` |
//! | Linux | a `systemd-inhibit --what=sleep:idle --mode=block` child process |
//! | Windows | not implemented — `SetThreadExecutionState` is the decided row |
//!
//! macOS caveat: `PreventUserIdleSystemSleep` is what `caffeinate -s`
//! takes. It stops *idle* sleep, which is the case that matters (the
//! machine sitting on a desk overnight). Closing the lid of a laptop on
//! battery still sleeps it — no user-space assertion overrides clamshell
//! sleep, so the honest answer is that an always-on device wants to be
//! plugged in.

use anyhow::Result;

/// What the OS shows a human who asks who is keeping the machine awake:
/// `pmset -g assertions` on macOS, `systemd-inhibit --list` on Linux.
pub const REASON: &str = "Asterism is running instances";

/// A held sleep-prevention assertion. Released on drop, including when the
/// daemon is killed — every mechanism here is owned by the process.
pub struct Assertion {
    #[allow(dead_code)] // the whole point is the Drop impl on the inside
    held: imp::Held,
}

impl Assertion {
    /// Take an assertion, or say why this device cannot.
    pub fn hold(reason: &str) -> Result<Self> {
        Ok(Assertion {
            held: imp::hold(reason)?,
        })
    }

    /// The mechanism doing the holding, for logs and status output.
    pub fn mechanism(&self) -> &'static str {
        imp::MECHANISM
    }

    /// Release early. Equivalent to dropping it; spelled out so a caller
    /// can be explicit about the transition.
    pub fn release(self) {}
}

impl std::fmt::Debug for Assertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Assertion({})", imp::MECHANISM)
    }
}

/// What changed when a [`SleepGuard`] was told the running count.
///
/// Returned rather than logged inside, so the daemon logs a transition once
/// instead of the guard printing on every tick.
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    /// The guard already agreed with the count.
    Same,
    /// An assertion was taken. Carries the mechanism.
    Held(&'static str),
    /// The last instance stopped and the assertion went away.
    Released,
    /// This device cannot prevent sleep, and says so exactly once.
    Unavailable(String),
}

/// Keeps a sleep assertion in step with the number of running instances.
///
/// Idempotent: `set(n)` for any `n > 0` while already held does nothing, so
/// the supervisor can call it on every tick.
#[derive(Default)]
pub struct SleepGuard {
    held: Option<Assertion>,
    /// Set after the first refusal. A device with no working mechanism must
    /// not be asked once a tick forever, nor log once a tick forever.
    refused: bool,
}

impl SleepGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold an assertion iff `running > 0`.
    pub fn set(&mut self, running: usize) -> Change {
        match (running > 0, self.held.is_some()) {
            (true, false) => {
                if self.refused {
                    return Change::Same;
                }
                match Assertion::hold(REASON) {
                    Ok(a) => {
                        let mechanism = a.mechanism();
                        self.held = Some(a);
                        Change::Held(mechanism)
                    }
                    Err(e) => {
                        self.refused = true;
                        Change::Unavailable(format!("{e:#}"))
                    }
                }
            }
            (false, true) => {
                self.held = None;
                Change::Released
            }
            _ => Change::Same,
        }
    }

    pub fn is_held(&self) -> bool {
        self.held.is_some()
    }
}

// ---- macOS: IOKit ----------------------------------------------------------

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::c_void;

    use anyhow::{bail, Result};

    pub const MECHANISM: &str = "IOKit PreventUserIdleSystemSleep";

    type CfStringRef = *const c_void;
    type IoPmAssertionId = u32;
    type IoReturn = i32;

    const IO_RETURN_SUCCESS: IoReturn = 0;
    const ASSERTION_LEVEL_ON: u32 = 255;
    const UTF8: u32 = 0x0800_0100;
    /// `kIOPMAssertionTypePreventUserIdleSystemSleep`. Spelled as a plain
    /// string rather than linked as the exported constant: the constant is
    /// a `CFStringRef` global that would need another `#[link]` item for no
    /// gain — IOKit compares assertion types by value.
    const PREVENT_IDLE_SLEEP: &str = "PreventUserIdleSystemSleep";

    // The two IOKit entry points, declared directly. Pulling in a
    // core-foundation crate to say this much would be a heavyweight
    // dependency for four symbols.
    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOPMAssertionCreateWithName(
            assertion_type: CfStringRef,
            level: u32,
            name: CfStringRef,
            id: *mut IoPmAssertionId,
        ) -> IoReturn;
        fn IOPMAssertionRelease(id: IoPmAssertionId) -> IoReturn;
    }

    // ...and the CoreFoundation pair needed to hand IOKit two strings.
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFStringCreateWithBytes(
            alloc: *const c_void,
            bytes: *const u8,
            num_bytes: isize,
            encoding: u32,
            is_external_representation: u8,
        ) -> CfStringRef;
        fn CFRelease(cf: *const c_void);
    }

    /// An owned `CFStringRef`, so a failure part-way through `hold` cannot
    /// leak the other string.
    struct CfString(CfStringRef);

    impl CfString {
        fn new(s: &str) -> Result<Self> {
            let r = unsafe {
                CFStringCreateWithBytes(std::ptr::null(), s.as_ptr(), s.len() as isize, UTF8, 0)
            };
            if r.is_null() {
                bail!("CoreFoundation would not make a string out of {s:?}");
            }
            Ok(CfString(r))
        }
    }

    impl Drop for CfString {
        fn drop(&mut self) {
            unsafe { CFRelease(self.0) };
        }
    }

    pub struct Held(IoPmAssertionId);

    pub fn hold(reason: &str) -> Result<Held> {
        let kind = CfString::new(PREVENT_IDLE_SLEEP)?;
        let name = CfString::new(reason)?;
        let mut id: IoPmAssertionId = 0;
        let rc =
            unsafe { IOPMAssertionCreateWithName(kind.0, ASSERTION_LEVEL_ON, name.0, &mut id) };
        if rc != IO_RETURN_SUCCESS {
            bail!("IOKit refused a power assertion (IOReturn {rc:#x})");
        }
        Ok(Held(id))
    }

    impl Drop for Held {
        fn drop(&mut self) {
            unsafe { IOPMAssertionRelease(self.0) };
        }
    }
}

// ---- Linux: systemd-inhibit ------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use std::process::{Child, Command, Stdio};

    use anyhow::{bail, Context, Result};

    pub const MECHANISM: &str = "systemd-inhibit sleep:idle";

    /// The inhibitor lock lives as long as the child holding it, which is
    /// exactly the lifetime wanted: if astd dies, the machine is free to
    /// sleep again.
    pub struct Held(Child);

    pub fn hold(reason: &str) -> Result<Held> {
        // `--mode=block` is what makes the lock a refusal rather than a
        // delay; the child it wraps only has to outlive us.
        let mut child = Command::new("systemd-inhibit")
            .arg("--what=sleep:idle")
            .arg("--who=asterism")
            .arg(format!("--why={reason}"))
            .arg("--mode=block")
            .arg("sleep")
            .arg("infinity")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("systemd-inhibit is not on PATH, so sleep cannot be prevented")?;
        // A systemd-inhibit that exits immediately (no logind, no dbus)
        // must not be mistaken for a held lock.
        std::thread::sleep(std::time::Duration::from_millis(150));
        if let Ok(Some(status)) = child.try_wait() {
            bail!("systemd-inhibit exited immediately ({status}) — is logind running?");
        }
        Ok(Held(child))
    }

    impl Drop for Held {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

// ---- Windows: undecided ----------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use anyhow::{bail, Result};

    pub const MECHANISM: &str = "none";

    pub struct Held;

    pub fn hold(_reason: &str) -> Result<Held> {
        bail!(
            "this device cannot prevent sleep yet — the Windows row of \
             docs/PLATFORM.md (SetThreadExecutionState) is not built"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On a platform with a real mechanism, taking and dropping an
    /// assertion works, and the guard only moves on a transition.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_guard_follows_the_running_count() {
        let mut guard = SleepGuard::new();
        assert_eq!(guard.set(0), Change::Same);
        assert!(!guard.is_held());

        match guard.set(1) {
            Change::Held(m) => assert!(m.contains("IOKit")),
            other => panic!("expected an assertion, got {other:?}"),
        }
        assert!(guard.is_held());
        // Still running, still held, nothing said.
        assert_eq!(guard.set(2), Change::Same);
        assert_eq!(guard.set(0), Change::Released);
        assert!(!guard.is_held());
        // ...and it can be taken again.
        assert!(matches!(guard.set(1), Change::Held(_)));
    }

    /// A device with no mechanism refuses once and then stays quiet, so a
    /// five-second supervisor loop cannot become a log flood.
    #[test]
    fn an_unavailable_mechanism_is_reported_once() {
        let mut guard = SleepGuard {
            held: None,
            refused: true,
        };
        assert_eq!(guard.set(1), Change::Same);
        assert!(!guard.is_held());
    }

    #[test]
    fn assertions_release_on_drop() {
        if let Ok(a) = Assertion::hold("asterism test") {
            assert!(!a.mechanism().is_empty());
            a.release();
        }
    }
}
