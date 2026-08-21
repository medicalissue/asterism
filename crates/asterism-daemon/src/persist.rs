//! Persistence: the part that makes "your agent's home never sleeps"
//! literally true.
//!
//! Three jobs, all of them about a guest that should be running and is not:
//!
//! 1. **Resurrection.** When astd starts, an instance the registry records
//!    as running whose process is gone is booted again ([`resurrect`]).
//!    That is the host-reboot case: the user left it up, the machine
//!    restarted, nobody typed anything, and the instance should be back.
//! 2. **Crash restart.** While astd runs, a supervisor ([`supervise`])
//!    notices a guest that died mid-session and restarts it on a backoff
//!    of 5s, 30s, 2m — then gives up, marks the instance stopped, and
//!    writes *why* to the instance's console log and the daemon's log.
//!    A guest that dies instantly on every boot must not become a restart
//!    loop that hammers the disk forever.
//!
//!    Whether it comes back at all is the instance's own
//!    `Instance::policy` — set with `ast up --restart`, shown by
//!    `ast status`, and read here rather than from a file this module used
//!    to keep beside the instance.
//! 3. **Staying awake.** While anything is running (or is between
//!    restarts) the device holds a [`power`] assertion, and drops it when
//!    the last instance stops.
//!
//! ### Startup and steady state are different
//!
//! `reconcile` in `main.rs` flips a running-with-a-dead-process instance to
//! stopped, which is the truth *right now* and stays that way: `ast ls`
//! must never claim a guest is up when it is not. What changes here is
//! what happens next. Before flipping anything, reconcile calls
//! [`note_died`], which hands the instance to this module — so the status
//! tells the truth and the supervisor still brings the guest back. At
//! startup [`resurrect`] runs first, holding the registry lock, so nothing
//! can be reconciled out from under it.
//!
//! ### Why a process-wide watch table
//!
//! Deaths are noticed in two places — the supervisor's own tick, and
//! reconcile, which runs on any request from any connection and has no
//! path to a supervisor handle. Threading one through every request would
//! mean touching the registry and protocol modules for what is bookkeeping
//! about processes, not about instances. So the watches live here, in one
//! table, owned by the module that acts on them.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use asterism_core::hv::{Hypervisor, RunState};
use asterism_core::instance::{Instance, Restart, Status};
use asterism_core::paths;
use asterism_core::power::{Change, SleepGuard};
use asterism_core::registry::Shard;

use crate::backend;

/// How often the supervisor looks. Short enough that a crashed agent is
/// back inside a minute, long enough to cost nothing.
const TICK: Duration = Duration::from_secs(5);

/// Gap before the 1st, 2nd and 3rd restart. Escalating on purpose: a guest
/// that died once deserves an immediate retry, a guest that keeps dying
/// deserves the disk left alone.
const BACKOFF: [u64; 3] = [5, 30, 120];

/// A guest that has stayed up this long has recovered: its restart budget
/// goes back to full, so a crash next week is not measured against a crash
/// today.
const STABLE: Duration = Duration::from_secs(300);

// ---- the watch table -------------------------------------------------------

#[derive(Debug)]
struct Watch {
    /// Restarts already made since this instance last ran cleanly.
    attempts: u32,
    /// When the next restart is due, while one is owed.
    due: Option<Instant>,
    /// When the guest was last seen (or booted) alive.
    seen_alive: Instant,
}

fn watches() -> MutexGuard<'static, BTreeMap<String, Watch>> {
    static WATCHES: OnceLock<StdMutex<BTreeMap<String, Watch>>> = OnceLock::new();
    WATCHES
        .get_or_init(|| StdMutex::new(BTreeMap::new()))
        // A panic inside this module's own short critical sections would
        // mean the table is unusable; take it anyway rather than poison
        // the whole daemon over bookkeeping.
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn backoff(attempts: u32) -> Duration {
    let idx = (attempts as usize).min(BACKOFF.len() - 1);
    Duration::from_secs(BACKOFF[idx])
}

/// Remember that `name`'s guest is gone and owe it a restart.
///
/// Called by `main::reconcile` before it flips the instance to stopped, and
/// by the supervisor's own sweep. Idempotent: a death already scheduled
/// keeps the schedule it has, so a burst of `ast ls` cannot pull a restart
/// forward.
pub fn note_died(name: &str) {
    let now = Instant::now();
    let mut watches = watches();
    let watch = watches
        .entry(name.to_owned())
        .or_insert_with(|| Watch { attempts: 0, due: None, seen_alive: now });
    if watch.due.is_none() {
        watch.due = Some(now + backoff(watch.attempts));
    }
}

/// Stop watching `name`. Called when a user takes the instance down or
/// removes it: a deliberate `ast down` is not a crash, and must not be
/// undone by the supervisor.
pub fn forget(name: &str) {
    watches().remove(name);
}

/// Names whose restart is due, taken off the queue.
fn take_due(now: Instant) -> Vec<String> {
    let mut watches = watches();
    let mut due = Vec::new();
    for (name, watch) in watches.iter_mut() {
        if watch.due.is_some_and(|at| at <= now) {
            watch.due = None;
            due.push(name.clone());
        }
    }
    due
}

/// Whether anything is owed a restart — the instances that are down right
/// now but are meant to be up.
fn owed() -> usize {
    watches().values().filter(|w| w.due.is_some()).count()
}

/// Count a restart against the budget and report the attempt number.
fn bump(name: &str) -> u32 {
    let now = Instant::now();
    let mut watches = watches();
    let watch = watches
        .entry(name.to_owned())
        .or_insert_with(|| Watch { attempts: 0, due: None, seen_alive: now });
    watch.attempts += 1;
    watch.seen_alive = now;
    watch.attempts
}

/// A guest that has been up longer than [`STABLE`] gets its budget back.
fn note_alive(name: &str) {
    let mut watches = watches();
    let Some(watch) = watches.get(name) else { return };
    if watch.due.is_none() && watch.seen_alive.elapsed() >= STABLE {
        watches.remove(name);
    }
}

// ---- resurrection ----------------------------------------------------------

/// Bring back what this device was running when it last had a daemon.
///
/// Runs before the accept loop and holds the registry lock throughout, so
/// a request arriving on the socket cannot reconcile a still-to-be-booted
/// instance to stopped underneath it.
///
/// Per-instance failures are logged and the instance is handed to the
/// supervisor. Nothing here aborts startup: a daemon that refuses to come
/// up because one guest will not boot is worse than the guest being down.
pub async fn resurrect(registry: &Arc<Mutex<Shard>>) {
    let mut reg = registry.lock().await;
    let hv = backend::select();
    let recorded: Vec<Instance> =
        reg.list().into_iter().filter(|i| i.status == Status::Running).collect();
    if recorded.is_empty() {
        return;
    }

    for inst in recorded {
        let name = inst.name.as_str();
        // astd can be restarted without the host going down: the guests
        // are their own processes and outlive us. Those are already home —
        // except for the parts of them this process was holding. A block
        // volume reaches the guest through a socket *this* daemon binds and
        // an accept loop it runs, and both died with the last one, so the
        // guest is sitting there retrying a socket nothing is behind.
        if alive(&*hv, &inst) {
            eprintln!(
                "astd: {name} was already running (pid {}) and kept running",
                inst.pid().unwrap_or(0)
            );
            crate::volume::reattach(&inst).await;
            continue;
        }
        if inst.policy.restart == Restart::Never {
            eprintln!("astd: {name} is down and its policy says restart=never");
            let _ = reg.set_stopped(name);
            continue;
        }
        eprintln!("astd: {name} was running when this device last had a daemon — booting it");
        match boot_again(&mut reg, &inst) {
            Ok(booted) => eprintln!(
                "astd: {name} is back{}",
                booted.endpoint().map(|e| format!(" on {e}")).unwrap_or_default()
            ),
            Err(e) => {
                eprintln!("astd: {name} did not come back: {e:#} — the supervisor will retry");
                note_died(name);
            }
        }
    }
    if let Err(e) = reg.save() {
        eprintln!("astd: saving the registry after resurrection: {e:#}");
    }
}

// ---- the supervisor --------------------------------------------------------

/// Start the supervisor loop. Runs for the life of the daemon.
pub fn supervise(registry: Arc<Mutex<Shard>>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut guard = SleepGuard::new();
        loop {
            tokio::time::sleep(TICK).await;
            tick(&registry, &mut guard).await;
        }
    })
}

/// One pass: notice deaths, make the restarts that are due, and keep the
/// sleep assertion in step with what is running.
async fn tick(registry: &Arc<Mutex<Shard>>, guard: &mut SleepGuard) {
    let mut reg = registry.lock().await;
    let hv = backend::select();

    for inst in reg.list() {
        if inst.status != Status::Running {
            continue;
        }
        if alive(&*hv, &inst) {
            note_alive(&inst.name);
        } else {
            note_died(&inst.name);
        }
    }

    let mut changed = false;
    for name in take_due(Instant::now()) {
        changed |= restart(&mut reg, &name, &*hv);
    }
    if changed {
        if let Err(e) = reg.save() {
            eprintln!("astd: saving the registry after a restart: {e:#}");
        }
    }

    // Counted after the restarts, not before, or a guest that just came
    // back would look stopped for one tick and the device would announce
    // that it may sleep and then immediately take the assertion again.
    // An instance waiting out its backoff is still meant to be up, so it
    // counts too: nothing sleeps during the gap.
    match guard.set(live_count(&reg, &*hv) + owed()) {
        Change::Held(mechanism) => eprintln!("astd: holding this device awake ({mechanism})"),
        Change::Released => eprintln!("astd: nothing is running — this device may sleep"),
        Change::Unavailable(why) => eprintln!("astd: cannot keep this device awake: {why}"),
        Change::Same => {}
    }
}

fn live_count(reg: &Shard, hv: &dyn Hypervisor) -> usize {
    reg.list()
        .iter()
        .filter(|i| i.status == Status::Running && alive(hv, i))
        .count()
}

/// Restart one instance whose guest died. Returns whether the registry
/// changed and needs saving.
fn restart(reg: &mut Shard, name: &str, hv: &dyn Hypervisor) -> bool {
    let Ok(inst) = reg.get(name).cloned() else {
        // Removed while it was owed a restart.
        forget(name);
        return false;
    };
    // It may have been started by hand while the backoff was running.
    if inst.status == Status::Running && alive(hv, &inst) {
        return false;
    }
    if inst.policy.restart == Restart::Never {
        // Leave it down, and leave the registry saying so, or every tick
        // would rediscover the same corpse.
        forget(name);
        if inst.status == Status::Running {
            eprintln!("astd: {name} is down and its policy says restart=never");
            let _ = reg.set_stopped(name);
            return true;
        }
        return false;
    }

    let attempt = bump(name);
    if attempt > inst.policy.max_attempts {
        give_up(reg, name, inst.policy.max_attempts);
        return true;
    }

    eprintln!(
        "astd: {name} is down — restarting it (attempt {attempt} of {})",
        inst.policy.max_attempts
    );
    match boot_again(reg, &inst) {
        Ok(booted) => {
            eprintln!(
                "astd: {name} is back{}",
                booted.endpoint().map(|e| format!(" on {e}")).unwrap_or_default()
            );
            true
        }
        Err(e) => {
            eprintln!("astd: {name} would not restart: {e:#}");
            // Owe it the next attempt, at the next step of the backoff.
            note_died(name);
            true
        }
    }
}

/// Stop trying, and leave the reason where the user will look: the
/// instance's console log (what `ast logs` prints) and the daemon log.
fn give_up(reg: &mut Shard, name: &str, attempts: u32) {
    let why = format!(
        "asterism: gave up restarting {name} after {attempts} attempts — the guest \
         died each time. Nothing will restart it now; the console above is where \
         the reason will be. Fix it, then: ast up {name}"
    );
    eprintln!("astd: {why}");
    if let Err(e) = append_to_console(name, &why) {
        eprintln!("astd: could not write that to {name}'s console log: {e:#}");
    }
    let _ = reg.set_stopped(name);
    forget(name);
}

fn append_to_console(name: &str, message: &str) -> anyhow::Result<()> {
    let path = paths::instance_dir(name).join("console.log");
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "\n[asterism t={}] {message}", asterism_core::instance::now_unix())?;
    Ok(())
}

/// Boot an instance whose recorded guest is gone, through the same path
/// `ast up` uses — a resurrected instance is not a special kind of boot.
fn boot_again(reg: &mut Shard, inst: &Instance) -> anyhow::Result<Instance> {
    // `up` refuses an instance that is recorded running, and this one is
    // recorded running with a dead process. Clearing the handle first is
    // what makes the two agree.
    if inst.status == Status::Running {
        let _ = reg.set_stopped(&inst.name);
    }
    clear_stale_control(inst);
    crate::instance::up(reg, &inst.name)
}

/// A killed guest leaves its control socket behind; the next boot binds
/// the same path. Removing it is crash cleanup, not policy — the process
/// that owned it has already been confirmed dead.
fn clear_stale_control(inst: &Instance) {
    if let Some(handle) = &inst.handle {
        let path = handle.ctl.path();
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A handle reloaded from the registry is never assumed valid.
fn alive(hv: &dyn Hypervisor, inst: &Instance) -> bool {
    inst.handle.as_ref().is_some_and(|h| matches!(hv.state(h), Ok(RunState::Running)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is process-wide, so tests name instances that no other
    /// test touches.
    fn scratch(tag: &str) -> String {
        format!("persist-test-{tag}")
    }

    /// Naming instances apart keeps `contains` and `forget` honest, and
    /// that is all it keeps. `owed` counts every watch in the table and
    /// `take_due` sweeps every watch in it, so a test asserting on either
    /// is asserting about instances other tests own. Cargo runs these on
    /// as many threads as the machine has cores, which is why this passed
    /// on a two-core runner and fails on a laptop.
    ///
    /// A test making a whole-table claim holds this while it does. Each of
    /// them leaves the table as it found it, so owning it is enough.
    fn own_the_table() -> MutexGuard<'static, ()> {
        static ONE_AT_A_TIME: StdMutex<()> = StdMutex::new(());
        // Poisoned by an earlier failing test is still usable: the table
        // itself is guarded separately and every holder leaves it empty.
        ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn the_backoff_escalates_and_then_holds() {
        assert_eq!(backoff(0), Duration::from_secs(5));
        assert_eq!(backoff(1), Duration::from_secs(30));
        assert_eq!(backoff(2), Duration::from_secs(120));
        // Past the end it stays at the longest gap rather than panicking.
        assert_eq!(backoff(9), Duration::from_secs(120));
    }

    #[test]
    fn a_death_is_owed_a_restart_only_once_its_backoff_has_passed() {
        let _table = own_the_table();
        let name = scratch("backoff");
        forget(&name);
        note_died(&name);
        let now = Instant::now();
        assert!(take_due(now).is_empty(), "the first restart waits out the backoff");
        assert_eq!(owed(), 1, "but it is owed, so the device stays awake");
        assert!(take_due(now + Duration::from_secs(6)).contains(&name));
        // Taken off the queue: a second sweep does not restart it twice.
        assert!(take_due(now + Duration::from_secs(600)).is_empty());
        forget(&name);
    }

    #[test]
    fn repeated_deaths_walk_up_the_backoff() {
        let _table = own_the_table();
        let name = scratch("escalate");
        forget(&name);
        note_died(&name);
        let start = Instant::now();
        take_due(start + Duration::from_secs(6));
        assert_eq!(bump(&name), 1);

        // Died again: the next gap is the second step, not the first.
        note_died(&name);
        assert!(
            take_due(start + Duration::from_secs(10)).is_empty(),
            "5s is no longer enough once one restart has been spent"
        );
        assert!(!take_due(Instant::now() + Duration::from_secs(31)).is_empty());
        assert_eq!(bump(&name), 2);
        forget(&name);
        assert_eq!(owed(), 0);
    }

    #[test]
    fn a_deliberate_down_cancels_the_restart() {
        let _table = own_the_table();
        let name = scratch("forget");
        note_died(&name);
        forget(&name);
        assert!(take_due(Instant::now() + Duration::from_secs(600)).is_empty());
    }

    /// The supervisor reads the policy off the instance now. An instance
    /// that has never been given one restarts, which is the answer every
    /// registry written before the field existed deserializes to.
    #[test]
    fn an_instance_with_no_policy_of_its_own_still_comes_back() {
        let inst: Instance = serde_json::from_str(
            r#"{"id":"i","name":"dev","cpu_device":"laptop","status":"stopped",
                "created_at":0,"volumes":[]}"#,
        )
        .unwrap();
        assert_eq!(inst.policy.restart, Restart::Always);
        assert_eq!(inst.policy.max_attempts, asterism_core::instance::MAX_ATTEMPTS);
    }
}
