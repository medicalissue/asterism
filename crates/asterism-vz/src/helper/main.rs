//! `astd-vz` — one Virtualization.framework guest, one process.
//!
//! This binary is the only thing in Asterism that touches VZ, and therefore
//! the only thing that has to carry `com.apple.security.virtualization` and
//! `com.apple.security.network.client`.
//! `astd` spawns one per running instance and drives it over the unix
//! socket in [`asterism_vz`]; the guest lives exactly as long as this
//! process does, which is *why* it is a separate process — restarting or
//! upgrading the daemon must not take anybody's agents down with it
//! (BACKENDS.md §4).
//!
//! ## This binary must be code-signed
//!
//! `cargo build` emits an unsigned binary and VZ refuses to create a
//! `VZVirtualMachine` in a process without the entitlement. Run
//! `scripts/sign-vz.sh` after every build — cargo rewrites the file, which
//! invalidates the signature. `astd` checks for the entitlement in
//! `probe()` and refuses the vz backend with that instruction rather than
//! letting a boot fail deep inside the framework.
//!
//! ## Shape
//!
//! ```text
//! main thread    VZ + the run loop it must never stop pumping
//! ctl threads    accept() and JSON, handing commands to the main thread
//! agent thread   the guest's own answers, over vsock — readiness, its
//!                address, health, a sync barrier, a stop it can act on
//! prober thread  lease file + ssh banner, for a guest with no agent
//! ```
//!
//! The agent is the authority on where the guest is and whether it is up
//! (`asterism_vz::guest`); the prober is what is left when a guest was
//! built from a seed that carries no agent, and it is inference — see that
//! module's header for why that was never good enough.
//!
//! ## The helper can end its own guest
//!
//! Usually the guest decides (`poweroff`) or the daemon does (`stop`,
//! `kill`). There is one case where this process decides for itself: a disk
//! attached over the network has failed for good. VZ cannot re-attach one
//! under a running VM, the guest's writes to it are going nowhere, and the
//! framework goes on reporting the machine as `Running` — so the helper
//! asks the guest to power down and then pulls the cord, which is the death
//! `astd`'s supervisor already knows how to act on.

#[cfg(target_os = "macos")]
use anyhow::Context;

#[cfg(target_os = "macos")]
mod agent;
#[cfg(target_os = "macos")]
mod ctl;
#[cfg(target_os = "macos")]
mod gpu;
#[cfg(target_os = "macos")]
mod net;
#[cfg(target_os = "macos")]
mod vm;

/// The helper's daemon-independent cleanup handle.
///
/// astd deliberately does not parent the helper for its whole lifetime: the
/// guest must survive an astd restart or upgrade. That also means a test
/// harness cannot rely on the daemon's last registry flush to find a helper
/// after stopping its daemon. This pidfile lives beside the helper's vz.json,
/// exactly like QEMU's qemu.pid, and is removed by the helper on every
/// ordinary exit. A forced stop leaves it for the owner of that home to
/// consume and remove.
#[cfg(target_os = "macos")]
struct PidFile {
    path: std::path::PathBuf,
    pid: u32,
}

#[cfg(target_os = "macos")]
impl PidFile {
    fn create(config_path: &std::path::Path) -> anyhow::Result<Self> {
        let dir = config_path.parent().ok_or_else(|| {
            anyhow::anyhow!("the vz config path {} has no parent", config_path.display())
        })?;
        let path = dir.join("vz.pid");
        let pid = std::process::id();
        std::fs::write(&path, format!("{pid}\n"))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(Self { path, pid })
    }
}

#[cfg(target_os = "macos")]
impl Drop for PidFile {
    fn drop(&mut self) {
        // Never remove a file a newer helper has replaced. This is normally
        // impossible because astd hands helpers over one at a time, but the
        // guard keeps cleanup local even if that invariant is broken.
        let ours = self.pid.to_string();
        if std::fs::read_to_string(&self.path)
            .ok()
            .is_some_and(|recorded| recorded.trim() == ours)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!(
        "astd-vz runs Apple's Virtualization.framework, so it only exists on macOS. \
         Other hosts use the qemu backend."
    );
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use anyhow::Context;

    use asterism_vz::guest::Key;
    use asterism_vz::{Command, Config, Discovery, Info, Reply, State, StopReason};

    /// What the address prober has managed to prove about the guest.
    #[derive(Default)]
    struct Discovered {
        ip: Option<IpAddr>,
        boot_secs: Option<f64>,
    }

    let config_path = parse_args()?;
    let config = Config::read(&config_path)?;
    // Keep this guard alive for the helper's entire lifetime. It gives suite
    // cleanup an ownership record that does not depend on astd getting
    // another chance to persist state.json after the helper has started.
    let _pidfile = PidFile::create(&config_path)?;

    // Leave the daemon's process group. A signal aimed at astd — or at the
    // whole group by a shell, a test script or launchd — must not reach a
    // running guest: that is the difference between "the daemon restarted"
    // and "everything you had running died".
    detach();

    let started_at = now_unix();
    let listener = ctl::listen(&config.ctl)?;
    let (jobs_tx, jobs_rx) = std::sync::mpsc::channel::<ctl::Job>();
    ctl::serve(listener, jobs_tx);

    let t0 = Instant::now();
    let machine = unsafe { vm::start(&config) }.with_context(|| {
        format!(
            "starting the {} guest under Virtualization.framework",
            config.instance
        )
    })?;
    eprintln!(
        "astd-vz: {} started in {:.2}s (pid {}, mac {})",
        config.instance,
        t0.elapsed().as_secs_f64(),
        std::process::id(),
        config.mac
    );

    // The key this guest's agent is authenticated with. Absent for a guest
    // booted by a daemon from before there were agents, and for one whose
    // key file has gone: both mean the same thing here — nothing to
    // authenticate with, so nothing to talk to, and the hunt below is what
    // is left.
    let agent_key = match config.agent_key.as_deref() {
        None => None,
        Some(path) => match Key::read(path) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("astd-vz: {}: {e:#} — no guest agent", config.instance);
                None
            }
        },
    };
    let mut agent = agent::Agent::default();
    let mut gpu = gpu::GpuHop::default();
    let mut gpu_reconnect = Reconnect::new();
    let mut reconnect = Reconnect::new();

    // The guest's address, hunted on a thread of its own — the fallback for
    // a guest with no agent to ask. Both halves of the hunt block — reading
    // the lease file and, much worse, connecting to a candidate that is not
    // there — and blocking the main thread starves the queue the VM is
    // bound to (spike landmine 9).
    let found = Arc::new(Mutex::new(Discovered::default()));
    {
        let (found, mac, host, lease_is_endpoint) = (
            found.clone(),
            config.mac.clone(),
            config.instance.clone(),
            config.dhcp_lease_is_endpoint,
        );
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(600);
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(500));
                // Candidates, not an answer: whichever one sends an ssh
                // banner is the live cloud guest (spike landmine 8). A
                // directly booted OCI guest is the exception: it has no
                // sshd, and its generated init requested this lease with the
                // exact pinned MAC/hostname the helper is querying.
                for ip in net::lease_candidates(&mac, &host) {
                    if lease_is_endpoint {
                        eprintln!(
                            "astd-vz: {host} received DHCP address {ip} after {:.1}s",
                            t0.elapsed().as_secs_f64()
                        );
                        let mut slot = found.lock().unwrap();
                        slot.ip = Some(ip);
                        slot.boot_secs = Some(t0.elapsed().as_secs_f64());
                        return;
                    }
                    if let Some(banner) = net::ssh_banner(ip, Duration::from_millis(250)) {
                        eprintln!(
                            "astd-vz: {host} answered at {ip} after {:.1}s — {banner}",
                            t0.elapsed().as_secs_f64()
                        );
                        let mut slot = found.lock().unwrap();
                        slot.ip = Some(ip);
                        slot.boot_secs = Some(t0.elapsed().as_secs_f64());
                        return;
                    }
                }
            }
            if lease_is_endpoint {
                eprintln!("astd-vz: {host} never received a matching DHCP lease");
            } else {
                eprintln!("astd-vz: {host} never answered on port 22");
            }
        });
    }

    // What `info` answers with, given everything this process knows. Not a
    // closure: `agent` is attached and detached by the run loop below, and
    // a closure holding a borrow of it would stop that.
    let info = |state: State, agent: &agent::Agent| -> Info {
        let (agent_info, agent_error) = agent.reported();
        // The guest's own answer, where there is one. It is not a better
        // guess than the lease file's — it is not a guess: one guest is at
        // the other end of one virtio socket, and it holds this instance's
        // key.
        let (guest_ip, endpoint_via, boot_secs) = match agent.endpoint() {
            Some((addr, secs)) => (Some(addr), Some(Discovery::Agent), Some(secs)),
            None => {
                let slot = found.lock().unwrap();
                let via = slot.ip.map(|_| Discovery::Ssh);
                (slot.ip, via, slot.boot_secs)
            }
        };
        Info {
            instance: config.instance.clone(),
            pid: std::process::id(),
            state,
            mac: config.mac.clone(),
            guest_ip,
            endpoint_via,
            agent: agent_info.map(Box::new),
            agent_error,
            started_at,
            boot_secs,
            console: config.console.clone(),
            // The *reason* for the state beside it: `machine.state()`
            // already refuses to call a guest with a dead disk live, and
            // this says which disk and why.
            storage_error: machine.signals.storage_failure(),
        }
    };

    // The run loop. Every wait is a pump rather than a sleep, and the only
    // work that happens here is work that must happen on the VM's queue.
    //
    // `losing_a_disk` is set the first time a disk fails for good, and is
    // the deadline the guest has to power itself off before the cord comes
    // out. Deliberately *not* `machine.graceful_stop`, which would block
    // this loop: `info` has to keep being answered while the guest goes, or
    // the daemon times out, falls back to the pid, and calls it running.
    let mut losing_a_disk: Option<Instant> = None;

    let reason: StopReason = 'run: loop {
        vm::pump(Duration::from_millis(100));

        if let Some(key) = agent_key.as_ref() {
            keep_session(
                &machine,
                &mut agent,
                key,
                &config.instance,
                t0,
                &mut reconnect,
            );
            keep_gpu_session(
                &machine,
                &mut gpu,
                key,
                &config.instance,
                &mut gpu_reconnect,
            );
        }

        while let Ok(job) = jobs_rx.try_recv() {
            match job.command {
                Command::Info => {
                    let _ = job
                        .reply
                        .send(Reply::Info(info(unsafe { machine.state() }, &agent)));
                }
                // A barrier the guest raises, or a named refusal. Never
                // silently "done": the caller is about to do something to
                // a disk on the strength of this answer.
                Command::Sync { timeout_secs } => {
                    let budget = Duration::from_secs(timeout_secs.unwrap_or(30));
                    let reply = match sync_guest(&agent, budget) {
                        Ok(seconds) => Reply::Synced { seconds },
                        Err(message) => Reply::Error { message },
                    };
                    let _ = job.reply.send(reply);
                }
                // `stop` and `kill` both answer with the outcome and then
                // end the process: the VM cannot outlive it, so a helper
                // whose guest is down has nothing left to serve.
                Command::Stop { timeout_secs } => {
                    let budget = Duration::from_secs(timeout_secs.unwrap_or(30));
                    let asked = Instant::now();
                    let stopped = stop_guest(&machine, &agent, budget, &config.instance);
                    // A guest that was already on its way out because a disk
                    // went did not "ignore ACPI"; say what actually happened.
                    let reason = exit_reason(machine.signals.storage_failure(), Some(stopped));
                    let _ = job.reply.send(Reply::Stopped {
                        reason: reason.clone(),
                        seconds: asked.elapsed().as_secs_f64(),
                    });
                    flush_reply();
                    break 'run reason;
                }
                Command::Kill => {
                    let asked = Instant::now();
                    let stopped = unsafe { machine.force_stop() };
                    let reason = exit_reason(machine.signals.storage_failure(), Some(stopped));
                    let _ = job.reply.send(Reply::Stopped {
                        reason: reason.clone(),
                        seconds: asked.elapsed().as_secs_f64(),
                    });
                    flush_reply();
                    break 'run reason;
                }
            }
        }

        // The guest powering itself off (`poweroff` inside, or a panic VZ
        // reported through the delegate) ends this process the same way.
        if machine.signals.stopped() {
            break 'run exit_reason(machine.signals.storage_failure(), machine.signals.reason());
        }

        // A disk that will never come back. Apple is explicit that the NBD
        // client is non-functional after `didEncounterError:`, and there is
        // no API to swap the attachment out from under a live guest — so
        // the only honest end is to stop, and to stop *soon*: every second
        // longer is another second of the guest believing writes landed.
        if let Some(failure) = machine.signals.storage_failure() {
            match losing_a_disk {
                None => {
                    eprintln!("astd-vz: {}: {failure}", config.instance);
                    // ACPI first, so the guest can flush the disks it has
                    // *not* lost — its root among them. A request VZ will
                    // not take leaves nothing to wait for, so the deadline
                    // is now and the next turn of this loop forces it.
                    losing_a_disk = Some(match unsafe { machine.request_stop() } {
                        true => {
                            eprintln!(
                                "astd-vz: asked {} to power off — up to {}s",
                                config.instance,
                                STORAGE_FAILURE_GRACE.as_secs()
                            );
                            Instant::now() + STORAGE_FAILURE_GRACE
                        }
                        false => Instant::now(),
                    });
                }
                // Out of budget. A guest that is not answering ACPI is
                // often one wedged flushing the disk that went.
                Some(until) if Instant::now() >= until => {
                    eprintln!(
                        "astd-vz: {} would not power down after losing a disk — forcing it",
                        config.instance
                    );
                    // One last barrier on the disks it has *not* lost. The
                    // agent is a process of its own and answers whatever
                    // systemd is doing; a guest wedged on the dead device
                    // simply does not answer in time, which is why this has
                    // a budget and takes it no further.
                    flush(&agent, LOST_DISK_FLUSH, &config.instance);
                    unsafe { machine.force_stop() };
                    break 'run exit_reason(Some(failure), machine.signals.reason());
                }
                Some(_) => {}
            }
        }
    };

    let _ = std::fs::remove_file(&config.ctl);
    eprintln!(
        "astd-vz: {} down after {:.1}s — {reason}{}",
        config.instance,
        t0.elapsed().as_secs_f64(),
        churn(
            machine.signals.net_disconnects(),
            machine.signals.nbd_connections(),
            machine.signals.nbd_terminal_errors(),
        )
    );
    Ok(())
}

/// Where the helper is in its attempts to have a session with the guest's
/// agent.
#[cfg(target_os = "macos")]
struct Reconnect {
    /// When it is worth asking for a connection again.
    next: std::time::Instant,
    /// How long to wait after the next failure.
    gap: std::time::Duration,
    /// When the session that is currently attached was attached, which is
    /// how a session that worked and then ended is told apart from one that
    /// never worked at all.
    attached: Option<std::time::Instant>,
    /// A guest with no virtio socket device is said once, not every turn.
    said_no_vsock: bool,
}

#[cfg(target_os = "macos")]
impl Reconnect {
    fn new() -> Self {
        Reconnect {
            next: std::time::Instant::now(),
            gap: FIRST_CONNECT_GAP,
            attached: None,
            said_no_vsock: false,
        }
    }
}

/// Keep a session with the guest agent open, without ever waiting for one.
///
/// Called on every turn of the run loop and returns immediately: VZ's
/// connect is asked for on one turn and collected on another, because
/// nothing may hold this thread — the guest runs on it, and the control
/// socket's jobs are drained on it.
///
/// The whole retry policy, in one place:
///
/// * **While a guest has never answered**, ask again every
///   [`FIRST_CONNECT_GAP`]. This is a guest booting: its agent binds the
///   port somewhere in the middle of that, and every moment between then
///   and noticing is a moment `ast up` spends waiting.
/// * **A session that ran and ended** is a guest that rebooted or an agent
///   that was restarted. There is something to talk to again, so ask at
///   once.
/// * **A session that ended about as fast as it opened** is a refused
///   handshake or a version neither side shares. The guest is answering
///   exactly as it means to, so back off to [`SETTLED_CONNECT_GAP`] rather
///   than spinning against it — and keep the reason, which is what `info`
///   reports and what a boot falling back to the lease hunt says out loud.
#[cfg(target_os = "macos")]
fn keep_session(
    machine: &vm::Machine,
    agent: &mut agent::Agent,
    key: &asterism_vz::guest::Key,
    instance: &str,
    t0: std::time::Instant,
    state: &mut Reconnect,
) {
    use std::time::Instant;

    if agent.live() {
        return;
    }
    // A session that has just ended. Let go of the connection it ran on,
    // and work out how soon to open another.
    if let Some(since) = state.attached.take() {
        agent.detach();
        unsafe { machine.close_agent() };
        state.gap = match since.elapsed() >= STABLE_SESSION {
            true => FIRST_CONNECT_GAP,
            false => (state.gap * 2).min(SETTLED_CONNECT_GAP),
        };
        state.next = Instant::now() + state.gap;
    }
    match unsafe { machine.take_connect() } {
        Some(Ok(fd)) => {
            agent.attach(fd, key.clone(), instance.to_owned(), t0);
            state.attached = Some(Instant::now());
        }
        Some(Err(_)) => {
            // Not logged: "nothing is listening yet" is what a booting guest
            // looks like, and it is the answer to every attempt until the
            // agent binds the port. The *session* logs when it opens, and
            // when it fails for a reason worth having.
            state.next = Instant::now() + state.gap;
            if agent.ever_connected() {
                state.gap = (state.gap * 2).min(SETTLED_CONNECT_GAP);
            }
        }
        None if !machine.connect_in_flight() && Instant::now() >= state.next => {
            if let Err(e) = unsafe { machine.start_connect(asterism_vz::guest::PORT) } {
                // No socket device to ask on: nothing here will ever be
                // different, so say it once and leave the guest to the
                // fallback.
                if !state.said_no_vsock {
                    state.said_no_vsock = true;
                    eprintln!("astd-vz: {instance}: {e:#}");
                }
                state.next = Instant::now() + SETTLED_CONNECT_GAP;
            }
        }
        // Still in flight, or not time to ask again.
        None => {}
    }
}

#[cfg(target_os = "macos")]
fn keep_gpu_session(
    machine: &vm::Machine,
    hop: &mut gpu::GpuHop,
    key: &asterism_vz::guest::Key,
    instance: &str,
    state: &mut Reconnect,
) {
    use std::time::Instant;

    if hop.live() {
        return;
    }
    if let Some(since) = state.attached.take() {
        unsafe { machine.close_gpu() };
        state.gap = match since.elapsed() >= STABLE_SESSION {
            true => FIRST_CONNECT_GAP,
            false => (state.gap * 2).min(SETTLED_CONNECT_GAP),
        };
        state.next = Instant::now() + state.gap;
    }
    match unsafe { machine.take_connect_gpu() } {
        Some(Ok(fd)) => {
            hop.attach(fd, *key.as_bytes(), instance.to_owned());
            state.attached = Some(Instant::now());
        }
        Some(Err(_)) => {
            state.next = Instant::now() + state.gap;
        }
        None if !machine.gpu_connect_in_flight() && Instant::now() >= state.next => {
            if let Err(e) = unsafe { machine.start_connect_gpu() } {
                if !state.said_no_vsock {
                    state.said_no_vsock = true;
                    eprintln!("astd-vz: {instance}: GPU vsock: {e:#}");
                }
                state.next = Instant::now() + SETTLED_CONNECT_GAP;
            }
        }
        None => {}
    }
}

/// How often a guest that has never answered is asked again. Held flat
/// rather than doubled — see the run loop.
#[cfg(target_os = "macos")]
const FIRST_CONNECT_GAP: std::time::Duration = std::time::Duration::from_millis(150);

/// How long a session has to last before it counts as having worked. A
/// handshake that is going to be refused is refused in milliseconds.
#[cfg(target_os = "macos")]
const STABLE_SESSION: std::time::Duration = std::time::Duration::from_secs(10);

/// The gap once a session has already opened and gone. A guest whose agent
/// refused this helper, or dropped a session, is not fixed by asking again
/// quickly.
#[cfg(target_os = "macos")]
const SETTLED_CONNECT_GAP: std::time::Duration = std::time::Duration::from_secs(15);

/// How long the agent gets to accept a stop before ACPI is tried instead.
/// It answers before it acts, so this is a round trip and not a shutdown.
#[cfg(target_os = "macos")]
const AGENT_STOP_ACK: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a barrier before the cord comes out may take.
#[cfg(target_os = "macos")]
const STOP_FLUSH: std::time::Duration = std::time::Duration::from_secs(10);

/// The same, when a disk has already been lost. Shorter: a guest may be
/// wedged in the kernel on the device that went, and waiting longer buys
/// nothing.
#[cfg(target_os = "macos")]
const LOST_DISK_FLUSH: std::time::Duration = std::time::Duration::from_secs(3);

/// Take the guest down, best path first.
///
/// 1. **The guest agent.** A request that reaches a process, which runs
///    `systemctl poweroff` — deterministic where ACPI is a button the guest
///    is free to have no handler for.
/// 2. **ACPI**, for a guest with no agent, or one whose agent could not act.
/// 3. **The cord**, with a file sync barrier in front of it, so what the
///    guest had written is on the disk rather than in a page cache that is
///    about to stop existing.
///
/// Every wait pumps the run loop rather than sleeping on it: the guest is
/// running on this queue, and a guest that cannot make progress cannot shut
/// down either (spike landmine 9).
#[cfg(target_os = "macos")]
fn stop_guest(
    machine: &vm::Machine,
    agent: &agent::Agent,
    budget: std::time::Duration,
    instance: &str,
) -> asterism_vz::StopReason {
    use std::time::{Duration, Instant};

    // A guest that powered itself off between the request arriving and us
    // acting on it is a clean stop, not a failure.
    if let Some(reason) = machine.signals.reason() {
        return reason;
    }
    let deadline = Instant::now() + budget;

    // A guest with no session is the ordinary case for an older seed, and
    // exactly why the two paths below are still here — so there is nothing
    // to say about `request_stop` failing, only about a guest that has an
    // agent and would not use it.
    let mut asked = false;
    if let Ok(pending) = agent.request_stop() {
        match await_agent(pending, AGENT_STOP_ACK) {
            Ok(()) => asked = true,
            Err(why) => {
                eprintln!("astd-vz: {instance}: the guest agent would not take a stop: {why}")
            }
        }
    }
    if !asked {
        asked = unsafe { machine.request_stop() };
    }
    if asked {
        while !machine.signals.stopped() && Instant::now() < deadline {
            vm::pump(Duration::from_millis(100));
        }
        if let Some(reason) = machine.signals.reason() {
            return reason;
        }
    }
    flush(agent, STOP_FLUSH, instance);
    unsafe { machine.force_stop() }
}

/// Ask the guest to flush, and say what came of it.
///
/// Never fatal: a guest with no agent, or one too far gone to answer, is
/// the case a forced stop is for. What it must not do is happen silently —
/// "the cord came out and nothing was flushed" is the whole explanation for
/// a filesystem that comes back needing a check.
#[cfg(target_os = "macos")]
fn flush(agent: &agent::Agent, budget: std::time::Duration, instance: &str) {
    match sync_guest(agent, budget) {
        Ok(seconds) => {
            eprintln!("astd-vz: {instance}: the guest flushed its disks in {seconds:.2}s")
        }
        Err(why) => {
            eprintln!("astd-vz: {instance}: no file sync barrier before the forced stop — {why}")
        }
    }
}

/// One `sync(2)` inside the guest, in seconds.
#[cfg(target_os = "macos")]
fn sync_guest(agent: &agent::Agent, budget: std::time::Duration) -> Result<f64, String> {
    let pending = agent.request_sync()?;
    await_agent(pending, budget).map(|ms| ms / 1000.0)
}

/// Wait for the guest agent without stopping the guest.
#[cfg(target_os = "macos")]
fn await_agent<T>(pending: agent::Pending<T>, budget: std::time::Duration) -> Result<T, String> {
    let until = std::time::Instant::now() + budget;
    loop {
        if let Some(answer) = pending.taken() {
            return answer;
        }
        if std::time::Instant::now() >= until {
            return Err(format!(
                "the guest agent did not answer within {}s",
                budget.as_secs()
            ));
        }
        vm::pump(std::time::Duration::from_millis(25));
    }
}

/// How long the guest gets to power itself off after a disk it is using has
/// failed for good.
///
/// Shorter than the thirty seconds a `stop` allows, and for the opposite
/// reason: the guest may well be blocked in the kernel flushing the device
/// that just went, in which case waiting the full budget buys nothing and
/// only delays the restart.
#[cfg(target_os = "macos")]
const STORAGE_FAILURE_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

/// Why this guest is going away, given what the delegate saw.
///
/// A disk that failed for good outranks whatever came after it: the guest
/// powering off politely is the *answer* to the shutdown that failure
/// forced, not the reason for it, and "guest powered off" would read like a
/// clean `ast down` in the log and in the daemon's `stop`.
///
/// Deliberately an existing [`StopReason`] rather than a new variant —
/// `StopReason` is internally tagged, so a new `kind` an older `astd`
/// cannot parse would fail the whole reply and send it off to signal a
/// helper that is already gone.
#[cfg(target_os = "macos")]
fn exit_reason(
    storage: Option<asterism_vz::StorageError>,
    delegate: Option<asterism_vz::StopReason>,
) -> asterism_vz::StopReason {
    match storage {
        Some(failure) => asterism_vz::StopReason::Failed {
            message: failure.to_string(),
        },
        None => delegate.unwrap_or(asterism_vz::StopReason::Forced),
    }
}

/// The line's worth of network trouble a boot accumulated, or nothing.
///
/// NBD reconnects and terminal failures are counted apart on purpose: the
/// first is VZ's reconnect loop working as designed and the guest never
/// knowing, the second is the disk being gone. Reporting them together was
/// how a permanent failure came to look like ordinary churn.
#[cfg(target_os = "macos")]
fn churn(net_disconnects: u32, nbd_connections: u32, nbd_terminal_errors: u32) -> String {
    let mut said = Vec::new();
    if net_disconnects > 0 {
        said.push(format!("{net_disconnects} network drop(s)"));
    }
    // The first connection is not a reconnect.
    if let Some(reconnects) = nbd_connections.checked_sub(1).filter(|n| *n > 0) {
        said.push(format!("{reconnects} nbd reconnect(s)"));
    }
    if nbd_terminal_errors > 0 {
        said.push(format!("{nbd_terminal_errors} nbd disk(s) lost for good"));
    }
    match said.is_empty() {
        true => String::new(),
        false => format!(" ({})", said.join(", ")),
    }
}

/// Let the control thread write its answer before this process exits.
///
/// The reply is handed over a channel, so `send` returning does not mean
/// the client has it. A quarter of a second is thousands of times what the
/// write needs and is invisible next to a guest shutdown.
#[cfg(target_os = "macos")]
fn flush_reply() {
    vm::pump(std::time::Duration::from_millis(250));
}

/// `--config <path>`, and nothing else that changes what runs: everything
/// about the guest is in the file, where a human can read what a running
/// instance was actually built from.
///
/// `--version` is the exception, and it earns its place at the release
/// boundary rather than here: the helper is shipped in the same tarball as
/// `ast` and `astd` and must be the same build as both, so whoever is
/// holding an installed release needs one command that says which build
/// this file is. It prints the workspace version, which is what the tag
/// names.
#[cfg(target_os = "macos")]
fn parse_args() -> anyhow::Result<std::path::PathBuf> {
    let mut config = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config = Some(std::path::PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--config needs a path"))?,
                ))
            }
            "-h" | "--help" => {
                println!(
                    "astd-vz --config <vz.json>\n\n\
                     Runs one Asterism instance under Virtualization.framework and \n\
                     serves its control socket. Spawned by astd; not meant to be run\n\
                     by hand. Must be code-signed: scripts/sign-vz.sh\n\n\
                     --version  the build this helper is, which must match ast and astd"
                );
                std::process::exit(0);
            }
            // The helper is shipped beside `ast` and `astd` and is the one
            // piece of the set that also has to be code-signed, so "is this
            // the helper that came with these binaries" is a question worth
            // being able to ask it directly. Spelled the same way `ast
            // version` spells it, so one comparison covers all three.
            "-V" | "--version" => {
                println!("version   {}", asterism_core::VERSION);
                println!("build     {}", asterism_core::BUILD_ID);
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    config.ok_or_else(|| anyhow::anyhow!("astd-vz needs --config <vz.json>"))
}

/// `setsid(2)`, declared here rather than taking on `libc` for one symbol —
/// the same call `asterism_core::cow` makes for `clonefile`.
#[cfg(target_os = "macos")]
fn detach() {
    extern "C" {
        fn setsid() -> i32;
    }
    // SAFETY: no arguments, no memory involved. Fails only when this
    // process already leads its group, which is harmless: it is detached
    // either way.
    unsafe {
        setsid();
    }
}

#[cfg(target_os = "macos")]
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(all(test, target_os = "macos"))]
mod pidfile_tests {
    use super::PidFile;

    #[test]
    fn helper_pidfile_is_removed_when_its_owner_exits() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("vz.json");
        let path = dir.path().join("vz.pid");

        let file = PidFile::create(&config).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n", std::process::id())
        );
        drop(file);

        assert!(!path.exists(), "a departed helper left its pidfile behind");
    }

    #[test]
    fn an_old_helper_never_removes_a_new_helpers_pidfile() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("vz.json");
        let path = dir.path().join("vz.pid");

        let file = PidFile::create(&config).unwrap();
        std::fs::write(&path, "999999\n").unwrap();
        drop(file);

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "999999\n");
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    use asterism_vz::{StopReason, StorageError};

    fn lost() -> StorageError {
        StorageError {
            uri: "nbd+unix:///team%2Fdata?socket=%2Ftmp%2Fv.sock".into(),
            message: "Connection reset by peer".into(),
        }
    }

    /// Whatever the guest does after losing a disk, the log and the daemon
    /// hear about the disk — including when it powers off politely, which
    /// is what our own ACPI request asked it to do.
    #[test]
    fn a_lost_disk_outranks_the_shutdown_it_caused() {
        for after in [
            None,
            Some(StopReason::GuestStopped),
            Some(StopReason::Forced),
        ] {
            let StopReason::Failed { message } = exit_reason(Some(lost()), after.clone()) else {
                panic!("a lost disk is a failure, whatever followed it: {after:?}");
            };
            assert!(message.contains("nbd+unix:///team%2Fdata"), "{message}");
            assert!(message.contains("Connection reset by peer"), "{message}");
        }
    }

    /// ...and with no disk lost, nothing changes: the delegate's own
    /// account stands, exactly as it did before.
    #[test]
    fn an_ordinary_stop_still_reads_as_itself() {
        assert_eq!(
            exit_reason(None, Some(StopReason::GuestStopped)),
            StopReason::GuestStopped
        );
        assert_eq!(
            exit_reason(
                None,
                Some(StopReason::Failed {
                    message: "vz gave up".into()
                })
            ),
            StopReason::Failed {
                message: "vz gave up".into()
            }
        );
        // Nothing said at all: the VM went without the delegate naming a
        // reason, which is a forced stop as far as anyone can tell.
        assert_eq!(exit_reason(None, None), StopReason::Forced);
    }

    #[test]
    fn reconnects_and_a_lost_disk_are_counted_apart() {
        assert_eq!(churn(0, 0, 0), "", "a quiet boot says nothing");
        assert_eq!(
            churn(0, 1, 0),
            "",
            "the first connection is not a reconnect"
        );
        assert_eq!(churn(0, 3, 0), " (2 nbd reconnect(s))");
        assert_eq!(churn(2, 1, 0), " (2 network drop(s))");
        let both = churn(1, 4, 1);
        assert!(both.contains("3 nbd reconnect(s)"), "{both}");
        assert!(both.contains("1 nbd disk(s) lost for good"), "{both}");
        assert!(both.contains("1 network drop(s)"), "{both}");
    }
}
