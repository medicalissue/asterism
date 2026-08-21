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
//! main thread   VZ + the run loop it must never stop pumping
//! ctl threads   accept() and JSON, handing commands to the main thread
//! prober thread lease file + ssh banner, because connect() blocks
//! ```
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
mod ctl;
#[cfg(target_os = "macos")]
mod net;
#[cfg(target_os = "macos")]
mod vm;

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

    use asterism_vz::{Command, Config, Info, Reply, State, StopReason};

    /// What the address prober has managed to prove about the guest.
    #[derive(Default)]
    struct Discovered {
        ip: Option<IpAddr>,
        boot_secs: Option<f64>,
    }

    let config_path = parse_args()?;
    let config = Config::read(&config_path)?;

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

    // The guest's address, hunted on a thread of its own. Both halves of
    // the hunt block — reading the lease file and, much worse, connecting
    // to a candidate that is not there — and blocking the main thread
    // starves the queue the VM is bound to (spike landmine 9).
    let found = Arc::new(Mutex::new(Discovered::default()));
    {
        let (found, mac, host) = (found.clone(), config.mac.clone(), config.instance.clone());
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(600);
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(500));
                // Candidates, not an answer: whichever one sends an ssh
                // banner is the live guest (spike landmine 8).
                for ip in net::lease_candidates(&mac, &host) {
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
            eprintln!("astd-vz: {host} never answered on port 22");
        });
    }

    let info = |state: State| -> Info {
        let slot = found.lock().unwrap();
        Info {
            instance: config.instance.clone(),
            pid: std::process::id(),
            state,
            mac: config.mac.clone(),
            guest_ip: slot.ip,
            started_at,
            boot_secs: slot.boot_secs,
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

        while let Ok(job) = jobs_rx.try_recv() {
            match job.command {
                Command::Info => {
                    let _ = job
                        .reply
                        .send(Reply::Info(info(unsafe { machine.state() })));
                }
                // `stop` and `kill` both answer with the outcome and then
                // end the process: the VM cannot outlive it, so a helper
                // whose guest is down has nothing left to serve.
                Command::Stop { timeout_secs } => {
                    let budget = Duration::from_secs(timeout_secs.unwrap_or(30));
                    let asked = Instant::now();
                    let stopped = unsafe { machine.graceful_stop(budget) };
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

/// `--config <path>`, and nothing else: everything about the guest is in
/// the file, where a human can read what a running instance was actually
/// built from.
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
                     by hand. Must be code-signed: scripts/sign-vz.sh"
                );
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
