//! `astd-vz` — one Virtualization.framework guest, one process.
//!
//! This binary is the only thing in Asterism that touches VZ, and therefore
//! the only thing that has to carry `com.apple.security.virtualization`.
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
        format!("starting the {} guest under Virtualization.framework", config.instance)
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
        }
    };

    // The run loop. Every wait is a pump rather than a sleep, and the only
    // work that happens here is work that must happen on the VM's queue.
    let reason: StopReason = 'run: loop {
        vm::pump(Duration::from_millis(100));

        while let Ok(job) = jobs_rx.try_recv() {
            match job.command {
                Command::Info => {
                    let _ = job.reply.send(Reply::Info(info(unsafe { machine.state() })));
                }
                // `stop` and `kill` both answer with the outcome and then
                // end the process: the VM cannot outlive it, so a helper
                // whose guest is down has nothing left to serve.
                Command::Stop { timeout_secs } => {
                    let budget = Duration::from_secs(timeout_secs.unwrap_or(30));
                    let asked = Instant::now();
                    let reason = unsafe { machine.graceful_stop(budget) };
                    let _ = job.reply.send(Reply::Stopped {
                        reason: reason.clone(),
                        seconds: asked.elapsed().as_secs_f64(),
                    });
                    flush_reply();
                    break 'run reason;
                }
                Command::Kill => {
                    let asked = Instant::now();
                    let reason = unsafe { machine.force_stop() };
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
            break 'run machine.signals.reason().unwrap_or(StopReason::Forced);
        }
    };

    let _ = std::fs::remove_file(&config.ctl);
    eprintln!(
        "astd-vz: {} down after {:.1}s — {reason}{}",
        config.instance,
        t0.elapsed().as_secs_f64(),
        match machine.signals.net_disconnects() {
            0 => String::new(),
            n => format!(" ({n} network drop(s))"),
        }
    );
    Ok(())
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
                    args.next().ok_or_else(|| anyhow::anyhow!("--config needs a path"))?,
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
