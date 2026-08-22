//! The instance's own life: defining it, booting it, stopping it, renaming
//! it, deleting it, listing what there is, and getting a shell or a console
//! log out of it.
//!
//! None of these names a device, and that is the model rather than a
//! convenience. The instance namespace is flat and orbit-wide, so the name is
//! the whole address: the daemon in front of you resolves it and forwards the
//! frame if the row lives elsewhere. `--device` is accepted here only to look
//! at one device's shard, and refused outright by the three commands where it
//! could not mean anything ([`crate::client::local_only`]).

use std::fs::File;
use std::io::Seek;
use std::io::Write as _;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Subcommand;

use asterism_core::hv::ImageKind;
use asterism_core::instance::{Instance, PortForward, Restart, Shape};
use asterism_core::paths;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::OrbitRow;

use crate::client::{self, Conversation};
use crate::cmd::image;
use crate::format;

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Define a new instance, sourcing its cpu and ram from this device.
    ///
    /// The name is claimed across the whole orbit, so it means one instance
    /// everywhere.
    Create {
        /// What to call it: ascii letters, digits and `-`. One name means
        /// one instance everywhere in the orbit.
        name: String,
        /// Image to boot: an alias (`ast images`), an https:// url, a path to
        /// a qcow2 or raw disk image, or an OCI/Docker reference such as
        /// `nginx` or `ghcr.io/owner/app:v1` — which is pulled, unpacked and
        /// booted as a microVM of its own.
        #[arg(long, default_value = "ubuntu:24.04")]
        image: String,
        /// Publish a guest port on this device's loopback: `-p 8080:80`.
        ///
        /// How an OCI instance is reached: a container image has no ssh
        /// server, so the port it listens on is the way in. Repeatable.
        #[arg(short = 'p', long = "publish", value_name = "HOST:GUEST")]
        publish: Vec<String>,
        /// How many cores the guest gets.
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        /// Memory, e.g. 2048M or 4G.
        #[arg(long, default_value = "2G")]
        mem: String,
        /// Disk size, e.g. 20G.
        #[arg(long, default_value = "20G")]
        disk: String,
        /// Hypervisor to run this instance on: `qemu`, `vz` on macOS, or the
        /// native `hyperv` backend on supported Windows hosts. If omitted,
        /// the daemon selects the first capable backend. Recorded on the
        /// instance and used for every later boot.
        #[arg(long, value_name = "NAME")]
        backend: Option<String>,
    },
    /// Boot an instance.
    ///
    /// Where its cpu and ram come from is the instance's business, not the
    /// command's: the name resolves across the orbit and the boot happens on
    /// whichever device supplies them.
    Up {
        /// The instance to boot.
        name: String,
        /// What to do when this guest dies: `always` (the default) brings it
        /// back after a crash and after a host reboot, `never` leaves it
        /// down. Recorded on the instance, so it holds for later boots too
        /// and shows up in `ast status`.
        #[arg(long, value_name = "always|never")]
        restart: Option<Restart>,
    },
    /// Shut an instance down.
    ///
    /// A deliberate stop, so nothing brings it back: `--restart always` is
    /// about a guest that died, not about one you turned off.
    Down {
        /// The instance to shut down.
        name: String,
    },
    /// Delete a stopped instance: its disk, its snapshots and its record.
    ///
    /// Everything under the instance's own directory goes, snapshots
    /// included — they were always files in there. Block volumes are not
    /// its bytes and are left alone; their leases are handed back to the
    /// devices holding them.
    Rm {
        /// The instance to delete.
        name: String,
    },
    /// Give an instance a different name.
    ///
    /// The new name is claimed across the orbit, the same as at create.
    /// Refused while the guest is running: the instance's directory, its
    /// control socket and its console log are all named after it.
    Rename {
        /// The instance to rename.
        name: String,
        /// What to call it instead.
        new_name: String,
    },
    /// List every instance in this orbit.
    ///
    /// One table, assembled from every device that answers. A row from a
    /// device that did not answer is still listed, with its status
    /// `unknown` — the instance is real, its state is merely stale.
    Ls {
        /// Only the instances this device supplies cpu for (debugging).
        #[arg(long)]
        local: bool,
    },
    /// Show one instance and the parts it is assembled from.
    Status {
        /// The instance to look at.
        name: String,
    },
    /// Open a shell in a running instance (or run a command).
    ///
    /// Works from any device in the orbit and never names one: the daemon
    /// in front of you answers with a loopback address, whether the guest
    /// is here or on the far side of the mesh.
    Ssh {
        /// The instance to connect to.
        name: String,
        /// A command to run instead of opening a shell, and its arguments.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Print an instance's guest console log.
    Logs {
        /// The instance whose console to print.
        name: String,
        /// Keep printing as the guest writes more. Needs the console log to be
        /// on this device's disk.
        #[arg(short, long)]
        follow: bool,
        /// How many lines to print (0 for all of it).
        #[arg(short = 'n', long, default_value_t = 200)]
        lines: u32,
    },
}

pub(crate) fn run(cmd: Commands, device: Option<&str>) -> Result<()> {
    match cmd {
        Commands::Create { name, image: reference, publish, cpus, mem, disk, backend } => {
            // An image for another device has to be on that device: pulling it
            // here would fill this disk and still leave the far one without it.
            let resolved = match device {
                Some(_) => reference.clone(),
                None => image::ensure_pulled(&reference)?,
            };
            let request = Request::Create {
                name,
                image: resolved,
                shape: Shape {
                    cpus,
                    mem_mib: parse_mem_mib(&mem)?,
                    disk_gib: parse_disk_gib(&disk)?,
                },
                backend,
                publish: publish
                    .iter()
                    .map(|p| p.parse::<PortForward>())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| anyhow::anyhow!(e))?,
            };
            if let Some(inst) = changed(&request, device)? {
                println!("{}  {}", inst.name, inst.status);
            }
            Ok(())
        }
        Commands::Up { name, restart } => {
            if let Some(inst) = changed(&Request::Up { name, restart }, device)? {
                print_booting(&inst);
            }
            Ok(())
        }
        Commands::Down { name } => {
            if let Some(inst) = changed(&Request::Down { name }, device)? {
                println!("{}  {}", inst.name, inst.status);
            }
            Ok(())
        }
        Commands::Rm { name } => {
            if let Some(inst) = changed(&Request::Remove { name }, device)? {
                println!("{}  removed", inst.name);
            }
            Ok(())
        }
        Commands::Rename { name, new_name } => {
            let was = name.clone();
            if let Some(inst) = changed(&Request::Rename { name, new_name }, device)? {
                println!("{was}  renamed to {}", inst.name);
            }
            Ok(())
        }
        // `ast ls` is the orbit's registry; `--local` is one device's shard of
        // it, and `--device X ls` is X's shard. Only the first is the model.
        Commands::Ls { local } => {
            let request = match local || device.is_some() {
                true => Request::List,
                false => Request::ListOrbit,
            };
            match client::ask(&request, device)? {
                Response::Orbit { rows } => format::print_table(&rows),
                // One device's shard, asked for by `--local` or `--device`.
                // Rows from a single shard are live by construction: the
                // device answered.
                Response::Instances { instances } => format::print_table(
                    &instances
                        .into_iter()
                        .map(|instance| OrbitRow { instance, live: true })
                        .collect::<Vec<_>>(),
                ),
                Response::Ok => {}
                _ => return Err(client::unexpected(&request)),
            }
            Ok(())
        }
        Commands::Status { name } => {
            let request = Request::Status { name };
            match client::ask(&request, device)? {
                Response::Instance { instance } => format::print_detail(&instance),
                Response::Ok => {}
                _ => return Err(client::unexpected(&request)),
            }
            Ok(())
        }
        // Which device is running the guest is the daemon's problem, not the
        // user's and not this process's: it answers with a loopback port
        // either way.
        Commands::Ssh { name, command } => {
            client::local_only("ssh", device)?;
            ssh(&name, &command)
        }
        Commands::Logs { name, follow, lines } => {
            client::local_only("logs", device)?;
            logs(&name, follow, lines)
        }
    }
}

/// The instance a command changed, or nothing when the daemon had nothing to
/// say about one.
///
/// Every mutation answers with the row as it now stands, and every one of
/// them prints a different sentence about it — so the reply is unwrapped
/// once, here, and the sentence stays next to the command that owns it.
fn changed(request: &Request, device: Option<&str>) -> Result<Option<Instance>> {
    match client::ask(request, device)? {
        Response::Ok => Ok(None),
        Response::Instance { instance } => Ok(Some(instance)),
        _ => Err(client::unexpected(request)),
    }
}

/// What `ast up` says once the guest is on its way.
fn print_booting(instance: &Instance) {
    println!("{}  {}", instance.name, instance.status);
    // An OCI guest has no ssh to offer, so it is told what it
    // does have: its ports, and its console.
    if instance.image_kind == ImageKind::OciRootfs {
        for p in &instance.publish {
            println!("published: http://127.0.0.1:{}  ->  guest :{}", p.host, p.guest);
        }
        println!("the image's output is on the console — ast logs {}", instance.name);
    } else if let Some(endpoint) = instance.endpoint() {
        println!(
            "guest booting; ssh on {endpoint} — try: ast ssh {}",
            instance.name
        );
    }
}

// ---- ssh -------------------------------------------------------------------

/// `ast ssh <name>`, from anywhere in the orbit.
///
/// The daemon answers with a loopback address whichever device is running the
/// guest: its own forwarded port when the guest is here, or an ephemeral
/// listener spliced over the mesh when it is not. Nothing below this line
/// knows the difference, and neither does the user.
///
/// The connection to the daemon is deliberately held open for the whole
/// session rather than `exec`'d away, because on the spliced path that socket
/// *is* the lease on the listener: when ssh exits and this process drops it,
/// the daemon tears the splice down.
fn ssh(name: &str, command: &[String]) -> Result<()> {
    refuse_ssh_to_an_oci_guest(name)?;
    let mut conn = Conversation::open(&Request::SshEndpoint { name: name.into() })?;
    let (host, port, identity) = match conn.next()? {
        Response::SshEndpoint { host, port, identity } => (host, port, identity),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    };

    // cloud-init needs a little time on first boot. QEMU's user-mode net
    // accepts the TCP connection itself, so a mere connect proves nothing —
    // wait until the guest's sshd actually sends its "SSH-" banner.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    let mut waited = false;
    while !ssh_banner_up(&host, port) {
        if std::time::Instant::now() > deadline {
            bail!("guest ssh did not come up within 180s — check: ast logs {name}");
        }
        if !waited {
            eprintln!("waiting for guest ssh (first boot runs cloud-init) ...");
            waited = true;
        }
        std::thread::sleep(Duration::from_millis(750));
    }

    let status = std::process::Command::new("ssh")
        .arg("-i").arg(&identity)
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "LogLevel=ERROR"])
        .args(["-o", "ConnectionAttempts=30"])
        .arg("-p").arg(port.to_string())
        .arg(format!("ast@{host}"))
        .args(command)
        .status()
        .context("running ssh")?;

    // Dropping the daemon connection is the teardown signal, so do it before
    // exiting rather than leaving it to process cleanup.
    drop(conn);
    std::process::exit(status.code().unwrap_or(1));
}

/// `ast ssh` into an OCI instance, said no to early and in full.
///
/// There is no ssh server in a container image and no cloud-init to install
/// one, so the honest answer is this message rather than three minutes of
/// waiting for a banner that is never coming. What the user wanted is one of
/// the two things named here: the console, or the port.
fn refuse_ssh_to_an_oci_guest(name: &str) -> Result<()> {
    let Ok(Response::Instance { instance }) =
        client::send(&Request::Status { name: name.into() })
    else {
        return Ok(()); // no such instance: let the endpoint request say so
    };
    if instance.image_kind != ImageKind::OciRootfs {
        return Ok(());
    }
    let ports: Vec<String> = instance.publish.iter().map(|p| p.to_string()).collect();
    let reach = match ports.is_empty() {
        true => format!(
            "it publishes no ports — recreate it with, say: \
             ast create {name} --image {} -p 8080:80",
            instance.image.as_deref().unwrap_or("<image>")
        ),
        false => format!("it is reachable on {}", ports.join(", ")),
    };
    bail!(
        "{name} boots an OCI image, which has no ssh server in it — \
         its output is the console (ast logs {name}), and {reach}"
    )
}

fn ssh_banner_up(host: &str, port: u16) -> bool {
    use std::io::Read;
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else { return false };
    let Ok(stream) = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500))
    else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let mut buf = [0u8; 4];
    let mut stream = stream;
    matches!(stream.read_exact(&mut buf), Ok(())) && &buf == b"SSH-"
}

/// Whether this device's own shard holds `name` — i.e. whether the console
/// log is a file we can open rather than bytes we have to ask for.
fn on_this_device(name: &str) -> Result<bool> {
    match client::send(&Request::List)? {
        Response::Instances { instances } => Ok(instances.iter().any(|i| i.name == name)),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

// ---- logs ------------------------------------------------------------------

/// Print the guest's serial console, wherever the guest is.
///
/// When this device is the one supplying the instance's cpu, the console is a
/// file in the instance directory and is read straight off disk — which is
/// also the only way `--follow` can work, since following is a file operation
/// and there is no file here otherwise. When the cpu is elsewhere, the daemon
/// reads it there and sends the tail back.
fn logs(name: &str, follow: bool, lines: u32) -> Result<()> {
    if !on_this_device(name)? {
        if follow {
            bail!(
                "following a console log across the orbit is not built yet — \
                 `ast logs {name}` prints the last lines of it"
            );
        }
        return match client::send(&Request::Logs { name: name.into(), lines })? {
            Response::Log { text, truncated } => {
                if truncated {
                    eprintln!("(last {lines} lines — more with: ast logs {name} -n 0)");
                }
                println!("{text}");
                Ok(())
            }
            Response::Error { message } => bail!(message),
            other => bail!("unexpected reply from astd: {other:?}"),
        };
    }
    logs_here(name, follow)
}

/// The console log as a file on this device's disk.
fn logs_here(name: &str, follow: bool) -> Result<()> {
    let path = paths::instance_dir(name).join("console.log");
    let mut file = File::open(&path).map_err(|_| {
        anyhow::anyhow!(
            "no console log for {name:?} yet — `ast up {name}` starts one at {}",
            path.display()
        )
    })?;

    let mut out = std::io::stdout();
    drain(&mut file, &mut out)?;
    if !follow {
        return Ok(());
    }

    // tail -f without the tail: the read cursor stays where the last drain
    // left it, so each poll picks up exactly what the guest appended. A
    // fresh `ast up` truncates the file; that shows up as a shrink, and we
    // reopen rather than sit and wait for the guest to write past the old
    // offset.
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let read_to = file.stream_position()?;
        if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(read_to) < read_to {
            file = File::open(&path)?;
        }
        drain(&mut file, &mut out)?;
    }
}

/// Copy everything the file has left to stdout. A closed pipe
/// (`ast logs dev | head`) is a normal way for the reader to stop, not an
/// error to report.
fn drain(file: &mut File, out: &mut std::io::Stdout) -> Result<u64> {
    match std::io::copy(file, out).and_then(|n| out.flush().map(|()| n)) {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        Err(e) => Err(e).context("reading the console log"),
    }
}

// ---- parsing ---------------------------------------------------------------

fn parse_mem_mib(s: &str) -> Result<u32> {
    let s = s.trim();
    if let Some(g) = s.strip_suffix(['G', 'g']) {
        return Ok(g.parse::<u32>().context("bad --mem")? * 1024);
    }
    let m = s.strip_suffix(['M', 'm']).unwrap_or(s);
    m.parse::<u32>().context("bad --mem (try 2048M or 4G)")
}

fn parse_disk_gib(s: &str) -> Result<u32> {
    let g = s.trim().strip_suffix(['G', 'g']).unwrap_or(s.trim());
    g.parse::<u32>().context("bad --disk (try 20G)")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--mem` is the one flag people write three ways, and the refusal has
    /// to name the flag: a bare "invalid digit" from the parser tells the
    /// user nothing about which of six arguments was wrong.
    #[test]
    fn memory_is_read_in_whichever_unit_it_was_written() {
        assert_eq!(parse_mem_mib("2048M").unwrap(), 2048);
        assert_eq!(parse_mem_mib("2048m").unwrap(), 2048);
        assert_eq!(parse_mem_mib("4G").unwrap(), 4096);
        assert_eq!(parse_mem_mib("4g").unwrap(), 4096);
        // No suffix means what the field is measured in.
        assert_eq!(parse_mem_mib(" 512 ").unwrap(), 512);
        assert!(parse_mem_mib("lots").unwrap_err().to_string().contains("--mem"));
    }

    #[test]
    fn a_disk_is_gibibytes_with_or_without_the_g() {
        assert_eq!(parse_disk_gib("20G").unwrap(), 20);
        assert_eq!(parse_disk_gib("20g").unwrap(), 20);
        assert_eq!(parse_disk_gib(" 20 ").unwrap(), 20);
        assert!(parse_disk_gib("20T").unwrap_err().to_string().contains("--disk"));
    }
}
