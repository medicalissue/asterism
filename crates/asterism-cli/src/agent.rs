//! `ast create --agent`, `ast attach`, `ast logs` — the agent scene.
//!
//! One command puts a named agent on a machine you own, authenticated, with
//! a repository checked out and a session running, and one more command drops
//! you into that session from anywhere. What that is worth over tmux, ssh and
//! a VPN is the second half: **the key never enters the box**. The guest is
//! given an opaque handle; the egress door on this device swaps it for the
//! real value on its way to exactly one authority. So the disk, the snapshot,
//! the console log and the bug report all have a handle in them and none of
//! them has a credential, and an agent that runs untrusted code cannot exfil
//! a key it was never given.
//!
//! Everything here is composed out of verbs Asterism already has —
//! `create`, `volume create`, `attach --volume`, `attach --secret`, `up`,
//! `exec` — deliberately, so that `--agent` is a *shorthand for a sequence a
//! person could type*, not a second way to make an instance. The one thing it
//! adds is the order and the refusals.
//!
//! ## The refusal comes first
//!
//! A required secret that does not exist is refused before the image is
//! pulled and before anything is created, because a half-built agent that
//! cannot authenticate is worse than no agent: it costs a gigabyte and a
//! minute, and then it has to be cleaned up by hand.
//!
//! ## What lives where
//!
//! The root disk is the image, and it is disposable. The workspace — the
//! cloned repository, the pane log, the session's start script — is a block
//! volume mounted at the preset's `workdir`, so a snapshot and restore of the
//! root disk leaves the work alone, and the agent comes back to it.

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use asterism_core::fix::{Fix, Fixable};
use asterism_core::instance::{Restart, Shape};
use asterism_core::preset::{self, AgentRecord, Preset};
use asterism_core::protocol::{Request, Response};
use asterism_core::{image, paths};

use crate::{local_only, send, ssh_banner_up, Conversation};

/// How long the guest gets to come up far enough to answer guest control.
const READY_TIMEOUT: Duration = Duration::from_secs(240);

/// Where an agent's workspace lives on this device.
///
/// Under the Asterism home rather than under the instance's own directory, so
/// that `ast rm` — which deletes everything in an instance's directory — does
/// not take a week of the agent's work with it. Removing an agent's workspace
/// is a second, deliberate command.
pub(crate) fn workspace_dir(name: &str) -> PathBuf {
    paths::home_dir().join("work").join(name)
}

/// Make and attach everything past the workspace that a preset declares.
///
/// Each mount is a host directory shared into the guest, for the same reasons
/// the workspace is: the host can see it, a fork can copy it, and the rewind
/// engine already knows how to clone and restore a tree. What the lifecycle
/// adds is which of them a rewind puts back — `ast rewind` rolls the
/// workspace and the root disk back and leaves memory and cache alone, so the
/// box comes back twenty minutes ago still holding the conversation.
///
/// A cache directory is named after its key, so the second agent box on this
/// device attaches the very directory the first one warmed.
fn attach_preset_mounts(name: &str, preset: &Preset) -> Result<()> {
    let root = paths::home_dir();
    for mount in &preset.mounts {
        let dir = mount.host_dir(&root, name);
        std::fs::create_dir_all(&dir).with_context(|| format!("making {}", dir.display()))?;
        ok(&Request::AttachVolume {
            name: name.to_owned(),
            path: dir.display().to_string(),
            host: None,
            mount_point: Some(mount.at.clone()),
            lifecycle: mount.lifecycle,
        })
        .with_context(|| format!("attaching {} to {name} at {}", dir.display(), mount.at))?;
    }
    Ok(())
}

/// The refusal for a required secret this orbit does not have.
///
/// A [`Fixable`], so the sentence stays exactly what the user should read and
/// the command they should type is also machine-readable — `ast --json` puts
/// it in a `fix` field, and `error_lines` prints it under the message.
fn missing_secret(preset: &Preset, secret: &preset::PresetSecret) -> anyhow::Error {
    anyhow::Error::new(Fixable::new(
        preset.missing_secret_refusal(secret),
        Fix::new(format!("ast secret add {}", secret.name)),
    ))
}

/// `ast agents` — what this device can be asked for.
pub(crate) fn print_catalog() -> Result<()> {
    let catalog = preset::catalog()?;
    println!("{:<16} {:<44} SUMMARY", "AGENT", "IMAGE");
    for preset in &catalog {
        let name = match preset.experimental {
            true => format!("{} (experimental)", preset.name),
            false => preset.name.clone(),
        };
        println!("{:<16} {:<44} {}", name, preset.image, preset.summary);
    }
    println!();
    println!("your own go in {}", preset::user_dir().display());
    Ok(())
}

/// `ast create <name> --agent <preset> [--repo <url>]`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn create(
    device: Option<&str>,
    name: &str,
    agent: &str,
    repo: Option<&str>,
    shape: Shape,
    backend: Option<String>,
) -> Result<()> {
    local_only("create --agent", device)?;
    let preset = preset::get(agent)?;

    // ---- everything that can be refused, refused first --------------------
    let have = orbit_secret_names()?;
    if let Some(missing) = preset.missing_required(&have).first() {
        return Err(missing_secret(&preset, missing));
    }
    let repo_path = match repo {
        Some(url) => Some(preset::repo_dir(&preset.workdir, url)?),
        None => None,
    };
    // The guest key has to exist before the guest does: it is what `ast
    // attach` will authenticate with, and generating it after the instance
    // is up would mean a boot that cannot be attached to.
    let public_key =
        asterism_core::seed::ensure_asterism_key().context("preparing this device's guest key")?;

    // ---- the image ---------------------------------------------------------
    let reference = preset.image_reference();
    let started = Instant::now();
    let pulled = image::pull(&reference).with_context(|| format!("pulling {reference}"))?;
    println!(
        "pulling {reference} … done ({}, {} s)",
        mib(pulled.bytes),
        started.elapsed().as_secs()
    );

    // ---- the instance and its parts ---------------------------------------
    ok(&Request::Create {
        name: name.to_owned(),
        image: pulled.reference.clone(),
        shape,
        backend,
        profiles: Vec::new(),
        publish: Vec::new(),
    })?;

    // A shared directory rather than a block volume, and the difference is
    // the whole reason the workspace exists: the repository, the session's
    // start script and the pane log are not on the root disk, so snapshotting
    // and restoring the root disk — or throwing the instance away and making
    // it again — leaves the work exactly where it was. It is also a directory
    // on this device, so the clone is one you can open in your own editor
    // while the agent works in it.
    let workspace = workspace_dir(name);
    std::fs::create_dir_all(&workspace)
        .with_context(|| format!("making {}", workspace.display()))?;
    ok(&Request::AttachVolume {
        name: name.to_owned(),
        path: workspace.display().to_string(),
        host: None,
        mount_point: Some(preset.workdir.clone()),
        // Instance data: the workspace is what a rewind is *for*. Rolling the
        // box back twenty minutes and leaving the repository as it is would
        // be a rewind that undid nothing anybody cares about.
        lifecycle: asterism_core::volume::Lifecycle::Instance,
    })
    .with_context(|| format!("attaching the workspace to {name}"))?;

    // The agent's memory, and the caches it shares with every other agent box
    // on this device. Declared in the preset rather than decided here, so the
    // thing that keeps `claude --resume` working across `ast rewind` is three
    // lines of JSON next to the agent that needs it.
    attach_preset_mounts(name, &preset)?;

    for binding in secret_bindings(name, &preset, &have)? {
        ok(&binding).with_context(|| format!("binding a secret to {name}"))?;
    }

    boot(name)?;

    // ---- inside the guest --------------------------------------------------
    wait_ready(name, &preset)?;

    let mut record = AgentRecord {
        preset: preset.name.clone(),
        session: name.to_owned(),
        workdir: preset.workdir.clone(),
        repo_path: repo_path.clone(),
        repo_url: repo.map(str::to_owned),
        start: preset.start.clone(),
        version: None,
    };

    let state = format!("{}/.asterism", preset.workdir);
    let vars = preset
        .secrets
        .iter()
        .map(|s| s.env_var())
        .collect::<Vec<_>>()
        .join("\n");
    guest_write(name, &format!("{state}/authorized_keys"), &public_key)?;
    guest_write(name, &format!("{state}/agent.vars"), &vars)?;
    guest_write(name, &format!("{state}/start.sh"), &record.start_script())?;
    guest(
        name,
        "install the host guest key and republish the environment",
        &format!(
            "mkdir -p /root/.ssh && chmod 0700 /root/.ssh && \
             cp {state}/authorized_keys /root/.ssh/authorized_keys && \
             chmod 0600 /root/.ssh/authorized_keys && \
             /usr/local/sbin/asterism-agent-env"
        ),
        60,
    )?;

    if let (Some(url), Some(path)) = (repo, repo_path.as_deref()) {
        clone(name, url, path, &preset, &have)?;
    }

    record.version = detect_version(name, &preset);
    guest(
        name,
        "start the agent session",
        &format!("sh {state}/start.sh"),
        120,
    )?;
    write_record(name, &record)?;

    println!("{}", ready_line(name, &record));
    Ok(())
}

/// One `AttachSecret` per preset secret this orbit actually has.
///
/// Only the secrets that exist. A required one that does not was refused
/// before any of this; an optional one that does not is simply not bound, and
/// the agent is told nothing about it — which is the honest outcome, because
/// an empty variable that looks like a credential is worse than no variable.
///
/// A function rather than a loop inside the create, because "the handle goes
/// in the variable the preset named, bound to the one authority it named, with
/// the placement it named" is the security-relevant half of this whole path
/// and deserves to be checked without booting anything.
fn secret_bindings(name: &str, preset: &Preset, have: &[String]) -> Result<Vec<Request>> {
    let mut bindings = Vec::new();
    for secret in &preset.secrets {
        if !have.iter().any(|h| h == &secret.name) {
            continue;
        }
        bindings.push(Request::AttachSecret {
            name: name.to_owned(),
            secret: secret.name.clone(),
            authority: secret.authority.clone(),
            placement: secret
                .placement
                .as_deref()
                .map(asterism_core::secret::Placement::parse)
                .transpose()?,
            env: Some(secret.env_var().to_owned()),
            source_device: None,
        });
    }
    Ok(bindings)
}

/// The line that says the scene worked.
///
/// A pure function so the wording is a test rather than something only a
/// real boot can check.
pub(crate) fn ready_line(name: &str, record: &AgentRecord) -> String {
    let version = match &record.version {
        Some(version) => format!("{} {version}", record.preset),
        None => record.preset.clone(),
    };
    let repo = match &record.repo_path {
        Some(path) => format!("repo cloned to {path}, "),
        None => String::new(),
    };
    format!(
        "{name} is up — {version}, {repo}session \"{}\" running",
        record.session
    )
}

/// `ast attach <name>` — the tmux session, from anywhere.
pub(crate) fn attach(device: Option<&str>, name: &str) -> Result<()> {
    local_only("attach", device)?;
    let record = read_record(name)?.ok_or_else(|| {
        anyhow::anyhow!(
            "{name} is not an agent instance — say which part to attach \
             (--volume, --secret, --gpu), or make an agent with \
             `ast create {name} --agent claude-code`"
        )
    })?;

    let mut conn = Conversation::open(&Request::SshEndpoint {
        name: name.to_owned(),
    })?;
    let (host, port, identity) = match conn.next()? {
        Response::SshEndpoint {
            host,
            port,
            identity,
        } => (host, port, identity),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    };

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut waited = false;
    while !ssh_banner_up(&host, port) {
        if Instant::now() > deadline {
            bail!("{name}'s ssh server did not answer — check: ast logs {name} --console");
        }
        if !waited {
            eprintln!("waiting for {name} ...");
            waited = true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    let status = std::process::Command::new("ssh")
        .args(ssh_options(&identity, port))
        .arg("-t")
        .arg(format!("root@{host}"))
        .arg(record.attach_command())
        .status()
        .context("running ssh")?;
    drop(conn);
    std::process::exit(status.code().unwrap_or(1));
}

/// The ssh options `ast attach` uses, in order.
///
/// A separate function so the shape of the command is a unit test: a guest
/// that is recreated gets a new host key every time, and an attach that
/// stopped to ask about it would be an attach that hangs in a script.
pub(crate) fn ssh_options(identity: &str, port: u16) -> Vec<String> {
    vec![
        "-i".into(),
        identity.to_owned(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
        "-p".into(),
        port.to_string(),
    ]
}

/// `ast logs <name>` for an agent: the tmux pane, not the console.
pub(crate) fn logs(name: &str, follow: bool, lines: u32) -> Result<()> {
    let record =
        read_record(name)?.ok_or_else(|| anyhow::anyhow!("{name} is not an agent instance"))?;
    let log = record.log_path();

    let tail = match lines {
        0 => format!("cat {log} 2>/dev/null || true"),
        n => format!("tail -n {n} {log} 2>/dev/null || true"),
    };
    let first = guest(name, "read the agent pane", &tail, 30)?;
    print!("{first}");
    std::io::stdout().flush()?;
    if !follow {
        return Ok(());
    }

    // Follow by byte offset rather than by holding a pipe open: guest control
    // is a bounded request/response channel on purpose, and a long-lived
    // stream through it would be a second protocol.
    let mut offset = guest(
        name,
        "measure the agent pane",
        &format!("wc -c < {log} 2>/dev/null || echo 0"),
        30,
    )?
    .trim()
    .parse::<u64>()
    .unwrap_or(0);
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let more = guest(
            name,
            "follow the agent pane",
            &format!("tail -c +{} {log} 2>/dev/null || true", offset + 1),
            30,
        )?;
        if !more.is_empty() {
            print!("{more}");
            std::io::stdout().flush()?;
            offset += more.len() as u64;
        }
    }
}

/// Whether this instance is one `--agent` made.
pub(crate) fn is_agent(name: &str) -> bool {
    matches!(read_record(name), Ok(Some(_)))
}

/// Type one instruction into a fork's running agent session.
///
/// What `ast fork --each` is for. A fork boots from a cloned disk, so its
/// agent comes up in the same session the parent's did, holding the same
/// context — and the only thing missing is the sentence saying which of the
/// three approaches this copy is meant to take. This is that sentence,
/// arriving where a person sitting at `ast session <fork>` would have typed
/// it.
///
/// The message goes in through a file and a tmux paste buffer rather than
/// through `send-keys -l`: an instruction is a sentence somebody wrote, and
/// putting it in argv would mean quoting it correctly through the daemon,
/// `/bin/sh` and tmux in turn. `load-buffer` reads bytes and stops there.
///
/// `Ok(false)` when this instance is not an agent — a fork of a plain
/// instance has no session to type into, and its note is the file in its
/// working volume.
pub(crate) fn tell(name: &str, message: &str) -> Result<bool> {
    let Some(record) = read_record(name)? else {
        return Ok(false);
    };
    let path = format!("{}/.asterism/fork-note", record.workdir);
    guest_write(name, &path, message)?;
    let session = &record.session;
    // The session is started by the image's entrypoint, so a fork that has
    // only just booted may not have one yet. Waiting is the whole reason
    // this is not one `send-keys`.
    guest(
        name,
        "give the fork its instruction",
        &format!(
            "for _ in $(seq 1 60); do\n\
             \x20 tmux has-session -t {session} 2>/dev/null && break\n\
             \x20 sleep 1\n\
             done\n\
             tmux has-session -t {session} 2>/dev/null || exit 1\n\
             tmux load-buffer -b asterism-fork {path}\n\
             tmux paste-buffer -b asterism-fork -d -t {session}\n\
             tmux send-keys -t {session} Enter\n"
        ),
        120,
    )?;
    Ok(true)
}

// ---- the guest side --------------------------------------------------------

/// Run a shell fragment in the guest and give back its stdout.
///
/// Every write below goes through this rather than through ssh, because at
/// this point in a create there is no ssh yet: the authorized key is one of
/// the things being written. Guest control is authenticated with a key pid 1
/// was handed at boot, and it is bounded, which is exactly right for the
/// short, total commands here.
fn guest(name: &str, what: &str, script: &str, timeout_secs: u64) -> Result<String> {
    match send(&Request::Exec {
        name: name.to_owned(),
        command: vec!["/bin/sh".into(), "-c".into(), script.to_owned()],
        timeout_ms: timeout_secs.saturating_mul(1000),
    })? {
        Response::Exec {
            status,
            stdout,
            stderr,
            ..
        } => {
            if status != 0 {
                bail!(
                    "could not {what} in {name} (exit {status}): {}",
                    stderr.trim()
                );
            }
            Ok(stdout)
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// Write a file into the guest without putting its content in argv.
///
/// A heredoc with a delimiter the content does not contain, so a start script
/// full of quotes arrives as itself. The content here is never a credential —
/// it is a public key, a list of variable *names*, and a tmux command — but
/// the same shape is what a credential would need, and having two shapes is
/// how the wrong one gets used.
fn guest_write(name: &str, path: &str, content: &str) -> Result<()> {
    let mut delimiter = "ASTERISM_AGENT_EOF".to_owned();
    while content.lines().any(|line| line == delimiter) {
        delimiter.push('X');
    }
    let body = match content.ends_with('\n') {
        true => content.to_owned(),
        false => format!("{content}\n"),
    };
    let dir = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("/");
    guest(
        name,
        &format!("write {path}"),
        &format!("mkdir -p {dir} && cat > {path} <<'{delimiter}'\n{body}{delimiter}\n"),
        30,
    )?;
    Ok(())
}

/// Wait for the guest to be an agent workspace, not merely a booted machine.
///
/// Two things, and the second is the one that matters: guest control answers
/// (the daemon admitted the agent), and the image's own entrypoint has
/// finished mounting the workspace volume. Writing the start script before
/// the volume is mounted would put it on the root disk, where a restore would
/// silently drop it.
fn wait_ready(name: &str, preset: &Preset) -> Result<()> {
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut announced = false;
    loop {
        if let Ok(out) = guest(
            name,
            "ask whether the workspace is ready",
            "test -f /run/asterism-agent.ready && echo ready",
            20,
        ) {
            if out.trim() == "ready" {
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            bail!(
                "{name} did not become an agent workspace within {}s — its console is \
                 `ast logs {name} --console`; the image must mount {} and touch \
                 /run/asterism-agent.ready",
                READY_TIMEOUT.as_secs(),
                preset.workdir
            );
        }
        if !announced {
            eprintln!("waiting for {name} to come up ...");
            announced = true;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Clone the repository into the workspace.
///
/// When the preset declares a `GITHUB_TOKEN` and the orbit has one, git is
/// given the handle as an `Authorization` header rather than in the url:
/// a url with a credential in it lands in `.git/config`, in the reflog and in
/// every `git remote -v` — and the whole point of this lane is that nothing
/// like that is on the disk. The handle is worthless anywhere but through
/// this instance's door, and it is not written to the repository either.
fn clone(name: &str, url: &str, path: &str, preset: &Preset, have: &[String]) -> Result<()> {
    let token = preset
        .secrets
        .iter()
        .find(|s| s.name == "GITHUB_TOKEN" && have.iter().any(|h| h == &s.name))
        .map(|s| s.env_var().to_owned());
    let auth = match &token {
        Some(var) => format!("-c http.extraHeader=\"Authorization: Bearer ${var}\" "),
        None => String::new(),
    };
    guest(
        name,
        &format!("clone {url}"),
        &format!(
            // git's libcurl does not always pick the egress CA up from
            // CURL_CA_BUNDLE, and a clone that fails on a certificate the
            // guest was handed at boot is the least explicable failure this
            // path has. Naming it in git's own variable settles it.
            "if [ -d {path}/.git ]; then exit 0; fi\n\
             [ -n \"${{CURL_CA_BUNDLE:-}}\" ] && export GIT_SSL_CAINFO=\"$CURL_CA_BUNDLE\"\n\
             git {auth}clone --depth 1 {url} {path}"
        ),
        asterism_core::guest::MAX_EXEC_TIMEOUT.as_secs(),
    )?;
    Ok(())
}

/// What the agent CLI in the guest says its version is.
///
/// Read from the guest rather than from the preset, because the preset says
/// what was asked for and the guest says what is there. A probe that fails is
/// not a failed create: the agent is running either way, and a missing
/// version is reported as a missing version.
fn detect_version(name: &str, preset: &Preset) -> Option<String> {
    let out = guest(
        name,
        "ask the agent its version",
        &format!("{} 2>/dev/null", preset.version_probe),
        60,
    )
    .ok()?;
    version_of(&out)
}

/// The version out of a `--version` line: the first word that is a version,
/// so `2.1.247 (Claude Code)`, `codex-cli 0.4.0` and `v1.2.3` all work.
///
/// Read rather than assumed, because the preset says what was asked for and
/// only the guest can say what is installed — and `latest` in a preset means
/// the answer is different next month.
pub(crate) fn version_of(output: &str) -> Option<String> {
    output
        .lines()
        .next()?
        .split_whitespace()
        .filter_map(|word| word.strip_prefix('v').or(Some(word)))
        .find(|word| word.starts_with(|c: char| c.is_ascii_digit()))
        .map(str::to_owned)
}

// ---- the record ------------------------------------------------------------

fn record_path(name: &str) -> PathBuf {
    paths::instance_dir(name).join("agent.json")
}

fn write_record(name: &str, record: &AgentRecord) -> Result<()> {
    let path = record_path(name);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(record)?)
        .with_context(|| format!("writing {}", path.display()))
}

fn read_record(name: &str) -> Result<Option<AgentRecord>> {
    let path = record_path(name);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    Ok(Some(
        serde_json::from_str(&text).with_context(|| format!("reading {}", path.display()))?,
    ))
}

// ---- odds and ends ---------------------------------------------------------

/// Boot the agent, surviving a first boot that does not take.
///
/// An instance's very first boot is the one that materializes a gigabyte of
/// root disk from the image while the daemon is already serving this
/// instance's other parts, and on this device that has been observed to lose
/// a part and take the VMM down with it — after which the boot rolls back and
/// leaves a stopped instance behind. Every later boot has the disk already
/// and comes up first time, which is why retrying works at all and why it is
/// bounded rather than a loop.
///
/// This is a workaround for a race below this command, not a fix for it. The
/// workspace is a shared directory rather than a block volume partly for the
/// same reason, and `docs/evidence/agent-preset-2026-08-27/README.md` records
/// what was seen.
///
/// It is announced rather than hidden. A boot that had to be retried is worth
/// knowing about, and a scene that quietly took three times as long as it
/// says it does is a scene nobody trusts the second time.
fn boot(name: &str) -> Result<()> {
    const TRIES: u32 = 3;
    let mut last = None;
    for attempt in 1..=TRIES {
        match ok(&Request::Up {
            name: name.to_owned(),
            // `always`, because "the agent keeps running" has to survive a
            // crash and a host reboot, not merely a closed terminal.
            restart: Some(Restart::Always),
        }) {
            Ok(()) => {
                if attempt > 1 {
                    eprintln!("{name} came up on boot {attempt} of {TRIES}");
                }
                return Ok(());
            }
            Err(error) => {
                if attempt < TRIES {
                    eprintln!(
                        "{name} did not come up ({error:#}); trying again — the first \
                         boot of an instance builds its root disk while its other \
                         parts are already being served"
                    );
                }
                last = Some(error);
            }
        }
    }
    Err(last.expect("a failed boot has an error"))
}

/// Send one request and keep only whether it worked.
///
/// Not `send_ok`: the commands composed here answer with the rows they
/// changed — a create says what it defined, an attach says what is attached —
/// and this path prints its own single line at the end instead of each of
/// theirs. Only a refusal is worth carrying up.
fn ok(request: &Request) -> Result<()> {
    match send(request)? {
        Response::Error { message } => bail!(message),
        _ => Ok(()),
    }
}

fn orbit_secret_names() -> Result<Vec<String>> {
    match send(&Request::SecretList)? {
        Response::Secrets { secrets } => Ok(secrets.into_iter().map(|s| s.name).collect()),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// Bytes as the size a person would say out loud.
pub(crate) fn mib(bytes: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    let mib = bytes as f64 / MIB;
    if mib >= 1024.0 {
        return format!("{:.1} GiB", mib / 1024.0);
    }
    format!("{} MiB", mib.round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> AgentRecord {
        AgentRecord {
            preset: "claude-code".into(),
            session: "bot".into(),
            workdir: "/work".into(),
            repo_path: Some("/work/app".into()),
            repo_url: Some("https://github.com/me/app.git".into()),
            start: "claude".into(),
            version: Some("2.1.247".into()),
        }
    }

    #[test]
    fn the_ready_line_says_agent_version_repository_and_session() {
        assert_eq!(
            ready_line("bot", &record()),
            "bot is up — claude-code 2.1.247, repo cloned to /work/app, session \"bot\" running"
        );
    }

    #[test]
    fn an_agent_with_no_repository_does_not_claim_one() {
        let mut record = record();
        record.repo_path = None;
        assert_eq!(
            ready_line("bot", &record),
            "bot is up — claude-code 2.1.247, session \"bot\" running"
        );
    }

    #[test]
    fn an_agent_whose_version_could_not_be_read_says_so_by_omission() {
        let mut record = record();
        record.version = None;
        record.repo_path = None;
        assert_eq!(
            ready_line("bot", &record),
            "bot is up — claude-code, session \"bot\" running"
        );
    }

    #[test]
    fn a_version_is_the_first_word_that_starts_with_a_digit() {
        assert_eq!(version_of("2.1.247 (Claude Code)").unwrap(), "2.1.247");
        assert_eq!(version_of("codex-cli 0.4.0\n").unwrap(), "0.4.0");
        assert_eq!(version_of("v1.2.3").unwrap(), "1.2.3");
        assert_eq!(version_of("command not found"), None);
        assert_eq!(version_of(""), None);
    }

    #[test]
    fn attach_never_stops_to_ask_about_a_host_key_it_has_never_seen() {
        let options = ssh_options("/home/me/.asterism/id_ed25519", 22);
        assert_eq!(options[0], "-i");
        assert_eq!(options[1], "/home/me/.asterism/id_ed25519");
        assert!(options.contains(&"StrictHostKeyChecking=no".to_owned()));
        assert!(options.contains(&"UserKnownHostsFile=/dev/null".to_owned()));
        assert_eq!(options[options.len() - 2], "-p");
        assert_eq!(options[options.len() - 1], "22");
    }

    #[test]
    fn a_missing_required_secret_refuses_with_the_command_that_fixes_it() {
        let preset =
            asterism_core::preset::Preset::parse(include_str!("../../../presets/codex.json"))
                .unwrap();
        let missing = preset.missing_required::<&str>(&[]);
        let error = missing_secret(&preset, missing[0]);
        assert_eq!(
            error.to_string(),
            "preset codex needs secret OPENAI_API_KEY — run `ast secret add OPENAI_API_KEY` first"
        );
        assert_eq!(
            asterism_core::fix::of(&error).unwrap().command,
            "ast secret add OPENAI_API_KEY"
        );
    }

    #[test]
    fn a_handle_lands_in_the_variable_the_preset_named_and_nowhere_else() {
        let preset =
            asterism_core::preset::Preset::parse(include_str!("../../../presets/claude-code.json"))
                .unwrap();
        let have = vec!["ANTHROPIC_API_KEY".to_owned(), "GITHUB_TOKEN".to_owned()];
        let bindings = secret_bindings("bot", &preset, &have).unwrap();
        assert_eq!(bindings.len(), 2);
        match &bindings[0] {
            Request::AttachSecret {
                name,
                secret,
                authority,
                placement,
                env,
                source_device,
            } => {
                assert_eq!(name, "bot");
                assert_eq!(secret, "ANTHROPIC_API_KEY");
                assert_eq!(authority, "api.anthropic.com");
                assert_eq!(env.as_deref(), Some("ANTHROPIC_API_KEY"));
                assert!(placement.is_some());
                assert!(source_device.is_none());
            }
            other => panic!("not an AttachSecret: {other:?}"),
        }
    }

    #[test]
    fn an_optional_secret_this_orbit_does_not_have_is_simply_not_bound() {
        let preset =
            asterism_core::preset::Preset::parse(include_str!("../../../presets/claude-code.json"))
                .unwrap();
        let bindings = secret_bindings("bot", &preset, &["ANTHROPIC_API_KEY".to_owned()]).unwrap();
        assert_eq!(bindings.len(), 1);
        assert!(secret_bindings("bot", &preset, &[]).unwrap().is_empty());
    }

    #[test]
    fn the_workspace_is_not_inside_the_instance_directory_ast_rm_deletes() {
        let workspace = workspace_dir("bot");
        assert!(workspace.ends_with("work/bot"), "{}", workspace.display());
        assert!(
            !workspace.starts_with(asterism_core::paths::instance_dir("bot")),
            "{}",
            workspace.display()
        );
    }

    #[test]
    fn sizes_read_the_way_a_person_says_them() {
        assert_eq!(mib(410 * 1024 * 1024), "410 MiB");
        assert_eq!(mib(2 * 1024 * 1024 * 1024), "2.0 GiB");
        assert_eq!(mib(0), "0 MiB");
    }
}
