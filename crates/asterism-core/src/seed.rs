//! cloud-init seeds and the ssh identity that goes in them.
//!
//! Backend-neutral by construction: a NoCloud seed is an ISO9660 image, and
//! every hypervisor on the roadmap can attach one as a read-only disk —
//! QEMU as a virtio drive, Virtualization.framework as a
//! `VZDiskImageStorageDeviceAttachment`. Backends receive a built seed in
//! `BootReq::seed`; they never build one.
//!
//! Per-instance files this module owns, in `~/.asterism/instances/<name>/`:
//!   seed.iso    — the NoCloud image
//!   seed.stamp  — fingerprint of what the current seed.iso was built from
//!   seed-files/ — staging directory, removed after each build

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::hv::ShareKind;
use crate::instance::{Instance, Volume};
use crate::profile::Bootstrap;
use crate::tools::{run, tool};
use crate::{instance, paths};

/// Bumped when the seed template changes, so an upgraded daemon reissues
/// seeds that were written by an older one.
///
/// 3: guest key durability — a `sync` at the end of cloud-init's final
/// stage, and a unit that regenerates missing host keys at boot.
/// 4: secrets egress — the per-instance CA, the proxy environment, and the
/// opaque handles that stand in for values.
/// 5: directory-share transport is part of the seed. A guest moving between
/// capable backends must replace a 9p unit with a virtiofs unit (or back),
/// even when the host paths and mount points did not change.
///
/// What earns a bump is a change to what a seed says about an instance that
/// already exists. Bootstrap profiles did not: an instance with none gets a
/// byte-identical seed, and an instance with one cannot have been created by
/// a daemon that did not have them. Reissuing every seed in every orbit for
/// a feature none of those guests use would have handed each of them a new
/// `instance-id` — and with it a first boot it has already had, host keys
/// included.
pub const SEED_TEMPLATE_VERSION: u32 = 5;

/// One locally-hosted volume, resolved into everything the two sides of a
/// directory share have to agree on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The directory on this device.
    pub host_path: String,
    /// Where it lands inside the guest.
    pub guest_path: String,
    /// The mount tag the two sides rendezvous on.
    pub tag: String,
    /// `host:path`, for humans reading the guest's unit files.
    pub label: String,
}

impl Share {
    pub fn new(volume: &Volume) -> Self {
        Share {
            host_path: volume.path.clone(),
            guest_path: volume.guest_path(),
            tag: volume.mount_tag(),
            label: format!("{}:{}", volume.host, volume.path),
        }
    }

    /// Name of the systemd unit that mounts this share in the guest.
    /// systemd derives `.mount` unit names from the mount point, and
    /// refuses to load a unit whose name does not match its `Where=`.
    pub fn unit(&self) -> String {
        format!("{}.mount", systemd_path_escape(&self.guest_path))
    }
}

/// What a guest is told about its egress proxy, and the whole of what a seed
/// says about secrets.
///
/// Read the fields and the invariant reads itself: an address, a certificate,
/// a list of hostnames, and a handle per secret. No value, and nothing a
/// value could be derived from. A seed ISO is a file on disk that a guest
/// mounts and that `ast logs` will happily show you the cloud-init log of, so
/// what may go in it is exactly what may be public to whoever holds the
/// instance — which is what a handle is for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Egress {
    /// Where the guest reaches the proxy: `http://10.0.2.2:38123`.
    pub proxy: String,
    /// PEM of this instance's own CA, whose private key stays on the host.
    pub ca_pem: String,
    /// The authorities that have a binding, so the guest's `NO_PROXY` can be
    /// the complement rather than the proxy being asked to carry everything.
    pub authorities: Vec<String>,
    /// `(environment variable, opaque handle)`, one per bound secret.
    pub handles: Vec<(String, String)>,
}

/// Backend-neutral and backend-supplied facts that determine one NoCloud
/// seed. Keeping these together means adding a new seed artifact does not
/// widen the seed builder's call boundary.
pub struct Input<'a> {
    pub shares: &'a [Share],
    pub share_kind: Option<ShareKind>,
    pub extra: &'a str,
    pub network_config: Option<&'a str>,
    pub egress: &'a Egress,
    pub bootstrap: &'a Bootstrap,
}

impl Egress {
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

/// The directory volumes this device can actually share into the guest.
///
/// Two filters, and they are different rules. Neither 9p nor virtiofs has a
/// network transport, and neither ever will — the backend has to map the
/// guest's memory — so a directory on another device is a record and nothing
/// more. And a block volume is not a share at all: it reaches the guest as a
/// disk, over NBD, and the guest mounts whatever filesystem it finds on it.
pub fn shares(inst: &Instance) -> Vec<Share> {
    inst.volumes
        .iter()
        .filter(|v| !v.is_block() && v.is_local())
        .map(Share::new)
        .collect()
}

/// Build the seed if it is missing, or if what it should say has changed
/// since it was built. Attaching a volume to an instance that has already
/// booted lands here: the fingerprint moves, the ISO is rewritten, and the
/// new `instance-id` inside it makes the guest's cloud-init treat the next
/// boot as a first boot and apply the new mounts.
///
/// `extra` is cloud-config the *backend* needs in the guest — see
/// [`crate::hv::Hypervisor::guest_config`]. It is appended verbatim, so it
/// arrives in the guest exactly as the backend wrote it.
///
/// `network` is a NoCloud `network-config` document the *backend* needs
/// in the guest — see [`crate::hv::Hypervisor::guest_network_config`]. It
/// is written as a sibling of `user-data`, not merged into cloud-config,
/// because cloud-init applies it before its Network Stage. `None` or empty
/// writes no file and does not move the fingerprint.
///
/// `bootstrap` is the instance's profiles ([`crate::profile`]), and it rides
/// the same mechanism for the same reason: bump a profile's version and the
/// fingerprint moves, so a guest that has been up for a month applies the
/// new work at its next boot rather than staying at whatever it was built
/// with.
pub fn ensure(name: &str, seed: &Path, input: Input<'_>) -> Result<()> {
    if !input.shares.is_empty() && input.share_kind.is_none() {
        bail!("cannot build mount units without a directory-share transport");
    }
    let stamp_path = seed.with_file_name("seed.stamp");
    let stamp = fingerprint(
        name,
        input.shares,
        input.share_kind,
        input.extra,
        input.network_config,
        input.egress,
        input.bootstrap,
    );
    let current = std::fs::read_to_string(&stamp_path).unwrap_or_default();
    if seed.exists() && current.trim() == stamp {
        return Ok(());
    }
    build(name, seed, &input)?;
    std::fs::write(&stamp_path, &stamp)?;
    Ok(())
}

/// Everything the seed's content depends on, hashed. Volumes are folded in
/// in registry order; two instances with the same volumes in a different
/// order legitimately get different seeds, because their mount units are
/// written in that order.
///
/// An empty `extra` is folded in as nothing at all rather than as an empty
/// line, so adding backend cloud-config to this module does not reissue the
/// seed of every instance that does not use any — a reissued seed carries a
/// new `instance-id`, which makes a guest run its first-boot work again.
/// A missing or empty `network` is folded the same way, for the same reason.
fn fingerprint(
    name: &str,
    shares: &[Share],
    share_kind: Option<ShareKind>,
    extra: &str,
    network: Option<&str>,
    egress: &Egress,
    bootstrap: &Bootstrap,
) -> String {
    let mut material = format!("v{SEED_TEMPLATE_VERSION}\n{name}\n");
    if !shares.is_empty() {
        // `ensure` proved this. Keeping the option at the public boundary
        // lets a guest with no directory shares be built by a backend that
        // offers none, without inventing a meaningless default transport.
        material.push_str(share_kind.expect("shares have a transport").as_str());
        material.push('\n');
    }
    for share in shares {
        material.push_str(&format!(
            "{}\t{}\t{}\n",
            share.tag, share.guest_path, share.host_path
        ));
    }
    if !extra.is_empty() {
        material.push_str(extra);
    }
    if let Some(network) = nocloud_network_config(network) {
        material.push_str(network);
    }
    // Folded in whole, and the port with it: a proxy that comes back on a
    // different port is a guest that has to be told, and the only way to tell
    // one is a new seed. An instance with no bindings folds in nothing at
    // all, so adding this section did not reissue every existing seed.
    if !egress.is_empty() {
        material.push_str(&egress.proxy);
        material.push('\n');
        material.push_str(&egress.ca_pem);
        for authority in &egress.authorities {
            material.push_str(authority);
            material.push('\n');
        }
        for (env, handle) in &egress.handles {
            material.push_str(env);
            material.push('\t');
            material.push_str(handle);
            material.push('\n');
        }
    }
    // Names and versions, not the rendered scripts: what the guest is asked
    // to become is the thing that has changed when this moves, and a comment
    // reworded in a bootstrap script is not a reason to make every guest
    // in the orbit run its first-boot work again. An instance with no
    // profiles folds in nothing, so adding this section reissued no seed.
    if !bootstrap.is_empty() {
        material.push_str(&bootstrap.stamp());
        material.push('\n');
    }
    format!("{:016x}", instance::fnv1a(&material))
}

/// Guests get an `ast` user carrying the dedicated Asterism key plus any
/// keys already in ~/.ssh, so both `ast ssh` and plain ssh work.
fn build(name: &str, seed: &Path, input: &Input<'_>) -> Result<()> {
    let stamp = fingerprint(
        name,
        input.shares,
        input.share_kind,
        input.extra,
        input.network_config,
        input.egress,
        input.bootstrap,
    );
    let mut keys = vec![ensure_asterism_key()?];
    if let Ok(home) = std::env::var("HOME") {
        if let Ok(entries) = std::fs::read_dir(PathBuf::from(home).join(".ssh")) {
            for e in entries.flatten() {
                if e.file_name().to_string_lossy().ends_with(".pub") {
                    if let Ok(k) = std::fs::read_to_string(e.path()) {
                        keys.push(k.trim().to_owned());
                    }
                }
            }
        }
    }
    let key_lines: String = keys.iter().map(|k| format!("      - {k}\n")).collect();

    // cloud-config is YAML, and a duplicate top-level key does not merge —
    // the later one silently replaces the earlier. Asterism's own half and
    // the backend's half both want `write_files` and `runcmd`, so they are
    // merged key by key rather than concatenated. A key that cannot be
    // merged says so instead of quietly losing one side.
    let config = merge(
        &asterism_config(
            input.shares,
            input.share_kind,
            input.egress,
            input.bootstrap,
        ),
        input.extra,
    )
    .with_context(|| format!("building the seed for {name:?}"))?;

    let user_data = format!(
        "#cloud-config\n\
         hostname: {name}\n\
         users:\n\
         \x20 - name: ast\n\
         \x20   sudo: ALL=(ALL) NOPASSWD:ALL\n\
         \x20   shell: /bin/bash\n\
         \x20   ssh_authorized_keys:\n{key_lines}{config}"
    );
    // The instance-id carries the fingerprint: cloud-init keys its
    // once-per-instance work off this string, so changing it is what makes
    // a guest that has already booted pick up a newly attached volume.
    let meta_data = format!("instance-id: {name}-{stamp}\nlocal-hostname: {name}\n");

    let stage = seed.parent().unwrap().join("seed-files");
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage)?;
    write_nocloud_files(&stage, &user_data, &meta_data, input.network_config)?;

    let _ = std::fs::remove_file(seed);
    if cfg!(target_os = "macos") {
        run(Command::new("hdiutil")
            .args([
                "makehybrid",
                "-iso",
                "-joliet",
                "-default-volume-name",
                "cidata",
                "-o",
            ])
            .arg(seed)
            .arg(&stage))?;
    } else {
        let mkiso = tool("xorriso")
            .map(|p| (p, vec!["-as", "mkisofs"]))
            .or_else(|_| tool("genisoimage").map(|p| (p, vec![])))?;
        let mut cmd = Command::new(mkiso.0);
        cmd.args(mkiso.1)
            .args(["-output"])
            .arg(seed)
            .args(["-volid", "cidata", "-joliet", "-rock"])
            .arg(&stage);
        run(&mut cmd)?;
    }
    let _ = std::fs::remove_dir_all(&stage);
    Ok(())
}

/// A NoCloud `network-config` document the seed should carry, or nothing.
/// Empty is nothing: adding this slot must not reissue seeds that do not
/// use it.
fn nocloud_network_config(network: Option<&str>) -> Option<&str> {
    network.filter(|body| !body.is_empty())
}

fn write_nocloud_files(
    stage: &Path,
    user_data: &str,
    meta_data: &str,
    network: Option<&str>,
) -> Result<()> {
    std::fs::write(stage.join("user-data"), user_data)?;
    std::fs::write(stage.join("meta-data"), meta_data)?;
    if let Some(network) = nocloud_network_config(network) {
        std::fs::write(stage.join("network-config"), network)?;
    }
    Ok(())
}

/// Everything Asterism itself puts in a guest: the ssh host keys it must not
/// lose, and the shared directories it was asked for.
///
/// One function because it is one cloud-config: `write_files` and `runcmd`
/// are written once each, whether or not there are volumes, and merged with
/// the backend's own half by [`merge`].
fn asterism_config(
    shares: &[Share],
    share_kind: Option<ShareKind>,
    egress: &Egress,
    bootstrap: &Bootstrap,
) -> String {
    let mut out = String::from("bootcmd:\n");
    out.push_str(HOSTKEY_BOOTCMD);
    out.push_str("write_files:\n");
    out.push_str(HOSTKEY_UNIT);
    out.push_str(&mount_units(shares, share_kind));
    out.push_str(&egress_files(egress));
    out.push_str(&bootstrap_files(bootstrap));
    out.push_str("runcmd:\n");
    out.push_str(&isolated_runcmd(HOSTKEY_RUNCMD));
    out.push_str(&isolated_runcmd(&mount_runcmd(shares, share_kind)));
    out.push_str(&isolated_runcmd(&egress_runcmd(egress)));
    out.push_str(&isolated_runcmd(&bootstrap_runcmd(bootstrap)));
    out
}

/// Keep one cloud-init shell fragment from terminating the entries after it.
///
/// `runcmd` looks like a YAML list of separate commands, but cloud-init writes
/// every block scalar into one `/bin/sh` script. An `exit` in an earlier item
/// therefore exits the combined script unless each item gets its own shell.
/// Every fragment Asterism contributes crosses this boundary, including ones
/// that do not exit today, so a later edit cannot silently recreate the same
/// ordering bug.
fn isolated_runcmd(entry: &str) -> String {
    if entry.is_empty() {
        return String::new();
    }
    let (header, body) = entry
        .split_once('\n')
        .expect("an Asterism runcmd entry has a YAML header");
    debug_assert_eq!(header.trim(), "- |");
    let indent = &header[..header.len() - header.trim_start().len()];
    let shell_indent = format!("{indent}  ");
    let mut out = format!("{header}\n{shell_indent}(\n{body}");
    if !body.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("{shell_indent})\n"));
    out
}

/// The unit that makes a guest survive losing its ssh host keys.
///
/// A guest's host keys are written by cloud-init on its first boot, and for
/// the first seconds of that guest's life they are in the page cache and
/// nowhere else. Cut the power there — `kill -9` on the hypervisor is
/// exactly that — and the guest comes back with `/etc/ssh` holding
/// zero-length files or nothing at all. `sshd` then refuses to start, on
/// that boot and on every boot after it, and an agent's home is unreachable
/// forever with no way in to fix it.
///
/// So: at every boot, before ssh is asked for, look for host keys and make
/// them if they are not there. `ssh-keygen -A` writes only what is missing,
/// so a healthy guest pays one `test` for this and nothing else.
///
/// The guest's identity does change when this fires. That is the point —
/// the alternative on offer is a machine nobody can reach — and `ast ssh`
/// does not pin host keys, so it is not a wall a user has to climb.
/// The work is a script rather than an inline `ExecStart=/bin/sh -c '...'`
/// because systemd expands `$k` in a command line itself, from its own
/// environment, and would hand the shell an empty string. A file also
/// happens to be the thing a user can run by hand when they are trying to
/// work out what happened.
const HOSTKEY_UNIT: &str = "\x20 - path: /usr/local/sbin/asterism-hostkeys\n\
     \x20   permissions: '0755'\n\
     \x20   content: |\n\
     \x20     #!/bin/sh\n\
     \x20     # A guest whose ssh host keys did not survive a power cut gets\n\
     \x20     # a new set here rather than being unreachable forever.\n\
     \x20     for key in /etc/ssh/ssh_host_*_key; do\n\
     \x20       [ -s \"$key\" ] && exit 0\n\
     \x20     done\n\
     \x20     echo 'asterism: no ssh host keys on this guest — generating a set' >&2\n\
     \x20     mkdir -p /etc/ssh\n\
     \x20     ssh-keygen -A\n\
     \x20     sync\n\
     \x20     for unit in ssh sshd; do\n\
     \x20       systemctl try-restart \"$unit\".service >/dev/null 2>&1 || true\n\
     \x20     done\n\
     \x20 - path: /etc/systemd/system/asterism-hostkeys.service\n\
     \x20   content: |\n\
     \x20     [Unit]\n\
     \x20     Description=Asterism: regenerate missing ssh host keys\n\
     \x20     Before=ssh.service sshd.service ssh.socket sshd.socket\n\
     \x20     [Service]\n\
     \x20     Type=oneshot\n\
     \x20     RemainAfterExit=yes\n\
     \x20     ExecStart=/usr/local/sbin/asterism-hostkeys\n\
     \x20     [Install]\n\
     \x20     WantedBy=multi-user.target\n";

/// The same check, run before systemd has finished starting anything.
///
/// The unit above cannot help on the boot that installs it: systemd works
/// out what a boot consists of before cloud-init has run, so a unit
/// `systemctl enable` adds in cloud-final joins the boot *after* it. That
/// leaves one window uncovered, and it is exactly the window that loses
/// guests — a first boot cut short between cloud-init writing the host keys
/// and cloud-final flushing them has no keys and no enabled unit, so the
/// second boot would come up with sshd failed and nothing to fix it.
///
/// `bootcmd` runs on every boot, from cloud-init's earliest stage, before
/// sshd. So the second boot is covered whatever happened to the first.
///
/// Skipped on a guest's very first boot — `/var/lib/cloud/instance` does
/// not exist yet — because cloud-init is about to write a set of host keys
/// itself, and generating a set for it to delete would be a second of
/// nothing on every instance anyone ever creates.
const HOSTKEY_BOOTCMD: &str = "\x20 - |\n\
     \x20   # A subshell, and it is load-bearing: cloud-init concatenates\n\
     \x20   # every `bootcmd` entry into one /bin/sh script, so an `exit`\n\
     \x20   # out here would end the entries that come after this one —\n\
     \x20   # the console fix and the guest agent among them.\n\
     \x20   (\n\
     \x20   [ -d /var/lib/cloud/instance ] || exit 0\n\
     \x20   for key in /etc/ssh/ssh_host_*_key; do\n\
     \x20     [ -s \"$key\" ] && exit 0\n\
     \x20   done\n\
     \x20   echo 'asterism: no ssh host keys on this guest — generating a set' >&2\n\
     \x20   mkdir -p /etc/ssh\n\
     \x20   ssh-keygen -A\n\
     \x20   sync\n\
     \x20   )\n";

/// Enable that unit, and flush what cloud-init has just written.
///
/// `runcmd` is cloud-final, the last stage cloud-init runs, so by the time
/// this `sync` returns the host keys the ssh module wrote earlier in the
/// same boot are on the disk rather than in the page cache. That is the
/// belt; the unit above is the braces.
const HOSTKEY_RUNCMD: &str = "\x20 - |\n\
     \x20   systemctl daemon-reload\n\
     \x20   systemctl enable asterism-hostkeys.service >/dev/null 2>&1 || true\n\
     \x20   sync\n";

/// The `write_files` entries that make the shared directories appear inside
/// the guest.
///
/// Mounting is expressed as systemd units rather than through cloud-init's
/// `mounts:` module: that module is written for block devices and drops
/// entries whose device is not one, and a unit is what an fstab line would
/// have become anyway. Enabling them means the mounts come back on every
/// later boot without cloud-init running again.
///
/// The transport is supplied by the selected backend's capability. That
/// keeps the seed backend-neutral without pretending the two transports use
/// the same mount syntax.
fn mount_units(shares: &[Share], share_kind: Option<ShareKind>) -> String {
    if shares.is_empty() {
        return String::new();
    }
    let kind = share_kind.expect("shares have a transport");
    let mut out = format!(
        "\x20 - path: /etc/modules-load.d/asterism-{kind}.conf\n\
         \x20   content: |\n"
    );
    for module in kind.modules() {
        out.push_str(&format!("\x20     {module}\n"));
    }
    out.push_str(&format!(
        "\x20 - path: /etc/systemd/system/asterism-{kind}-modules.service\n\
         \x20   content: |\n\
         \x20     [Unit]\n\
         \x20     Description=Load Asterism {kind} share modules\n\
         \x20     After=systemd-modules-load.service\n\
         \x20     [Service]\n\
         \x20     Type=oneshot\n\
         \x20     RemainAfterExit=yes\n"
    ));
    for module in kind.modules() {
        out.push_str(&format!("\x20     ExecStart=/sbin/modprobe {module}\n"));
    }
    for share in shares {
        let options = match kind.mount_options() {
            "" => String::new(),
            value => format!("\x20     Options={value}\n"),
        };
        out.push_str(&format!(
            "\x20 - path: /etc/systemd/system/{unit}\n\
             \x20   content: |\n\
             \x20     [Unit]\n\
             \x20     Description=Asterism volume {label}\n\
             \x20     Requires=asterism-{kind}-modules.service\n\
             \x20     After=asterism-{kind}-modules.service\n\
             \x20     [Mount]\n\
             \x20     What={tag}\n\
             \x20     Where={where_}\n\
             \x20     Type={kind}\n\
             {options}\
             \x20     [Install]\n\
             \x20     WantedBy=multi-user.target\n",
            unit = share.unit(),
            label = share.label,
            tag = share.tag,
            where_ = share.guest_path,
        ));
    }
    out
}

/// The `write_files` entries that make a guest trust this instance's CA and
/// send bound traffic through the proxy.
///
/// Three files, and each of them is deliberately inert on its own:
///
/// * The CA certificate, written to both trust-store drop-in directories the
///   distributions use. It is a *certificate*: the key that signs with it
///   never leaves the host, so a guest that copies this file out has copied
///   something already public to it.
/// * A `profile.d` script, which is what an interactive shell and anything
///   started from one will read.
/// * An `environment.d` drop-in, which is what a systemd *user* service will
///   read. `/etc/environment` is appended in `runcmd` rather than written
///   here, because the image already ships one and `write_files` replaces.
///
/// `NO_PROXY` is the complement of the bound set and not a blanket: a guest
/// that sent every connection through this proxy would have its package
/// manager and its own health checks queueing behind a listener whose whole
/// job is a handful of API calls.
fn egress_files(egress: &Egress) -> String {
    if egress.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for path in [
        "/usr/local/share/ca-certificates/asterism-egress.crt",
        "/etc/pki/ca-trust/source/anchors/asterism-egress.crt",
    ] {
        out.push_str(&format!(
            "\x20 - path: {path}\n\
             \x20   permissions: '0644'\n\
             \x20   content: |\n"
        ));
        for line in egress.ca_pem.lines() {
            out.push_str(&format!("\x20     {line}\n"));
        }
    }
    let exports = egress_environment(egress);
    out.push_str(
        "\x20 - path: /etc/profile.d/asterism-egress.sh\n\
         \x20   permissions: '0644'\n\
         \x20   content: |\n\
         \x20     # Written by Asterism. The values below are opaque handles,\n\
         \x20     # not credentials: each one is honoured by this instance's\n\
         \x20     # egress proxy, for one host, and is worth nothing anywhere\n\
         \x20     # else. The real value never enters this machine.\n",
    );
    for (key, value) in &exports {
        out.push_str(&format!("\x20     export {key}={}\n", shell_quote(value)));
    }
    out.push_str(
        "\x20 - path: /etc/environment.d/50-asterism-egress.conf\n\
         \x20   permissions: '0644'\n\
         \x20   content: |\n",
    );
    for (key, value) in &exports {
        out.push_str(&format!("\x20     {key}={value}\n"));
    }
    out
}

/// The `runcmd` that installs the CA and puts the environment where processes
/// that never read a profile will find it.
///
/// Both trust-store updaters are tried and neither is required: an image with
/// neither still boots, and the guest sees a TLS failure it can act on rather
/// than a machine that would not come up.
///
/// The `/etc/environment` edit is a delete-then-append between two markers, so
/// it is idempotent — `runcmd` runs again whenever a binding changes and the
/// seed is reissued, and a guest must not end up with three copies of its own
/// proxy settings.
///
/// Two shapes here are deliberate and both were bugs first. The lines are
/// written with one `printf` rather than a heredoc, because a heredoc's
/// terminator has to sit at column zero and every line of this string is
/// indented inside a YAML block scalar. And the delete is `sed` to a temporary
/// file rather than `sed -i`, because `-i` takes a mandatory suffix argument
/// on BSD and none on GNU — the one spelling that works on both is neither.
/// Writing back with `cat` rather than `mv` keeps the file's mode and owner,
/// which `pam_env` cares about.
fn egress_runcmd(egress: &Egress) -> String {
    if egress.is_empty() {
        return String::new();
    }
    let lines: Vec<String> = egress_environment(egress)
        .iter()
        .map(|(key, value)| shell_quote(&format!("{key}={value}")))
        .collect();
    format!(
        "\x20 - |\n\
         \x20   for cert in /usr/local/share/ca-certificates/asterism-egress.crt \\\n\
         \x20               /etc/pki/ca-trust/source/anchors/asterism-egress.crt; do\n\
         \x20     [ -s \"$cert\" ] || rm -f \"$cert\"\n\
         \x20   done\n\
         \x20   update-ca-certificates >/dev/null 2>&1 \\\n\
         \x20     || update-ca-trust extract >/dev/null 2>&1 \\\n\
         \x20     || echo 'asterism: this image has no ca-certificates tool, so the egress \
         proxy is not trusted yet — install one and re-run it' >&2\n\
         \x20   if [ -f /etc/environment ]; then\n\
         \x20     sed '/^# BEGIN asterism egress$/,/^# END asterism egress$/d' \
         /etc/environment >/tmp/asterism-env \\\n\
         \x20       && cat /tmp/asterism-env >/etc/environment\n\
         \x20     rm -f /tmp/asterism-env\n\
         \x20   fi\n\
         \x20   {{\n\
         \x20     echo '# BEGIN asterism egress'\n\
         \x20     printf '%s\\n' {lines}\n\
         \x20     echo '# END asterism egress'\n\
         \x20   }} >>/etc/environment\n\
         \x20   exit 0\n",
        lines = lines.join(" \\\n\x20                  "),
    )
}

/// The environment a bound guest runs with, in the order it is written.
/// Environment presented to a guest process for one egress binding set.
///
/// Shared with the OCI bootstrap path: cloud images receive these lines via
/// cloud-init, while OCI images export the identical values from their
/// generated pid 1 before starting the image entrypoint.
pub fn egress_environment(egress: &Egress) -> Vec<(String, String)> {
    let mut out = vec![
        ("HTTPS_PROXY".to_owned(), egress.proxy.clone()),
        ("https_proxy".to_owned(), egress.proxy.clone()),
        // Everything that is not bound goes out of the guest's own NAT.
        // Naming the exceptions rather than the rule keeps this proxy on the
        // path of the traffic it exists for and off everything else's.
        (
            "NO_PROXY".to_owned(),
            "localhost,127.0.0.1,::1,169.254.169.254".to_owned(),
        ),
        (
            "no_proxy".to_owned(),
            "localhost,127.0.0.1,::1,169.254.169.254".to_owned(),
        ),
        (
            "ASTERISM_EGRESS_HOSTS".to_owned(),
            egress.authorities.join(","),
        ),
    ];
    out.extend(egress.handles.iter().cloned());
    out
}

/// Single-quote for `sh`, which is the only quoting a handle could need and
/// is written out rather than assumed because a value here reaches a shell.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The `write_files` entries that carry an instance's bootstrap profiles
/// into its guest.
///
/// [`crate::profile`] decides what a guest needs; this decides what survives
/// the trip. A `write_files` entry is a YAML block scalar, so every line of
/// a shell script is indented under it — a blank line in a script included,
/// because a line carrying only the block's own indentation reads back as
/// the empty line it was, and it keeps the one invariant this file's YAML
/// can be checked against: every line is either a key or indented under one.
fn bootstrap_files(bootstrap: &Bootstrap) -> String {
    let mut out = String::new();
    for (path, mode, content) in bootstrap.files() {
        out.push_str(&format!(
            "\x20 - path: {path}\n\x20   permissions: '{mode}'\n\x20   content: |\n"
        ));
        for line in content.lines() {
            out.push_str(&format!("\x20     {line}\n"));
        }
    }
    out
}

/// The `runcmd` entry that sets the bootstrap going.
///
/// It comes last in the list on purpose: the host-key insurance and the
/// mounts are seconds and this is minutes, and a share an agent is about to
/// work in should be there before the thing that installs the agent.
fn bootstrap_runcmd(bootstrap: &Bootstrap) -> String {
    let runcmd = bootstrap.runcmd();
    if runcmd.is_empty() {
        return String::new();
    }
    let mut out = String::from("\x20 - |\n");
    for line in runcmd.lines() {
        out.push_str(&format!("\x20   {line}\n"));
    }
    out
}

/// The `runcmd` entry that enables those mount units.
///
/// Enabling rather than just starting is what carries the mounts across
/// later boots, when cloud-init has nothing left to do. A share that will
/// not mount says so and steps aside: the guest is still a usable machine,
/// and the unit stays `failed` where systemd can explain it.
fn mount_runcmd(shares: &[Share], share_kind: Option<ShareKind>) -> String {
    if shares.is_empty() {
        return String::new();
    }
    let kind = share_kind.expect("shares have a transport");
    let units: Vec<String> = shares.iter().map(Share::unit).collect();
    format!(
        "\x20 - |\n\
         \x20   systemctl daemon-reload\n\
         \x20   modprobe {modules} 2>/dev/null || true\n\
         \x20   failed=\n\
         \x20   for unit in {units}; do\n\
         \x20     systemctl enable --now \"$unit\" && continue\n\
         \x20     failed=1\n\
         \x20     echo \"asterism: $unit did not mount\" >&2\n\
         \x20     systemctl --no-pager --full status \"$unit\" >&2 || true\n\
         \x20   done\n\
         \x20   if [ -n \"$failed\" ] && ! grep -q {kind} /proc/filesystems; then\n\
         \x20     echo \"asterism: this kernel has no {kind} filesystem, so host \
         volumes cannot be mounted here — boot an image whose kernel ships \
         {modules}\" >&2\n\
         \x20   fi\n\
         \x20   exit 0\n",
        // Single-quoted for the shell: escaped mount points contain
        // `\xNN`, and an unquoted backslash would be eaten, sending
        // `systemctl` a unit name that does not exist. The escape alphabet
        // is [A-Za-z0-9:_.\-] plus backslash, so a single quote never
        // appears in a unit name.
        units = units
            .iter()
            .map(|u| format!("'{u}'"))
            .collect::<Vec<_>>()
            .join(" "),
        modules = kind.modules().join(" "),
    )
}

// ---- merging two halves of one cloud-config --------------------------------

/// Merge a backend's guest config into Asterism's own, key by key.
///
/// cloud-config is YAML, and a duplicate top-level key does not merge: the
/// later one silently replaces the earlier, so a seed built by pasting two
/// fragments together would arrive in the guest having lost half of itself.
/// Both halves legitimately want `write_files` and `runcmd` — this file
/// needs them for host keys and mounts, and a backend needs them for
/// whatever its guests cannot be told any other way — so the entries under
/// a shared key are concatenated, ours first.
///
/// Only list-valued keys can be merged that way. A key that carries a value
/// on its own line (`final_message: "..."`) has one answer, not a list of
/// them, and two answers is a thing to refuse rather than to guess at.
fn merge(ours: &str, theirs: &str) -> Result<String> {
    let mut merged = blocks(ours);
    for block in blocks(theirs) {
        match merged.iter_mut().find(|b| b.key == block.key) {
            None => merged.push(block),
            Some(mine) => {
                if !mine.value.is_empty() || !block.value.is_empty() {
                    bail!(
                        "the guest configuration and this backend's would both set \
                         `{}`, and it takes one value rather than a list — one of \
                         them has to give it up",
                        mine.key
                    );
                }
                mine.entries.extend(block.entries);
            }
        }
    }
    Ok(merged.iter().map(Block::render).collect())
}

/// How far the lines under a top-level key are indented once merged.
///
/// Normalised rather than preserved, because the two halves do not agree:
/// this file writes a list at two spaces and a backend's `guest_config` may
/// write one at a different depth, and a YAML sequence whose items are
/// indented inconsistently is not a sequence. Shifting every line of a
/// block by the same amount keeps what is *inside* it — block scalars, and
/// the shell in them — exactly as it was.
const INDENT: &str = "  ";

/// Whether a backend's [`crate::hv::Hypervisor::guest_config`] can be
/// carried in a seed alongside Asterism's own half.
///
/// The contract a backend has to meet, in a form it can be held to before a
/// guest is waiting on it: every key it defines is either one nothing else
/// claims, or a list that can absorb ours. `build` runs the same check, but
/// it runs it at boot — this is here so a backend's test can run it now.
pub fn mergeable(guest_config: &str) -> Result<()> {
    merge(
        &asterism_config(&[], None, &Egress::default(), &Bootstrap::default()),
        guest_config,
    )
    .map(|_| ())
}

/// One top-level cloud-config key and what is under it.
#[derive(Debug, PartialEq, Eq)]
struct Block {
    key: String,
    /// Anything written on the key's own line: `final_message: "hi"` has
    /// one, `runcmd:` has none. A key with a value is not a list.
    value: String,
    /// The lines beneath it, with the block's own indentation taken off, so
    /// two blocks from different sources can be concatenated.
    entries: Vec<String>,
}

impl Block {
    fn render(&self) -> String {
        let mut out = match self.value.is_empty() {
            true => format!("{}:\n", self.key),
            false => format!("{}: {}\n", self.key, self.value),
        };
        for line in &self.entries {
            if !line.trim().is_empty() {
                out.push_str(INDENT);
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }
}

/// Split a cloud-config fragment into its top-level keys.
///
/// Line-oriented on purpose: both fragments are written in this repository,
/// one here and one as a backend's `guest_config`, so what has to be
/// understood is the shape they are actually written in — a key at column
/// zero, and indented lines under it — rather than the whole of YAML.
fn blocks(config: &str) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    // How far in the current block's first line sat, so the rest of it can
    // be measured against the same edge.
    let mut base: Option<usize> = None;
    for line in config.lines() {
        let starts_a_key = !line.starts_with([' ', '\t'])
            && !line.trim().is_empty()
            && !line.starts_with('#')
            && line.contains(':');
        if starts_a_key {
            let (key, value) = line.split_once(':').expect("just checked");
            out.push(Block {
                key: key.trim().to_owned(),
                value: value.trim().to_owned(),
                entries: Vec::new(),
            });
            base = None;
        } else if let Some(block) = out.last_mut() {
            let indent = line.len() - line.trim_start_matches(' ').len();
            if !line.trim().is_empty() {
                base.get_or_insert(indent);
            }
            let strip = base.unwrap_or(0).min(indent);
            block.entries.push(line[strip..].to_owned());
        }
    }
    out
}

/// systemd names a `.mount` unit after its mount point: slashes become
/// dashes and anything outside `[A-Za-z0-9:_.]` becomes `\xNN`.
fn systemd_path_escape(path: &str) -> String {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if components.is_empty() {
        return "-".into(); // the root mount is called `-.mount`
    }
    let mut out = String::new();
    let mut buf = [0u8; 4];
    for (i, c) in components.join("/").chars().enumerate() {
        if c == '/' {
            out.push('-');
        } else if c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.') {
            // A leading dot would make a hidden file of the unit name.
            if i == 0 && c == '.' {
                out.push_str("\\x2e");
            } else {
                out.push(c);
            }
        } else {
            for b in c.encode_utf8(&mut buf).as_bytes() {
                out.push_str(&format!("\\x{b:02x}"));
            }
        }
    }
    out
}

/// The dedicated Asterism keypair, generated on first use. Lives with the
/// seed because it exists to be put *into* one.
pub fn ensure_asterism_key() -> Result<String> {
    let key = paths::ssh_key_path();
    let pubkey = key.with_extension("pub");
    if !pubkey.exists() {
        if let Some(dir) = key.parent() {
            std::fs::create_dir_all(dir)?;
        }
        run(Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-C", "asterism", "-f"])
            .arg(&key))?;
    }
    Ok(std::fs::read_to_string(&pubkey)?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::local_host;

    fn share(host_path: &str, guest_path: &str) -> Share {
        Share::new(&Volume::dir(
            host_path,
            &local_host(),
            Some(guest_path.into()),
        ))
    }

    /// Tests that do not speak network-config keep the pre-seam fingerprint
    /// helper: a missing document must not move existing seeds.
    fn fingerprint(
        name: &str,
        shares: &[Share],
        share_kind: Option<ShareKind>,
        extra: &str,
        egress: &Egress,
        bootstrap: &Bootstrap,
    ) -> String {
        super::fingerprint(name, shares, share_kind, extra, None, egress, bootstrap)
    }

    /// The shape a backend's `Hypervisor::guest_config` has: keys of its
    /// own, and keys this file also writes. Kept close to what the vz
    /// backend really sends, without this crate depending on it.
    const VZ_LIKE: &str = "final_message: \"asterism: cloud-init finished\"\n\
         bootcmd:\n\
         \x20- [ sh, -c, \"echo hi > /dev/hvc0\" ]\n\
         runcmd:\n\
         \x20- |\n\
         \x20  systemctl enable --now serial-getty@hvc0.service 2>/dev/null || true\n";

    #[test]
    fn unit_names_follow_systemds_escaping() {
        assert_eq!(systemd_path_escape("/mnt/ast/media"), "mnt-ast-media");
        assert_eq!(systemd_path_escape("/mnt//ast/media/"), "mnt-ast-media");
        assert_eq!(systemd_path_escape("/"), "-");
        // Dashes and spaces are not name characters; a leading dot hides.
        assert_eq!(systemd_path_escape("/mnt/my-vol"), "mnt-my\\x2dvol");
        assert_eq!(systemd_path_escape("/mnt/my vol"), "mnt-my\\x20vol");
        assert_eq!(systemd_path_escape("/.cache"), "\\x2ecache");
        assert_eq!(
            share("/tank/media", "/mnt/ast/media").unit(),
            "mnt-ast-media.mount"
        );
    }

    /// A guest with no volumes still gets the two things every guest needs:
    /// its host keys flushed, and a way back if it lost them anyway.
    #[test]
    fn every_guest_gets_the_host_key_insurance_volumes_or_not() {
        let bare = asterism_config(&[], None, &Egress::default(), &Bootstrap::default());
        assert!(bare.contains("- path: /etc/systemd/system/asterism-hostkeys.service"));
        assert!(bare.contains("ssh-keygen -A"));
        assert!(bare.contains("systemctl enable asterism-hostkeys.service"));
        // The same check runs from `bootcmd` too, because the unit cannot
        // help on the boot that installs it — and that boot is the one
        // whose keys are least likely to be on the disk.
        let boot = &bare[..bare.find("write_files:").unwrap()];
        assert!(boot.starts_with("bootcmd:\n"), "{boot}");
        assert!(boot.contains("[ -d /var/lib/cloud/instance ] || exit 0"));
        assert!(boot.contains("ssh-keygen -A"));
        // The `sync` is the belt: runcmd is cloud-final, so cloud-init has
        // already written this guest's host keys by the time it runs. The
        // fragment closes its isolation subshell after it.
        let runcmd = compiled_runcmd(&bare);
        assert!(runcmd.contains("\nsync\n)\n"), "{runcmd}");
        // No 9p anywhere near a guest that was not given a directory.
        assert!(!bare.contains("9p"), "{bare}");
        // The unit runs before anything would want to use a host key.
        assert!(bare.contains("Before=ssh.service sshd.service"));
    }

    #[test]
    fn each_share_gets_a_unit_that_is_written_and_enabled() {
        let shares = vec![
            share("/tank/media", "/mnt/ast/media"),
            share("/tank/code", "/srv/code"),
        ];
        let config = asterism_config(
            &shares,
            Some(ShareKind::NinePfs),
            &Egress::default(),
            &Bootstrap::default(),
        );
        assert!(config.contains("- path: /etc/systemd/system/mnt-ast-media.mount"));
        assert!(config.contains("- path: /etc/systemd/system/srv-code.mount"));
        assert!(config.contains("Where=/mnt/ast/media"));
        assert!(config.contains("Where=/srv/code"));
        assert!(config.contains(&format!("What={}", shares[0].tag)));
        assert!(config.contains("Type=9p"));
        assert!(config.contains("asterism-9p-modules.service"));
        assert!(config.contains("Requires=asterism-9p-modules.service"));
        assert!(config.contains("After=asterism-9p-modules.service"));
        assert!(config.contains("for unit in 'mnt-ast-media.mount' 'srv-code.mount'; do"));
        assert!(config.contains("systemctl enable --now \"$unit\""));

        // One of each key, whatever is under them — a second of either
        // would silently replace the first.
        let keys: Vec<String> = blocks(&config).into_iter().map(|b| b.key).collect();
        assert_eq!(keys, vec!["bootcmd", "write_files", "runcmd"]);

        // A dash in the mount point becomes `\x2d` in the unit name; the
        // runcmd list must deliver that backslash to systemctl intact.
        let dashed = asterism_config(
            &[share("/tank/a", "/mnt/ast/e2e-vol")],
            Some(ShareKind::NinePfs),
            &Egress::default(),
            &Bootstrap::default(),
        );
        assert!(dashed.contains(r"- path: /etc/systemd/system/mnt-ast-e2e\x2dvol.mount"));
        assert!(dashed.contains(r"for unit in 'mnt-ast-e2e\x2dvol.mount'; do"));
        // Everything sits under a top-level key, at an indent cloud-init
        // will read as part of it.
        for line in config.lines() {
            assert!(
                line.starts_with(' ') || line.ends_with(':'),
                "unindented line in cloud-config: {line:?}"
            );
        }
    }

    #[test]
    fn virtiofs_units_name_only_the_transport_vz_attaches() {
        let shares = [share("/workspace/source", "/mnt/ast/source")];
        let config = asterism_config(
            &shares,
            Some(ShareKind::Virtiofs),
            &Egress::default(),
            &Bootstrap::default(),
        );
        assert!(config.contains("Type=virtiofs"), "{config}");
        assert!(config.contains("modprobe virtiofs"), "{config}");
        assert!(config.contains("asterism-virtiofs.conf"), "{config}");
        assert!(
            config.contains("Requires=asterism-virtiofs-modules.service"),
            "{config}"
        );
        assert!(
            config.contains("After=asterism-virtiofs-modules.service"),
            "{config}"
        );
        assert!(
            config.contains(&format!("What={}", shares[0].tag)),
            "{config}"
        );
        assert!(!config.contains("Type=9p"), "{config}");
        assert!(!config.contains("trans=virtio"), "{config}");
    }

    /// Two halves of the user-data can each need `runcmd:`, and YAML would
    /// silently keep only the second. They are merged rather than pasted, so
    /// both arrive in the guest.
    #[test]
    fn both_halves_of_the_config_keep_their_runcmd() {
        let ours = asterism_config(
            &[share("/tank/media", "/mnt/ast/media")],
            Some(ShareKind::NinePfs),
            &Egress::default(),
            &Bootstrap::default(),
        );
        let vz = VZ_LIKE;
        let merged = merge(&ours, vz).unwrap();

        // One of each key, in the order the first half wrote them. The
        // backend's `bootcmd` joins ours rather than replacing it — which
        // is the case that used to be refused, and the one vz brings.
        let keys: Vec<String> = blocks(&merged).into_iter().map(|b| b.key).collect();
        assert_eq!(
            keys,
            vec!["bootcmd", "write_files", "runcmd", "final_message"]
        );
        // Both sides' work is under the one `runcmd`.
        assert!(merged.contains("systemctl enable asterism-hostkeys.service"));
        assert!(merged.contains("systemctl enable --now \"$unit\""));
        // ...and under the one `bootcmd`.
        assert!(merged.contains("echo hi > /dev/hvc0"));
        assert!(merged.contains("[ -d /var/lib/cloud/instance ] || exit 0"));

        // Either half alone comes out with the same content. A backend that
        // indents its list one space rather than two is re-indented, which
        // is the whole reason the two can share a key at all — a sequence
        // whose items sit at two different depths is not a sequence.
        assert_eq!(merge(&ours, "").unwrap(), ours);
        let alone = merge("", vz).unwrap();
        assert!(
            alone.contains("\n  - [ sh, -c, \"echo hi > /dev/hvc0\" ]\n"),
            "{alone}"
        );
        for line in merged.lines() {
            assert!(
                !line.starts_with(" -"),
                "a list item at one space, next to ours at two: {line:?}"
            );
        }
        // The shell inside a block scalar is shifted with everything around
        // it, so its own indentation survives.
        assert!(
            merged.contains("\n  - |\n    systemctl enable --now serial-getty"),
            "{merged}"
        );

        // A key that carries one value rather than a list cannot be merged,
        // and saying so beats picking a winner.
        let mine = "final_message: \"ours\"\n";
        assert_eq!(
            merge(mine, "final_message: \"theirs\"\n")
                .unwrap_err()
                .to_string(),
            "the guest configuration and this backend's would both set \
             `final_message`, and it takes one value rather than a list — one of \
             them has to give it up"
        );
        // One of them alone is fine, wherever it comes from.
        assert!(merge(&ours, mine)
            .unwrap()
            .contains("final_message: \"ours\""));
    }

    /// cloud-init does not execute block-scalar `runcmd` items separately:
    /// it concatenates them into one script. The egress fragment ends in
    /// `exit 0`, so it used to prevent the bootstrap item after it from ever
    /// enabling its unit. Exercise that exact ordering rule as shell, not as
    /// a string-position assertion.
    #[test]
    fn an_earlier_runcmd_exit_cannot_end_the_later_fragment() {
        let first = isolated_runcmd(" - |\n   printf 'first\\n' >>\"$1\"\n   exit 0\n");
        let second = isolated_runcmd(" - |\n   printf 'second\\n' >>\"$1\"\n");
        let config = format!("runcmd:\n{first}{second}");
        let script = compiled_runcmd(&config);
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("order");
        let ran = Command::new("sh")
            .arg("-c")
            .arg(&script)
            .arg("cloud-init-runcmd")
            .arg(&marker)
            .output()
            .unwrap();
        assert!(
            ran.status.success(),
            "the compiled runcmd failed: {}\n{script}",
            String::from_utf8_lossy(&ran.stderr)
        );
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "first\nsecond\n");

        // And the production ordering is the one this proves: egress, with
        // its early exit, precedes the profile unit start in the same script.
        let bootstrap = Bootstrap::resolve(&["claude".to_owned()]).unwrap();
        let actual = compiled_runcmd(&asterism_config(&[], None, &egress(), &bootstrap));
        let egress = actual.find("# BEGIN asterism egress").unwrap();
        let exit = actual[egress..].find("exit 0").unwrap() + egress;
        let bootstrap = actual
            .find("systemctl enable asterism-bootstrap.service")
            .unwrap();
        assert!(egress < exit && exit < bootstrap, "{actual}");
        assert!(actual[exit..bootstrap].contains("\n)\n"), "{actual}");
    }

    /// Reproduce the one part of cloud-init's `runcmd` compiler this module
    /// relies on: block-scalar list items become consecutive shell text.
    fn compiled_runcmd(config: &str) -> String {
        let block = blocks(config)
            .into_iter()
            .find(|block| block.key == "runcmd")
            .expect("runcmd block");
        let mut out = String::new();
        let mut scalar = false;
        for line in block.entries {
            if line == "- |" {
                scalar = true;
            } else if line.starts_with("- ") {
                scalar = false;
            } else if scalar {
                out.push_str(line.strip_prefix("  ").unwrap_or(&line));
                out.push('\n');
            }
        }
        out
    }

    /// The whole user-data as a guest receives it, with a backend's half
    /// merged in — the thing that actually has to be YAML.
    ///
    /// The property is that no top-level key appears twice, anywhere in it,
    /// because that is the failure nothing downstream would report: YAML
    /// keeps the later one and the guest silently loses half its
    /// configuration.
    ///
    /// Set `ASTERISM_DUMP_SEED` to a path to also write it out and look at
    /// it: `ASTERISM_DUMP_SEED=/tmp/user-data cargo test -p asterism-core seed`.
    #[test]
    fn the_assembled_user_data_never_says_the_same_key_twice() {
        let shares = vec![share("/tank/media", "/mnt/ast/media")];
        // The whole of what a seed can carry: mounts, a bound secret, and a
        // guest that is being made into somewhere an agent can work.
        let bootstrap = Bootstrap::resolve(&["claude".to_owned(), "codex".to_owned()]).unwrap();
        let config = merge(
            &asterism_config(&shares, Some(ShareKind::NinePfs), &egress(), &bootstrap),
            VZ_LIKE,
        )
        .unwrap();
        let user_data = format!(
            "#cloud-config\n\
             hostname: dev\n\
             users:\n\
             \x20 - name: ast\n\
             \x20   sudo: ALL=(ALL) NOPASSWD:ALL\n\
             \x20   shell: /bin/bash\n\
             \x20   ssh_authorized_keys:\n\
             \x20     - ssh-ed25519 AAAA asterism\n{config}"
        );
        if let Ok(dest) = std::env::var("ASTERISM_DUMP_SEED") {
            std::fs::write(dest, &user_data).unwrap();
        }

        let mut seen: Vec<String> = Vec::new();
        for block in blocks(&user_data) {
            assert!(
                !seen.contains(&block.key),
                "{:?} appears twice:\n{user_data}",
                block.key
            );
            seen.push(block.key);
        }
        assert_eq!(
            seen,
            vec![
                "hostname",
                "users",
                "bootcmd",
                "write_files",
                "runcmd",
                "final_message"
            ]
        );
    }

    fn egress() -> Egress {
        Egress {
            proxy: "http://10.0.2.2:38123".into(),
            ca_pem: "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----".into(),
            authorities: vec!["api.anthropic.com".into()],
            handles: vec![("ANTHROPIC_API_KEY".into(), "sk-ant-ast-ZZZ".into())],
        }
    }

    #[test]
    fn a_seed_carries_the_certificate_and_the_handle_and_nothing_else() {
        let config = asterism_config(&[], None, &egress(), &Bootstrap::default());
        // The certificate, in both places a distribution looks.
        assert!(config.contains("/usr/local/share/ca-certificates/asterism-egress.crt"));
        assert!(config.contains("/etc/pki/ca-trust/source/anchors/asterism-egress.crt"));
        assert!(config.contains("-----BEGIN CERTIFICATE-----"));
        // The proxy, where a shell and a systemd unit will each find it.
        assert!(config.contains("export HTTPS_PROXY='http://10.0.2.2:38123'"));
        assert!(config.contains("HTTPS_PROXY=http://10.0.2.2:38123"));
        // The handle, which is what the guest uses instead of the value.
        assert!(config.contains("export ANTHROPIC_API_KEY='sk-ant-ast-ZZZ'"));
        // And nothing that is or leads to a private key: the CA signs on the
        // host, so only the certificate half of it may be in here.
        assert!(!config.contains("PRIVATE KEY"), "{config}");
        assert!(!config.contains("BEGIN EC"), "{config}");

        // Still one of each key after the merge, which is the rule this
        // file's whole `merge` exists to keep.
        let merged = merge(&config, "runcmd:\n - [ sh, -c, x ]\n").unwrap();
        let keys: Vec<String> = blocks(&merged).into_iter().map(|b| b.key).collect();
        assert_eq!(keys, vec!["bootcmd", "write_files", "runcmd"]);

        // An instance with no bindings gets none of it, and its seed does not
        // move just because this section was added to the file.
        let bare = asterism_config(&[], None, &Egress::default(), &Bootstrap::default());
        assert!(!bare.contains("asterism-egress"));
    }

    /// The guest's half of a binding is a shell script, and a shell script in
    /// a YAML block scalar has two ways to be quietly wrong. Both were, once.
    #[test]
    fn the_script_a_bound_guest_runs_is_shell_a_guest_can_actually_run() {
        let config = asterism_config(&[], None, &egress(), &Bootstrap::default());
        // Pull every runcmd entry back out the way cloud-init compiles it:
        // consecutive shell text, including each fragment's isolation.
        let script = compiled_runcmd(&config);
        assert!(script.contains("BEGIN asterism egress"), "{script}");

        // 1. A heredoc's terminator has to be at column zero, and nothing in
        //    a block scalar is. So there is no heredoc.
        assert!(
            !script.contains("<<"),
            "a heredoc cannot terminate in here:\n{script}"
        );
        assert!(script.contains("printf '%s\\n'"), "{script}");
        // 2. `sed -i` takes a mandatory suffix on BSD and none on GNU. The
        //    guest is Linux, but the spelling that works on both is neither,
        //    and this is testable where `sed -i` would not be.
        assert!(!script.contains("sed -i"), "{script}");

        // And it is shell. `sh -n` parses without running, which is exactly
        // the question being asked.
        let checked = Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("this machine has an sh");
        assert!(
            checked.status.success(),
            "the guest's script does not parse: {}\n{script}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }

    #[test]
    fn a_binding_that_changes_reissues_the_seed_and_one_that_does_not_does_not() {
        // A reissued seed carries a new instance-id, which makes a guest redo
        // its first-boot work — so this must move exactly when the guest has
        // something new to be told, and never otherwise.
        let none = fingerprint(
            "dev",
            &[],
            None,
            "",
            &Egress::default(),
            &Bootstrap::default(),
        );
        let bound = fingerprint("dev", &[], None, "", &egress(), &Bootstrap::default());
        assert_ne!(none, bound);
        assert_eq!(
            bound,
            fingerprint("dev", &[], None, "", &egress(), &Bootstrap::default())
        );

        // The port is in it: a proxy that came back somewhere else is a guest
        // that has to be told where.
        let moved = Egress {
            proxy: "http://10.0.2.2:39000".into(),
            ..egress()
        };
        assert_ne!(
            bound,
            fingerprint("dev", &[], None, "", &moved, &Bootstrap::default())
        );

        // So is the handle: revoking a binding and making a new one must not
        // leave a guest holding the old handle.
        let reminted = Egress {
            handles: vec![("ANTHROPIC_API_KEY".into(), "sk-ant-ast-YYY".into())],
            ..egress()
        };
        assert_ne!(
            bound,
            fingerprint("dev", &[], None, "", &reminted, &Bootstrap::default())
        );
    }

    /// A profile reaches the guest as files and one `runcmd`, under the same
    /// two keys everything else in this seed uses.
    #[test]
    fn a_profile_reaches_the_guest_in_the_seed_that_carries_everything_else() {
        let bootstrap = Bootstrap::resolve(&["claude".to_owned()]).unwrap();
        let config = asterism_config(&[], None, &Egress::default(), &bootstrap);

        // Still one of each key. Two `write_files` would mean the host-key
        // insurance or the bootstrap silently not arriving.
        let keys: Vec<String> = blocks(&config).into_iter().map(|b| b.key).collect();
        assert_eq!(keys, vec!["bootcmd", "write_files", "runcmd"]);

        assert!(config.contains("- path: /usr/local/sbin/asterism-bootstrap"));
        assert!(config.contains("- path: /usr/local/sbin/asterism-check"));
        assert!(config.contains("- path: /etc/systemd/system/asterism-bootstrap.service"));
        assert!(config.contains("- path: /etc/asterism/bootstrap.stamp"));
        assert!(config.contains("permissions: '0755'"));
        assert!(config.contains("systemctl start --no-block asterism-bootstrap.service"));

        // The host keys are seen to first: seconds of work before minutes of
        // it, and a guest that is reachable while the packages land.
        let hostkeys = config.find("systemctl enable asterism-hostkeys").unwrap();
        let boot = config.find("systemctl enable asterism-bootstrap").unwrap();
        assert!(hostkeys < boot, "{config}");

        // Every line of a block scalar is indented under its key, and the
        // shell inside one is not YAML that a parser could reinterpret.
        for line in config.lines() {
            assert!(
                line.starts_with(' ') || line.ends_with(':'),
                "unindented line in cloud-config: {line:?}"
            );
        }
    }

    /// A script comes back out of the seed as the script that went in.
    ///
    /// The trip is a YAML block scalar, and the failure it can have is
    /// silent: an indentation bug does not stop cloud-init writing the file,
    /// it writes a *different* file, and the first sign of that is a unit
    /// that dies at boot inside a guest nobody is watching. So the block is
    /// read back the way cloud-init would — strip the block's indentation,
    /// keep everything else — and compared to what the profile said.
    #[test]
    fn a_script_survives_the_trip_through_the_seed() {
        let bootstrap = Bootstrap::resolve(&["claude".to_owned()]).unwrap();
        let config = asterism_config(&[], None, &Egress::default(), &bootstrap);
        for (path, _, content) in bootstrap.files() {
            let entry = config
                .find(&format!("- path: {path}\n"))
                .unwrap_or_else(|| panic!("{path} is not in the seed:\n{config}"));
            let body = config[entry..]
                .split_once("content: |\n")
                .expect("a block scalar")
                .1;
            let mut back = String::new();
            for line in body.lines() {
                // The block ends at the first line that is not part of it.
                let Some(rest) = line.strip_prefix("\x20     ") else {
                    break;
                };
                back.push_str(rest);
                back.push('\n');
            }
            assert_eq!(back, content, "{path} did not survive the seed");
        }
    }

    /// An instance with no profiles is byte-for-byte the instance it was
    /// before profiles existed. Nothing written, nothing run, and — the
    /// half that matters — nothing in the fingerprint, so adding this
    /// feature did not hand every guest in every orbit a new instance-id
    /// and a fresh set of first-boot work.
    #[test]
    fn no_profiles_leaves_the_seed_exactly_as_it_was() {
        let bare = asterism_config(&[], None, &Egress::default(), &Bootstrap::default());
        assert!(!bare.contains("asterism-bootstrap"), "{bare}");
        assert!(!bare.contains("asterism-check"), "{bare}");
        assert_eq!(
            fingerprint(
                "dev",
                &[],
                None,
                "",
                &Egress::default(),
                &Bootstrap::default()
            ),
            fingerprint(
                "dev",
                &[],
                None,
                "",
                &Egress::default(),
                &Bootstrap::resolve(&[]).unwrap()
            )
        );
    }

    /// The fingerprint is what carries a changed profile set into a guest
    /// that has already booted: it moves when the set does, and a set that
    /// has not changed does not reissue a seed.
    #[test]
    fn a_changed_profile_set_reissues_the_seed() {
        let none = fingerprint(
            "dev",
            &[],
            None,
            "",
            &Egress::default(),
            &Bootstrap::default(),
        );
        let claude = Bootstrap::resolve(&["claude".to_owned()]).unwrap();
        let both = Bootstrap::resolve(&["claude".to_owned(), "codex".to_owned()]).unwrap();
        let with_claude = fingerprint("dev", &[], None, "", &Egress::default(), &claude);
        assert_ne!(none, with_claude);
        assert_ne!(
            with_claude,
            fingerprint("dev", &[], None, "", &Egress::default(), &both)
        );
        assert_eq!(
            with_claude,
            fingerprint(
                "dev",
                &[],
                None,
                "",
                &Egress::default(),
                &Bootstrap::resolve(&["claude".to_owned()]).unwrap()
            )
        );
        // Asking for the same set the long way round is the same set: the
        // fingerprint is what the guest will be, not what was typed.
        assert_eq!(
            with_claude,
            fingerprint(
                "dev",
                &[],
                None,
                "",
                &Egress::default(),
                &Bootstrap::resolve(&["base".to_owned(), "node".to_owned(), "claude".to_owned()])
                    .unwrap()
            )
        );
    }

    #[test]
    fn the_fingerprint_moves_when_the_volumes_do() {
        let bare = Egress::default();
        let none = fingerprint("dev", &[], None, "", &bare, &Bootstrap::default());
        let one = fingerprint(
            "dev",
            &[share("/tank/media", "/mnt/ast/media")],
            Some(ShareKind::NinePfs),
            "",
            &bare,
            &Bootstrap::default(),
        );
        let elsewhere = fingerprint(
            "dev",
            &[share("/tank/media", "/srv/media")],
            Some(ShareKind::NinePfs),
            "",
            &bare,
            &Bootstrap::default(),
        );
        assert_eq!(
            none,
            fingerprint("dev", &[], None, "", &bare, &Bootstrap::default())
        );
        assert_ne!(none, one);
        assert_ne!(one, elsewhere);
        assert_ne!(
            one,
            fingerprint(
                "dev",
                &[share("/tank/media", "/mnt/ast/media")],
                Some(ShareKind::Virtiofs),
                "",
                &bare,
                &Bootstrap::default(),
            ),
            "a backend transport change has to reissue the guest's mount unit"
        );
        assert_ne!(
            one,
            fingerprint(
                "other",
                &[share("/tank/media", "/mnt/ast/media")],
                Some(ShareKind::NinePfs),
                "",
                &bare,
                &Bootstrap::default(),
            )
        );

        // Backend cloud-config is part of what the seed says, so it moves
        // the fingerprint too — a guest that changes backends gets a seed
        // built for the backend it is actually running on.
        assert_ne!(
            none,
            fingerprint(
                "dev",
                &[],
                None,
                "bootcmd:\n - [ sh, -c, x ]\n",
                &bare,
                &Bootstrap::default()
            )
        );
    }

    #[test]
    fn nocloud_network_config_is_absent_when_the_backend_has_none() {
        assert_eq!(nocloud_network_config(None), None);
        assert_eq!(nocloud_network_config(Some("")), None);
        assert_eq!(
            nocloud_network_config(Some("version: 2\n")),
            Some("version: 2\n")
        );
    }

    #[test]
    fn a_network_config_reissues_the_seed_and_an_empty_one_does_not() {
        let none = super::fingerprint(
            "dev",
            &[],
            None,
            "",
            None,
            &Egress::default(),
            &Bootstrap::default(),
        );
        assert_eq!(
            none,
            super::fingerprint(
                "dev",
                &[],
                None,
                "",
                Some(""),
                &Egress::default(),
                &Bootstrap::default(),
            )
        );
        assert_ne!(
            none,
            super::fingerprint(
                "dev",
                &[],
                None,
                "",
                Some("version: 2\n"),
                &Egress::default(),
                &Bootstrap::default(),
            )
        );
    }

    #[test]
    fn the_seed_stage_writes_network_config_only_when_the_backend_supplies_one() {
        let dir = tempfile::tempdir().unwrap();
        write_nocloud_files(dir.path(), "#cloud-config\n", "instance-id: x\n", None).unwrap();
        assert!(dir.path().join("user-data").is_file());
        assert!(dir.path().join("meta-data").is_file());
        assert!(
            !dir.path().join("network-config").exists(),
            "DHCP backends must not grow a network-config file"
        );

        write_nocloud_files(
            dir.path(),
            "#cloud-config\n",
            "instance-id: x\n",
            Some("version: 2\n"),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("network-config")).unwrap(),
            "version: 2\n"
        );
    }

    #[test]
    fn only_volumes_on_this_device_reach_the_hypervisor() {
        let mut inst =
            crate::registry::Shard::load(&std::env::temp_dir().join("nonexistent-registry.json"))
                .unwrap()
                .create(
                    "dev",
                    &local_host(),
                    "debian:13",
                    Default::default(),
                    crate::hv::Machine {
                        backend: "qemu".into(),
                        machine_type: "virt".into(),
                        cpu: "host".into(),
                        hv_version: "test".into(),
                    },
                )
                .unwrap();
        inst.volumes = vec![
            Volume::dir("/tank/here", &local_host(), None),
            Volume::dir("/tank/there", "some-other-box", None),
            // A block volume on this very device is still not a 9p share:
            // it is a disk, and it reaches the guest as one.
            Volume::block("tank", &local_host(), 1, 1 << 30),
        ];
        let shares = shares(&inst);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].host_path, "/tank/here");
    }

    /// cloud-init concatenates every `bootcmd` entry into **one** `/bin/sh`
    /// script, so an `exit` in one entry ends the entries after it too.
    ///
    /// That is not hypothetical: the host-key check exits early on a first
    /// boot, and a first boot is exactly when the backend's own entries —
    /// the vz console fix, and the guest agent that gives the host a
    /// control channel — have to run. Hence the subshell in
    /// [`HOSTKEY_BOOTCMD`], and hence this.
    ///
    /// Run for real, with nothing on `PATH`: every external command fails
    /// harmlessly, both guards take their early exit, and what is being
    /// asserted is that the script got to the end anyway.
    #[test]
    fn one_bootcmd_entry_cannot_end_the_others() {
        let backend = "bootcmd:\n - |\n   echo the-backends-own-entry\n";
        let merged = merge(
            &asterism_config(&[], None, &Egress::default(), &Bootstrap::default()),
            backend,
        )
        .unwrap();

        // What cloud-init makes of it: the entries, in order, as one
        // script. (Block scalars only — the list form a backend may also
        // use is quoted and joined, and is not what this is about.)
        let mut script = String::new();
        let mut inside = false;
        for line in merged.lines() {
            if !line.starts_with(' ') {
                inside = line.starts_with("bootcmd:");
                continue;
            }
            if inside && line.trim() != "- |" {
                script.push_str(line.strip_prefix("    ").unwrap_or(line.trim_start()));
                script.push('\n');
            }
        }
        assert!(script.contains("ssh-keygen -A"), "{script}");

        let ran = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("PATH=''\n{script}"))
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&ran.stdout).contains("the-backends-own-entry"),
            "the entry after the host-key check never ran:\nstdout {}\nstderr {}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr),
        );
    }
}
