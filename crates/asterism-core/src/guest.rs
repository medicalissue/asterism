//! The guest's own control channel, and the service at the other end of it.
//!
//! ## Why this exists
//!
//! Before this module the helper *hunted* its guest: parse
//! `/var/db/dhcpd_leases` for records matching a MAC or a hostname, then
//! connect to port 22 on each candidate until something sends an ssh
//! banner (see `helper/net.rs`). Every part of that is inference. The lease
//! file never removes a record, so a rebuilt instance has two; a guest
//! whose DHCP client sends an RFC 4361 client identifier writes no MAC at
//! all; and "something answered on :22" is the strongest statement
//! available about an address that was only ever a guess. Readiness then
//! means "sshd is serving", which is late, variable, and says nothing about
//! anything else one might want to ask a guest.
//!
//! Virtualization.framework already attaches a `VZVirtioSocketDevice` to
//! every guest this helper builds. A virtio socket is point-to-point: there
//! is exactly one guest at the other end of the device this helper holds,
//! it is not on any network, and nothing else on the host or the LAN can
//! reach or answer it. So the guest can simply *say* what its address is,
//! and say it over a channel that cannot be confused with another guest's.
//!
//! ## Shape
//!
//! ```text
//! astd-vz                                 guest
//!   connectToPort:1023  ------------->  AF_VSOCK listener (asterism-guest)
//!   <----------------  {"agent":"asterism","versions":[1],"nonce":…}
//!   {"version":1,"nonce":…,"proof":…} ->
//!   <----------------  {"ok":true,"proof":…,"facts":{…}}
//!   {"id":1,"op":"status"} ----------->
//!   <----------------  {"id":1,"ok":true,"status":{…}}
//! ```
//!
//! One JSON object per line in each direction, the guest answering the host
//! request by request. The guest speaks first, because the host has nothing
//! to say until it knows which versions it is talking to.
//!
//! ## Authentication
//!
//! Both sides prove possession of one per-instance key
//! ([`Key`]) over two fresh nonces, and the key itself never crosses the
//! wire:
//!
//! ```text
//! proof = HMAC-SHA256(key, "asterism-guest/<version> <side> <guest nonce> <host nonce>")
//! ```
//!
//! The side label is in the message so a host proof can never be replayed
//! as a guest proof, and the nonces are per connection so nothing can be
//! replayed at all.
//!
//! What this buys, given that vsock is already point-to-point: the guest at
//! the other end is the guest *this seed built*. A disk cloned from another
//! instance, or an image carrying somebody else's agent, holds a different
//! key and is refused by name rather than believed. And inside the guest
//! the key is root-only, which — with [`PORT`] being a privileged port —
//! means an unprivileged process there can neither bind the port nor pass
//! the handshake if it somehow did.
//!
//! ## Versioning
//!
//! The guest advertises every version it can speak and the host picks the
//! highest it shares. There is no "assume v1": an empty intersection is a
//! refusal that names both lists, on both sides, immediately — a guest and
//! a helper a release apart find out in milliseconds instead of hanging.

use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// The vsock port the guest agent listens on.
///
/// Below 1024 deliberately. Linux refuses an `AF_VSOCK` bind under that to
/// a process without `CAP_NET_BIND_SERVICE`, exactly as it does for TCP, so
/// the thing answering here is necessarily a privileged process in the
/// guest. An unprivileged one cannot squat the port and pretend to be the
/// agent. 1023 is the highest such port, chosen to stay out of the way of
/// anything conventional.
pub const PORT: u32 = 1023;

/// Protocol versions this build of the helper can speak, newest last.
///
/// * **1** — status, ping, sync, stop.
/// * **2** — bounded `exec` of one argv.
/// * **3** — the agent's own channel out: the host arms the guest with a
///   per-instance token, long-polls for `ast` calls the agent made inside the
///   box, and hands the answers back. See [`Session::agent_arm`].
pub const VERSIONS: &[u32] = &[1, 2, 3];

/// TCP port used by the static agent injected into direct-kernel OCI guests.
///
/// Native cloud-image agents keep using AF_VSOCK on [`PORT`]. OCI images may
/// contain no Python or init system, so their audited static agent listens on
/// the guest's private NIC instead. The same per-instance HMAC handshake is
/// required before any command is accepted.
pub const OCI_TCP_PORT: u16 = 1023;

/// Written by the static OCI agent after the host has authenticated, read a
/// status reply, and closed that readiness session. PID 1 waits for this
/// before launching the image entrypoint, so a one-shot cannot finish in the
/// gap between the agent listening and `ast up` learning that it is ready.
pub const OCI_ADMITTED_PATH: &str = "/run/asterism-guest-admitted";

/// Longest command the v2 guest-control wire accepts.
pub const MAX_EXEC_TIMEOUT: Duration = Duration::from_secs(300);

/// Bytes retained independently for stdout and stderr. Readers keep draining
/// after this cap so a noisy child cannot deadlock on a full pipe.
pub const MAX_EXEC_OUTPUT_BYTES: usize = 24 * 1024;

const MAX_GUEST_AGENT_BYTES: u64 = 32 * 1024 * 1024;

/// Audited static Linux agent injected into every direct-kernel OCI guest.
#[derive(Debug, Clone)]
pub struct Artifact {
    bytes: Vec<u8>,
}

impl Artifact {
    pub fn from_path(path: &Path) -> io::Result<Self> {
        let metadata = std::fs::metadata(path)?;
        if metadata.len() == 0 || metadata.len() > MAX_GUEST_AGENT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "guest-control artifact {} has invalid size {}",
                    path.display(),
                    metadata.len()
                ),
            ));
        }
        let bytes = std::fs::read(path)?;
        if !bytes.starts_with(b"\x7fELF") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("guest-control artifact {} is not ELF", path.display()),
            ));
        }
        let expected_machine = if cfg!(target_arch = "x86_64") {
            Some(62u16)
        } else if cfg!(target_arch = "aarch64") {
            Some(183u16)
        } else {
            None
        };
        if bytes.len() < 20 || bytes[4] != 2 || bytes[5] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "guest-control artifact {} is not a 64-bit little-endian ELF",
                    path.display()
                ),
            ));
        }
        let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
        if expected_machine.is_some_and(|expected| machine != expected) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "guest-control artifact {} has ELF machine {machine}, not this host's {expected}",
                    path.display(),
                    expected = expected_machine.unwrap()
                ),
            ));
        }
        Ok(Self { bytes })
    }

    /// Explicit packaging override, then the release layout beside `astd`,
    /// then each installed system layout — `lib/asterism` under this
    /// installation's prefix, `/usr/lib/asterism` for a native package,
    /// `/usr/local/lib/asterism` for a system-wide flat install. Absence is
    /// a boot refusal, never a guest that silently starts without its
    /// control plane.
    pub fn discover() -> io::Result<Self> {
        if let Some(path) = std::env::var_os("ASTERISM_GUEST_AGENT_ARTIFACT") {
            return Self::from_path(Path::new(&path));
        }
        let mut last = io::Error::new(
            io::ErrorKind::NotFound,
            "no installed guest-control artifact",
        );
        for dir in crate::layout::data_dirs() {
            match Self::from_path(&dir.join("guest/bin/asterism-guest")) {
                Ok(found) => return Ok(found),
                Err(error) if error.kind() == io::ErrorKind::NotFound => last = error,
                Err(error) => return Err(error),
            }
        }
        Err(last)
    }

    /// BusyBox fragment used by the generated OCI init after it has entered
    /// the image's configured working directory and exported its environment.
    pub fn oci_boot_script(&self, key: &Key) -> String {
        use data_encoding::BASE64;
        format!(
            "$BB mkdir -p /etc/asterism /.asterism /var/log\n\
             printf '%s\\n' '{}' > /etc/asterism/agent.key\n\
             $BB chmod 0600 /etc/asterism/agent.key\n\
             printf '%s' '{}' | $BB base64 -d > /.asterism/guest\n\
             $BB chmod 0755 /.asterism/guest\n\
             $BB mkdir -p /usr/local/bin\n\
             $BB ln -sf /.asterism/guest '{ast}'\n\
             $BB rm -f '{socket}'\n\
             $BB rm -f '{ready}'\n\
             /.asterism/guest >>/var/log/asterism-guest.log 2>&1 &\n\
             guest_control_pid=$!\n\
             i=0\n\
             while [ ! -f '{ready}' ] && [ $i -lt 1000 ]; do\n\
             \x20 if ! $BB kill -0 $guest_control_pid 2>/dev/null; then\n\
             \x20   echo 'asterism: OCI guest control exited before host admission'\n\
             \x20   $BB cat /var/log/asterism-guest.log 2>/dev/null\n\
             \x20   halt\n\
             \x20 fi\n\
             \x20 $BB sleep 0.1\n\
             \x20 i=$((i + 1))\n\
             done\n\
             if [ ! -f '{ready}' ]; then\n\
             \x20 echo 'asterism: host did not admit OCI guest control before the deadline'\n\
             \x20 halt\n\
             fi\n",
            key.hex(),
            BASE64.encode(&self.bytes),
            ast = GUEST_AST_PATH,
            socket = AGENT_CLI_SOCKET,
            ready = OCI_ADMITTED_PATH,
        )
    }

    #[cfg(test)]
    pub fn fixture(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// The most bytes either side will retain for one JSON frame, excluding its
/// newline.
///
/// Every v1 message is normally below a few kilobytes. This leaves generous
/// room for additive status fields while making the memory cost of a peer
/// that never sends a newline a property of the protocol rather than a value
/// that peer gets to choose. The embedded guest agent carries the same cap.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Where the guest keeps its copy of the key. Root-only, written by the
/// seed's `bootcmd` on every boot.
pub const GUEST_KEY_PATH: &str = "/etc/asterism/agent.key";

/// Where `ast` is on the guest's own PATH.
///
/// A symlink to the guest agent rather than a second binary: invoked under
/// this name the agent is the small client that hands one `ast` command to
/// the host and prints the answer. Nothing about the guest image carries it —
/// the link is made at boot beside the agent itself, so an agent image stays
/// a plain OCI image that anyone can `docker run`.
pub const GUEST_AST_PATH: &str = "/usr/local/bin/ast";

/// The guest-local socket that `ast` inside the box connects to.
///
/// Root-owned but world-connectable on purpose: everything in the box is the
/// agent, and the point of the feature is that the agent can reach it. It
/// grants nothing an instance did not already have — every call is executed
/// by the daemon against the one instance the host armed this guest for.
pub const AGENT_CLI_SOCKET: &str = "/run/asterism-ast.sock";

/// Where the guest's agent is installed.
pub const GUEST_AGENT_PATH: &str = "/usr/local/sbin/asterism-guest";

/// Where the guest records which revision of all this it already has.
pub const GUEST_STAMP_PATH: &str = "/etc/asterism/installed";

/// The unit that keeps it running.
pub const GUEST_UNIT: &str = "asterism-guest.service";

// ---- the key ---------------------------------------------------------------

/// The per-instance secret both ends prove possession of.
///
/// Thirty-two bytes of `/dev/urandom`, written once per instance and read
/// back on every boot. Stable on purpose: it is folded into the cloud-init
/// seed, and a seed whose bytes move is a seed with a new `instance-id`,
/// which makes a guest redo its whole first boot.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; 32]);

impl std::fmt::Debug for Key {
    /// Never the bytes. This type ends up on a `Config` that is written to
    /// disk and printed in error context.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl Key {
    /// Read the key at `path`, or mint one there if it is not there yet.
    ///
    /// The file is created at 0600 before anything is written into it, so
    /// the bytes are never briefly world-readable.
    pub fn ensure(path: &Path) -> Result<Key> {
        if let Some(key) = Self::read(path)? {
            return Ok(key);
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let key = Key(random()?);
        write_private(path, format!("{}\n", key.hex()).as_bytes())
            .with_context(|| format!("writing the guest agent key at {}", path.display()))?;
        Ok(key)
    }

    /// Read the key at `path`, or `None` if there is no file there.
    pub fn read(path: &Path) -> Result<Option<Key>> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(e).with_context(|| format!("reading {}", path.display()));
            }
        };
        Ok(Some(Key::parse(text.trim()).with_context(|| {
            format!("{} does not hold a guest agent key", path.display())
        })?))
    }

    pub fn parse(hex: &str) -> Result<Key> {
        let bytes = unhex(hex).context("a guest agent key is 64 hex characters")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("a guest agent key is 32 bytes"))?;
        Ok(Key(bytes))
    }

    pub fn hex(&self) -> String {
        hex(&self.0)
    }

    /// Borrow the raw key for protocols that derive a separate scoped key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The proof one side sends for this handshake.
    ///
    /// `side` is `"host"` or `"guest"` and is part of the message, so the
    /// two proofs of one handshake are different values and neither can
    /// stand in for the other.
    pub fn proof(&self, version: u32, side: &str, guest_nonce: &str, host_nonce: &str) -> String {
        hex(&hmac_sha256(
            &self.0,
            format!("asterism-guest/{version} {side} {guest_nonce} {host_nonce}").as_bytes(),
        ))
    }
}

/// Compare two proofs without leaking where they first differ.
fn same_proof(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---- the wire --------------------------------------------------------------

/// What the guest says the moment a connection opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Always `asterism`. A guard against having connected to something
    /// else entirely, answered before any secret is involved.
    pub agent: String,
    /// Every version the guest can speak.
    pub versions: Vec<u32>,
    pub nonce: String,
}

/// The host's answer: the version it picked, its nonce, and its proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accept {
    pub version: u32,
    pub nonce: String,
    pub proof: String,
}

/// The guest's answer to that: its own proof, and what it is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Welcome {
    pub ok: bool,
    #[serde(default)]
    pub proof: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub facts: Option<Facts>,
}

/// What does not change while a guest is up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Facts {
    pub hostname: String,
    /// `/proc/sys/kernel/random/boot_id` — a fresh value per boot, so the
    /// host can tell a reconnect from a reboot.
    #[serde(default)]
    pub boot_id: String,
    #[serde(default)]
    pub kernel: String,
    /// The agent's own identification, e.g. `asterism-guest/1`.
    #[serde(default)]
    pub agent: String,
}

/// One request. `id` comes back on the answer, so a reply can never be
/// mistaken for the answer to a question that timed out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub op: String,
    /// For `status`: how long the guest may hold the answer back waiting to
    /// become reachable.
    ///
    /// This is what makes readiness an event rather than a poll. A guest
    /// that is not up yet does not answer "not yet" — it answers the moment
    /// it *is* up, so a boot waits for the guest and not for the next turn
    /// of somebody's timer. Bounded, because a session that is busy holding
    /// an answer cannot carry a stop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    /// Argument vector for protocol-v2 `exec`. There is deliberately no shell
    /// string: quoting belongs to the caller and the guest executes exactly
    /// the argv it authenticated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// Guest-side lifecycle deadline for protocol-v2 `exec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Protocol-v3 `agent_arm`: the per-instance token the guest agent is to
    /// stamp on every `ast` call it forwards from inside the box.
    ///
    /// It travels only on this already-authenticated channel and the guest
    /// agent keeps it in memory. Nothing in the guest writes it down, so it
    /// is in no disk, no snapshot and no bug report — and the agent in the
    /// box cannot read it, which is the point: the token says *which
    /// instance is calling*, and an instance does not get to choose that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Protocol-v3 `agent_reply`: what the host made of one forwarded call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_reply: Option<AgentReply>,
}

/// One answer.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Answer {
    pub id: u64,
    #[serde(default)]
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// How long the guest spent inside `sync(2)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<f64>,
    /// Protocol-v2 command result. Output fields are base64 so arbitrary guest
    /// bytes stay valid JSON without becoming arrays four times their size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecWireResult>,
    /// Protocol-v3 `agent_next`: one `ast` call the agent made inside the
    /// box, or absent when it made none before the poll expired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentCall>,
}

/// One `ast …` an agent typed inside the box, on its way out to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AgentCall {
    /// Unique within this guest's boot; the answer carries it back.
    pub id: u64,
    /// The token the host armed this guest with. The daemon uses it to decide
    /// which instance the call is about, and it will not accept the
    /// instance's own opinion on that.
    pub token: String,
    /// The words after `ast`, exactly as typed.
    pub argv: Vec<String>,
}

/// What the host made of one forwarded call: what to print, and what to exit.
///
/// More than one of these may answer a single call. `status: None` is an
/// interim write — print it and keep waiting — which is what lets `ast ask`
/// say *waiting for a reply…* the moment the question has been delivered and
/// then print the answer whenever it arrives, minutes or hours later. The
/// first reply carrying a status ends the call.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AgentReply {
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
    #[serde(default)]
    pub stdout_b64: String,
    #[serde(default)]
    pub stderr_b64: String,
}

impl AgentReply {
    /// Print this and stop.
    pub fn done(id: u64, status: i32, stdout: &str, stderr: &str) -> Self {
        use data_encoding::BASE64;
        Self {
            id,
            status: Some(status),
            stdout_b64: BASE64.encode(stdout.as_bytes()),
            stderr_b64: BASE64.encode(stderr.as_bytes()),
        }
    }

    /// Print this and keep waiting.
    pub fn interim(id: u64, stdout: &str) -> Self {
        use data_encoding::BASE64;
        Self {
            id,
            status: None,
            stdout_b64: BASE64.encode(stdout.as_bytes()),
            stderr_b64: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExecWireResult {
    pub status: i32,
    pub stdout_b64: String,
    pub stderr_b64: String,
    #[serde(default)]
    pub stdout_truncated: bool,
    #[serde(default)]
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

/// What the guest reports about itself right now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    /// The guest's own addresses, the one its default route would send
    /// from first. This is the answer the lease file was being asked for.
    #[serde(default)]
    pub addrs: Vec<IpAddr>,
    #[serde(default)]
    pub uptime_secs: f64,
    /// Is anything in the guest accepting ssh yet?
    ///
    /// This is what makes the agent's readiness mean what the ssh-banner
    /// hunt meant — `ast up` returns an endpoint a user can immediately
    /// `ast ssh` to. The guest answers from its own `/proc`, which is both
    /// cheaper and more direct than knocking on port 22 from outside.
    #[serde(default)]
    pub ssh: bool,
    /// `done`, `running`, `error` or `unknown` — cloud-init's own view,
    /// read from `/run/cloud-init`, so a guest that is up but still
    /// provisioning is distinguishable from one that has finished.
    #[serde(default)]
    pub cloud_init: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load1: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_available_kib: Option<u64>,
}

impl Status {
    /// The address `ast ssh` should use, once the guest is actually
    /// reachable on it.
    ///
    /// Two conditions, and the second is what keeps `ast up` meaning what
    /// it always meant: the guest has an address, and something in there is
    /// serving ssh. An address on its own arrives a second or two earlier —
    /// DHCP completes long before sshd does — and handing it back then
    /// would turn `ast up && ast ssh` into a race.
    ///
    /// Filtered rather than taken on trust. A guest is the user's own root
    /// and is not an adversary here, but "whatever the guest says" is still
    /// the wrong thing to hand an ssh client: a wrong or hostile answer
    /// would have this host open a connection to an arbitrary address on
    /// the internet. A guest lives behind macOS's NAT, so its address is
    /// private by construction, and anything else is not an address of the
    /// guest we are talking to.
    pub fn endpoint(&self) -> Option<IpAddr> {
        if !self.ssh {
            return None;
        }
        self.addrs.iter().copied().find(is_guest_addr)
    }
}

/// Is this an address a guest can plausibly have, and this host reach?
pub fn is_guest_addr(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private() && !v4.is_loopback() && !v4.is_link_local() && !v4.is_broadcast()
        }
        // Unique local addresses (fc00::/7). VZ's NAT hands out v4, so this
        // is here for completeness rather than for today's path.
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

// ---- the host's half -------------------------------------------------------

/// An authenticated conversation with one guest agent.
///
/// Generic over the two halves of whatever carries it: a duped vsock
/// descriptor in the helper, a child process's pipes in this module's
/// tests. The protocol is the same either way, and testing it against the
/// *actual* agent is the point — a Rust reimplementation of the guest side
/// would prove only that this file agrees with itself.
pub struct Session<R: BufRead, W: Write> {
    reader: R,
    writer: W,
    version: u32,
    facts: Facts,
    next_id: u64,
}

impl<R: BufRead, W: Write> Session<R, W> {
    /// Do the handshake, or fail saying which half of it went wrong.
    pub fn open(reader: R, writer: W, key: &Key) -> Result<Self> {
        Self::open_with_nonce(reader, writer, key, &nonce()?)
    }

    /// [`Session::open`] with the host nonce supplied, so a test can pin
    /// both halves of a handshake and check the exact bytes.
    pub fn open_with_nonce(
        mut reader: R,
        mut writer: W,
        key: &Key,
        host_nonce: &str,
    ) -> Result<Self> {
        let hello: Hello = read_line(&mut reader).context("reading the guest agent's hello")?;
        if hello.agent != "asterism" {
            bail!(
                "the service on vsock port {PORT} calls itself {:?}, which is not the \
                 asterism guest agent",
                hello.agent
            );
        }
        let version = pick_version(&hello.versions).ok_or_else(|| {
            anyhow::anyhow!(
                "no protocol version in common: the guest agent speaks {:?} and this \
                 helper speaks {:?} — the guest's seed is from a different release",
                hello.versions,
                VERSIONS
            )
        })?;
        write_line(
            &mut writer,
            &Accept {
                version,
                nonce: host_nonce.to_owned(),
                proof: key.proof(version, "host", &hello.nonce, host_nonce),
            },
        )?;
        let welcome: Welcome =
            read_line(&mut reader).context("reading the guest agent's answer to our proof")?;
        if !welcome.ok {
            bail!(
                "the guest agent refused this helper: {}",
                welcome.error.as_deref().unwrap_or("no reason given")
            );
        }
        let expected = key.proof(version, "guest", &hello.nonce, host_nonce);
        if !same_proof(&welcome.proof, &expected) {
            bail!(
                "the guest agent did not prove it holds this instance's key — \
                 something else is answering on vsock port {PORT}"
            );
        }
        Ok(Session {
            reader,
            writer,
            version,
            facts: welcome.facts.unwrap_or_else(|| Facts {
                hostname: String::new(),
                boot_id: String::new(),
                kernel: String::new(),
                agent: String::new(),
            }),
            next_id: 1,
        })
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn facts(&self) -> &Facts {
        &self.facts
    }

    /// Ask for the guest's current view of itself.
    pub fn status(&mut self) -> Result<Status> {
        self.status_within(None)
    }

    /// The same, but let the guest hold the answer until it is reachable.
    ///
    /// Returns whatever the guest has when the wait runs out, so a caller
    /// loops on this rather than treating one answer as final.
    pub fn ready_within(&mut self, wait: Duration) -> Result<Status> {
        self.status_within(Some(wait))
    }

    fn status_within(&mut self, wait: Option<Duration>) -> Result<Status> {
        self.request("status", wait.map(|w| w.as_millis() as u64))?
            .status
            .ok_or_else(|| anyhow::anyhow!("the guest agent answered status with no status"))
    }

    /// Cheapest possible liveness question.
    pub fn ping(&mut self) -> Result<()> {
        self.call("ping").map(|_| ())
    }

    /// `sync(2)` in the guest, answered when it returns.
    ///
    /// The barrier: after this, what the guest had in its page cache is on
    /// the disk the host is holding. Every forced stop takes one first,
    /// because a guest that will not answer ACPI may well still answer
    /// this — the agent is a process of its own and does not care what
    /// systemd is doing.
    pub fn sync(&mut self) -> Result<f64> {
        Ok(self.call("sync")?.elapsed_ms.unwrap_or(0.0))
    }

    /// Ask the guest to power itself off.
    ///
    /// Deterministic where ACPI is a hint: this reaches a process that runs
    /// `systemctl poweroff`, rather than a virtual power button the guest
    /// is free to have no handler for. The answer means the guest accepted
    /// the request, not that it is down — the delegate says that.
    pub fn stop(&mut self) -> Result<()> {
        self.call("stop").map(|_| ())
    }

    /// Execute one argv through a protocol-v2 guest agent.
    pub fn exec(&mut self, argv: Vec<String>, timeout: Duration) -> Result<ExecResult> {
        if self.version < 2 {
            bail!(
                "the guest agent speaks protocol {}, which has no exec operation",
                self.version
            );
        }
        if argv.is_empty() {
            bail!("guest exec needs a command");
        }
        if timeout.is_zero() || timeout > MAX_EXEC_TIMEOUT {
            bail!(
                "guest exec timeout must be between 1 ms and {} seconds",
                MAX_EXEC_TIMEOUT.as_secs()
            );
        }
        let answer = self.request_with("exec", None, argv, Some(timeout.as_millis() as u64))?;
        let wire = answer
            .exec
            .ok_or_else(|| anyhow::anyhow!("the guest agent answered exec with no result"))?;
        use data_encoding::BASE64;
        let stdout = BASE64
            .decode(wire.stdout_b64.as_bytes())
            .context("the guest agent returned invalid base64 stdout")?;
        let stderr = BASE64
            .decode(wire.stderr_b64.as_bytes())
            .context("the guest agent returned invalid base64 stderr")?;
        if stdout.len() > MAX_EXEC_OUTPUT_BYTES || stderr.len() > MAX_EXEC_OUTPUT_BYTES {
            bail!("the guest agent returned exec output above the negotiated cap");
        }
        Ok(ExecResult {
            status: wire.status,
            stdout,
            stderr,
            stdout_truncated: wire.stdout_truncated,
            stderr_truncated: wire.stderr_truncated,
        })
    }

    /// Hand the guest agent the token it is to stamp on every `ast` call the
    /// agent inside the box makes, and have it start listening for them.
    ///
    /// Idempotent and re-armable: a fresh token replaces the one before it,
    /// which is how a rewind or a fork revokes the old one without anything
    /// in the guest having to be told.
    pub fn agent_arm(&mut self, token: &str) -> Result<()> {
        self.require_agent_channel("agent_arm")?;
        self.send(
            "agent_arm",
            None,
            Vec::new(),
            None,
            Some(token.to_owned()),
            None,
        )
        .map(|_| ())
    }

    /// Wait up to `wait` for the agent in the box to run one `ast` command.
    ///
    /// A long poll rather than a callback because the control channel is, and
    /// stays, host-initiated: the guest never dials the host. `Ok(None)` is
    /// the ordinary answer — it means the agent was busy doing its job.
    pub fn agent_next(&mut self, wait: Duration) -> Result<Option<AgentCall>> {
        self.require_agent_channel("agent_next")?;
        let answer = self.send(
            "agent_next",
            Some(wait.as_millis().min(u128::from(u64::MAX)) as u64),
            Vec::new(),
            None,
            None,
            None,
        )?;
        Ok(answer.agent)
    }

    /// Complete one forwarded call. The `ast` waiting inside the box prints
    /// this and exits with this status.
    pub fn agent_reply(&mut self, reply: AgentReply) -> Result<()> {
        self.require_agent_channel("agent_reply")?;
        self.send("agent_reply", None, Vec::new(), None, None, Some(reply))
            .map(|_| ())
    }

    fn require_agent_channel(&self, op: &str) -> Result<()> {
        if self.version < 3 {
            bail!(
                "the guest agent speaks protocol {}, which has no {op} operation",
                self.version
            );
        }
        Ok(())
    }

    fn call(&mut self, op: &str) -> Result<Answer> {
        self.request(op, None)
    }

    fn request(&mut self, op: &str, wait_ms: Option<u64>) -> Result<Answer> {
        self.request_with(op, wait_ms, Vec::new(), None)
    }

    fn request_with(
        &mut self,
        op: &str,
        wait_ms: Option<u64>,
        argv: Vec<String>,
        timeout_ms: Option<u64>,
    ) -> Result<Answer> {
        self.send(op, wait_ms, argv, timeout_ms, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        op: &str,
        wait_ms: Option<u64>,
        argv: Vec<String>,
        timeout_ms: Option<u64>,
        token: Option<String>,
        agent_reply: Option<AgentReply>,
    ) -> Result<Answer> {
        let id = self.next_id;
        self.next_id += 1;
        write_line(
            &mut self.writer,
            &Request {
                id,
                op: op.to_owned(),
                wait_ms,
                argv,
                timeout_ms,
                token: token.clone(),
                agent_reply: agent_reply.clone(),
            },
        )?;
        let answer: Answer = read_line(&mut self.reader)
            .with_context(|| format!("reading the guest agent's answer to {op:?}"))?;
        if answer.id != id {
            bail!(
                "the guest agent answered request {} while {id} was outstanding",
                answer.id
            );
        }
        if !answer.ok {
            bail!(
                "the guest agent refused {op:?}: {}",
                answer.error.as_deref().unwrap_or("no reason given")
            );
        }
        Ok(answer)
    }
}

/// The newest version both ends can speak.
pub fn pick_version(theirs: &[u32]) -> Option<u32> {
    VERSIONS
        .iter()
        .filter(|v| theirs.contains(v))
        .max()
        .copied()
}

fn read_line<T: serde::de::DeserializeOwned>(reader: &mut impl BufRead) -> Result<T> {
    let line = read_frame(reader)?;
    let line =
        std::str::from_utf8(&line).context("the guest agent sent a frame that was not utf-8")?;
    serde_json::from_str(line.trim())
        .with_context(|| format!("the guest agent sent {:?}", truncate(line.trim())))
}

/// Read one frame without first letting `BufRead::read_line` grow a `String`
/// to a size chosen by the peer.
///
/// The prospective size is checked before a chunk is retained. In
/// particular, the chunk containing the newline is checked too: a peer
/// cannot fill the buffer to the limit and smuggle one more byte beside the
/// terminator.
fn read_frame(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            if frame.is_empty() {
                bail!("the guest agent closed the connection");
            }
            // Preserve the old EOF-after-a-line behaviour for scripted and
            // older agents. A live socket does not reach this path until its
            // writer closes.
            return Ok(frame);
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let would_be = frame.len() + newline.unwrap_or(chunk.len());
        if would_be > MAX_FRAME_BYTES {
            bail!("the guest agent sent more than {MAX_FRAME_BYTES} bytes before ending a frame");
        }
        if let Some(at) = newline {
            frame.extend_from_slice(&chunk[..at]);
            reader.consume(at + 1);
            return Ok(frame);
        }
        let taken = chunk.len();
        frame.extend_from_slice(chunk);
        reader.consume(taken);
    }
}

fn write_line(writer: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()?;
    Ok(())
}

/// A guest can say anything at all, including a megabyte of it. Error
/// context quotes what arrived, so what arrived is trimmed first.
fn truncate(line: &str) -> String {
    match line.char_indices().nth(160) {
        None => line.to_owned(),
        Some((cut, _)) => format!("{}…", &line[..cut]),
    }
}

// ---- primitives ------------------------------------------------------------

/// HMAC-SHA256 (RFC 2104), spelled out rather than taken as a dependency.
///
/// It is nine lines and the alternative is another crate in the signed
/// helper's build. `sha2` is already compiled in this tree.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    // A key longer than the block is hashed first; ours never is, and the
    // rule is here so this stays HMAC rather than something adjacent to it.
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(padded.map(|b| b ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(padded.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// Sixteen bytes of `/dev/urandom`, hex. Fresh per connection, which is
/// what stops a proof being replayed.
pub fn nonce() -> Result<String> {
    let mut bytes = [0u8; 16];
    fill(&mut bytes)?;
    Ok(hex(&bytes))
}

fn random() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    fill(&mut bytes)?;
    Ok(bytes)
}

/// The kernel's random device. No crate: this is one `read` of a file that
/// exists on every host this runs on, and getting it wrong is loud.
fn fill(bytes: &mut [u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
        f.read_exact(bytes).context("reading /dev/urandom")?;
        Ok(())
    }
    #[cfg(windows)]
    {
        // uuid v4 is already the workspace's portable CSPRNG. Two draws fill
        // the 32-byte guest-agent key without adding a second random crate.
        let mut at = 0;
        while at < bytes.len() {
            let uuid = uuid::Uuid::new_v4();
            let src = uuid.as_bytes();
            let n = (bytes.len() - at).min(src.len());
            bytes[at..at + n].copy_from_slice(&src[..n]);
            at += n;
        }
        Ok(())
    }
}

/// Write a file only its owner can read, without it existing readable
/// first.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("{:?} is not hex", truncate(s));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| anyhow::anyhow!("{:?} is not hex", truncate(s)))
        })
        .collect()
}

// ---- the guest's half ------------------------------------------------------

/// The agent itself.
///
/// Python 3 for one reason: every image that can read a cloud-init seed has
/// a Python 3 to read it with, and `AF_VSOCK` has been in that language's
/// standard library since 3.7. The alternative is a compiled binary, which
/// would mean cross-compiling per guest architecture, shipping it, getting
/// it into the guest, and keeping all of that signed and versioned — for a
/// service whose whole job is to read a line and answer it.
///
/// It is installed by [`cloud_config`] and run by `asterism-guest.service`.
/// Everything it answers is in this file's protocol section; the two halves
/// are tested against each other in this module's tests, by running this
/// very text.
pub const AGENT_PY: &str = r##"#!/usr/bin/env python3
"""Asterism guest agent: the host's control channel into this guest.

Installed by cloud-init, run by asterism-guest.service, and driven by the
astd-vz helper over AF_VSOCK. The protocol is documented in
crates/asterism-vz/src/guest.rs; this file is the other half of it.

Nothing here imports anything that is not in the standard library, because
the guest is somebody's stock cloud image and installing into it is not
this agent's business.
"""

import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import time

NAME = "asterism-guest"
VERSIONS = [1]
PORT = 1023
# The one path that is not fixed: a test drives this very file without a
# virtual machine, and it has no /etc to write into.
KEY_PATH = os.environ.get("ASTERISM_AGENT_KEY", "/etc/asterism/agent.key")
# A connection nobody has said anything on for this long is gone. The host
# reconnects rather than resuming, so holding it open serves nobody.
IDLE_TIMEOUT = 300
# Maximum bytes in one JSON object, not counting its newline. Kept in step
# with MAX_FRAME_BYTES in the Rust half. `recv` checks it before JSON or the
# authentication proof sees the frame.
MAX_FRAME_BYTES = 65536


def log(message):
    sys.stderr.write("%s: %s\n" % (NAME, message))
    sys.stderr.flush()


def read_text(path, default=""):
    try:
        with open(path) as handle:
            return handle.read().strip()
    except OSError:
        return default


def load_key():
    text = read_text(KEY_PATH)
    if not text:
        raise SystemExit("%s: no key at %s" % (NAME, KEY_PATH))
    return bytes.fromhex(text)


def proof(key, version, side, guest_nonce, host_nonce):
    message = "asterism-guest/%d %s %s %s" % (version, side, guest_nonce, host_nonce)
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def facts():
    return {
        "hostname": socket.gethostname(),
        "boot_id": read_text("/proc/sys/kernel/random/boot_id"),
        "kernel": os.uname().release,
        "agent": "%s/%d" % (NAME, VERSIONS[-1]),
    }


# Where a route lookup is aimed to find out which address this guest would
# answer on. The first is the default route (TEST-NET-1, RFC 5737, routed
# nowhere); the rest are the private blocks, so a guest with more than one
# interface reports the address of each. Every one is a *connected UDP
# socket*, which asks the routing table and sends nothing at all.
#
# Deliberately no name resolution anywhere in here: getaddrinfo() on this
# guest's own hostname is the obvious way to enumerate addresses and it
# blocks for as long as a broken resolver takes, which would make the
# host's readiness wait on the guest's DNS.
ROUTE_PROBES = [
    (socket.AF_INET, "192.0.2.1"),
    (socket.AF_INET, "10.0.0.1"),
    (socket.AF_INET, "172.16.0.1"),
    (socket.AF_INET, "192.168.0.1"),
    (socket.AF_INET6, "2001:db8::1"),
]


def addresses():
    """This guest's addresses, the one the host should use first."""
    addrs = []
    for family, probe in ROUTE_PROBES:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.connect((probe, 9))
            addr = sock.getsockname()[0].split("%")[0]  # a scope id is not one
            if addr not in addrs and not addr.startswith("127.") and addr != "::1":
                addrs.append(addr)
        except OSError:
            pass
        finally:
            sock.close()
    return addrs


def ssh_listening():
    """Is anything in this guest accepting ssh yet?

    Read out of /proc rather than by connecting to port 22: a connection
    that opens and says nothing writes a line into this guest's own logs,
    and the host asks this several times a second while a guest boots.

    `0A` is TCP_LISTEN and `0016` is port 22. A socket-activated sshd counts
    and should: systemd is listening on its behalf, and a connection will be
    accepted.
    """
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as handle:
                next(handle, None)  # the header row
                for line in handle:
                    fields = line.split()
                    if (len(fields) > 3 and fields[3] == "0A"
                            and fields[1].endswith(":0016")):
                        return True
        except OSError:
            pass
    return False


def cloud_init_state():
    if os.path.exists("/run/cloud-init/result.json"):
        try:
            with open("/run/cloud-init/result.json") as handle:
                errors = json.load(handle).get("v1", {}).get("errors") or []
            return "error" if errors else "done"
        except (OSError, ValueError):
            return "done"
    if os.path.exists("/run/cloud-init/status.json"):
        return "running"
    return "unknown"


def load1():
    try:
        return float(read_text("/proc/loadavg").split()[0])
    except (IndexError, ValueError):
        return None


def mem_available_kib():
    for line in read_text("/proc/meminfo").splitlines():
        if line.startswith("MemAvailable:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def uptime_secs():
    try:
        return float(read_text("/proc/uptime").split()[0])
    except (IndexError, ValueError):
        return 0.0


def status():
    return {
        "addrs": addresses(),
        "ssh": ssh_listening(),
        "uptime_secs": uptime_secs(),
        "cloud_init": cloud_init_state(),
        "load1": load1(),
        "mem_available_kib": mem_available_kib(),
    }


def power_off():
    """Take this guest down, having already answered that we would."""
    log("the host asked this guest to power off")
    os.sync()
    for command in (["systemctl", "poweroff"], ["poweroff"], ["/sbin/poweroff"]):
        try:
            subprocess.Popen(command, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            return
        except OSError:
            continue
    log("nothing in this guest can power it off")


def reachable(state):
    """Is this guest something the host can actually reach yet?

    The two things the host is waiting for, judged here so that the guest
    can answer the moment they are true rather than the next time it is
    asked.
    """
    return bool(state["addrs"]) and state["ssh"]


def handle(op, wait_ms):
    if op == "ping":
        return {}
    if op == "status":
        state = status()
        # Hold the answer back until this guest is up, if the host said it
        # would wait. Cheap to re-check and it is what turns the host's
        # readiness from "the next poll after it happened" into "when it
        # happened".
        deadline = time.monotonic() + (wait_ms or 0) / 1000.0
        while not reachable(state) and time.monotonic() < deadline:
            time.sleep(0.05)
            state = status()
        return {"status": state}
    if op == "sync":
        started = time.time()
        os.sync()
        return {"elapsed_ms": (time.time() - started) * 1000.0}
    if op == "stop":
        # Answered first, acted on once the answer is on the wire: a guest
        # that powers off before saying it would leaves the host guessing.
        return {}
    raise ValueError("this agent has no %r" % (op,))


def send(out, obj):
    out.write((json.dumps(obj) + "\n").encode())
    out.flush()


def recv(inp):
    # The extra byte distinguishes an exactly-full frame from one that has
    # crossed the limit. Unlike bare readline(), this never allocates in
    # proportion to a peer that withholds its newline.
    line = inp.readline(MAX_FRAME_BYTES + 1)
    if not line:
        return None
    payload_len = len(line) - (1 if line.endswith(b"\n") else 0)
    if payload_len > MAX_FRAME_BYTES:
        log("closing a connection whose frame exceeded %d bytes" % MAX_FRAME_BYTES)
        return None
    try:
        return json.loads(line.decode().strip())
    except ValueError:
        log("ignoring a line that is not json")
        return None


def serve(key, inp, out):
    """One connection: the handshake, then requests until it closes."""
    guest_nonce = os.urandom(16).hex()
    send(out, {"agent": "asterism", "versions": VERSIONS, "nonce": guest_nonce})
    accept = recv(inp)
    if accept is None:
        return
    version = accept.get("version")
    if version not in VERSIONS:
        send(out, {"ok": False, "error":
                   "this guest agent speaks %s, and the host chose %r"
                   % (VERSIONS, version)})
        return
    host_nonce = str(accept.get("nonce", ""))
    want = proof(key, version, "host", guest_nonce, host_nonce)
    if not hmac.compare_digest(want, str(accept.get("proof", ""))):
        log("refused a caller that does not hold this instance's key")
        send(out, {"ok": False, "error":
                   "the host did not prove it holds this instance's key"})
        return
    send(out, {"ok": True,
               "proof": proof(key, version, "guest", guest_nonce, host_nonce),
               "facts": facts()})
    while True:
        request = recv(inp)
        if request is None:
            return
        rid = request.get("id", 0)
        op = request.get("op", "")
        try:
            answer = handle(op, request.get("wait_ms"))
            answer["id"] = rid
            answer["ok"] = True
        except Exception as failure:  # an op that cannot be done is an answer
            answer = {"id": rid, "ok": False, "error": str(failure)}
        send(out, answer)
        if op == "stop" and answer["ok"]:
            power_off()
            return


def listener(argv):
    """Where to serve: vsock in a guest, a unix socket or stdio in a test.

    The two test transports exist so the protocol can be exercised without
    a virtual machine -- the code they reach is the same code a helper
    reaches, which is the whole point of having them.
    """
    if "--stdio" in argv:
        return None
    if "--listen-unix" in argv:
        path = argv[argv.index("--listen-unix") + 1]
        try:
            os.unlink(path)
        except OSError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(path)
    else:
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.bind((socket.VMADDR_CID_ANY, PORT))
    sock.listen(1)
    return sock


def main(argv):
    key = load_key()
    sock = listener(argv)
    if sock is None:
        serve(key, sys.stdin.buffer, sys.stdout.buffer)
        return 0
    log("listening")
    while True:
        conn, _ = sock.accept()
        conn.settimeout(IDLE_TIMEOUT)
        try:
            with conn.makefile("rb") as inp, conn.makefile("wb") as out:
                serve(key, inp, out)
        except OSError as failure:
            log("connection ended: %s" % failure)
        finally:
            conn.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
"##;

/// The systemd unit that keeps the agent running.
///
/// `modprobe` first because the host-specific vsock transport is a module in
/// most distributions and nothing else in a guest ever asks for it. Hyper-V
/// uses `hv_sock`; VZ, Cloud Hypervisor and QEMU use the virtio transport.
/// Loading a transport that has no matching device is harmless, and failures
/// are ignored for guests that build their one applicable transport in.
/// `Restart` because the agent is the host's only deterministic way in, and
/// the guest is unattended by definition.
const AGENT_UNIT: &str = "\
[Unit]
Description=Asterism guest agent (the host's control channel, over vsock)
After=local-fs.target systemd-modules-load.service
Documentation=https://asterism.run

[Service]
Type=simple
ExecStartPre=-/sbin/modprobe hv_sock
ExecStartPre=-/sbin/modprobe vmw_vsock_virtio_transport
ExecStart=/usr/local/sbin/asterism-guest
Restart=always
RestartSec=1
StandardOutput=append:/var/log/asterism-guest.log
StandardError=append:/var/log/asterism-guest.log
# Never the reason a guest cannot shut down.
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
";

/// The cloud-config that puts the agent in a guest and starts it.
///
/// Everything is in `bootcmd`, which is unusual and deliberate:
///
/// * `bootcmd` runs on **every** boot, from cloud-init's earliest stage. So
///   the agent is up within seconds of userspace on the very first boot,
///   long before `runcmd`/cloud-final — which is where a `write_files` +
///   `runcmd` installation could first start it, i.e. after the slowest
///   part of provisioning. Readiness that arrives before sshd is the
///   difference this whole module is for.
/// * It is idempotent, so it is also the repair: a guest whose agent was
///   deleted, or whose unit was masked, gets it back on the next boot.
/// * Nothing here `exit`s at the top level. cloud-init concatenates every
///   `bootcmd` entry into one `/bin/sh` script, so an `exit` in one entry
///   ends the others too — hence the subshell.
///
/// The key is written into the guest at 0600. That is the same deal every
/// other thing in a seed gets: readable by whoever holds the instance, and
/// meaningless to anybody else — it authenticates the pairing of this
/// helper with this guest and grants nothing outside it.
pub fn cloud_config(key: &Key) -> String {
    let mut out = String::from("bootcmd:\n - |\n");
    for line in install_script(key).lines() {
        if line.trim().is_empty() {
            out.push('\n');
        } else {
            out.push_str("   ");
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// The `/bin/sh` half of [`cloud_config`], before it is folded into YAML.
///
/// Separate so it can be handed to `sh -n` in a test: this text is written
/// once and then runs, unattended, inside every guest, and a heredoc closed
/// in the wrong place would be found by whoever's agent stopped answering.
fn install_script(key: &Key) -> String {
    let revision = revision(key);
    let mut script = String::new();
    script.push_str(
        "\
# Asterism: install and start the guest agent. Early, every boot, idempotent.
(
set -e
command -v python3 >/dev/null 2>&1 || {
echo 'asterism: this guest has no python3, so it can have no guest agent' >&2
exit 0
}
",
    );
    // Everything below the stamp is skipped on a boot that would only write
    // back what is already there. It is not just tidiness: `systemctl
    // daemon-reload` runs before this guest has reached basic.target, and
    // paying for one on every boot is most of a second of somebody's `ast
    // up` spent reloading units that did not change.
    script.push_str(&format!(
        "if [ \"$(cat {GUEST_STAMP_PATH} 2>/dev/null)\" = '{revision}' ]; then\n\
         # Already the agent we ship. Make sure it is running and get out of\n\
         # the boot's way.\n\
         systemctl start --no-block {GUEST_UNIT} || true\n\
         exit 0\n\
         fi\n"
    ));
    script.push_str(
        "umask 077
mkdir -p /etc/asterism
",
    );
    script.push_str(&format!(
        "printf '%s\\n' '{}' > {GUEST_KEY_PATH}\nchmod 0600 {GUEST_KEY_PATH}\n",
        key.hex()
    ));
    script.push_str(&format!(
        "cat > {GUEST_AGENT_PATH} <<'ASTERISM_AGENT_PY'\n{AGENT_PY}ASTERISM_AGENT_PY\n\
         chmod 0755 {GUEST_AGENT_PATH}\n"
    ));
    script.push_str(&format!(
        "cat > /etc/systemd/system/{GUEST_UNIT} <<'ASTERISM_AGENT_UNIT'\n{AGENT_UNIT}\
         ASTERISM_AGENT_UNIT\n\
         # 0644 despite the umask above: a unit systemd cannot read as\n\
         # anyone but root works, and says so in the journal on every boot.\n\
         chmod 0644 /etc/systemd/system/{GUEST_UNIT}\n"
    ));
    script.push_str(&format!(
        "printf '%s\\n' '{revision}' > {GUEST_STAMP_PATH}\n\
         systemctl daemon-reload\n\
         systemctl enable {GUEST_UNIT} >/dev/null 2>&1 || true\n\
         # --no-block: this runs before basic.target, and waiting for a job\n\
         # systemd has not reached yet would hold up the boot it is part of.\n\
         # `restart`, because what was just written is not what is running.\n\
         systemctl restart --no-block {GUEST_UNIT} || true\n\
         ) || echo 'asterism: the guest agent could not be installed' >&2\n"
    ));
    script
}

/// What is installed in the guest right now, as one short string.
///
/// Covers the agent, its unit and the key, so any change to any of them is
/// a different revision and the next boot installs it. Short because it is
/// compared with `[` in a shell on every boot, and a truncated sha256 is
/// still far more than enough to tell two builds of this file apart.
fn revision(key: &Key) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(AGENT_PY.as_bytes());
    h.update(AGENT_UNIT.as_bytes());
    h.update(key.hex().as_bytes());
    hex(&h.finalize()[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::BufReader;
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

    /// Drive a handshake against a canned script and return why it failed.
    /// `Session` holds a reader and a writer, neither of which is `Debug`,
    /// so the error comes back as text rather than through `unwrap_err`.
    fn one_shot(script: &str, host_nonce: &str) -> String {
        let script = format!("{}\n", script.trim_end());
        match Session::open_with_nonce(
            BufReader::new(script.as_bytes()),
            Vec::new(),
            &key(),
            host_nonce,
        ) {
            Ok(_) => panic!("that handshake should not have completed"),
            Err(e) => format!("{e:#}"),
        }
    }

    fn key() -> Key {
        Key::parse("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap()
    }

    // ---- the primitives -----------------------------------------------------

    /// RFC 4231's first two HMAC-SHA256 vectors. This is hand-written code
    /// on both sides of an authentication, so it is held to the standard's
    /// own numbers rather than to itself.
    #[test]
    fn hmac_matches_rfc_4231() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Case 6: a key longer than the 64-byte block, which is hashed first.
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    /// Nothing about one handshake may be reusable in another. The side
    /// label, the version and both nonces all change the proof.
    #[test]
    fn a_proof_is_bound_to_its_side_version_and_nonces() {
        let k = key();
        let base = k.proof(1, "host", "aaaa", "bbbb");
        assert_ne!(base, k.proof(1, "guest", "aaaa", "bbbb"), "sides differ");
        assert_ne!(base, k.proof(2, "host", "aaaa", "bbbb"), "versions differ");
        assert_ne!(base, k.proof(1, "host", "cccc", "bbbb"), "guest nonce");
        assert_ne!(base, k.proof(1, "host", "aaaa", "cccc"), "host nonce");
        assert_eq!(base, k.proof(1, "host", "aaaa", "bbbb"), "and it is stable");
        // A different key over the same handshake is a different proof, which
        // is the whole point: this is what a cloned disk fails.
        let other = Key::parse(&"11".repeat(32)).unwrap();
        assert_ne!(base, other.proof(1, "host", "aaaa", "bbbb"));
    }

    #[test]
    fn a_key_is_minted_once_readable_only_by_its_owner_and_read_back() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("agent.key");
        assert!(Key::read(&path).unwrap().is_none(), "nothing there yet");
        let first = Key::ensure(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the key is a secret in a directory the user's other tools read"
        );
        // Stable: a seed's fingerprint covers this, and a key that moved
        // would reissue the seed and make the guest redo its first boot.
        assert_eq!(first.hex(), Key::ensure(&path).unwrap().hex());
        assert_eq!(first.hex(), Key::read(&path).unwrap().unwrap().hex());
        assert_eq!(first.hex().len(), 64);
        assert_ne!(
            first.hex(),
            Key::ensure(&dir.path().join("b.key")).unwrap().hex()
        );
    }

    #[test]
    fn a_key_never_prints_itself() {
        let printed = format!("{:?}", key());
        assert!(!printed.contains("0011"), "{printed}");
        assert_eq!(printed, "Key(<redacted>)");
    }

    /// The wire is one object per line, and a request that asks for
    /// nothing unusual says nothing unusual — an agent from before
    /// `wait_ms` reads it exactly as it always did.
    #[test]
    fn a_request_carries_only_what_it_needs() {
        assert_eq!(
            serde_json::to_string(&Request {
                id: 7,
                op: "status".into(),
                wait_ms: None,
                argv: Vec::new(),
                timeout_ms: None,
                token: None,
                agent_reply: None,
            })
            .unwrap(),
            r#"{"id":7,"op":"status"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request {
                id: 8,
                op: "status".into(),
                wait_ms: Some(500),
                argv: Vec::new(),
                timeout_ms: None,
                token: None,
                agent_reply: None,
            })
            .unwrap(),
            r#"{"id":8,"op":"status","wait_ms":500}"#
        );
    }

    /// The first thing on a connection is wholly unauthenticated. It must
    /// not get an unbounded allocation merely because it is valid JSON that
    /// serde would otherwise accept.
    #[test]
    fn an_oversized_unauthenticated_hello_is_refused_before_it_is_parsed() {
        let hello = format!(
            r#"{{"agent":"asterism","versions":[1],"nonce":"aaaa","padding":"{}"}}"#,
            "x".repeat(MAX_FRAME_BYTES)
        );
        let err = one_shot(&hello, "bbbb");
        assert!(err.contains(&MAX_FRAME_BYTES.to_string()), "{err}");
        assert!(err.contains("before ending a frame"), "{err}");
    }

    /// The cap excludes the newline and applies even when the byte that
    /// crosses it arrives in the same buffered chunk as that newline.
    #[test]
    fn the_frame_cap_is_incremental_and_exact() {
        let frame = |len: usize| {
            let mut bytes = b"{}".to_vec();
            bytes.resize(len, b' ');
            bytes.push(b'\n');
            bytes
        };
        let mut exact =
            BufReader::with_capacity(1024, std::io::Cursor::new(frame(MAX_FRAME_BYTES)));
        let value: serde_json::Value = read_line(&mut exact).expect("exactly the cap is valid");
        assert_eq!(value, serde_json::json!({}));

        let mut over =
            BufReader::with_capacity(1024, std::io::Cursor::new(frame(MAX_FRAME_BYTES + 1)));
        let err = read_line::<serde_json::Value>(&mut over).unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains(&MAX_FRAME_BYTES.to_string()), "{err}");
    }

    #[test]
    fn version_negotiation_takes_the_newest_in_common_and_refuses_none() {
        assert_eq!(pick_version(&[1]), Some(1));
        assert_eq!(
            pick_version(&[1, 2, 3, 4]),
            Some(3),
            "what we can both speak"
        );
        assert_eq!(pick_version(&[1, 2]), Some(2), "a guest a release behind");
        assert_eq!(pick_version(&[]), None);
        assert_eq!(pick_version(&[7, 9]), None, "a guest from another release");
    }

    /// An address a guest reports is used to open an ssh connection, so a
    /// wrong one has this host talking to something else entirely.
    #[test]
    fn only_a_private_unicast_address_is_taken_as_a_guest() {
        let addr = |s: &str| s.parse::<IpAddr>().unwrap();
        for good in ["192.168.64.7", "10.1.2.3", "172.16.0.9", "fd00::1"] {
            assert!(is_guest_addr(&addr(good)), "{good}");
        }
        for bad in [
            "8.8.8.8",         // the internet
            "127.0.0.1",       // this host, or the guest's own loopback
            "169.254.7.7",     // a link-local address nobody routed
            "255.255.255.255", // broadcast
            "::1",
            "2606:4700::1111",
        ] {
            assert!(!is_guest_addr(&addr(bad)), "{bad}");
        }
        let status = Status {
            addrs: vec![addr("127.0.0.1"), addr("8.8.8.8"), addr("192.168.64.7")],
            ssh: true,
            uptime_secs: 3.0,
            cloud_init: "running".into(),
            load1: None,
            mem_available_kib: None,
        };
        assert_eq!(status.endpoint(), Some(addr("192.168.64.7")));
        assert_eq!(
            Status {
                addrs: vec![addr("8.8.8.8")],
                ..status.clone()
            }
            .endpoint(),
            None,
            "a guest with nothing but a public address has no endpoint here"
        );
        // The address arrives a second or two before sshd does. Handing it
        // back then would make `ast up && ast ssh` a race.
        assert_eq!(
            Status {
                ssh: false,
                ..status.clone()
            }
            .endpoint(),
            None,
            "an address nobody can ssh to yet is not an endpoint"
        );
    }

    /// The helper and an older or newer guest are routinely a release
    /// apart, so `info` grows by addition and old JSON keeps parsing.
    #[test]
    fn a_status_from_a_newer_agent_still_parses() {
        let status: Status = serde_json::from_str(
            r#"{"addrs":["192.168.64.7"],"ssh":true,"uptime_secs":9.5,"cloud_init":"done",
                "something_we_have_never_heard_of":{"a":1}}"#,
        )
        .unwrap();
        assert_eq!(status.endpoint().unwrap().to_string(), "192.168.64.7");
        assert_eq!(status.cloud_init, "done");
        // ...and one from an older agent that says less.
        let sparse: Status = serde_json::from_str("{}").unwrap();
        assert!(sparse.addrs.is_empty());
        assert_eq!(sparse.endpoint(), None);
    }

    // ---- the guest's half, run for real -------------------------------------
    //
    // These drive the actual agent text this module ships, in `--stdio`
    // mode, over the child's pipes. A Rust reimplementation of the guest
    // side would prove that this file agrees with itself; running the
    // Python proves the two halves agree with each other, which is the
    // only thing that matters when one of them is inside somebody's VM.

    struct Agent {
        child: Child,
        _dir: tempfile::TempDir,
    }

    impl Drop for Agent {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Start the agent with `key` on disk, or `None` where this host has no
    /// python3 to run it with.
    fn spawn_agent(key: &Key) -> Option<(Agent, BufReader<ChildStdout>, ChildStdin)> {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("asterism-guest");
        std::fs::write(&script, AGENT_PY).unwrap();
        let key_path = dir.path().join("agent.key");
        std::fs::write(&key_path, key.hex()).unwrap();
        let mut child = match Command::new("python3")
            .arg(&script)
            .arg("--stdio")
            .env("ASTERISM_AGENT_KEY", &key_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            // No python3 on this host. The agent still runs where it is
            // installed — every cloud-init image has one, because cloud-init
            // is written in it.
            Err(_) => return None,
        };
        let out = BufReader::new(child.stdout.take().unwrap());
        let inp = child.stdin.take().unwrap();
        Some((Agent { child, _dir: dir }, out, inp))
    }

    #[test]
    fn the_agent_this_module_ships_is_python_that_parses() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("asterism-guest");
        std::fs::write(&script, AGENT_PY).unwrap();
        let checked = Command::new("python3")
            .arg("-c")
            .arg("import sys, py_compile; py_compile.compile(sys.argv[1], doraise=True)")
            .arg(&script)
            .output();
        let Ok(checked) = checked else { return };
        assert!(
            checked.status.success(),
            "the agent is written into every guest, so it has to compile:\n{}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }

    /// The whole conversation, end to end: handshake, facts, status, a sync
    /// barrier, and a ping — against the real agent.
    #[test]
    fn a_helper_and_the_real_agent_complete_a_session() {
        let Some((_agent, out, inp)) = spawn_agent(&key()) else {
            return;
        };
        let mut session = Session::open(out, inp, &key()).expect("the handshake");
        assert_eq!(session.version(), 1);
        assert!(
            session.facts().agent.starts_with("asterism-guest/"),
            "{:?}",
            session.facts()
        );
        assert!(!session.facts().hostname.is_empty());

        let status = session.status().expect("status");
        // Whatever this host's addresses are, the agent reported some and
        // none of them is a loopback address it should have filtered.
        assert!(
            !status.addrs.iter().any(|a| a.is_loopback()),
            "{:?}",
            status.addrs
        );
        // `ssh` is read from /proc/net/tcp, which the machine running this
        // test may not have at all. An agent that raised on a missing file
        // would take the whole session down with it, so what is asserted is
        // that asking worked — and, off Linux, that it answered honestly.
        if !cfg!(target_os = "linux") {
            assert!(!status.ssh, "there is no /proc/net/tcp here to read");
        }
        assert!(status.uptime_secs >= 0.0);
        assert!(
            ["done", "running", "unknown", "error"].contains(&status.cloud_init.as_str()),
            "{:?}",
            status.cloud_init
        );

        session.ping().expect("ping");

        // Readiness is an event: the guest holds the answer until it is
        // reachable, or until the wait runs out. Nothing here is a guest,
        // so what is proved is the *waiting* — it neither returns at once
        // nor sits there forever.
        let asked = std::time::Instant::now();
        let waited = session
            .ready_within(Duration::from_millis(300))
            .expect("status");
        assert!(
            asked.elapsed() >= Duration::from_millis(250) || waited.endpoint().is_some(),
            "the guest answered a wait in {:?} without being reachable",
            asked.elapsed()
        );
        assert!(
            asked.elapsed() < Duration::from_secs(5),
            "and it did come back"
        );

        // Deliberately no `sync` here: the agent's sync *is* `sync(2)`, and
        // on the machine running this test that flushes the developer's own
        // disks and takes the better part of a minute. The barrier is
        // exercised against a scripted guest below.
        // An op no agent has is a refusal that names it, not a hang.
        let refused = match session.call("dance") {
            Ok(_) => panic!("this agent does not dance"),
            Err(e) => format!("{e:#}"),
        };
        assert!(refused.contains("dance"), "{refused}");
    }

    /// A guest that answers exactly this, for the answers a real agent
    /// gives but this test host must not be made to act out.
    fn scripted(answers: &[&str]) -> Session<BufReader<std::io::Cursor<Vec<u8>>>, Vec<u8>> {
        scripted_at(1, answers)
    }

    fn scripted_at(
        version: u32,
        answers: &[&str],
    ) -> Session<BufReader<std::io::Cursor<Vec<u8>>>, Vec<u8>> {
        let (guest_nonce, host_nonce) = ("aaaa", "bbbb");
        let mut script = format!(
            "{}\n{}\n",
            serde_json::to_string(&Hello {
                agent: "asterism".into(),
                versions: vec![version],
                nonce: guest_nonce.into(),
            })
            .unwrap(),
            serde_json::to_string(&Welcome {
                ok: true,
                proof: key().proof(version, "guest", guest_nonce, host_nonce),
                error: None,
                facts: Some(Facts {
                    hostname: "dev".into(),
                    boot_id: "b".into(),
                    kernel: "6.12.0".into(),
                    agent: "asterism-guest/1".into(),
                }),
            })
            .unwrap()
        );
        for answer in answers {
            script.push_str(answer);
            script.push('\n');
        }
        Session::open_with_nonce(
            BufReader::new(std::io::Cursor::new(script.into_bytes())),
            Vec::new(),
            &key(),
            host_nonce,
        )
        .expect("the handshake")
    }

    #[test]
    fn protocol_two_exec_decodes_bounded_binary_output_and_exit_status() {
        use data_encoding::BASE64;
        let answer = serde_json::json!({
            "id": 1,
            "ok": true,
            "exec": {
                "status": 17,
                "stdout_b64": BASE64.encode(b"out\0\n"),
                "stderr_b64": BASE64.encode(b"err\n"),
                "stdout_truncated": true,
                "stderr_truncated": false
            }
        })
        .to_string();
        let mut session = scripted_at(2, &[&answer]);
        let result = session
            .exec(vec!["/bin/false".into()], Duration::from_secs(1))
            .unwrap();
        assert_eq!(result.status, 17);
        assert_eq!(result.stdout, b"out\0\n");
        assert_eq!(result.stderr, b"err\n");
        assert!(result.stdout_truncated);
        assert!(!result.stderr_truncated);
    }

    #[test]
    fn v1_agent_refuses_exec_before_writing_an_unknown_operation() {
        let mut session = scripted(&[]);
        let error = session
            .exec(vec!["true".into()], Duration::from_secs(1))
            .unwrap_err()
            .to_string();
        assert!(error.contains("protocol 1"), "{error}");
    }

    #[test]
    fn oci_artifact_fragment_is_keyed_and_starts_the_static_agent() {
        let artifact = Artifact::fixture(b"\x7fELFfixture".to_vec());
        let script = artifact.oci_boot_script(&key());
        assert!(script.contains("chmod 0600 /etc/asterism/agent.key"));
        assert!(script.contains("/.asterism/guest >>/var/log/asterism-guest.log"));
        assert!(script.contains(OCI_ADMITTED_PATH));
        assert!(script.contains("while [ ! -f"));
        assert!(
            script.find("/.asterism/guest >>").unwrap() < script.find("while [ ! -f").unwrap(),
            "pid 1 must start guest control before waiting for host admission: {script}"
        );
        assert!(script.contains(&key().hex()));
    }

    #[test]
    fn oci_artifact_refuses_non_elf_and_the_wrong_guest_architecture() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asterism-guest");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        assert_eq!(
            Artifact::from_path(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        let wrong = if cfg!(target_arch = "x86_64") {
            183u16
        } else {
            62u16
        };
        elf[18..20].copy_from_slice(&wrong.to_le_bytes());
        std::fs::write(&path, elf).unwrap();
        let error = Artifact::from_path(&path).unwrap_err().to_string();
        assert!(error.contains("ELF machine"), "{error}");
    }

    /// The barrier's whole value is that the answer arrives *after* the
    /// guest's `sync(2)` returned, and that a guest which could not raise
    /// one says so rather than answering.
    #[test]
    fn a_sync_barrier_is_the_answer_and_a_refusal_is_not_a_barrier() {
        let mut session = scripted(&[
            r#"{"id":1,"ok":true,"elapsed_ms":37.5}"#,
            r#"{"id":2,"ok":false,"error":"read-only file system"}"#,
        ]);
        assert_eq!(session.sync().unwrap(), 37.5);
        let refused = match session.sync() {
            Ok(_) => panic!("a refusal is not a barrier"),
            Err(e) => format!("{e:#}"),
        };
        assert!(refused.contains("read-only file system"), "{refused}");
    }

    /// An answer to a question nobody asked is not an answer. The ids are
    /// there so a reply that arrived late cannot be taken for the next
    /// one's.
    #[test]
    fn an_answer_to_the_wrong_request_is_refused() {
        let mut session = scripted(&[r#"{"id":97,"ok":true,"elapsed_ms":1.0}"#]);
        let err = match session.sync() {
            Ok(_) => panic!("that answered a different request"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("97"), "{err}");
    }

    /// Authentication does not turn the guest into a trusted allocator.
    /// Additive JSON fields are ignored by serde, so without a framing cap
    /// this otherwise-valid answer would be accepted after retaining all of
    /// it.
    #[test]
    fn an_oversized_answer_is_refused_after_authentication_too() {
        let answer = format!(
            r#"{{"id":1,"ok":true,"padding":"{}"}}"#,
            "x".repeat(MAX_FRAME_BYTES)
        );
        let mut session = scripted(&[&answer]);
        let err = match session.ping() {
            Ok(()) => panic!("an oversized answer crossed the frame boundary"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains(&MAX_FRAME_BYTES.to_string()), "{err}");
        assert!(err.contains("before ending a frame"), "{err}");
    }

    /// The case the whole handshake exists for: something is answering on
    /// the port, and it does not hold this instance's key.
    #[test]
    fn the_real_agent_refuses_a_helper_with_the_wrong_key() {
        let Some((_agent, out, inp)) = spawn_agent(&key()) else {
            return;
        };
        let wrong = Key::parse(&"ab".repeat(32)).unwrap();
        let err = match Session::open(out, inp, &wrong) {
            Ok(_) => panic!("the agent let a stranger in"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("refused this helper"), "{err}");
        assert!(err.contains("did not prove it holds"), "{err}");
    }

    /// The Python half applies the same ceiling to established sessions.
    /// The padding is valid, ignorable JSON, so an agent that parses before
    /// enforcing its frame boundary would answer it.
    #[test]
    fn the_real_agent_closes_on_an_oversized_post_auth_request() {
        let k = key();
        let Some((_agent, mut out, mut inp)) = spawn_agent(&k) else {
            return;
        };
        let hello: Hello = read_line(&mut out).expect("hello");
        let host_nonce = "bbbb";
        write_line(
            &mut inp,
            &Accept {
                version: 1,
                nonce: host_nonce.into(),
                proof: k.proof(1, "host", &hello.nonce, host_nonce),
            },
        )
        .unwrap();
        let welcome: Welcome = read_line(&mut out).expect("welcome");
        assert!(welcome.ok, "the test handshake authenticates");

        let request = format!(
            r#"{{"id":1,"op":"ping","padding":"{}"}}\n"#,
            "x".repeat(MAX_FRAME_BYTES)
        );
        inp.write_all(request.as_bytes()).unwrap();
        inp.flush().unwrap();
        let mut reply = String::new();
        let received = out.read_line(&mut reply).unwrap();
        assert_eq!(received, 0, "the oversized frame was answered: {reply:?}");
    }

    /// ...and the mirror image: a guest whose proof does not check out is
    /// not talked to, however friendly it sounds.
    #[test]
    fn a_helper_refuses_a_guest_whose_proof_does_not_check_out() {
        let hello = r#"{"agent":"asterism","versions":[1],"nonce":"aaaa"}"#;
        let welcome = r#"{"ok":true,"proof":"deadbeef","facts":{"hostname":"liar"}}"#;
        let script = format!("{hello}\n{welcome}\n");
        let err = one_shot(&script, "bbbb");
        assert!(
            err.contains("did not prove it holds this instance's key"),
            "{err}"
        );

        // Something else entirely on the port is refused before any of that.
        let err = one_shot(r#"{"agent":"sshd","versions":[1],"nonce":"a"}"#, "bbbb");
        assert!(err.contains("sshd"), "{err}");
    }

    /// A guest and a helper from different releases find out immediately,
    /// by name, rather than hanging or guessing at a version.
    #[test]
    fn a_version_neither_side_shares_is_named_on_both_sides() {
        // The helper's half.
        let hello = r#"{"agent":"asterism","versions":[7,9],"nonce":"aaaa"}"#;
        let err = one_shot(hello, "bbbb");
        assert!(err.contains("no protocol version in common"), "{err}");
        assert!(err.contains("[7, 9]"), "{err}");

        // The agent's half, for real: a host that picks a version it does
        // not have is refused with both lists rather than answered.
        let Some((_agent, mut out, mut inp)) = spawn_agent(&key()) else {
            return;
        };
        let _hello: Hello = read_line(&mut out).unwrap();
        write_line(
            &mut inp,
            &Accept {
                version: 99,
                nonce: "bbbb".into(),
                proof: "whatever".into(),
            },
        )
        .unwrap();
        let refusal: Welcome = read_line(&mut out).unwrap();
        assert!(!refusal.ok);
        let why = refusal.error.unwrap();
        assert!(why.contains("99"), "{why}");
        assert!(why.contains('1'), "{why}");
    }

    // ---- what goes into the guest ------------------------------------------

    /// This text is written into every guest by cloud-init and then runs
    /// unattended. `sh -n` is the cheapest way to be sure a heredoc is
    /// closed where it looks closed.
    #[test]
    fn the_installer_is_a_shell_script_that_parses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("install.sh");
        std::fs::write(&path, install_script(&key())).unwrap();
        let checked = Command::new("sh").arg("-n").arg(&path).output().unwrap();
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }

    /// Running it for real, with the guest's absolute paths pointed at a
    /// scratch root: the agent, the key and the unit all land, and the key
    /// that lands is the one the host holds.
    #[test]
    fn the_installer_writes_the_agent_the_key_and_the_unit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().to_string();
        // Rewritten rather than chrooted: this is a test of the script's
        // content, and `sh` in a chroot needs a chroot to be in. Only the
        // shell around the agent is rewritten — the agent's own text is
        // what is being checked, so it is put back untouched.
        let whole = install_script(&key());
        let (before, rest) = whole.split_once(AGENT_PY).expect("the agent goes in whole");
        let rewrite = |part: &str| {
            part.replace("/etc/", &format!("{root}/etc/"))
                .replace("/usr/local/sbin/", &format!("{root}/sbin/"))
                // systemd is not this host's business.
                .replace("systemctl ", "true systemctl ")
        };
        let script = format!("{}{AGENT_PY}{}", rewrite(before), rewrite(rest));
        std::fs::create_dir_all(dir.path().join("sbin")).unwrap();
        std::fs::create_dir_all(dir.path().join("etc/systemd/system")).unwrap();
        let ran = Command::new("sh").arg("-c").arg(&script).output().unwrap();
        assert!(
            ran.status.success(),
            "{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        let landed = std::fs::read_to_string(dir.path().join("sbin/asterism-guest")).unwrap();
        assert_eq!(landed, AGENT_PY, "the guest runs exactly what we ship");
        let landed_key =
            std::fs::read_to_string(dir.path().join("etc/asterism/agent.key")).unwrap();
        assert_eq!(landed_key.trim(), key().hex());
        let unit =
            std::fs::read_to_string(dir.path().join("etc/systemd/system/asterism-guest.service"))
                .unwrap();
        assert!(unit.contains("Restart=always"), "{unit}");
        assert!(unit.contains("modprobe hv_sock"), "{unit}");
        assert!(
            unit.contains("modprobe vmw_vsock_virtio_transport"),
            "{unit}"
        );
        assert!(
            !unit.contains("Before=ssh"),
            "guest readiness must not block the guest's SSH boot transaction: {unit}"
        );
        // The path in the unit is the one the rewrite above moved, so what
        // is checked here is that the unit runs the agent it just wrote.
        assert!(
            unit.contains(&format!("ExecStart={root}/sbin/asterism-guest")),
            "{unit}"
        );
        assert!(
            AGENT_UNIT.contains(GUEST_AGENT_PATH),
            "and the real one is absolute"
        );
    }

    /// cloud-init concatenates every `bootcmd` entry into one `/bin/sh`
    /// script, and this one shares that script with the host-key check and
    /// the console fix. So it may not `exit` at the top level, and it has
    /// to survive being indented into a YAML block scalar.
    #[test]
    fn the_cloud_config_is_one_indented_bootcmd_entry_that_never_exits() {
        let config = cloud_config(&key());
        assert!(config.starts_with("bootcmd:\n - |\n"), "{}", &config[..40]);
        for line in config.lines().skip(2) {
            assert!(
                line.is_empty() || line.starts_with("   "),
                "a line that leaves the block scalar ends it: {line:?}"
            );
        }
        assert!(install_script(&key()).starts_with("# Asterism"));
    }

    /// The `exit` this script takes when a guest has no python3 is the one
    /// that would end cloud-init's whole `bootcmd` script, taking the
    /// host-key check and the console fix with it. It is inside a subshell,
    /// and this proves it by running the thing with nothing on `PATH`.
    #[test]
    fn giving_up_on_a_guest_with_no_python_does_not_end_the_other_bootcmds() {
        let ran = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "PATH=''\n{}\necho STILL-RUNNING\n",
                install_script(&key())
            ))
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&ran.stdout);
        assert!(
            said.contains("STILL-RUNNING"),
            "an exit here would end the entries cloud-init runs after this one:              {said}{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        assert!(
            String::from_utf8_lossy(&ran.stderr).contains("no python3"),
            "and it says why it gave up"
        );
    }
}
