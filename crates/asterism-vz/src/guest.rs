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

use std::io::{BufRead, Write};
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
pub const VERSIONS: &[u32] = &[1];

/// Where the guest keeps its copy of the key. Root-only, written by the
/// seed's `bootcmd` on every boot.
pub const GUEST_KEY_PATH: &str = "/etc/asterism/agent.key";

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
    pub fn open_with_nonce(mut reader: R, mut writer: W, key: &Key, host_nonce: &str) -> Result<Self> {
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

    fn call(&mut self, op: &str) -> Result<Answer> {
        self.request(op, None)
    }

    fn request(&mut self, op: &str, wait_ms: Option<u64>) -> Result<Answer> {
        let id = self.next_id;
        self.next_id += 1;
        write_line(
            &mut self.writer,
            &Request { id, op: op.to_owned(), wait_ms },
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
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        bail!("the guest agent closed the connection");
    }
    serde_json::from_str(line.trim())
        .with_context(|| format!("the guest agent sent {:?}", truncate(line.trim())))
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
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    f.read_exact(bytes).context("reading /dev/urandom")?;
    Ok(())
}

/// Write a file only its owner can read, without it existing readable
/// first.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
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
    line = inp.readline()
    if not line:
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
/// `modprobe` first because the virtio vsock transport is a module in most
/// distributions and nothing else in a guest ever asks for it; the `-`
/// prefix means a guest that has it built in is not a failure. `Restart`
/// because the agent is the host's only deterministic way in, and the guest
/// is unattended by definition.
const AGENT_UNIT: &str = "\
[Unit]
Description=Asterism guest agent (the host's control channel, over vsock)
After=local-fs.target
# Before ssh, so that by the time the host can see this guest's sshd it can
# already ask the guest about it. The same ordering the host-key unit takes,
# and for the same reason: what runs after sshd cannot answer for it.
Before=ssh.service sshd.service ssh.socket sshd.socket
Documentation=https://asterism.run

[Service]
Type=simple
ExecStartPre=-/bin/sh -c 'modprobe vmw_vsock_virtio_transport 2>/dev/null || true'
ExecStart=/usr/local/sbin/asterism-guest
Restart=always
RestartSec=1
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
    script.push_str("umask 077
mkdir -p /etc/asterism
");
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
        assert_ne!(first.hex(), Key::ensure(&dir.path().join("b.key")).unwrap().hex());
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
            serde_json::to_string(&Request { id: 7, op: "status".into(), wait_ms: None }).unwrap(),
            r#"{"id":7,"op":"status"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request {
                id: 8,
                op: "status".into(),
                wait_ms: Some(500)
            })
            .unwrap(),
            r#"{"id":8,"op":"status","wait_ms":500}"#
        );
    }

    #[test]
    fn version_negotiation_takes_the_newest_in_common_and_refuses_none() {
        assert_eq!(pick_version(&[1]), Some(1));
        assert_eq!(pick_version(&[1, 2, 3]), Some(1), "what we can both speak");
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
            Status { addrs: vec![addr("8.8.8.8")], ..status.clone() }.endpoint(),
            None,
            "a guest with nothing but a public address has no endpoint here"
        );
        // The address arrives a second or two before sshd does. Handing it
        // back then would make `ast up && ast ssh` a race.
        assert_eq!(
            Status { ssh: false, ..status.clone() }.endpoint(),
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
        let waited = session.ready_within(Duration::from_millis(300)).expect("status");
        assert!(
            asked.elapsed() >= Duration::from_millis(250) || waited.endpoint().is_some(),
            "the guest answered a wait in {:?} without being reachable",
            asked.elapsed()
        );
        assert!(asked.elapsed() < Duration::from_secs(5), "and it did come back");

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
        let (guest_nonce, host_nonce) = ("aaaa", "bbbb");
        let mut script = format!(
            "{}\n{}\n",
            serde_json::to_string(&Hello {
                agent: "asterism".into(),
                versions: vec![1],
                nonce: guest_nonce.into(),
            })
            .unwrap(),
            serde_json::to_string(&Welcome {
                ok: true,
                proof: key().proof(1, "guest", guest_nonce, host_nonce),
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

    /// ...and the mirror image: a guest whose proof does not check out is
    /// not talked to, however friendly it sounds.
    #[test]
    fn a_helper_refuses_a_guest_whose_proof_does_not_check_out() {
        let hello = r#"{"agent":"asterism","versions":[1],"nonce":"aaaa"}"#;
        let welcome = r#"{"ok":true,"proof":"deadbeef","facts":{"hostname":"liar"}}"#;
        let script = format!("{hello}\n{welcome}\n");
        let err = one_shot(&script, "bbbb");
        assert!(err.contains("did not prove it holds this instance's key"), "{err}");

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
            &Accept { version: 99, nonce: "bbbb".into(), proof: "whatever".into() },
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
        // The path in the unit is the one the rewrite above moved, so what
        // is checked here is that the unit runs the agent it just wrote.
        assert!(unit.contains(&format!("ExecStart={root}/sbin/asterism-guest")), "{unit}");
        assert!(AGENT_UNIT.contains(GUEST_AGENT_PATH), "and the real one is absolute");
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
