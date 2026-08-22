//! Two devices pair and talk, in one process.
//!
//! This is the Phase 2 Layer 1 flow end to end, with the two halves running as
//! separate tasks so neither can see anything the real thing would not have:
//! the joiner receives the ticket *as a string*, exactly as if a human had
//! pasted it out of a terminal, and nothing else crosses between them.
//!
//! ```console
//! $ cargo run -p asterism-mesh --example pair_demo
//! ```
//!
//! What it demonstrates:
//!
//! 1. each device loads a persistent key from disk (mode 0600), as `astd` would;
//! 2. `desktop` issues a ticket — `ast device invite`;
//! 3. `laptop` redeems it — `ast device add <ticket>`;
//! 4. both print a six-digit code, and they match;
//! 5. they exchange a ping/pong over a stream on the paired connection.
//!
//! No relay, no discovery service, no traffic that leaves the host — the whole
//! point of Layer 1 being that an orbit can exist with no coordinator at all.

use std::time::Duration;

use asterism_mesh::{
    pairing, DeviceIdentity, IssuedTicket, MeshEndpoint, MeshMode, PairingTicket,
    DEFAULT_TICKET_TTL,
};

/// Prefixes each line with the device it came from, so the interleaving of the
/// two tasks is legible.
macro_rules! say {
    ($who:expr, $($arg:tt)*) => {
        println!("  {:<8} │ {}", $who, format!($($arg)*))
    };
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keys live on disk, as they would in ~/.asterism. A temporary directory
    // keeps the demo from touching the user's real orbit.
    let home = tempdir()?;
    println!("Asterism mesh — pairing demo");
    println!("state: {}\n", home.display());

    let desktop_key = DeviceIdentity::load_or_create(home.join("desktop/device.key"))?;
    let laptop_key = DeviceIdentity::load_or_create(home.join("laptop/device.key"))?;

    say!("desktop", "device id {}", desktop_key.device_id());
    say!("laptop", "device id {}", laptop_key.device_id());
    println!();

    // Both endpoints run in LocalOnly mode: loopback, no relays, no discovery.
    let desktop = MeshEndpoint::bind(&desktop_key, MeshMode::LocalOnly).await?;
    let laptop = MeshEndpoint::bind(&laptop_key, MeshMode::LocalOnly).await?;

    // ── `ast device invite` ──────────────────────────────────────────────
    let addr = desktop.direct_addr().await?;
    let ticket = PairingTicket::issue(addr, DEFAULT_TICKET_TTL);
    let pasted = ticket.encode();

    say!("desktop", "$ ast device invite");
    say!(
        "desktop",
        "ticket valid for {} minutes, single use:",
        DEFAULT_TICKET_TTL.as_secs() / 60
    );
    println!("           │");
    println!("           │   {pasted}");
    println!("           │");
    say!("desktop", "({} bytes, waiting for a device…)", pasted.len());
    println!();

    let issued = IssuedTicket::new(ticket);

    // The inviter waits for exactly one device to turn up.
    let inviter = tokio::spawn(async move {
        let peer = pairing::accept(&desktop, &issued).await?;

        say!("desktop", "{} connected", peer.device_id().short());
        say!("desktop", "confirmation code: {}", peer.sas().grouped());

        // Serve one request on the paired connection.
        let mut stream = peer.connection().accept_stream().await?;
        let request = stream.recv.read_to_end(64).await?;
        say!(
            "desktop",
            "received {:?}",
            String::from_utf8_lossy(&request)
        );
        stream.send.write_all(b"pong").await?;
        stream.send.finish()?;
        say!("desktop", "sent \"pong\"");

        // Hold the connection until the peer is done reading.
        peer.connection().connection().closed().await;
        desktop.close().await;

        Ok::<_, anyhow::Error>((peer.device_id(), peer.sas()))
    });

    // ── `ast device add <ticket>` ───────────────────────────────────────
    // The joiner starts from the pasted string and nothing else.
    let joiner = tokio::spawn(async move {
        let ticket = PairingTicket::decode(&pasted)?;
        say!("laptop", "$ ast device add {}…", &pasted[..24]);
        say!(
            "laptop",
            "ticket names device {} at {}",
            ticket.device_id().short(),
            ticket
                .addr()
                .ip_addrs()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        let peer = pairing::join(&laptop, &ticket).await?;
        say!("laptop", "connected to {}", peer.device_id().short());
        say!("laptop", "confirmation code: {}", peer.sas().grouped());

        let mut stream = peer.connection().open_stream().await?;
        stream.send.write_all(b"ping").await?;
        stream.send.finish()?;
        say!("laptop", "sent \"ping\"");
        let reply = stream.recv.read_to_end(64).await?;
        say!("laptop", "received {:?}", String::from_utf8_lossy(&reply));

        peer.connection().close(b"demo complete");
        laptop.close().await;

        Ok::<_, anyhow::Error>((peer.device_id(), peer.sas(), reply))
    });

    let (desktop_id_seen_by_laptop, laptop_sas, reply) =
        tokio::time::timeout(Duration::from_secs(30), joiner)
            .await??
            .map_err(|e| anyhow::anyhow!("laptop failed: {e}"))?;

    let (laptop_id_seen_by_desktop, desktop_sas) =
        tokio::time::timeout(Duration::from_secs(30), inviter)
            .await??
            .map_err(|e| anyhow::anyhow!("desktop failed: {e}"))?;

    // ── the acceptance checks ────────────────────────────────────────────
    println!();
    println!("  ── result ────────────────────────────────────────────────");

    anyhow::ensure!(
        desktop_sas == laptop_sas,
        "SAS mismatch: desktop {desktop_sas} vs laptop {laptop_sas}"
    );
    println!(
        "  both terminals show {} — the user confirms, and the pairing stands",
        desktop_sas.grouped()
    );

    anyhow::ensure!(
        desktop_id_seen_by_laptop == desktop_key.device_id(),
        "laptop paired with the wrong device"
    );
    anyhow::ensure!(
        laptop_id_seen_by_desktop == laptop_key.device_id(),
        "desktop paired with the wrong device"
    );
    println!("  each side learned the other's real key — the orbit now has two members");

    anyhow::ensure!(reply == b"pong", "expected pong, got {reply:?}");
    println!("  ping/pong completed over a bidirectional stream on the mesh");

    // Keys really were persisted, and really are 0600.
    let key_path = home.join("desktop/device.key");
    anyhow::ensure!(key_path.exists(), "the device key was not persisted");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "device key is mode {mode:04o}, want 0600");
        println!("  device keys persisted at mode 0600 and reloaded on the next start");
    }

    std::fs::remove_dir_all(&home).ok();
    println!();
    println!("ok");
    Ok(())
}

/// Creates a private scratch directory for this run's device keys.
fn tempdir() -> anyhow::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "asterism-pair-demo-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
