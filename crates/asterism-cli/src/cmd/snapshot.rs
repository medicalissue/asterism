//! `ast snapshot`, `ast snapshots` and `ast restore` — the three words a disk
//! snapshot needs.
//!
//! Kept apart from [`crate::cmd::instance`] because a snapshot is not part of
//! an instance's life: it is a copy-on-write clone of its disk, it costs
//! almost nothing, and it outlives being restored from. The daemon answers
//! all three without writing the registry, and this module is the CLI's half
//! of that same seam.

use anyhow::{bail, Result};
use clap::Subcommand;

use asterism_core::protocol::{Request, Response};
use asterism_core::snapshot;

use crate::client;

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Snapshot a stopped instance's disk, or delete a snapshot.
    ///
    /// Two forms:
    ///
    ///   ast snapshot <instance> [tag]      take one (default tag: a timestamp)
    ///
    ///   ast snapshot rm <instance> <tag>   delete one
    ///
    /// A snapshot is a copy-on-write clone of the root disk, so it costs
    /// almost nothing until the live disk moves away from it, and deleting
    /// one is an unlink. Both forms need the guest stopped. (An instance
    /// called `rm` would be shadowed by the second form; instance names are
    /// yours to choose.)
    #[command(
        subcommand,
        override_usage = "ast snapshot <INSTANCE> [TAG]\n       \
                          ast snapshot rm <INSTANCE> <TAG>"
    )]
    Snapshot(SnapshotCommand),
    /// List an instance's snapshots.
    ///
    /// Reads only, so it answers while the guest is running.
    Snapshots {
        /// The instance whose snapshots to list.
        name: String,
    },
    /// Roll a stopped instance's disk back to a snapshot.
    ///
    /// The snapshot survives its own restore, so the same one can be rolled
    /// back to again.
    Restore {
        /// The instance to roll back.
        name: String,
        /// The snapshot to roll back to, as `ast snapshots` lists it.
        tag: String,
    },
}

/// `ast snapshot ...` — taking one, and deleting one.
///
/// Taking is the bare form (`ast snapshot dev nightly`), which is what
/// people type and what every script already types, so it stays a bare
/// form rather than becoming `ast snapshot take`. Deleting is a word,
/// because deleting should be.
#[derive(Subcommand)]
pub(crate) enum SnapshotCommand {
    /// Delete one snapshot. The instance has to be stopped, and a snapshot
    /// an interrupted restore is still reading from is refused.
    Rm {
        /// The instance the snapshot belongs to.
        name: String,
        /// The snapshot to delete, as `ast snapshots <instance>` lists it.
        tag: String,
    },
    /// `ast snapshot <instance> [tag]` — take one.
    #[command(external_subcommand)]
    Take(Vec<String>),
}

pub(crate) fn run(cmd: Commands, device: Option<&str>) -> Result<()> {
    match cmd {
        Commands::Snapshot(SnapshotCommand::Rm { name, tag }) => {
            remove_snapshot(&name, &tag, device)
        }
        Commands::Snapshot(SnapshotCommand::Take(words)) => {
            let (name, tag) = snapshot_target(&words)?;
            take_snapshot(name, tag, device)
        }
        Commands::Snapshots { name } => print_snapshots(&name, device),
        Commands::Restore { name, tag } => restore_snapshot(&name, &tag, device),
    }
}

/// The instance and tag out of `ast snapshot <instance> [tag]`.
///
/// Hand-checked rather than declared, because the bare form shares its slot
/// with the `rm` subcommand — so the words arrive raw, and the refusals
/// have to be as good as clap's own.
fn snapshot_target(words: &[String]) -> Result<(&str, Option<String>)> {
    match words {
        [name] => Ok((name.as_str(), None)),
        [name, tag] => Ok((name.as_str(), Some(tag.clone()))),
        [] => bail!("which instance? try: ast snapshot <instance> [tag]"),
        [name, tag, extra @ ..] => bail!(
            "a snapshot takes one instance and one tag, so {:?} is {} too many \
             — try: ast snapshot {name} {tag}",
            extra.join(" "),
            extra.len()
        ),
    }
}

fn take_snapshot(name: &str, tag: Option<String>, device: Option<&str>) -> Result<()> {
    let tag = tag.unwrap_or_else(snapshot::timestamped_tag);
    client::send_ok(&client::aimed(
        Request::Snapshot { name: name.into(), tag: tag.clone() },
        device,
    ))?;
    println!("{name}  snapshot {tag}");
    Ok(())
}

fn restore_snapshot(name: &str, tag: &str, device: Option<&str>) -> Result<()> {
    client::send_ok(&client::aimed(
        Request::SnapshotRestore { name: name.into(), tag: tag.into() },
        device,
    ))?;
    println!("{name}  restored to {tag}");
    Ok(())
}

fn remove_snapshot(name: &str, tag: &str, device: Option<&str>) -> Result<()> {
    client::send_ok(&client::aimed(
        Request::SnapshotRemove { name: name.into(), tag: tag.into() },
        device,
    ))?;
    println!("{name}  snapshot {tag} deleted");
    Ok(())
}

fn print_snapshots(name: &str, device: Option<&str>) -> Result<()> {
    let request = client::aimed(Request::SnapshotList { name: name.into() }, device);
    let snapshots = match client::send(&request)? {
        Response::Snapshots { snapshots } => snapshots,
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    };
    if snapshots.is_empty() {
        println!("no snapshots — take one with: ast snapshot {name}");
        return Ok(());
    }
    // SIZE is what the snapshot occupies, which on a copy-on-write clone
    // starts near zero and grows only as the live disk moves away from it.
    println!("{:<6} {:<26} {:<9} DATE", "ID", "TAG", "SIZE");
    for snap in &snapshots {
        println!("{:<6} {:<26} {:<9} {}", snap.id, snap.tag, snap.size, snap.date);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bare form shares its slot with a subcommand, so clap cannot check
    /// its arity and the refusals here are the only ones the user gets. Each
    /// of them has to end in the command they meant to type.
    #[test]
    fn the_bare_form_refuses_in_the_words_clap_would_have_used() {
        let words = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();

        let one = words(&["dev"]);
        assert_eq!(snapshot_target(&one).unwrap(), ("dev", None));

        let two = words(&["dev", "nightly"]);
        assert_eq!(snapshot_target(&two).unwrap(), ("dev", Some("nightly".to_owned())));

        let none: Vec<String> = Vec::new();
        let refusal = snapshot_target(&none).unwrap_err().to_string();
        assert!(refusal.contains("ast snapshot <instance> [tag]"), "{refusal}");

        // Too many words is the mistake worth spelling out: it is what
        // `ast snapshot dev my nightly build` looks like from here.
        let many = words(&["dev", "nightly", "build", "two"]);
        let refusal = snapshot_target(&many).unwrap_err().to_string();
        assert!(refusal.contains("is 2 too many"), "{refusal}");
        assert!(refusal.contains("ast snapshot dev nightly"), "{refusal}");
    }
}
