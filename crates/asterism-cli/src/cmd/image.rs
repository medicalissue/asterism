//! `ast images` and `ast pull` — this device's image store.
//!
//! Both are about *this* device and are refused with `--device`, because an
//! image store is per device: pulling an image for another machine here would
//! fill this disk and still leave that one without it.
//!
//! The downloads are the reason this module is not in the daemon. A cloud
//! image is a gigabyte and a conversion on top; an OCI pull is that plus a
//! guest kernel. It happens in the foreground, where the user can watch it,
//! because the alternative is a mysterious three-minute pause inside the
//! first `ast up` — and that is the version of this that people hate.

use anyhow::{bail, Context, Result};
use clap::Subcommand;

use asterism_core::{image, oci};

use crate::format::short_image;

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// List known images and whether they are downloaded.
    ///
    /// This device's image store: the aliases it knows and what is already
    /// on its disk. Every device has its own.
    Images,
    /// Download an image into this device's store.
    Pull {
        /// The image to download: an alias, an https:// url, a path, or an
        /// OCI/Docker reference.
        image: String,
    },
}

pub(crate) fn run(cmd: Commands, device: Option<&str>) -> Result<()> {
    // The image store is per device, so both of these are about this one.
    match cmd {
        Commands::Images => {
            crate::client::local_only("images", device)?;
            print_images()
        }
        Commands::Pull { image } => {
            crate::client::local_only("pull", device)?;
            ensure_pulled(&image)?;
            Ok(())
        }
    }
}

/// Resolve an image reference, download it if it is not cached yet, and
/// leave the store holding a raw base image either way.
/// Returns the canonical name to record on the instance.
///
/// Cloud images are published as qcow2 and instances are built from raw
/// (BACKENDS.md §4), so a pull is a download *and* a conversion. Both run
/// here, in the foreground, where the user can see them: the alternative is
/// a mysterious pause inside the first `ast up`.
pub(crate) fn ensure_pulled(reference: &str) -> Result<String> {
    let resolved = image::resolve(reference)?;
    if let Some(image) = &resolved.oci {
        return pull_oci(image);
    }
    if resolved.path.exists() {
        return Ok(resolved.name);
    }
    let (Some(url), Some(staging)) = (&resolved.url, &resolved.staging) else {
        return Ok(resolved.name); // local file, used in place
    };

    if !staging.exists() {
        if let Some(dir) = staging.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let part = staging.with_extension("qcow2.part");
        eprintln!("pulling {} ({})", resolved.name, url);
        let status = std::process::Command::new("curl")
            .arg("--location")
            .arg("--fail")
            .arg("--progress-bar")
            .arg("--output")
            .arg(&part)
            .arg(url)
            .status()
            .context("running curl")?;
        if !status.success() {
            let _ = std::fs::remove_file(&part);
            bail!("download failed for {url}");
        }
        // A base image that everything on this device clones from is worth
        // forcing down before it takes its final name: half a cloud image
        // under the name of a whole one is a boot failure with no clue in it.
        asterism_core::durable::publish_file(&part, staging)?;
    }

    // Converting an image already in the store is how a cache written by an
    // older Asterism migrates; `ast pull` is just the polite place to do it.
    eprintln!("converting {} to a raw base image", resolved.name);
    resolved.materialise()?;
    eprintln!("pulled {} -> {}", resolved.name, resolved.path.display());
    Ok(resolved.name)
}

/// Pull an OCI image and leave a bootable filesystem in the store.
///
/// Here rather than in the daemon for the same reason a cloud image download
/// is: it is minutes of network and disk that the user should be able to
/// watch, and a daemon doing it silently inside `ast up` is the version of
/// this that people hate. The guest kernel comes first — the image has none,
/// and finding that out at the first `ast up` would be worse than a slightly
/// longer pull.
fn pull_oci(image: &oci::Reference) -> Result<String> {
    if oci::ensure_kernel(|url, dest| {
        eprintln!("fetching the guest kernel ({url})");
        download(url, dest)
    })? {
        eprintln!("guest kernel ready — every OCI instance on this device shares it");
    }

    eprintln!("pulling {image}");
    let pulled = oci::pull(image, true)?;
    match pulled.built {
        true => eprintln!(
            "pulled {image} -> {} ({})",
            pulled.image.display(),
            pulled.digest
        ),
        false => eprintln!("{image} is already built on this device ({})", pulled.digest),
    }
    // What the machine will actually run, said out loud: it is the one thing
    // about a container image that decides whether the instance does anything.
    let argv = pulled.config.argv();
    if !argv.is_empty() {
        eprintln!("entrypoint: {}", argv.join(" "));
    }
    let ports = pulled.config.tcp_ports();
    if let Some(first) = ports.first() {
        let list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        // Suggest a host port the user can actually bind: below 1024 needs
        // root on macOS and Linux alike.
        let host = if *first < 1024 { first + 8000 } else { *first };
        eprintln!(
            "the image listens on {} — publish it with: \
             ast create <name> --image {image} -p {host}:{first}",
            list.join(", "),
        );
    }
    Ok(image.canonical())
}

/// One file off the network, with a progress bar. The same `curl` the cloud
/// image path uses, for the same reason: it is already on every host and it
/// reports progress better than anything worth linking in.
fn download(url: &str, dest: &std::path::Path) -> Result<()> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let status = std::process::Command::new("curl")
        .args(["--location", "--fail", "--progress-bar", "--output"])
        .arg(dest)
        .arg(url)
        .status()
        .context("running curl")?;
    if !status.success() {
        let _ = std::fs::remove_file(dest);
        bail!("download failed for {url}");
    }
    Ok(())
}

fn print_images() -> Result<()> {
    println!("{:<14} {:<8} SOURCE ({})", "NAME", "PULLED", image::host_arch());
    for (alias, _, _) in image::CATALOG {
        let r = image::resolve(alias)?;
        // An image pulled by an older Asterism is still on this device even
        // though it has not been converted yet, and saying "-" would send
        // the user off to re-download something they already have.
        let pulled = if r.is_pulled() { "yes" } else { "-" };
        println!("{:<14} {:<8} {}", alias, pulled, r.url.as_deref().unwrap_or("-"));
    }
    // Container images are not a catalog — the catalog is Docker Hub — but
    // the ones this device has built are as real as any row above, and
    // nothing else would tell the user what is taking up the space.
    for reference in oci::built()? {
        println!("{:<14} {:<8} {}", short_image(&reference), "yes", reference);
    }
    println!("\nalso accepted: an https:// url, a path to a local qcow2 or raw image, or");
    println!("an OCI/Docker reference — `nginx`, `ghcr.io/owner/app:v1` — booted as a");
    println!("microVM from the image's own filesystem (ast create web --image nginx -p 8080:80)");
    Ok(())
}
