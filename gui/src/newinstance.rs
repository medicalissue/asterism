//! What the New Instance window asks for, and what happens when you press
//! Create.
//!
//! Everything the window can do lives here as plain functions over plain
//! data. The Tauri commands in [`crate::window`] are one-line wrappers, and
//! `--create-via-window` calls the same functions with a different progress
//! sink, so the headless proof drives the code the button drives.
//!
//! The rules the form enforces are not written here. A name is checked by
//! [`registry::check_name`], the one the daemon uses; images come out of
//! [`image::CATALOG`], the one `ast images` prints; the shape defaults are
//! [`Shape::default`], the ones `ast create` documents. A second surface
//! that restated any of them would be a second surface that could disagree.
//!
//! ## The backend row
//!
//! `Automatic` is the product default: the daemon probes and chooses the
//! lightest capable backend, VZ first. QEMU is always available as an explicit
//! force, and VZ appears as an explicit force when this device can run it.
//!
//! Answering "can it" means running the daemon's own probe conditions
//! ([`vz_available`]) against the daemon's own binary: the helper the
//! daemon would launch sits next to the daemon, so that is where this
//! looks. What it cannot do is bind the daemon to the answer, and it does
//! not try — `astd` re-probes on every `--backend vz` create, and its
//! refusal is what the window shows if the two ever disagree.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use asterism_core::image;
use asterism_core::instance::Shape;
use asterism_core::registry;

use crate::client;
use crate::feedback;

/// The UI value that means capability-based selection by the daemon.
pub const DEFAULT_BACKEND: &str = "auto";
/// The concrete backends `astd` can be forced to use.
pub const QEMU_BACKEND: &str = "qemu";
pub const VZ_BACKEND: &str = "vz";

/// One row of the image dropdown: a catalog alias, and whether the bytes
/// are on this device already.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Image {
    pub name: String,
    /// Downloaded, in either the raw form instances clone from or the
    /// qcow2 an older Asterism left behind. Both count: saying "not
    /// pulled" about an image that is plainly there would send the user
    /// off to re-download 400 MB they have.
    pub pulled: bool,
}

/// One choice in the backend control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Backend {
    pub id: String,
    /// What the control says. One word.
    pub label: String,
}

/// Everything the window needs before it can draw itself.
#[derive(Debug, Clone, Serialize)]
pub struct Form {
    pub images: Vec<Image>,
    pub backends: Vec<Backend>,
    pub default_image: String,
    pub default_backend: String,
    pub shape: Shape,
    /// Names the daemon already has, so the field can say "taken" before
    /// the user presses anything. The daemon claims names across the whole
    /// orbit and is still the one that decides; this only saves a trip.
    pub taken: Vec<String>,
    /// Why [`Form::taken`] is empty, when it is empty because we could not
    /// ask. An empty list and an unanswered daemon must not look alike.
    pub taken_error: Option<String>,
}

impl Form {
    /// Read the catalog and ask the daemon what it holds.
    pub fn load() -> Form {
        let (taken, taken_error) = match client::list() {
            Ok(instances) => (instances.into_iter().map(|i| i.name).collect(), None),
            Err(e) => (Vec::new(), Some(format!("{e:#}"))),
        };
        Form {
            images: catalog(),
            backends: backends(),
            default_image: DEFAULT_IMAGE.to_owned(),
            // Whatever Settings was last told, filtered back through what
            // this device can offer today.
            default_backend: crate::settings::preferred_backend(),
            shape: Shape::default(),
            taken,
            taken_error,
        }
    }

    /// The form as text, one line per field, for `--dump-form`. The window's
    /// answer to `--dump-menu`: it is generated from the data the window
    /// renders, so it cannot describe a different form.
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for image in &self.images {
            let default = if image.name == self.default_image { "  (default)" } else { "" };
            let pulled = if image.pulled { "pulled" } else { "not pulled" };
            out.push(format!("image {:<14} {pulled}{default}", image.name));
        }
        match self.backends.len() {
            // One backend is no choice, and the window draws no row for it.
            1 => out.push(format!("backend {} (only, no row)", self.default_backend)),
            _ => {
                for backend in &self.backends {
                    let default =
                        if backend.id == self.default_backend { "  (default)" } else { "" };
                    out.push(format!("backend {:<6} {}{default}", backend.id, backend.label));
                }
            }
        }
        out.push(format!(
            "shape cpus={} mem_mib={} disk_gib={}",
            self.shape.cpus, self.shape.mem_mib, self.shape.disk_gib
        ));
        match &self.taken_error {
            Some(reason) => out.push(format!("taken unavailable — {reason}")),
            None if self.taken.is_empty() => out.push("taken (none)".to_owned()),
            None => out.push(format!("taken {}", self.taken.join(" "))),
        }
        out
    }
}

/// The image a fresh form starts on: the smallest thing that boots, so the
/// first instance somebody makes from this window is the fastest one.
const DEFAULT_IMAGE: &str = "debian:13";

/// The catalog `ast images` prints, plus whether each one is on this disk.
pub fn catalog() -> Vec<Image> {
    image::CATALOG
        .iter()
        .filter_map(|entry| {
            let resolved = image::resolve(entry.alias).ok()?;
            Some(Image { name: entry.alias.to_owned(), pulled: resolved.is_pulled() })
        })
        .collect()
}

/// The backends this device can offer. One entry means the window draws no
/// backend row at all: a choice between one thing is not a choice.
pub fn backends() -> Vec<Backend> {
    let mut out = vec![Backend {
        id: DEFAULT_BACKEND.to_owned(),
        label: "Automatic".to_owned(),
    }];
    if vz_available() {
        out.push(Backend { id: VZ_BACKEND.to_owned(), label: "Apple".to_owned() });
    }
    out.push(Backend { id: QEMU_BACKEND.to_owned(), label: "QEMU".to_owned() });
    out
}

/// Oldest macOS the vz backend runs on, and the two names its helper is
/// known by. All three are `astd`'s, restated here rather than imported:
/// the crate that owns them (`asterism-vz`) links
/// Virtualization.framework, and an unsigned menu bar app has no business
/// pulling that in to read two strings.
const VZ_MIN_MACOS: u32 = 14;
const VZ_HELPER_BIN: &str = "astd-vz";
const VZ_ENTITLEMENT: &str = "com.apple.security.virtualization";

/// Whether `astd` would find a usable vz backend on this device.
///
/// The same three conditions `Vz::probe` checks, asked of the same files:
/// macOS 14 or newer, a helper binary next to the daemon, and the
/// virtualization entitlement on it. The daemon runs them again at create
/// and is the one whose answer counts; this only decides whether the window
/// draws a row.
///
/// Wrong in the cautious direction by construction: everything it cannot
/// verify reads as "no", so the worst case is a hidden option on a device
/// that would have run it, and never an option that fails when pressed.
pub fn vz_available() -> bool {
    if !cfg!(target_os = "macos") || macos_major() < VZ_MIN_MACOS {
        return false;
    }
    match vz_helper() {
        Some(helper) => is_entitled(&helper),
        None => false,
    }
}

/// The helper `astd` would launch: `$ASTERISM_VZ_HELPER`, or the binary
/// sitting next to the daemon. Not next to *us* — an installed `.app` has
/// no daemon inside it, and a helper shipped in the bundle is not the one
/// the daemon would run.
fn vz_helper() -> Option<std::path::PathBuf> {
    if let Some(explicit) = std::env::var_os("ASTERISM_VZ_HELPER") {
        let path = std::path::PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    let sibling = client::daemon_path().with_file_name(VZ_HELPER_BIN);
    sibling.is_file().then_some(sibling)
}

/// `codesign -d --entitlements -` prints the entitlement plist; an unsigned
/// binary prints an error instead, and either way the answer is the same.
fn is_entitled(bin: &std::path::Path) -> bool {
    let Ok(out) = std::process::Command::new("codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(bin)
        .output()
    else {
        return false;
    };
    // Older codesign writes the plist to stderr, newer to stdout.
    let printed =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    printed.contains(VZ_ENTITLEMENT)
}

/// Leading integer of `sw_vers -productVersion`, or 0 when we could not
/// ask — which fails the version check rather than passing it by accident.
fn macos_major() -> u32 {
    let Ok(out) = std::process::Command::new("sw_vers").arg("-productVersion").output() else {
        return 0;
    };
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .split('.')
        .next()
        .unwrap_or("")
        .parse()
        .unwrap_or(0)
}

/// Why this name will not do, in the words the daemon would use. `None`
/// means the daemon has no objection to the *spelling*; it still owns the
/// question of whether the name is free across the orbit.
pub fn name_error(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("Name it.".to_owned());
    }
    registry::check_name(name).err().map(|_| "Letters, digits and dashes.".to_owned())
}

/// The form, filled in. What the window sends and what
/// `--create-via-window` parses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wanted {
    pub name: String,
    pub image: String,
    pub cpus: u32,
    /// Memory in GiB. The daemon wants MiB and the CLI parses `2G` into it;
    /// a stepper has no room for both units, so the window counts in the
    /// larger one and [`Wanted::shape`] does the multiplication.
    pub mem_gib: u32,
    pub disk_gib: u32,
    pub backend: String,
    /// Boot it as soon as it exists.
    pub start: bool,
}

impl Wanted {
    pub fn shape(&self) -> Shape {
        Shape {
            cpus: self.cpus,
            mem_mib: self.mem_gib * 1024,
            disk_gib: self.disk_gib,
        }
    }

    /// The `backend` field of the frame. Automatic is sent as absence, exactly
    /// like `ast create` without `--backend`; concrete ids force that backend.
    pub fn backend(&self) -> Option<&str> {
        match self.backend.as_str() {
            DEFAULT_BACKEND | "" => None,
            other => Some(other),
        }
    }

    /// Everything wrong with this before anything is sent.
    fn check(&self) -> Result<()> {
        if let Some(reason) = name_error(&self.name) {
            bail!("{reason}");
        }
        if self.cpus == 0 || self.mem_gib == 0 || self.disk_gib == 0 {
            bail!("cpus, memory and disk are all at least 1");
        }
        Ok(())
    }
}

/// One step of a create, on its way to a window or to a log. The same type
/// a pairing and a wake report through; see [`feedback::Progress`].
pub use crate::feedback::Progress;

/// Define the instance, and boot it if that was asked for.
///
/// Every daemon-facing step is the one `ast` takes: `ast pull` is spawned
/// rather than reimplemented, and the create and the boot are the frames
/// [`client`] already sends. A failure here is the daemon's own message,
/// which is the one worth showing.
///
/// The outcome is written to `gui.log` here rather than by the caller, so
/// that a create from the window and a create from `--create-via-window`
/// leave the same line behind — the log is the record of what the app did,
/// and it should not depend on who pressed the button.
pub fn create(wanted: &Wanted, progress: Progress) -> Result<()> {
    let what = format!("creating {}", wanted.name);
    let done = run(wanted, progress);
    match &done {
        Ok(()) => feedback::log(&format!("ok   {what}")),
        Err(e) => feedback::log(&format!("FAIL {what}: {e:#}")),
    }
    done
}

fn run(wanted: &Wanted, progress: Progress) -> Result<()> {
    wanted.check()?;

    let resolved = image::resolve(&wanted.image)
        .with_context(|| format!("looking up {}", wanted.image))?;
    if !resolved.is_pulled() {
        progress(&format!("Pulling {}. This downloads a few hundred MB.", resolved.name));
        pull(&wanted.image).with_context(|| format!("pulling {}", wanted.image))?;
    }

    progress(&format!("Defining {}.", wanted.name));
    client::create(&wanted.name, &wanted.image, wanted.shape(), wanted.backend())?;

    if wanted.start {
        progress(&format!("Booting {}. First boot runs cloud-init.", wanted.name));
        // No policy named: `ast up` with no flag, which keeps whatever the
        // instance was created with rather than deciding for it here.
        client::up(&wanted.name, None)?;
    }
    Ok(())
}

/// Download an image, by running the command that downloads images.
///
/// `ast pull` converts as well as downloads, retries into the same staging
/// file, and is the code path every other pull on this device takes. A
/// second downloader living in the app would be a second thing to keep
/// correct, and the first one to rot.
fn pull(reference: &str) -> Result<()> {
    let ast = client::ast_path();
    let status = std::process::Command::new(&ast)
        .arg("pull")
        .arg(reference)
        .status()
        .with_context(|| format!("running {} pull", ast.display()))?;
    if !status.success() {
        bail!("{} pull {reference} exited with {status}", ast.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A form with nothing interesting in it, for the tests that are about
    /// one field.
    fn bare_form() -> Form {
        Form {
            images: Vec::new(),
            backends: backends(),
            default_image: DEFAULT_IMAGE.into(),
            default_backend: DEFAULT_BACKEND.into(),
            shape: Shape::default(),
            taken: Vec::new(),
            taken_error: None,
        }
    }

    fn wanted() -> Wanted {
        Wanted {
            name: "dev".into(),
            image: "debian:13".into(),
            cpus: 2,
            mem_gib: 2,
            disk_gib: 20,
            backend: DEFAULT_BACKEND.into(),
            start: false,
        }
    }

    /// The window opens on the shape `ast create` documents. Two numbers
    /// disagreeing about what "the default" is would be two products.
    #[test]
    fn the_form_opens_on_the_shape_the_cli_defaults_to() {
        let shape = wanted().shape();
        let cli = Shape::default();
        assert_eq!((shape.cpus, shape.mem_mib, shape.disk_gib), (2, 2048, 20));
        assert_eq!((shape.cpus, shape.mem_mib, shape.disk_gib), (cli.cpus, cli.mem_mib, cli.disk_gib));
    }

    #[test]
    fn gibibytes_of_memory_become_the_mebibytes_the_daemon_wants() {
        let mut w = wanted();
        w.mem_gib = 8;
        assert_eq!(w.shape().mem_mib, 8192);
    }

    /// Automatic is sent as absence so the daemon can choose VZ first when
    /// capable. Concrete ids are sent as themselves and therefore forced.
    #[test]
    fn automatic_travels_as_absence_and_concrete_backends_force_themselves() {
        assert_eq!(wanted().backend(), None);
        let mut w = wanted();
        w.backend = String::new();
        assert_eq!(w.backend(), None);
        w.backend = VZ_BACKEND.into();
        assert_eq!(w.backend(), Some("vz"));
        w.backend = QEMU_BACKEND.into();
        assert_eq!(w.backend(), Some("qemu"));
    }

    /// The field's rule is the daemon's rule, reached through the daemon's
    /// own function. A copy of it here would drift the first time the
    /// daemon's changed.
    #[test]
    fn names_are_judged_by_the_daemons_rule() {
        assert_eq!(name_error("dev"), None);
        assert_eq!(name_error("build-2"), None);
        assert!(name_error("").is_some(), "an empty name is not a name");
        for bad in ["my dev", "dev_1", "dev.1", "café", "dev/1"] {
            assert!(name_error(bad).is_some(), "{bad:?} must be refused");
            assert!(registry::check_name(bad).is_err(), "{bad:?}: and by the daemon too");
        }
    }

    /// Nothing leaves the window until the name would survive the trip,
    /// so a typo costs a socket round trip rather than a daemon error.
    #[test]
    fn a_bad_form_is_refused_before_anything_is_sent() {
        let mut w = wanted();
        w.name = "my dev".into();
        assert!(w.check().is_err());

        for zero in [
            Wanted { cpus: 0, ..wanted() },
            Wanted { mem_gib: 0, ..wanted() },
            Wanted { disk_gib: 0, ..wanted() },
        ] {
            assert!(zero.check().is_err(), "{zero:?} is not a machine");
        }
        assert!(wanted().check().is_ok());
    }

    /// The dropdown is the catalog, in the catalog's order, and nothing
    /// else. An image the daemon has never heard of would be an option
    /// that only ever produces an error.
    #[test]
    fn the_dropdown_is_the_catalog_ast_images_prints() {
        let found = catalog();
        let names: Vec<&str> = found.iter().map(|i| i.name.as_str()).collect();
        let want: Vec<&str> = image::CATALOG.iter().map(|entry| entry.alias).collect();
        assert_eq!(names, want);
        assert!(names.contains(&DEFAULT_IMAGE), "the form's default is in the catalog");
    }

    /// Automatic and qemu are always offered; vz only when this device could
    /// run it. The list never names a concrete backend `astd` has not got.
    #[test]
    fn qemu_is_always_offered_and_vz_only_when_it_would_work() {
        let offered = backends();
        let ids: Vec<&str> = offered.iter().map(|b| b.id.as_str()).collect();
        assert_eq!(ids[0], DEFAULT_BACKEND);
        assert_eq!(ids.len(), if vz_available() { 3 } else { 2 });
        assert!(ids.contains(&QEMU_BACKEND));
        assert!(ids
            .iter()
            .all(|id| matches!(*id, DEFAULT_BACKEND | QEMU_BACKEND | VZ_BACKEND)));
    }

    /// The probe is wrong in the cautious direction only. Pointed at a file
    /// that is not a signed helper it must say no, whatever else is true of
    /// this machine.
    #[test]
    fn an_unsigned_helper_is_not_an_available_backend() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join(VZ_HELPER_BIN);
        std::fs::write(&fake, b"not a signed binary").unwrap();
        assert!(!is_entitled(&fake), "an unsigned file carries no entitlement");
        assert!(!is_entitled(&dir.path().join("absent")));
    }

    /// A backend row with one option is clutter pretending to be a choice,
    /// so the dump says so rather than listing it.
    #[test]
    fn a_lone_backend_gets_no_row() {
        let mut form = bare_form();
        form.backends = vec![Backend {
            id: DEFAULT_BACKEND.into(),
            label: "Automatic".into(),
        }];
        assert!(form.lines().contains(&"backend auto (only, no row)".to_owned()));

        form.backends.push(Backend { id: QEMU_BACKEND.into(), label: "QEMU".into() });
        let lines = form.lines().join("\n");
        assert!(lines.contains("backend auto   Automatic  (default)"), "{lines}");
        assert!(lines.contains("backend qemu   QEMU"), "{lines}");
    }

    /// An empty fleet and an unreachable daemon must not both render as
    /// "no names taken", because only one of them means the field can
    /// trust itself.
    #[test]
    fn an_unanswered_daemon_is_not_an_empty_fleet() {
        let mut form = bare_form();
        form.images = catalog();
        assert!(form.lines().contains(&"taken (none)".to_owned()));

        form.taken_error = Some("astd is not answering".into());
        let lines = form.lines().join("\n");
        assert!(lines.contains("taken unavailable — astd is not answering"), "{lines}");
        assert!(!lines.contains("taken (none)"), "{lines}");
    }

    #[test]
    fn dumping_the_form_names_every_image_and_its_state() {
        let mut form = bare_form();
        form.images = vec![
            Image { name: "debian:13".into(), pulled: true },
            Image { name: "alpine:3.22".into(), pulled: false },
        ];
        form.taken = vec!["dev".into()];
        let lines = form.lines();
        assert_eq!(lines[0], "image debian:13      pulled  (default)");
        assert_eq!(lines[1], "image alpine:3.22    not pulled");
        assert!(lines.iter().any(|l| l.starts_with("backend auto")));
        assert!(lines.iter().any(|l| l.starts_with("backend qemu")));
        assert!(lines.contains(&"shape cpus=2 mem_mib=2048 disk_gib=20".to_owned()));
        assert!(lines.contains(&"taken dev".to_owned()));
    }

    /// The form travels to the webview as JSON, so its field names are an
    /// interface. Renaming one silently would leave a window drawing
    /// blanks.
    #[test]
    fn the_form_reaches_the_webview_under_the_names_it_reads() {
        let mut form = bare_form();
        form.images = vec![Image { name: "debian:13".into(), pulled: true }];
        let json = serde_json::to_value(form).unwrap();
        for key in ["images", "backends", "default_image", "default_backend", "shape", "taken"] {
            assert!(json.get(key).is_some(), "the form has no {key:?}: {json}");
        }
        assert_eq!(json["images"][0]["pulled"], serde_json::json!(true));
        // The shape crosses to the webview under the daemon's own field
        // names, because it is the daemon's own struct.
        assert_eq!(json["shape"]["mem_mib"], serde_json::json!(2048));
    }

    /// And back the other way: what the window posts has to parse here.
    #[test]
    fn what_the_window_posts_parses_back_into_a_form() {
        let posted = r#"{"name":"dev","image":"debian:13","cpus":4,"mem_gib":8,
                         "disk_gib":40,"backend":"vz","start":true}"#;
        let w: Wanted = serde_json::from_str(posted).unwrap();
        assert_eq!(w.name, "dev");
        assert_eq!(w.shape().mem_mib, 8192);
        assert_eq!(w.backend(), Some("vz"));
        assert!(w.start);
    }
}
