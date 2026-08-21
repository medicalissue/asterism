//! The main window's three sections, as one thing that can be named.
//!
//! The window is a sidebar and a pane. Which pane is showing decides which
//! question gets asked of the daemon, so the sections are an enum rather
//! than three strings spread across Rust and TypeScript: `--dump-main
//! devices` and the sidebar's second row are the same [`Section`], and a
//! section nobody can load is a section nobody can name.

use serde::Serialize;

use crate::devices::Devices;
use crate::instances::Instances;
use crate::settings::Settings;
use crate::volumes::Volumes;

/// One row of the sidebar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Instances,
    Devices,
    Volumes,
    Settings,
}

impl Section {
    /// Every section, in sidebar order: what you have, who is holding it,
    /// and how this device behaves.
    pub const ALL: [Section; 4] =
        [Section::Instances, Section::Devices, Section::Volumes, Section::Settings];

    /// The name on the wire, in `--dump-main` and in the webview.
    pub fn id(self) -> &'static str {
        match self {
            Section::Instances => "instances",
            Section::Devices => "devices",
            Section::Volumes => "volumes",
            Section::Settings => "settings",
        }
    }

    pub fn parse(id: &str) -> Option<Section> {
        Section::ALL.into_iter().find(|s| s.id() == id)
    }
}

/// The whole window, loaded. Built for `--dump-main all` and for the tests;
/// the window itself asks for one section at a time, because Devices probes
/// the mesh and Instances does not, and a pane nobody is looking at should
/// not be paying for either.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MainModel {
    pub instances: Instances,
    pub devices: Devices,
    pub volumes: Volumes,
    pub settings: Settings,
}

impl MainModel {
    pub fn load(autostart: bool) -> MainModel {
        MainModel {
            instances: Instances::load(),
            devices: Devices::load(),
            volumes: Volumes::load(),
            settings: Settings::load(autostart),
        }
    }

    pub fn lines(&self) -> Vec<String> {
        let mut out = self.instances.lines();
        out.extend(self.devices.lines());
        out.extend(self.volumes.lines());
        out.extend(self.settings.lines());
        out
    }
}

/// Load one section and print it, or all three. What `--dump-main` runs.
///
/// The dumps are generated from the data the panes render, so they cannot
/// describe a window other than the one on screen — the same property
/// `--dump-menu` and `--dump-form` have.
pub fn dump(section: Option<Section>, autostart: bool) -> Vec<String> {
    match section {
        Some(Section::Instances) => Instances::load().lines(),
        Some(Section::Devices) => Devices::load().lines(),
        Some(Section::Volumes) => Volumes::load().lines(),
        Some(Section::Settings) => Settings::load(autostart).lines(),
        None => MainModel::load(autostart).lines(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_section_round_trips_through_its_id() {
        for section in Section::ALL {
            assert_eq!(Section::parse(section.id()), Some(section));
        }
        assert_eq!(Section::parse("bogus"), None);
        assert_eq!(Section::parse("Instances"), None, "the id is the lowercase one");
    }

    /// The sidebar reads what you have, then who is holding it, then how
    /// this device behaves. Settings last, the way every app puts it.
    #[test]
    fn the_sidebar_is_in_the_order_the_window_draws_it() {
        let ids: Vec<&str> = Section::ALL.iter().map(|s| s.id()).collect();
        assert_eq!(ids, ["instances", "devices", "volumes", "settings"]);
    }

    /// Every dump names its section on the first line, so a `--dump-main`
    /// of all three is still readable as three things.
    #[test]
    fn each_section_dump_opens_by_naming_itself() {
        for section in Section::ALL {
            let head = format!("section {}", section.id());
            assert_eq!(
                match section {
                    Section::Instances => crate::instances::Instances::of(&[]).lines(),
                    Section::Devices => crate::devices::Devices::of(&[], &[]).lines(),
                    Section::Volumes => crate::volumes::Volumes::of(&[]).lines(),
                    Section::Settings => crate::settings::Settings {
                        autostart: false,
                        backends: Vec::new(),
                        default_backend: "qemu".into(),
                        daemon: None,
                        daemon_error: None,
                        daemon_build: None,
                        app_build: "0.0.2+0123456789ab".into(),
                        home: "/tmp".into(),
                        service: crate::settings::Service {
                            mechanism: "launchd".into(),
                            summary: "not installed".into(),
                            installed: false,
                            unit: String::new(),
                        },
                    }
                    .lines(),
                }[0],
                head
            );
        }
    }
}
