//! The block volumes supplied by this device.
//!
//! The daemon protocol deliberately scopes `VolumeList` to one device. The
//! Control Center says that plainly instead of presenting a partial list as
//! an orbit-wide inventory.

use serde::Serialize;

use asterism_core::volume::BlockVolume;

use crate::client;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Row {
    pub name: String,
    pub size: String,
    pub state: String,
    pub holder: String,
    pub holder_device: String,
    pub epoch: u64,
}

impl Row {
    fn of(volume: &BlockVolume) -> Row {
        let (state, holder, holder_device) = match &volume.lease {
            Some(lease) => (
                "attached".to_owned(),
                lease.holder.clone(),
                lease.holder_device.clone(),
            ),
            None => ("available".to_owned(), String::new(), String::new()),
        };
        Row {
            name: volume.name.clone(),
            size: asterism_core::volume::format_size(volume.size_bytes),
            state,
            holder,
            holder_device,
            epoch: volume.epoch,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Inventory {
    Unreachable { reason: String },
    Rows { rows: Vec<Row> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Volumes {
    pub inventory: Inventory,
}

impl Volumes {
    pub fn load() -> Volumes {
        match client::volumes() {
            Ok(volumes) => Volumes::of(&volumes),
            Err(error) => Volumes {
                inventory: Inventory::Unreachable { reason: format!("{error:#}") },
            },
        }
    }

    pub fn of(volumes: &[BlockVolume]) -> Volumes {
        Volumes {
            inventory: Inventory::Rows { rows: volumes.iter().map(Row::of).collect() },
        }
    }

    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec!["section volumes".to_owned()];
        match &self.inventory {
            Inventory::Unreachable { reason } => lines.push(format!("unreachable {reason}")),
            Inventory::Rows { rows } if rows.is_empty() => lines.push("empty".to_owned()),
            Inventory::Rows { rows } => {
                for row in rows {
                    lines.push(format!(
                        "volume {:<20} {:<10} {:<9} holder={} device={} epoch={}",
                        row.name,
                        row.size,
                        row.state,
                        if row.holder.is_empty() { "-" } else { &row.holder },
                        if row.holder_device.is_empty() { "-" } else { &row.holder_device },
                        row.epoch
                    ));
                }
            }
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_inventory_is_honest_about_its_scope() {
        assert_eq!(Volumes::of(&[]).lines(), ["section volumes", "empty"]);
    }
}
