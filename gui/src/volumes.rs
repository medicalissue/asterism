//! The orbit's block-storage catalog from this device's point of view.

use serde::Serialize;

use asterism_core::volume::{Catalog, CatalogVolume, UnreachableStorage};

use crate::client;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Row {
    pub name: String,
    pub owner: String,
    pub size: String,
    pub access: String,
    pub durability: String,
    pub sharing: String,
    pub state: String,
    pub holder: String,
    pub holder_device: String,
    pub epoch: u64,
}

impl Row {
    fn of(part: &CatalogVolume) -> Row {
        let volume = &part.volume;
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
            owner: part.owner_device.clone(),
            size: asterism_core::volume::format_size(volume.size_bytes),
            access: match part.latency_micros {
                Some(0) => "local".to_owned(),
                Some(us) if us < 1000 => format!("{} · {us}µs", part.path),
                Some(us) => format!("{} · {:.1}ms", part.path, us as f64 / 1000.0),
                None => format!("{} · latency unknown", part.path),
            },
            durability: volume.durability.to_string(),
            sharing: volume.sharing.to_string(),
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
    pub unreachable: Vec<ProviderFailure>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProviderFailure {
    pub device: String,
    pub reason: String,
}

impl From<&UnreachableStorage> for ProviderFailure {
    fn from(value: &UnreachableStorage) -> Self {
        Self {
            device: value.device.clone(),
            reason: value.reason.clone(),
        }
    }
}

impl Volumes {
    pub fn load() -> Volumes {
        match client::volumes() {
            Ok(volumes) => Volumes::of(&volumes),
            Err(error) => Volumes {
                inventory: Inventory::Unreachable {
                    reason: format!("{error:#}"),
                },
                unreachable: Vec::new(),
            },
        }
    }

    pub fn of(catalog: &Catalog) -> Volumes {
        Volumes {
            inventory: Inventory::Rows {
                rows: catalog.volumes.iter().map(Row::of).collect(),
            },
            unreachable: catalog
                .unreachable
                .iter()
                .map(ProviderFailure::from)
                .collect(),
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
                        "volume {:<20} owner={:<12} {:<10} {:<9} access={} durability={} sharing={} holder={} device={} epoch={}",
                        row.name,
                        row.owner,
                        row.size,
                        row.state,
                        row.access,
                        row.durability,
                        row.sharing,
                        if row.holder.is_empty() { "-" } else { &row.holder },
                        if row.holder_device.is_empty() { "-" } else { &row.holder_device },
                        row.epoch
                    ));
                }
            }
        }
        for provider in &self.unreachable {
            lines.push(format!(
                "provider-unreachable {} {}",
                provider.device, provider.reason
            ));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_inventory_is_honest_about_its_scope() {
        assert_eq!(
            Volumes::of(&Catalog::default()).lines(),
            ["section volumes", "empty"]
        );
    }
}
