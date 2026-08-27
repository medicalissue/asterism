//! What a token costs, in dollars, per model.
//!
//! # Why this is a data file and not code
//!
//! Prices change on somebody else's schedule, and an Asterism release is not
//! on it. `pricing.json` beside this file is compiled in so a fresh install
//! has useful numbers with no setup, and `$ASTERISM_HOME/pricing.json` is
//! read over the top of it so nobody has to wait for a release — or for us —
//! to correct a rate. The overlay uses the same shape as the built-in table,
//! so the way to fix a price is to copy the row and change the number.
//!
//! # Why an unpriced model reports no dollars rather than an estimate
//!
//! The whole value of this feature is that the figure can be trusted enough
//! to act on. A guessed rate for a model nobody has entered would be
//! indistinguishable, in the output, from a real one — and the first time it
//! was wrong the user would stop believing the ones that were right. So a
//! model matched by no row is reported in tokens, with the dollar column
//! blank and `usd: null` in the JSON. See [`Table::price`].
//!
//! # Matching
//!
//! Longest matching prefix wins. Model ids carry suffixes that the price does
//! not depend on — a dated snapshot (`claude-sonnet-4-5-20250929`), a
//! platform prefix stripped upstream, a `-latest` alias — and a table keyed on
//! exact ids would go blank every time a provider published a new snapshot of
//! a model whose price had not moved. Longest-prefix means `claude-opus-4-8`
//! is chosen over `claude-opus-4` when both are present, so a more specific
//! row always beats a more general one.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// The built-in table. Its `updated` date is what `ast cost --json` reports,
/// so a stale figure can always be told from a fresh one.
const BUILT_IN: &str = include_str!("pricing.json");

/// Where a device's own corrections and additions live.
pub fn overlay_path() -> std::path::PathBuf {
    crate::paths::home_dir().join("pricing.json")
}

/// USD per million tokens for one model family.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelPrice {
    /// The model id prefix this row prices.
    pub prefix: String,
    pub input: f64,
    pub output: f64,
    /// Writing a prompt cache entry. Absent where a provider does not charge
    /// separately for it, in which case cache writes are billed as input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write: Option<f64>,
    /// Reading one back. Absent means "billed as input", which is the honest
    /// reading of a table that does not mention caching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read: Option<f64>,
}

impl ModelPrice {
    /// What one call's counters cost, in dollars.
    pub fn usd(
        &self,
        input_tokens: u64,
        output_tokens: u64,
        cache_write_tokens: u64,
        cache_read_tokens: u64,
    ) -> f64 {
        let per = |tokens: u64, rate: f64| tokens as f64 * rate / 1_000_000.0;
        per(input_tokens, self.input)
            + per(output_tokens, self.output)
            + per(cache_write_tokens, self.cache_write.unwrap_or(self.input))
            + per(cache_read_tokens, self.cache_read.unwrap_or(self.input))
    }
}

/// A whole price list, with the date it was true.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Table {
    /// ISO date the rates were taken from the published price lists.
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub models: Vec<ModelPrice>,
}

impl Table {
    /// The row that prices `model`, or `None` when nothing does.
    pub fn price(&self, model: &str) -> Option<&ModelPrice> {
        self.models
            .iter()
            .filter(|row| model.starts_with(&row.prefix))
            .max_by_key(|row| row.prefix.len())
    }

    /// Overlay `other` on top of this table: a row whose prefix already
    /// exists replaces it, and a new prefix is added.
    fn overlay(&mut self, other: Table) {
        if !other.updated.is_empty() {
            self.updated = other.updated;
        }
        for row in other.models {
            match self
                .models
                .iter_mut()
                .find(|existing| existing.prefix == row.prefix)
            {
                Some(existing) => *existing = row,
                None => self.models.push(row),
            }
        }
    }
}

/// The table this device prices with: the built-in list, with
/// `$ASTERISM_HOME/pricing.json` applied over it.
///
/// Read once. A daemon that ran for a month would otherwise stat a file on
/// every API call the guests made, and a price correction is worth a restart.
pub fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(load)
}

fn load() -> Table {
    let mut table: Table =
        serde_json::from_str(BUILT_IN).expect("the built-in pricing table is valid JSON");
    let path = overlay_path();
    let Ok(bytes) = std::fs::read(&path) else {
        return table;
    };
    match serde_json::from_slice::<Table>(&bytes) {
        Ok(overlay) => table.overlay(overlay),
        // Named, not silent, and not fatal: a typo in an optional price file
        // must not take a daemon down, and it must not quietly change a bill.
        Err(error) => eprintln!(
            "asterism: ignoring {} — it is not a pricing table ({error})",
            path.display()
        ),
    }
    table
}

/// What one call cost, or `None` if this device cannot price that model.
pub fn usd(
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
    cache_write_tokens: u64,
    cache_read_tokens: u64,
) -> Option<f64> {
    table().price(model).map(|price| {
        price.usd(
            input_tokens,
            output_tokens,
            cache_write_tokens,
            cache_read_tokens,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_table_parses_and_is_dated() {
        let table = built_in();
        assert!(!table.updated.is_empty(), "the table names no date");
        assert!(table.models.len() > 5);
        for row in &table.models {
            assert!(row.input >= 0.0 && row.output >= 0.0, "{row:?}");
            assert!(!row.prefix.is_empty());
        }
    }

    fn built_in() -> Table {
        serde_json::from_str(BUILT_IN).expect("valid")
    }

    /// The reason the match is a prefix at all: a dated snapshot of a model
    /// costs what the model costs.
    #[test]
    fn a_dated_snapshot_is_priced_as_its_family() {
        let table = built_in();
        let dated = table
            .price("claude-sonnet-4-5-20250929")
            .expect("a dated snapshot is priced");
        assert_eq!(dated.prefix, "claude-sonnet-4-5");
    }

    /// A more specific row must win, or every `claude-*` id would be priced
    /// by whichever short prefix happened to be listed first.
    #[test]
    fn the_longest_matching_prefix_wins() {
        let table = Table {
            updated: "2026-01-01".into(),
            models: vec![
                ModelPrice {
                    prefix: "claude-opus-4".into(),
                    input: 1.0,
                    output: 1.0,
                    cache_write: None,
                    cache_read: None,
                },
                ModelPrice {
                    prefix: "claude-opus-4-8".into(),
                    input: 5.0,
                    output: 25.0,
                    cache_write: None,
                    cache_read: None,
                },
            ],
        };
        assert_eq!(table.price("claude-opus-4-8").unwrap().input, 5.0);
        assert_eq!(table.price("claude-opus-4-6").unwrap().input, 1.0);
    }

    #[test]
    fn an_unknown_model_is_not_guessed_at() {
        assert!(built_in().price("some-model-nobody-listed").is_none());
    }

    #[test]
    fn a_price_is_per_million_tokens_of_each_kind() {
        let price = ModelPrice {
            prefix: "x".into(),
            input: 3.0,
            output: 15.0,
            cache_write: Some(3.75),
            cache_read: Some(0.3),
        };
        // 1M input, 1M output, 1M cache write, 1M cache read.
        let total = price.usd(1_000_000, 1_000_000, 1_000_000, 1_000_000);
        assert!((total - (3.0 + 15.0 + 3.75 + 0.3)).abs() < 1e-9, "{total}");
    }

    /// A table that says nothing about caching must bill cache tokens at the
    /// input rate rather than at zero — free is a much worse default than
    /// approximately right.
    #[test]
    fn a_row_without_cache_rates_bills_cache_as_input() {
        let price = ModelPrice {
            prefix: "x".into(),
            input: 2.0,
            output: 10.0,
            cache_write: None,
            cache_read: None,
        };
        let total = price.usd(0, 0, 1_000_000, 1_000_000);
        assert!((total - 4.0).abs() < 1e-9, "{total}");
    }

    #[test]
    fn an_overlay_replaces_a_row_and_adds_a_new_one() {
        let mut table = built_in();
        let before = table.models.len();
        table.overlay(Table {
            updated: "2027-03-01".into(),
            models: vec![
                ModelPrice {
                    prefix: "claude-sonnet-5".into(),
                    input: 99.0,
                    output: 100.0,
                    cache_write: None,
                    cache_read: None,
                },
                ModelPrice {
                    prefix: "some-new-model".into(),
                    input: 1.0,
                    output: 2.0,
                    cache_write: None,
                    cache_read: None,
                },
            ],
        });
        assert_eq!(table.updated, "2027-03-01");
        assert_eq!(table.models.len(), before + 1);
        assert_eq!(table.price("claude-sonnet-5").unwrap().input, 99.0);
        assert_eq!(table.price("some-new-model").unwrap().output, 2.0);
    }
}
