//! The per-instance token and cost ledger: append a line, read a window.
//!
//! # Shape
//!
//! ```text
//! $ASTERISM_HOME/instances/<name>/cost/2026-08-27.jsonl
//! ```
//!
//! One JSON object per line, one line per API call that went through the
//! secrets egress door, one file per local calendar day.
//!
//! **Append-only, one line at a time, no read-modify-write.** That is the
//! whole durability story and it is deliberate. A daemon writing a running
//! total would have to read, add and rewrite on every call a guest makes; a
//! crash in the middle of that loses or duplicates a day. A line appended
//! with `O_APPEND` in a single `write` is atomic against every other writer
//! on the same file, so the worst a crash can do is lose the line that was
//! in flight. Nothing here uses [`crate::durable`] for the same reason:
//! `durable` is for files with one authoritative version, and this file has
//! no version — it has a tail.
//!
//! **A day per file, so forgetting is `rm`.** Rotation is the filename, not
//! a size check and not a compactor. Reading "this week" opens seven small
//! files; deleting a month is a glob. Nothing ever rewrites a file that is
//! not today's.
//!
//! # What is in a line, and what is deliberately not
//!
//! Counters. There is no request body, no response body, no header, no
//! prompt, no completion, no handle and no secret in a ledger line, and no
//! code path exists that could put one there — [`crate::usage::extract`]
//! returns integers, and [`Entry`] is what those integers go into. The
//! authority is recorded because "which API" is the question the numbers are
//! useless without; the path is not, because a path can carry an identifier
//! that belongs to the guest and not to this file.
//!
//! # Days are local days
//!
//! "Today" means the user's today. A ledger that rolled over at UTC midnight
//! would show a Californian an empty afternoon, which is the exact moment
//! somebody checks. The offset comes from the platform's own timezone
//! database on Unix; on Windows the day boundary is UTC, which is a known
//! gap rather than a silent one.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::usage::{CallUsage, Provider};

/// One call, as it is written down.
///
/// Every field is either a count or a label. See the module docs for what is
/// deliberately absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Unix seconds when the answer came back.
    pub ts: u64,
    /// Which wire format the counters were read from. Absent when the
    /// response was not a recognised model API answer, in which case this
    /// row is a call and a byte count and nothing more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    /// `host` or `host:port` the bound request went to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// The model the response named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Always 1 today; a field rather than an implied one so that a future
    /// roll-up can put a summed row in the same file without a second shape.
    #[serde(default = "one")]
    pub calls: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub input_tokens: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub output_tokens: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cache_write_tokens: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cache_read_tokens: u64,
    /// Request body bytes as they crossed the door. The only number
    /// available for an API this device does not know how to read.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub request_bytes: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub response_bytes: u64,
}

fn one() -> u64 {
    1
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl Entry {
    /// A row for one call, from what the door saw.
    pub fn record(
        ts: u64,
        host: &str,
        usage: Option<&CallUsage>,
        request_bytes: u64,
        response_bytes: u64,
    ) -> Self {
        let mut entry = Entry {
            ts,
            host: host.to_owned(),
            calls: 1,
            request_bytes,
            response_bytes,
            ..Default::default()
        };
        if let Some(usage) = usage {
            entry.provider = usage.provider;
            entry.model.clone_from(&usage.model);
            entry.input_tokens = usage.input_tokens;
            entry.output_tokens = usage.output_tokens;
            entry.cache_write_tokens = usage.cache_write_tokens;
            entry.cache_read_tokens = usage.cache_read_tokens;
        }
        entry
    }

    /// What this row cost, or `None` when the model is unpriced or unknown.
    pub fn usd(&self) -> Option<f64> {
        let model = self.model.as_deref()?;
        crate::pricing::usd(
            model,
            self.input_tokens,
            self.output_tokens,
            self.cache_write_tokens,
            self.cache_read_tokens,
        )
    }
}

/// The directory holding one instance's ledger.
pub fn dir(instance: &str) -> PathBuf {
    crate::paths::instance_dir(instance).join("cost")
}

/// The file a call at `ts` belongs in.
pub fn day_path(instance: &str, ts: u64) -> PathBuf {
    day_path_in(&dir(instance), ts)
}

/// The same, in a ledger directory named outright.
pub fn day_path_in(dir: &Path, ts: u64) -> PathBuf {
    dir.join(format!("{}.jsonl", day_stamp(ts)))
}

/// Append one call to an instance's ledger.
///
/// Errors are returned rather than swallowed so the caller can decide, but
/// the caller in the daemon deliberately only warns: a full disk must not
/// turn a working API call into a failed one. Accounting is not the product.
pub fn append(instance: &str, entry: &Entry) -> Result<()> {
    append_in(&dir(instance), entry)
}

/// The same, into a ledger directory named outright.
///
/// The `_in` twin beside each function here exists so that tests — and
/// anything else that wants to be certain which bytes it is touching — never
/// have to move `ASTERISM_HOME`. That is one process-wide variable shared
/// with every other test running at the same moment, and a test that sets it
/// makes an unrelated one fail somewhere else.
pub fn append_in(dir: &Path, entry: &Entry) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating the cost ledger directory {}", dir.display()))?;
    let path = day_path_in(dir, entry.ts);
    let mut line = serde_json::to_vec(entry)?;
    line.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening the cost ledger {}", path.display()))?;
    // One `write_all` of one line: `O_APPEND` makes a write under the pipe
    // buffer size atomic against concurrent writers, so two guests' calls
    // landing at once cannot interleave into a corrupt line.
    file.write_all(&line)
        .with_context(|| format!("appending to the cost ledger {}", path.display()))?;
    Ok(())
}

/// Every entry for `instance` at or after `since`.
///
/// Unreadable or half-written lines are skipped rather than fatal. A ledger
/// is an observation: one bad line must not make the other ten thousand
/// unreadable, and a torn tail after a hard power loss is the ordinary way
/// this file ends.
pub fn read_since(instance: &str, since: u64) -> Vec<Entry> {
    read_since_in(&dir(instance), since)
}

/// The same, from a ledger directory named outright.
pub fn read_since_in(dir: &Path, since: u64) -> Vec<Entry> {
    let mut days: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
            .collect(),
        Err(_) => return Vec::new(),
    };
    days.sort();
    let mut out = Vec::new();
    for day in days {
        // A whole day file is small: one line per API call, and the busiest
        // agent makes thousands, not millions. Reading it whole is simpler
        // than a buffered scan and costs nothing at that size.
        let Ok(text) = std::fs::read_to_string(&day) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<Entry>(line) {
                if entry.ts >= since {
                    out.push(entry);
                }
            }
        }
    }
    out.sort_by_key(|entry| entry.ts);
    out
}

/// Which instances on this device have a ledger.
///
/// The registry is not consulted: an instance that was removed but whose
/// spend is still on disk is a row somebody may still want to see, and one
/// that never made a call has nothing to show.
pub fn instances() -> Vec<String> {
    instances_in(&crate::paths::home_dir().join("instances"))
}

/// The same, under an instances root named outright.
pub fn instances_in(root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().join("cost").is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

// ---- roll-up ---------------------------------------------------------------

/// One model's share of a window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelTotal {
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    pub calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_write_tokens: u64,
    pub cache_read_tokens: u64,
    /// `null` when this device has no rate for the model. Never a guess.
    pub usd: Option<f64>,
}

/// What one instance spent over one window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub instance: String,
    /// The window's name as the user asked for it: `today`, `week`, or
    /// `since 6h`.
    pub window: String,
    /// Unix seconds the window starts at, inclusive.
    pub since: u64,
    /// The sum of every priced row. `null` when nothing in the window could
    /// be priced at all, which is different from `0.0`.
    pub usd: Option<f64>,
    pub calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_write_tokens: u64,
    pub cache_read_tokens: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    /// Calls whose model this device has no rate for. When this is not zero,
    /// `usd` is a floor and not a total, and the CLI says so.
    pub unpriced_calls: u64,
    /// Per model, busiest first.
    pub models: Vec<ModelTotal>,
    /// The date the pricing table was taken from published rates.
    pub priced_at: String,
}

/// Roll a window of entries up into one report.
pub fn summarize(instance: &str, window: &str, since: u64, entries: &[Entry]) -> Report {
    let mut report = Report {
        instance: instance.to_owned(),
        window: window.to_owned(),
        since,
        usd: None,
        calls: 0,
        input_tokens: 0,
        output_tokens: 0,
        cache_write_tokens: 0,
        cache_read_tokens: 0,
        request_bytes: 0,
        response_bytes: 0,
        unpriced_calls: 0,
        models: Vec::new(),
        priced_at: crate::pricing::table().updated.clone(),
    };
    let mut by_model: std::collections::BTreeMap<String, ModelTotal> = Default::default();
    let mut priced = 0.0f64;
    let mut any_priced = false;
    for entry in entries {
        report.calls += entry.calls;
        report.input_tokens += entry.input_tokens;
        report.output_tokens += entry.output_tokens;
        report.cache_write_tokens += entry.cache_write_tokens;
        report.cache_read_tokens += entry.cache_read_tokens;
        report.request_bytes += entry.request_bytes;
        report.response_bytes += entry.response_bytes;
        let usd = entry.usd();
        match usd {
            Some(amount) => {
                priced += amount;
                any_priced = true;
            }
            None => report.unpriced_calls += entry.calls,
        }
        let Some(model) = entry.model.clone() else {
            continue;
        };
        let total = by_model.entry(model.clone()).or_insert(ModelTotal {
            model,
            provider: entry.provider,
            calls: 0,
            input_tokens: 0,
            output_tokens: 0,
            cache_write_tokens: 0,
            cache_read_tokens: 0,
            usd: None,
        });
        total.calls += entry.calls;
        total.input_tokens += entry.input_tokens;
        total.output_tokens += entry.output_tokens;
        total.cache_write_tokens += entry.cache_write_tokens;
        total.cache_read_tokens += entry.cache_read_tokens;
        if let Some(amount) = usd {
            total.usd = Some(total.usd.unwrap_or(0.0) + amount);
        }
    }
    report.usd = any_priced.then_some(priced);
    report.models = by_model.into_values().collect();
    // Busiest first: the model that dominates the bill is the one somebody
    // opened this for, and it should not be alphabetically third.
    report
        .models
        .sort_by(|left, right| match right.usd.partial_cmp(&left.usd) {
            Some(std::cmp::Ordering::Equal) | None => right.calls.cmp(&left.calls),
            Some(order) => order,
        });
    report
}

/// Build a report straight off disk.
pub fn report(instance: &str, window: &str, since: u64) -> Report {
    summarize(instance, window, since, &read_since(instance, since))
}

/// The same, from a ledger directory named outright.
pub fn report_in(dir: &Path, instance: &str, window: &str, since: u64) -> Report {
    summarize(instance, window, since, &read_since_in(dir, since))
}

// ---- calendar --------------------------------------------------------------

/// Seconds this device's local time is ahead of UTC at `ts`.
///
/// Read from the platform's timezone database rather than an environment
/// variable, so it is right across a DST boundary and right for a daemon
/// started by launchd with an empty environment.
pub fn local_offset(ts: u64) -> i64 {
    #[cfg(unix)]
    {
        // SAFETY: `localtime_r` writes into the caller's `tm` and takes a
        // pointer to a `time_t` we own. Both live for the call. The `_r`
        // form is used precisely because the plain one returns a shared
        // static that another thread could be reading.
        unsafe {
            let time = ts as libc::time_t;
            let mut tm: libc::tm = std::mem::zeroed();
            if libc::localtime_r(&time, &mut tm).is_null() {
                return 0;
            }
            tm.tm_gmtoff as i64
        }
    }
    #[cfg(not(unix))]
    {
        // Windows: days are UTC days. Named in the module docs so a report
        // that straddles midnight can be explained rather than doubted.
        let _ = ts;
        0
    }
}

/// The local calendar date `ts` falls on, as `YYYY-MM-DD`.
pub fn day_stamp(ts: u64) -> String {
    let local = ts as i64 + local_offset(ts);
    let days = local.div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The unix second local midnight began, for the day `ts` falls on.
pub fn local_midnight(ts: u64) -> u64 {
    let offset = local_offset(ts);
    let local = ts as i64 + offset;
    let midnight = local.div_euclid(86_400) * 86_400 - offset;
    midnight.max(0) as u64
}

/// Local midnight `days` days ago.
pub fn local_midnight_days_ago(ts: u64, days: u64) -> u64 {
    local_midnight(ts).saturating_sub(days * 86_400)
}

/// Days since the unix epoch to a civil `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, which is the standard branch-free
/// form of this conversion and is exact for every date this program can see.
/// Written out rather than taken as a dependency: it is fifteen lines, and a
/// date library would be the only reason this crate needed one.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test here works in a directory of its own and never touches
    /// `ASTERISM_HOME`. See [`append_in`] for why that matters.
    fn ledger() -> (tempfile::TempDir, PathBuf) {
        let home = tempfile::tempdir().expect("a temp dir");
        let dir = home.path().join("instances/bot/cost");
        (home, dir)
    }

    fn usage(model: &str, input: u64, output: u64) -> CallUsage {
        CallUsage {
            provider: Some(Provider::Anthropic),
            model: Some(model.into()),
            input_tokens: input,
            output_tokens: output,
            cache_write_tokens: 0,
            cache_read_tokens: 0,
        }
    }

    #[test]
    fn a_call_is_appended_and_read_back() {
        let (_home, dir) = ledger();
        let call = usage("claude-sonnet-5", 1000, 200);
        let entry = Entry::record(1_756_300_000, "api.anthropic.com", Some(&call), 512, 4096);
        append_in(&dir, &entry).expect("the ledger accepts a line");
        let back = read_since_in(&dir, 0);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0], entry);
    }

    /// The property the whole storage design rests on: appending never
    /// rewrites, so a crash can lose at most the line that was in flight.
    #[test]
    fn many_calls_accumulate_without_rewriting() {
        let (_home, dir) = ledger();
        let call = usage("claude-sonnet-5", 10, 20);
        for i in 0..250u64 {
            let entry = Entry::record(1_756_300_000 + i, "api.anthropic.com", Some(&call), 1, 2);
            append_in(&dir, &entry).unwrap();
        }
        assert_eq!(read_since_in(&dir, 0).len(), 250);
        let report = report_in(&dir, "bot", "today", 0);
        assert_eq!(report.calls, 250);
        assert_eq!(report.input_tokens, 2500);
        assert_eq!(report.output_tokens, 5000);
    }

    #[test]
    fn a_window_excludes_what_is_older_than_it() {
        let (_home, dir) = ledger();
        let call = usage("claude-sonnet-5", 10, 20);
        for ts in [1_756_000_000u64, 1_756_300_000] {
            append_in(
                &dir,
                &Entry::record(ts, "api.anthropic.com", Some(&call), 0, 0),
            )
            .unwrap();
        }
        assert_eq!(read_since_in(&dir, 0).len(), 2);
        assert_eq!(read_since_in(&dir, 1_756_200_000).len(), 1);
    }

    /// A torn tail is the ordinary way this file ends after a power loss,
    /// and it must not take the rest of the day with it.
    #[test]
    fn a_half_written_line_does_not_hide_the_good_ones() {
        let (_home, dir) = ledger();
        let call = usage("claude-sonnet-5", 10, 20);
        append_in(
            &dir,
            &Entry::record(1_756_300_000, "api.anthropic.com", Some(&call), 0, 0),
        )
        .unwrap();
        let path = day_path_in(&dir, 1_756_300_000);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"{\"ts\":1756300001,\"input_to").unwrap();
        drop(file);
        assert_eq!(read_since_in(&dir, 0).len(), 1);
    }

    /// Rotation is the filename and nothing else, so a call on another day
    /// lands in another file and both are read.
    #[test]
    fn each_local_day_gets_its_own_file() {
        let (_home, dir) = ledger();
        let call = usage("claude-sonnet-5", 10, 20);
        let now = 1_756_300_000u64;
        let yesterday = now - 86_400;
        for ts in [now, yesterday] {
            append_in(
                &dir,
                &Entry::record(ts, "api.anthropic.com", Some(&call), 0, 0),
            )
            .unwrap();
        }
        let files = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(files, 2, "one file per day");
        assert_ne!(day_stamp(now), day_stamp(yesterday));
        assert_eq!(read_since_in(&dir, 0).len(), 2);
    }

    /// The one thing this file must never do.
    #[test]
    fn no_request_or_response_bytes_reach_the_ledger() {
        let (_home, dir) = ledger();
        const SECRET: &str = "sk-ant-NEVER-WRITE-THIS";
        let call = usage("claude-sonnet-5", 10, 20);
        append_in(
            &dir,
            &Entry::record(1_756_300_000, "api.anthropic.com", Some(&call), 4096, 8192),
        )
        .unwrap();
        let text = std::fs::read_to_string(day_path_in(&dir, 1_756_300_000)).unwrap();
        assert!(!text.contains(SECRET));
        // Positively, not just by absence: every key on the line is one this
        // test can name, so a field added later has to be argued for here.
        let value: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        for key in value.as_object().unwrap().keys() {
            assert!(
                matches!(
                    key.as_str(),
                    "ts" | "provider"
                        | "host"
                        | "model"
                        | "calls"
                        | "input_tokens"
                        | "output_tokens"
                        | "cache_write_tokens"
                        | "cache_read_tokens"
                        | "request_bytes"
                        | "response_bytes"
                ),
                "a ledger line carries an unexpected field {key:?}"
            );
        }
    }

    #[test]
    fn an_unpriced_model_is_counted_but_not_costed() {
        let known = usage("claude-sonnet-5", 1_000_000, 0);
        let unknown = usage("some-model-nobody-listed", 1_000_000, 0);
        let entries = vec![
            Entry::record(1, "api.anthropic.com", Some(&known), 0, 0),
            Entry::record(2, "api.example.com", Some(&unknown), 0, 0),
        ];
        let report = summarize("bot", "today", 0, &entries);
        assert_eq!(report.calls, 2);
        assert_eq!(report.input_tokens, 2_000_000);
        assert_eq!(report.unpriced_calls, 1);
        assert!((report.usd.unwrap() - 2.0).abs() < 1e-9, "{:?}", report.usd);
        let unpriced = report
            .models
            .iter()
            .find(|model| model.model == "some-model-nobody-listed")
            .unwrap();
        assert_eq!(unpriced.usd, None);
    }

    /// A window with calls but nothing priceable must report `null`, not
    /// `$0.00` — those mean opposite things to somebody deciding whether to
    /// trust the number.
    #[test]
    fn a_window_with_nothing_priceable_reports_no_dollars_rather_than_zero() {
        let entries = vec![Entry::record(1, "api.example.com", None, 100, 200)];
        let report = summarize("bot", "today", 0, &entries);
        assert_eq!(report.usd, None);
        assert_eq!(report.calls, 1);
        assert_eq!(report.request_bytes, 100);
        assert_eq!(report.response_bytes, 200);
    }

    #[test]
    fn an_instance_with_no_ledger_reports_an_empty_window() {
        let (home, _dir) = ledger();
        let missing = home.path().join("instances/never-called/cost");
        let report = report_in(&missing, "never-called", "today", 0);
        assert_eq!(report.calls, 0);
        assert_eq!(report.usd, None);
        assert!(instances_in(&home.path().join("instances")).is_empty());
    }

    #[test]
    fn instances_are_those_with_a_ledger() {
        let (home, _dir) = ledger();
        let root = home.path().join("instances");
        let call = usage("claude-sonnet-5", 1, 1);
        for name in ["bot-2", "bot"] {
            append_in(
                &root.join(name).join("cost"),
                &Entry::record(1, "h", Some(&call), 0, 0),
            )
            .unwrap();
        }
        // A directory with no ledger in it is not a row.
        std::fs::create_dir_all(root.join("never-called")).unwrap();
        assert_eq!(
            instances_in(&root),
            vec!["bot".to_owned(), "bot-2".to_owned()]
        );
    }

    #[test]
    fn the_busiest_model_is_reported_first() {
        let cheap = usage("claude-haiku-4-5", 1000, 10);
        let dear = usage("claude-opus-5", 1_000_000, 100_000);
        let mut entries = vec![Entry::record(1, "h", Some(&cheap), 0, 0)];
        entries.push(Entry::record(2, "h", Some(&dear), 0, 0));
        let report = summarize("bot", "today", 0, &entries);
        assert_eq!(report.models[0].model, "claude-opus-5");
        assert_eq!(report.models[1].model, "claude-haiku-4-5");
    }

    #[test]
    fn the_civil_calendar_matches_known_dates() {
        // 1970-01-01, 2000-02-29 (a leap day in a leap century), 2026-08-27.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_692), (2026, 8, 27));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn local_midnight_is_the_start_of_the_day_a_moment_falls_in() {
        let now = 1_756_300_000u64;
        let midnight = local_midnight(now);
        assert!(midnight <= now);
        assert!(now - midnight < 86_400);
        assert_eq!(day_stamp(midnight), day_stamp(now));
        assert_eq!(local_midnight(midnight), midnight);
    }

    /// Seven local days, today included — the window `ast cost --week` uses.
    #[test]
    fn a_week_reaches_back_six_midnights() {
        let now = 1_756_300_000u64;
        let week = local_midnight_days_ago(now, 6);
        assert_eq!(local_midnight(now) - week, 6 * 86_400);
    }
}
