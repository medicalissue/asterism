//! Where the ledger meets the door.
//!
//! One function, called from [`crate::egress`] once per bound request that
//! got an answer, and one function that answers [`Request::Cost`]. Everything
//! about *what* a counter means lives in [`asterism_core::usage`] and
//! [`asterism_core::ledger`]; this file is the seam, and it is deliberately
//! this small so that the change to the egress data plane is one call.
//!
//! # The two rules this seam enforces
//!
//! **It never fails a request.** Recording happens after the answer is in
//! hand and its result is discarded. A full disk, a read-only home, a
//! permission the user changed — none of those may turn a working API call
//! into a broken one. Accounting is a by-product; the call is the product.
//!
//! **It never sees a body twice.** [`record`] borrows the response bytes that
//! are already in memory on their way back to the guest, reads integers out
//! of them, and returns. Nothing is copied, buffered, or retained.

use asterism_core::ledger::{self, Entry};
use asterism_core::protocol::EgressResponse;
use asterism_core::protocol::Response;
use asterism_core::usage;

/// Write down one bound call.
///
/// `dir` is the instance's ledger directory, taken from the proxy's context
/// rather than derived here: it is decided once, when the proxy starts, and
/// a test can then point one proxy at a directory of its own instead of at
/// the process-wide `ASTERISM_HOME` that every other test shares.
///
/// `authority` is the `host[:port]` the guest asked for; `target` is the
/// origin-form path, used only to hint at which provider's shape to expect
/// and never written down. Errors are reported once and dropped — see the
/// module docs.
pub(crate) fn record(
    dir: &std::path::Path,
    instance: &str,
    authority: &str,
    target: &str,
    request_bytes: u64,
    response: &EgressResponse,
) {
    // A refusal is not a call anybody was billed for, and counting it would
    // make a key that stopped working look like one that is spending.
    if !(200..300).contains(&response.status) {
        return;
    }
    let usage = usage::extract(target, &response.body);
    let entry = Entry::record(
        asterism_core::instance::now_unix(),
        authority,
        usage.as_ref(),
        request_bytes,
        response.body.len() as u64,
    );
    if let Err(error) = ledger::append_in(dir, &entry) {
        // Named once and no louder: a guest in a loop against a read-only
        // home would otherwise fill the daemon's log with a problem that is
        // not stopping it from working.
        eprintln!("astd: {instance} could not record what a model call cost: {error:#}");
    }
}

/// Answer `ast cost`.
///
/// `name` absent means every instance on this device that has a ledger,
/// which is what `--all` asks for.
pub(crate) fn serve(name: Option<&str>, since: u64, window: &str) -> Response {
    let window = if window.is_empty() { "since" } else { window };
    let reports = match name {
        Some(name) => vec![ledger::report(name, window, since)],
        None => ledger::instances()
            .into_iter()
            .map(|instance| ledger::report(&instance, window, since))
            .collect(),
    };
    Response::Cost { reports }
}

/// The same, under an instances root named outright. See [`record`].
#[cfg(test)]
fn serve_in(root: &std::path::Path, name: Option<&str>, since: u64, window: &str) -> Response {
    let names = match name {
        Some(name) => vec![name.to_owned()],
        None => ledger::instances_in(root),
    };
    Response::Cost {
        reports: names
            .into_iter()
            .map(|instance| {
                ledger::report_in(&root.join(&instance).join("cost"), &instance, window, since)
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, body: &[u8]) -> EgressResponse {
        EgressResponse {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    const ANTHROPIC: &[u8] = br#"{"type":"message","model":"claude-sonnet-5",
      "usage":{"input_tokens":1000,"output_tokens":100,
      "cache_creation_input_tokens":0,"cache_read_input_tokens":0}}"#;

    #[test]
    fn a_bound_call_becomes_one_ledger_line() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("instances/bot/cost");
        record(
            &dir,
            "bot",
            "api.anthropic.com",
            "/v1/messages",
            256,
            &answer(200, ANTHROPIC),
        );
        let report = ledger::report_in(&dir, "bot", "today", 0);
        assert_eq!(report.calls, 1);
        assert_eq!(report.input_tokens, 1000);
        assert_eq!(report.output_tokens, 100);
        assert_eq!(report.request_bytes, 256);
        // claude-sonnet-5 is $2/MTok in and $10/MTok out.
        let usd = report.usd.expect("a priced call");
        assert!((usd - (0.002 + 0.001)).abs() < 1e-9, "{usd}");
    }

    /// A 401 is the shape of a key that stopped working, and it must not
    /// look like spending.
    #[test]
    fn a_refused_call_is_not_recorded() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("instances/bot/cost");
        record(
            &dir,
            "bot",
            "api.anthropic.com",
            "/v1/messages",
            256,
            &answer(
                401,
                br#"{"type":"error","error":{"type":"authentication_error"}}"#,
            ),
        );
        assert_eq!(ledger::report_in(&dir, "bot", "today", 0).calls, 0);
    }

    /// An API this device has never heard of still gets counted, because
    /// "how many calls and how many bytes" is information too.
    #[test]
    fn an_unknown_api_is_counted_as_calls_and_bytes() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("instances/bot/cost");
        record(
            &dir,
            "bot",
            "api.example.com",
            "/v3/generate",
            10,
            &answer(200, b"{\"text\":\"hello\"}"),
        );
        let report = ledger::report_in(&dir, "bot", "today", 0);
        assert_eq!(report.calls, 1);
        assert_eq!(report.input_tokens, 0);
        assert_eq!(report.response_bytes, 16);
        assert_eq!(report.usd, None);
    }

    /// A streaming answer arrives whole, because the egress plane buffers a
    /// bounded body rather than piping one — so the counters spread across
    /// an SSE stream are all in hand at once.
    #[test]
    fn a_streamed_answer_is_recorded_from_its_own_frames() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("instances/bot/cost");
        let stream = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"type\":\"message\",",
            "\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":5000,",
            "\"output_tokens\":1,\"cache_read_input_tokens\":20000}}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":800}}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        record(
            &dir,
            "bot",
            "api.anthropic.com",
            "/v1/messages",
            99,
            &answer(200, stream.as_bytes()),
        );
        let report = ledger::report_in(&dir, "bot", "today", 0);
        assert_eq!(report.input_tokens, 5000);
        assert_eq!(report.output_tokens, 800);
        assert_eq!(report.cache_read_tokens, 20000);
        assert_eq!(report.models[0].model, "claude-opus-5");
    }

    #[test]
    fn all_reports_every_instance_with_a_ledger() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("instances");
        for instance in ["bot", "bot-2"] {
            record(
                &root.join(instance).join("cost"),
                instance,
                "api.anthropic.com",
                "/v1/messages",
                0,
                &answer(200, ANTHROPIC),
            );
        }
        let Response::Cost { reports } = serve_in(&root, None, 0, "today") else {
            panic!("cost answers with a cost report");
        };
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].instance, "bot");
        assert_eq!(reports[1].instance, "bot-2");
        assert_eq!(reports[0].calls, 1);
    }

    /// Asking about an instance that never made a call is an empty report,
    /// not an error: "nothing yet" is a real and common answer.
    #[test]
    fn a_named_instance_with_no_ledger_answers_empty() {
        let home = tempfile::tempdir().unwrap();
        let Response::Cost { reports } =
            serve_in(&home.path().join("instances"), Some("bot"), 0, "today")
        else {
            panic!("cost answers with a cost report");
        };
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].calls, 0);
        assert_eq!(reports[0].usd, None);
    }
}
