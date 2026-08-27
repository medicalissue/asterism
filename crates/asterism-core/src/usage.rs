//! What one model API call spent, read out of the answer it already gave.
//!
//! # Why this is information and not a limit
//!
//! An agent that runs unattended is worth exactly as much as the keys you are
//! willing to hand it, and what stops people handing over the key is not
//! knowing what it will do with it. Every quota, allowlist and hard stop that
//! could be built here would answer that fear by making the agent less
//! useful. A number answers it by making the fear unnecessary — so nothing in
//! this module or the ones beside it refuses, throttles or blocks anything.
//! It reads a counter the provider already put in the response and writes it
//! down.
//!
//! # Why the host can read it at all
//!
//! Because the secrets egress door already terminates the guest's TLS: a
//! bound request is decrypted on this device, sent upstream by the device
//! holding the value, and the answer comes back through
//! [`crate::protocol::egress::EgressResponse`] as bytes in memory. Token
//! counters are in those bytes. Nothing new is intercepted, nothing new is
//! decrypted, and no new copy of anything is kept: [`extract`] takes a
//! borrowed slice and returns integers.
//!
//! **Bodies are never persisted.** This module's whole output is
//! [`CallUsage`], which is six integers and two short strings. There is no
//! path from a request or response body to disk.
//!
//! # Detection: shape first, host second
//!
//! The obvious rule is "if the host is `api.anthropic.com`, parse Anthropic".
//! That rule is wrong for the traffic this feature exists for. Agents are
//! routinely pointed at a gateway — `ANTHROPIC_BASE_URL`, an OpenAI-compatible
//! router, a company proxy — and a ledger that went blank the moment somebody
//! did that would be worse than no ledger, because it would be silently
//! wrong rather than obviously absent.
//!
//! So the path is a hint and the response body is the evidence. A JSON object
//! carrying a recognisable `usage` alongside a model name is recorded as that
//! provider's call whatever host answered it. The cost of being wrong is one
//! mis-labelled row in a file the user reads; the cost of being narrow is a
//! feature that does not work for the people most likely to want it.

use serde::{Deserialize, Serialize};

/// Which provider's counters a response carried.
///
/// Not "which company was billed" — a gateway may sit in between. It is which
/// wire format the numbers came in, which is what decides how to read them
/// and which pricing rows apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// Anthropic Messages: `usage.input_tokens`, `output_tokens`,
    /// `cache_creation_input_tokens`, `cache_read_input_tokens`.
    Anthropic,
    /// OpenAI Chat Completions (`prompt_tokens`/`completion_tokens`) or
    /// Responses (`input_tokens`/`output_tokens`). One variant because the
    /// two differ only in field names, and both are read here.
    Openai,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::Openai => "openai",
        }
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The counters one call reported.
///
/// Every field is a count the provider stated. Nothing here is estimated: a
/// number this struct does not carry is a number the response did not
/// contain, and it stays zero rather than being guessed at from body length.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallUsage {
    pub provider: Option<Provider>,
    /// The model the *response* named, which is the one that was billed —
    /// an alias in the request (`claude-sonnet-5`) can resolve to something
    /// more specific, and the answer says which.
    pub model: Option<String>,
    /// Fresh input tokens: what was neither written to nor read from cache.
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Tokens written into the prompt cache. Billed above the input rate.
    pub cache_write_tokens: u64,
    /// Tokens served from the prompt cache. Billed far below it, and the
    /// single most useful number on this struct for anyone tuning a prompt.
    pub cache_read_tokens: u64,
}

impl CallUsage {
    /// Whether the provider actually stated a count.
    ///
    /// A model name on its own is not enough to record a call: an OpenAI
    /// stream's chunks all carry one, and so does many an unrelated JSON
    /// body. Without a counter the door falls back to counting the call and
    /// its bytes, which is the honest thing to record when nothing was said.
    pub fn has_counters(&self) -> bool {
        self.input_tokens > 0
            || self.output_tokens > 0
            || self.cache_write_tokens > 0
            || self.cache_read_tokens > 0
    }
}

/// Read one response's usage counters.
///
/// `target` is the request's origin-form path, used only as a hint when the
/// body is ambiguous. `body` is the whole response as the door buffered it —
/// a JSON object for an ordinary call, or a complete SSE stream for a
/// streaming one, because [`crate::protocol::egress::EgressResponse`] carries
/// the answer whole either way.
///
/// Returns `None` when the bytes are not a model API answer at all.
pub fn extract(target: &str, body: &[u8]) -> Option<CallUsage> {
    // A body big enough to be a download is not a completion, and parsing it
    // would cost more than the information is worth.
    if body.len() > MAX_PARSE_BYTES {
        return None;
    }
    let hint = hint_from_path(target);
    let text = std::str::from_utf8(body).ok()?;
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        let value: serde_json::Value = serde_json::from_str(trimmed).ok()?;
        return from_object(&value, hint).filter(CallUsage::has_counters);
    }
    if looks_like_sse(trimmed) {
        return from_sse(trimmed, hint).filter(CallUsage::has_counters);
    }
    None
}

/// Above this a body is a file, not a completion. Ten megabytes is far above
/// any answer a chat API gives and far below what would make parsing every
/// response a cost worth thinking about.
const MAX_PARSE_BYTES: usize = 10 * 1024 * 1024;

/// What the path suggests, before the body is looked at.
///
/// Only ever a tie-breaker: OpenAI's Responses API and Anthropic's Messages
/// API both spell their counters `input_tokens`/`output_tokens`, so when a
/// body carries neither of the distinguishing markers this is what decides.
fn hint_from_path(target: &str) -> Option<Provider> {
    let path = target.split('?').next().unwrap_or(target);
    // Suffix rather than equality: a gateway commonly mounts the upstream
    // shape under a prefix of its own (`/anthropic/v1/messages`).
    if path.ends_with("/v1/messages") || path.ends_with("/messages") {
        return Some(Provider::Anthropic);
    }
    if path.ends_with("/chat/completions")
        || path.ends_with("/completions")
        || path.ends_with("/responses")
    {
        return Some(Provider::Openai);
    }
    None
}

fn looks_like_sse(text: &str) -> bool {
    text.starts_with("data:") || text.starts_with("event:") || text.contains("\ndata:")
}

/// One JSON object: a non-streaming answer, or one SSE frame's payload.
fn from_object(value: &serde_json::Value, hint: Option<Provider>) -> Option<CallUsage> {
    // An Anthropic stream's first frame nests the message it is starting.
    if let Some(message) = value.get("message").filter(|m| m.is_object()) {
        if let Some(usage) = from_object(message, hint.or(Some(Provider::Anthropic))) {
            if usage.has_counters() {
                return Some(usage);
            }
        }
    }
    let model = value
        .get("model")
        .and_then(|m| m.as_str())
        .filter(|m| !m.is_empty())
        .map(ToOwned::to_owned);
    let Some(usage) = value.get("usage").filter(|u| u.is_object()) else {
        // A frame with a model and no usage still tells us which model, which
        // is what an OpenAI stream's chunks carry before the final one.
        return model.map(|model| CallUsage {
            provider: provider_of(value, hint),
            model: Some(model),
            ..Default::default()
        });
    };
    let provider = provider_of(value, hint);
    let mut out = CallUsage {
        provider,
        model,
        ..Default::default()
    };
    // Anthropic and OpenAI Responses: `input_tokens` / `output_tokens`.
    // OpenAI Chat Completions: `prompt_tokens` / `completion_tokens`.
    let input = number(usage, "input_tokens").or_else(|| number(usage, "prompt_tokens"));
    let output = number(usage, "output_tokens").or_else(|| number(usage, "completion_tokens"));
    out.output_tokens = output.unwrap_or(0);
    out.cache_write_tokens = number(usage, "cache_creation_input_tokens")
        .or_else(|| number(usage, "cache_creation_tokens"))
        .unwrap_or(0);
    let cache_read = number(usage, "cache_read_input_tokens")
        .or_else(|| nested(usage, "prompt_tokens_details", "cached_tokens"))
        .or_else(|| nested(usage, "input_tokens_details", "cached_tokens"))
        .unwrap_or(0);
    out.cache_read_tokens = cache_read;
    // The two providers disagree about what "input tokens" includes, and the
    // difference is money. Anthropic's `input_tokens` counts only the
    // uncached part; OpenAI's `prompt_tokens`/`input_tokens` is the total,
    // with the cached part broken out inside it. Normalising here to "fresh
    // input, priced at the input rate" is what makes one pricing row able to
    // read both.
    out.input_tokens = match out.provider {
        Some(Provider::Openai) => input.unwrap_or(0).saturating_sub(cache_read),
        _ => input.unwrap_or(0),
    };
    Some(out)
}

/// Which provider a body's own markers say it is.
fn provider_of(value: &serde_json::Value, hint: Option<Provider>) -> Option<Provider> {
    let kind = value.get("type").and_then(|t| t.as_str()).unwrap_or("");
    let object = value.get("object").and_then(|o| o.as_str()).unwrap_or("");
    if kind == "message" || value.get("stop_reason").is_some() {
        return Some(Provider::Anthropic);
    }
    if object.starts_with("chat.completion") || object == "response" || object == "text_completion"
    {
        return Some(Provider::Openai);
    }
    if let Some(usage) = value.get("usage") {
        if usage.get("prompt_tokens").is_some() || usage.get("completion_tokens").is_some() {
            return Some(Provider::Openai);
        }
        if usage.get("cache_creation_input_tokens").is_some()
            || usage.get("cache_read_input_tokens").is_some()
        {
            return Some(Provider::Anthropic);
        }
    }
    hint
}

fn number(object: &serde_json::Value, key: &str) -> Option<u64> {
    let value = object.get(key)?;
    // `null` is how both providers spell "not counted on this frame", and it
    // must not read as zero — a zero would overwrite a real count on a later
    // merge.
    value.as_u64().or_else(|| {
        value
            .as_f64()
            .filter(|n| n.is_finite() && *n >= 0.0)
            .map(|n| n as u64)
    })
}

fn nested(object: &serde_json::Value, outer: &str, key: &str) -> Option<u64> {
    number(object.get(outer)?, key)
}

/// A complete SSE stream, walked frame by frame.
///
/// Both providers spread the counters across the stream, and in opposite
/// directions: Anthropic states input and cache on `message_start` and then
/// revises `output_tokens` upward on `message_delta`, while OpenAI sends
/// nothing until a final chunk that carries the lot. Merging with "keep the
/// larger of each counter" reads both correctly and is not confused by a
/// frame that repeats an earlier one.
fn from_sse(text: &str, hint: Option<Provider>) -> Option<CallUsage> {
    let mut merged = CallUsage::default();
    let mut seen = false;
    for line in text.lines() {
        let Some(payload) = line.strip_prefix("data:") else {
            continue;
        };
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };
        let Some(frame) = from_object(&value, hint) else {
            continue;
        };
        seen = true;
        merge(&mut merged, frame);
    }
    seen.then_some(merged)
}

fn merge(into: &mut CallUsage, frame: CallUsage) {
    if into.provider.is_none() {
        into.provider = frame.provider;
    }
    if into.model.is_none() {
        into.model = frame.model;
    }
    into.input_tokens = into.input_tokens.max(frame.input_tokens);
    into.output_tokens = into.output_tokens.max(frame.output_tokens);
    into.cache_write_tokens = into.cache_write_tokens.max(frame.cache_write_tokens);
    into.cache_read_tokens = into.cache_read_tokens.max(frame.cache_read_tokens);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_anthropic_messages_answer_is_read_whole() {
        let body = br#"{
          "id": "msg_01",
          "type": "message",
          "role": "assistant",
          "model": "claude-sonnet-5",
          "content": [{"type": "text", "text": "hello"}],
          "stop_reason": "end_turn",
          "usage": {
            "input_tokens": 1200,
            "output_tokens": 340,
            "cache_creation_input_tokens": 2048,
            "cache_read_input_tokens": 8192
          }
        }"#;
        let usage = extract("/v1/messages", body).expect("an Anthropic answer");
        assert_eq!(usage.provider, Some(Provider::Anthropic));
        assert_eq!(usage.model.as_deref(), Some("claude-sonnet-5"));
        assert_eq!(usage.input_tokens, 1200);
        assert_eq!(usage.output_tokens, 340);
        assert_eq!(usage.cache_write_tokens, 2048);
        assert_eq!(usage.cache_read_tokens, 8192);
    }

    /// Anthropic states input once and revises output as it goes. The last
    /// `message_delta` is authoritative for output; `message_start` is
    /// authoritative for everything else.
    #[test]
    fn an_anthropic_stream_takes_input_from_the_start_and_output_from_the_last_delta() {
        let body = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",",
            "\"role\":\"assistant\",\"model\":\"claude-opus-5\",\"content\":[],",
            "\"usage\":{\"input_tokens\":900,\"output_tokens\":1,",
            "\"cache_creation_input_tokens\":100,\"cache_read_input_tokens\":4000}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,",
            "\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},",
            "\"usage\":{\"output_tokens\":275}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        let usage = extract("/v1/messages", body.as_bytes()).expect("an Anthropic stream");
        assert_eq!(usage.provider, Some(Provider::Anthropic));
        assert_eq!(usage.model.as_deref(), Some("claude-opus-5"));
        assert_eq!(usage.input_tokens, 900);
        assert_eq!(usage.output_tokens, 275);
        assert_eq!(usage.cache_write_tokens, 100);
        assert_eq!(usage.cache_read_tokens, 4000);
    }

    /// OpenAI's `prompt_tokens` is the *total* input including the cached
    /// part. Recording it as fresh input would bill cache reads at the input
    /// rate, which is ten times what they cost.
    #[test]
    fn an_openai_chat_completion_has_its_cached_prompt_taken_out_of_fresh_input() {
        let body = br#"{
          "id": "chatcmpl-1",
          "object": "chat.completion",
          "model": "gpt-4o",
          "choices": [],
          "usage": {
            "prompt_tokens": 10000,
            "completion_tokens": 512,
            "total_tokens": 10512,
            "prompt_tokens_details": {"cached_tokens": 8000}
          }
        }"#;
        let usage = extract("/v1/chat/completions", body).expect("an OpenAI answer");
        assert_eq!(usage.provider, Some(Provider::Openai));
        assert_eq!(usage.model.as_deref(), Some("gpt-4o"));
        assert_eq!(usage.input_tokens, 2000);
        assert_eq!(usage.cache_read_tokens, 8000);
        assert_eq!(usage.output_tokens, 512);
    }

    #[test]
    fn an_openai_responses_answer_is_read_by_its_own_field_names() {
        let body = br#"{
          "id": "resp_1",
          "object": "response",
          "model": "gpt-5",
          "usage": {
            "input_tokens": 4000,
            "output_tokens": 900,
            "input_tokens_details": {"cached_tokens": 1000}
          }
        }"#;
        let usage = extract("/v1/responses", body).expect("a Responses answer");
        assert_eq!(usage.provider, Some(Provider::Openai));
        assert_eq!(usage.input_tokens, 3000);
        assert_eq!(usage.cache_read_tokens, 1000);
        assert_eq!(usage.output_tokens, 900);
    }

    /// `stream_options: {include_usage: true}` puts the counters on a final
    /// chunk whose `choices` is empty. Every chunk before it has
    /// `"usage": null`, which must not read as zero.
    #[test]
    fn an_openai_stream_takes_its_counters_from_the_final_chunk() {
        let body = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",",
            "\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}],",
            "\"usage\":null}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",",
            "\"model\":\"gpt-4o-mini\",\"choices\":[],",
            "\"usage\":{\"prompt_tokens\":700,\"completion_tokens\":88,\"total_tokens\":788}}\n\n",
            "data: [DONE]\n\n",
        );
        let usage = extract("/v1/chat/completions", body.as_bytes()).expect("an OpenAI stream");
        assert_eq!(usage.provider, Some(Provider::Openai));
        assert_eq!(usage.model.as_deref(), Some("gpt-4o-mini"));
        assert_eq!(usage.input_tokens, 700);
        assert_eq!(usage.output_tokens, 88);
    }

    /// The reason detection is shape-first: an agent pointed at a gateway is
    /// the ordinary case, and the ledger has to keep working through one.
    #[test]
    fn a_gateway_on_an_unrecognised_path_is_still_read() {
        let body = br#"{"type":"message","model":"claude-sonnet-5",
          "usage":{"input_tokens":10,"output_tokens":20}}"#;
        let usage = extract("/proxy/anthropic/messages/v2", body).expect("a gateway answer");
        assert_eq!(usage.provider, Some(Provider::Anthropic));
        assert_eq!(usage.input_tokens, 10);
    }

    #[test]
    fn an_answer_that_is_not_a_model_call_yields_nothing() {
        assert!(extract("/v1/messages", b"{\"upstream\":\"ok\"}").is_none());
        assert!(extract("/anything", b"not json at all").is_none());
        assert!(extract("/v1/messages", b"").is_none());
    }

    /// An error body carries no counters and must not be recorded as a
    /// zero-token success with a model attached.
    #[test]
    fn an_error_body_is_not_mistaken_for_a_call() {
        let body =
            br#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#;
        assert!(extract("/v1/messages", body).is_none());
    }

    #[test]
    fn a_body_too_large_to_be_a_completion_is_not_parsed() {
        let huge = vec![b'x'; MAX_PARSE_BYTES + 1];
        assert!(extract("/v1/messages", &huge).is_none());
    }
}
