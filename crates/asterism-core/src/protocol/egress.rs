//! One outbound request, in flight between the device holding a guest and the
//! device holding a secret.
//!
//! These two types are the only reason the secrets data plane can span an
//! orbit at all. The value never leaves the source device, and the guest's
//! handle never leaves the consumer device — so the request has to travel
//! instead, and this is what it travels as: a whole request, framed, with a
//! blank where the credential goes.
//!
//! They are serde types and not [`http`] ones because they cross a JSON wire
//! and `http::Request` is not serialisable; the conversions in both directions
//! are here, so every other file in the tree works in `http`'s vocabulary and
//! this is the only place the two meet.
//!
//! # Why a frame and not a stream
//!
//! Buffering a request whole is a cap on how much a guest can make either
//! daemon hold, and a cap is the thing this plane most needs; the ceilings
//! are [`crate::rewrite::MAX_BODY_BYTES`] and
//! [`crate::rewrite::MAX_RESPONSE_BYTES`]. It also means the substitution has
//! exactly one place to happen — [`crate::rewrite::fill`], on the source,
//! immediately before the connection out — rather than being smeared across a
//! stream where "before egress" has no single moment.
//!
//! The cost is that this plane carries API calls and not downloads, which is
//! the traffic it is for.

use http::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::rewrite::{is_hop_by_hop, Refusal};
use crate::secret::Placement;

/// A request the source device is being asked to make on a guest's behalf.
///
/// It arrives with the bound header *present and empty*: the consumer took
/// the guest's handle out ([`crate::rewrite::strip`]) and the source puts the
/// value in ([`crate::rewrite::fill`]). Neither credential is ever on the
/// wire between them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressRequest {
    /// `host` or `host:port`, as the guest asked for it in its CONNECT line
    /// and therefore as the certificate it accepted was minted for.
    pub authority: String,
    /// Whether to speak TLS upstream. Always true today — the plane is only
    /// reached through an intercepted CONNECT — and named rather than assumed
    /// so that a plain-HTTP binding is a value here and not a second frame.
    pub tls: bool,
    pub method: String,
    /// Origin form: `/v1/messages`.
    pub target: String,
    /// Every header the guest sent that a proxy may carry, in arrival order,
    /// with the bound one blanked.
    pub headers: Vec<(String, String)>,
    /// Where the source device must put the material. Carried on the frame
    /// rather than re-derived, so the source performs the substitution the
    /// consumer authenticated and not one of its own choosing.
    pub placement: Placement,
    /// What the source device must *do* to produce the credential it puts at
    /// that placement: substitute the stored bytes, exchange a grant for an
    /// access token first, or sign the whole request.
    ///
    /// On the frame for the same reason `placement` is. A source that looked
    /// the rule up from a provider name would be performing an operation of
    /// its own choosing — and a source running a different build would
    /// perform a different one. Defaulted to substitution, so a frame from a
    /// consumer that predates credential parts means what it always meant.
    #[serde(default)]
    pub rule: crate::credential::CredentialRule,
    /// Base64 in the frame — see [`base64`]. The cap on how much of it there
    /// may be is [`crate::rewrite::MAX_BODY_BYTES`].
    #[serde(with = "base64")]
    pub body: Vec<u8>,
}

impl EgressRequest {
    /// The headers this frame carries, back in `http`'s vocabulary.
    ///
    /// The hop-by-hop set is dropped on the way *in* as well as on the way
    /// out. A `Connection: close` the guest sent described the guest's own
    /// connection, and forwarding it would close the source device's upstream
    /// pool for everyone.
    pub fn header_map(&self) -> Result<HeaderMap, Refusal> {
        let mut map = HeaderMap::with_capacity(self.headers.len());
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            if is_hop_by_hop(&lower) {
                continue;
            }
            let name = HeaderName::try_from(lower.as_str())
                .map_err(|_| Refusal::Malformed("a header name is not an HTTP token"))?;
            let value = HeaderValue::try_from(value.as_str())
                .map_err(|_| Refusal::Malformed("a header value is not a header value"))?;
            map.append(name, value);
        }
        Ok(map)
    }

    /// Flatten a header map back onto the wire, dropping what a proxy may not
    /// carry between two connections.
    pub fn flatten(headers: &HeaderMap) -> Vec<(String, String)> {
        headers
            .iter()
            .filter(|(name, _)| !is_hop_by_hop(name.as_str()))
            .filter_map(|(name, value)| {
                Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect()
    }
}

/// What the upstream said, carried back to the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    #[serde(with = "base64")]
    pub body: Vec<u8>,
}

impl EgressResponse {
    /// A response the proxy makes up, for the requests that never leave.
    ///
    /// The text says which rule was broken and never what the guest sent: a
    /// proxy that echoes a rejected credential has written it into the
    /// guest's own logs, where the whole point was that it would not be.
    pub fn refused(status: u16, message: &str) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
            body: format!("asterism: {message}\n").into_bytes(),
        }
    }

    /// The headers to send the guest.
    ///
    /// The upstream's framing described the upstream's connection: this end
    /// buffered the body, so `Content-Length` and `Transfer-Encoding` are
    /// dropped here and written again by hyper from the body it is actually
    /// given. Carrying them forward is how two implementations come to
    /// disagree about where a response ends.
    pub fn header_map(&self) -> HeaderMap {
        let mut map = HeaderMap::with_capacity(self.headers.len());
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            if is_hop_by_hop(&lower) {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::try_from(lower.as_str()),
                HeaderValue::try_from(value.as_str()),
            ) {
                map.append(name, value);
            }
        }
        map
    }
}

/// Bodies as base64, because the frame they travel in has a hard size cap.
///
/// serde's default for `Vec<u8>` in a self-describing format is an array of
/// numbers: `[123,34,111,...]`, four characters a byte. Against a transport
/// that refuses a frame over [`MESH_FRAME_LIMIT`] that turns a request this
/// plane is happy to carry into one the mesh drops, and the guest is told the
/// upstream did not answer when in fact nothing was ever sent. Base64 is
/// four characters per *three* bytes, which is the difference between the two.
mod base64 {
    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], out: S) -> Result<S::Ok, S::Error> {
        out.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(input)?;
        BASE64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// The largest frame the mesh will read, which is what bounds
/// [`crate::rewrite::MAX_BODY_BYTES`] and
/// [`crate::rewrite::MAX_RESPONSE_BYTES`].
///
/// Written here as well as in the daemon's mesh module because it is the
/// reason those two numbers are what they are, and a cap whose reason lives
/// in another crate is a cap somebody will raise.
pub const MESH_FRAME_LIMIT: usize = 4 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::try_from(*name).unwrap(),
                HeaderValue::try_from(*value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn a_response_does_not_carry_the_framing_of_a_connection_that_is_gone() {
        // Both headers below are true about the upstream's connection and
        // false about this one. Carrying either forward is how a response
        // comes to have two possible ends.
        let response = EgressResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("content-length".into(), "99999".into()),
                ("transfer-encoding".into(), "chunked".into()),
                ("connection".into(), "keep-alive".into()),
            ],
            body: b"{\"ok\":true}".to_vec(),
        };
        let headers = response.header_map();
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
        assert!(headers.get("content-length").is_none());
        assert!(headers.get("transfer-encoding").is_none());
        assert!(headers.get("connection").is_none());
    }

    #[test]
    fn a_request_drops_the_guests_own_connection_management_in_both_directions() {
        let flattened = EgressRequest::flatten(&map(&[
            ("host", "api.anthropic.com"),
            ("connection", "close"),
            ("content-length", "11"),
            ("proxy-authorization", "Basic zzz"),
            ("x-api-key", ""),
        ]));
        assert_eq!(
            flattened,
            vec![
                ("host".to_owned(), "api.anthropic.com".to_owned()),
                ("x-api-key".to_owned(), String::new()),
            ]
        );

        let request = EgressRequest {
            authority: "api.anthropic.com".into(),
            tls: true,
            method: "POST".into(),
            target: "/v1/messages".into(),
            headers: vec![
                ("host".into(), "api.anthropic.com".into()),
                ("transfer-encoding".into(), "chunked".into()),
            ],
            placement: Placement::Header {
                name: "x-api-key".into(),
            },
            body: Vec::new(),
            rule: crate::credential::CredentialRule::Substitute,
        };
        let rebuilt = request.header_map().unwrap();
        assert_eq!(rebuilt.get("host").unwrap(), "api.anthropic.com");
        assert!(rebuilt.get("transfer-encoding").is_none());
    }

    #[test]
    fn a_full_sized_request_and_answer_both_fit_in_a_mesh_frame() {
        // The caps in `rewrite` and the frame limit the mesh enforces are two
        // numbers that have to agree, and they live in two crates. If they
        // stop agreeing, a request this plane accepted is dropped in transit
        // and the guest is told the upstream did not answer — when nothing
        // was ever sent. So they are checked against each other here.
        let request = EgressRequest {
            authority: "api.anthropic.com".into(),
            tls: true,
            method: "POST".into(),
            target: "/v1/messages".into(),
            headers: vec![("host".into(), "api.anthropic.com".into())],
            placement: Placement::Header {
                name: "x-api-key".into(),
            },
            body: vec![0xff; crate::rewrite::MAX_BODY_BYTES],
            rule: crate::credential::CredentialRule::Substitute,
        };
        let wire = serde_json::to_vec(&request).unwrap();
        assert!(
            wire.len() < MESH_FRAME_LIMIT,
            "a full request is {} bytes, over the {MESH_FRAME_LIMIT} the mesh reads",
            wire.len()
        );
        // And it survives the trip.
        let back: EgressRequest = serde_json::from_slice(&wire).unwrap();
        assert_eq!(back.body.len(), crate::rewrite::MAX_BODY_BYTES);

        let response = EgressResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: vec![0xff; crate::rewrite::MAX_RESPONSE_BYTES],
        };
        let wire = serde_json::to_vec(&response).unwrap();
        assert!(
            wire.len() < MESH_FRAME_LIMIT,
            "a full response is {} bytes, over the {MESH_FRAME_LIMIT} the mesh reads",
            wire.len()
        );
    }

    #[test]
    fn a_refusal_says_which_rule_and_never_what_was_sent() {
        let refusal = EgressResponse::refused(401, "that is not this instance's handle");
        assert_eq!(refusal.status, 401);
        assert_eq!(
            String::from_utf8(refusal.body).unwrap(),
            "asterism: that is not this instance's handle\n"
        );
    }
}
