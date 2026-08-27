//! AWS Signature Version 4, computed at the door.
//!
//! This is the third door rule and the reason the set has three members. A
//! GitHub token is a string an API compares, so a door can carry it by
//! swapping a header. An AWS credential is not a string anybody sends: what
//! goes on the request is an HMAC over the request itself, keyed by a secret
//! the request never contains. A door that could only substitute could not
//! carry AWS at all — and "hand the agent every key you own" with a hole in it
//! exactly where the biggest keys are is not the promise.
//!
//! So the shape is the same as every other rule and the operation is
//! different: the source device holds the key pair, the guest holds a handle
//! that is worth nothing, and the last thing that happens before the
//! connection out is this function. The guest never holds anything that could
//! sign anything, which is a stronger statement than the substitute rule can
//! make — a substituted token is a token the upstream will accept from anyone
//! who steals it, and a signature is good for one request.
//!
//! # What is implemented
//!
//! The header-authorization form of SigV4 over a request whose body is
//! already buffered — which is every request this plane carries, because
//! [`crate::protocol::egress`] buffers by construction. Not the query-string
//! (presigned URL) form, not chunked payload signing, not SigV4a: none of
//! them can arrive through a door that hands the source a complete request.
//!
//! The published test vectors from AWS's own `aws4_testsuite` are in the
//! tests below, next to a verifier that recomputes the signature the way a
//! service would rather than comparing against a string this file also wrote.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// The algorithm identifier, which is also the first line of the string to
/// sign.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The credential a signature is computed with.
///
/// Borrowed rather than owned: this is constructed on the source device from
/// bytes that are about to be dropped, and an owned copy here would be a
/// second lifetime for material whose whole design is that it has one.
pub struct Key<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub session_token: Option<&'a str>,
}

/// Everything about the request that the signature covers.
pub struct Request<'a> {
    pub method: &'a str,
    /// Origin form, path and query together: `/v1/x?a=b`.
    pub target: &'a str,
    /// The `host` this request is going to, which the signature always covers.
    pub host: &'a str,
    /// Every other header to sign, as `(lowercased name, value)`. `host`,
    /// `x-amz-date`, `x-amz-content-sha256` and `x-amz-security-token` are
    /// added by this module and must not be here.
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    pub service: &'a str,
    pub region: &'a str,
    /// Seconds since the epoch. A parameter rather than a clock read, so the
    /// vectors below can be checked against the times AWS published them for.
    pub now: u64,
}

/// The headers to set on the request, in the order they should be applied.
///
/// Returned rather than mutated in place because the caller holds an
/// [`http::HeaderMap`] and this module deliberately does not: what a header
/// map is, and which of its values are marked sensitive, is the caller's
/// business — see [`crate::rewrite::fill`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub headers: Vec<(String, String)>,
}

/// The `x-amz-content-sha256` a body signs as.
///
/// Public because it is the one part of a signature a caller can check
/// without recomputing the whole thing: the payload hash is a function of the
/// bytes alone, so a test that asserts it is asserting that the signature
/// covers the body the guest actually sent.
pub fn payload_hash(body: &[u8]) -> String {
    hex(&Sha256::digest(body))
}

/// Sign one request.
///
/// The only fallible thing here is the clock: a `now` that does not convert
/// to a civil date cannot happen from a system clock and would be a
/// programming error, so it is clamped rather than returned as an error a
/// caller would have no way to act on.
pub fn sign(key: &Key<'_>, request: &Request<'_>) -> Signed {
    let (date, timestamp) = stamps(request.now);
    let payload_hash = hex(&Sha256::digest(request.body));

    // The signed set: what the caller gave, plus the four this module owns.
    // A `BTreeMap` because canonical headers are sorted by name and because
    // a duplicate name in the input must not produce two canonical lines.
    let mut signed: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in request.headers {
        let name = name.to_ascii_lowercase();
        // Hop-by-hop headers describe a connection, not a request, and the
        // client will rewrite the framing ones anyway — a signature over a
        // `content-length` that reqwest then recomputes is a signature that
        // fails at the far end.
        if crate::rewrite::is_hop_by_hop(&name) || name == "authorization" {
            continue;
        }
        signed.insert(name, collapse(value));
    }
    signed.insert("host".into(), collapse(request.host));
    signed.insert("x-amz-date".into(), timestamp.clone());
    signed.insert("x-amz-content-sha256".into(), payload_hash.clone());
    if let Some(token) = key.session_token {
        signed.insert("x-amz-security-token".into(), collapse(token));
    }

    let signed_headers: Vec<&str> = signed.keys().map(String::as_str).collect();
    let signed_header_list = signed_headers.join(";");
    let canonical_headers: String = signed
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();

    let (path, query) = split_target(request.target);
    let canonical_request = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_header_list}\n{payload_hash}",
        request.method.to_ascii_uppercase(),
        canonical_path(path, request.service),
        canonical_query(query),
    );

    let scope = format!("{date}/{}/{}/aws4_request", request.region, request.service);
    let string_to_sign = format!(
        "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let signature = hex(&hmac(
        &signing_key(
            key.secret_access_key,
            &date,
            request.region,
            request.service,
        ),
        string_to_sign.as_bytes(),
    ));

    let mut headers = vec![
        ("x-amz-date".to_owned(), timestamp),
        ("x-amz-content-sha256".to_owned(), payload_hash),
    ];
    if let Some(token) = key.session_token {
        headers.push(("x-amz-security-token".to_owned(), token.to_owned()));
    }
    headers.push((
        "authorization".to_owned(),
        format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_header_list}, \
             Signature={signature}",
            key.access_key_id
        ),
    ));
    Signed { headers }
}

/// `AWS4<secret>` beaten into a key that is scoped to one day, one region and
/// one service — which is what makes a leaked signature worth a day rather
/// than a lifetime.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let initial = format!("AWS4{secret}");
    let key = hmac(initial.as_bytes(), date.as_bytes());
    let key = hmac(&key, region.as_bytes());
    let key = hmac(&key, service.as_bytes());
    hmac(&key, b"aws4_request")
}

fn split_target(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    }
}

/// The canonical URI.
///
/// Every segment is URI-encoded, and then encoded again — except for S3,
/// which signs the path as it appears on the wire. That exception is AWS's,
/// not this module's, and it is the single most common reason a
/// hand-rolled signer works everywhere except against buckets.
fn canonical_path(path: &str, service: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    if service == "s3" {
        return path.to_owned();
    }
    path.split('/')
        .map(|segment| uri_encode(&uri_encode(segment, false), false))
        .collect::<Vec<_>>()
        .join("/")
}

/// The canonical query string: every parameter encoded, sorted by name and
/// then by value, with a bare name spelled as `name=`.
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (uri_encode(name, true), uri_encode(value, true)),
            None => (uri_encode(pair, true), String::new()),
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// RFC 3986 unreserved, plus `/` when a path is being encoded whole.
///
/// `already_encoded` is a lie the caller tells on purpose: a query string
/// arrives percent-encoded and re-encoding its `%` would change the request.
fn uri_encode(value: &str, already_encoded: bool) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b'%' if already_encoded && i + 2 < bytes.len() => {
                out.push_str(&value[i..i + 3]);
                i += 3;
                continue;
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
        i += 1;
    }
    out
}

/// A header value as the canonical form wants it: trimmed, with runs of
/// internal whitespace collapsed to one space.
fn collapse(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut space = false;
    for ch in value.trim().chars() {
        if ch.is_whitespace() {
            space = true;
            continue;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        out.push(ch);
    }
    out
}

/// `(20150830, 20150830T123600Z)` from seconds since the epoch.
///
/// Written out rather than pulled in: the whole of what this needs from a
/// date library is the civil date of a UTC instant, and the algorithm below
/// is Howard Hinnant's, which is exact for every day this program will ever
/// see and is twenty lines.
fn stamps(now: u64) -> (String, String) {
    let days = (now / 86_400) as i64;
    let secs = now % 86_400;
    let (year, month, day) = civil_from_days(days);
    (
        format!("{year:04}{month:02}{day:02}"),
        format!(
            "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        ),
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// HMAC-SHA256, written out for the same reason it is written out in
/// [`crate::egress_door`]: it is fourteen lines and it removes a dependency
/// from the path a credential travels.
fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(padded.map(|byte| byte ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(padded.map(|byte| byte ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's own published example credential. It is in their documentation
    /// and it authenticates nothing.
    const ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
    const SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    /// 2015-08-30T12:36:00Z, the instant every `aws4_testsuite` vector is
    /// signed at.
    const WHEN: u64 = 1_440_938_160;

    fn key() -> Key<'static> {
        Key {
            access_key_id: ACCESS_KEY_ID,
            secret_access_key: SECRET_ACCESS_KEY,
            session_token: None,
        }
    }

    fn header(signed: &Signed, name: &str) -> String {
        signed
            .headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("no {name} header"))
    }

    #[test]
    fn the_clock_conversion_lands_on_the_day_aws_published_its_vectors_for() {
        assert_eq!(stamps(WHEN), ("20150830".into(), "20150830T123600Z".into()));
        // The two edges a hand-written civil date gets wrong.
        assert_eq!(stamps(0).0, "19700101");
        assert_eq!(stamps(951_782_400).0, "20000229");
        assert_eq!(stamps(1_709_164_800).0, "20240229");
    }

    /// The published `get-vanilla` string-to-sign and signature, checked
    /// against the primitives rather than against `sign` — because `sign`
    /// adds a header AWS's example does not have.
    ///
    /// This is the assertion that proves the *cryptography* is AWS's and not
    /// merely self-consistent: the constant below is from AWS's own
    /// documentation.
    #[test]
    fn the_signing_primitives_match_the_constant_aws_published() {
        let empty = hex(&Sha256::digest(b""));
        let canonical = format!(
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n\
             host;x-amz-date\n{empty}"
        );
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let signature = hex(&hmac(
            &signing_key(SECRET_ACCESS_KEY, "20150830", "us-east-1", "service"),
            to_sign.as_bytes(),
        ));
        assert_eq!(
            signature,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    /// A verifier that does what a service does: take the request off the
    /// wire, rebuild the canonical form from *the request*, and see whether
    /// the signature the client sent is the one that falls out.
    ///
    /// This is the mock the lane proves against. It shares no code with
    /// `sign` above the primitives, so a signer that canonicalised wrongly
    /// would disagree with it.
    fn verify(
        secret: &str,
        method: &str,
        target: &str,
        host: &str,
        extra: &[(String, String)],
        body: &[u8],
        sent: &Signed,
    ) -> Result<(), String> {
        let authorization = sent
            .headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone())
            .ok_or("no Authorization header")?;
        let rest = authorization
            .strip_prefix("AWS4-HMAC-SHA256 ")
            .ok_or("not SigV4")?;
        let mut credential = String::new();
        let mut signed_headers = String::new();
        let mut signature = String::new();
        for field in rest.split(", ") {
            let (name, value) = field.split_once('=').ok_or("malformed field")?;
            match name {
                "Credential" => credential = value.to_owned(),
                "SignedHeaders" => signed_headers = value.to_owned(),
                "Signature" => signature = value.to_owned(),
                other => return Err(format!("unknown field {other}")),
            }
        }
        let mut scope_parts = credential.splitn(2, '/');
        let _key_id = scope_parts.next().ok_or("no key id")?;
        let scope = scope_parts.next().ok_or("no scope")?.to_owned();
        let mut scope_fields = scope.split('/');
        let date = scope_fields.next().ok_or("no date")?.to_owned();
        let region = scope_fields.next().ok_or("no region")?.to_owned();
        let service = scope_fields.next().ok_or("no service")?.to_owned();

        // Rebuild the header set from what actually arrived.
        let mut arrived: BTreeMap<String, String> = BTreeMap::new();
        for (name, value) in extra.iter().chain(sent.headers.iter()) {
            if name == "authorization" {
                continue;
            }
            arrived.insert(name.to_ascii_lowercase(), collapse(value));
        }
        arrived.insert("host".into(), host.to_owned());
        let timestamp = arrived.get("x-amz-date").cloned().ok_or("no x-amz-date")?;

        let mut canonical_headers = String::new();
        for name in signed_headers.split(';') {
            let value = arrived
                .get(name)
                .ok_or_else(|| format!("signed header {name} did not arrive"))?;
            canonical_headers.push_str(&format!("{name}:{value}\n"));
        }
        let payload = hex(&Sha256::digest(body));
        let (path, query) = split_target(target);
        let canonical = format!(
            "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{payload}",
            method.to_ascii_uppercase(),
            canonical_path(path, &service),
            canonical_query(query),
        );
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let expected = hex(&hmac(
            &signing_key(secret, &date, &region, &service),
            to_sign.as_bytes(),
        ));
        match expected == signature {
            true => Ok(()),
            false => Err("signature mismatch".into()),
        }
    }

    #[test]
    fn a_mock_verifier_accepts_what_the_door_signs_and_refuses_a_tampered_request() {
        let extra = vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("x-request-id".to_owned(), "  spaced   out  ".to_owned()),
        ];
        let body = br#"{"Action":"GetCallerIdentity"}"#;
        let signed = sign(
            &key(),
            &Request {
                method: "POST",
                target: "/v1/things?b=2&a=1&flag",
                host: "sts.us-east-1.amazonaws.com",
                headers: &extra,
                body,
                service: "sts",
                region: "us-east-1",
                now: WHEN,
            },
        );
        verify(
            SECRET_ACCESS_KEY,
            "POST",
            "/v1/things?b=2&a=1&flag",
            "sts.us-east-1.amazonaws.com",
            &extra,
            body,
            &signed,
        )
        .expect("the verifier accepts a request this door signed");

        // Each of these is a thing the signature is supposed to cover.
        assert!(verify(
            SECRET_ACCESS_KEY,
            "POST",
            "/v1/things?b=2&a=1&flag",
            "sts.us-east-1.amazonaws.com",
            &extra,
            b"{\"Action\":\"DeleteEverything\"}",
            &signed,
        )
        .is_err());
        assert!(verify(
            SECRET_ACCESS_KEY,
            "POST",
            "/v1/things?b=2&a=1&flag&extra=1",
            "sts.us-east-1.amazonaws.com",
            &extra,
            body,
            &signed,
        )
        .is_err());
        assert!(verify(
            SECRET_ACCESS_KEY,
            "POST",
            "/v1/things?b=2&a=1&flag",
            "sts.eu-west-1.amazonaws.com",
            &extra,
            body,
            &signed,
        )
        .is_err());
        // And a different secret does not open it, which is the whole point.
        assert!(verify(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEZ",
            "POST",
            "/v1/things?b=2&a=1&flag",
            "sts.us-east-1.amazonaws.com",
            &extra,
            body,
            &signed,
        )
        .is_err());
    }

    #[test]
    fn a_session_token_is_signed_as_well_as_sent() {
        let signed = sign(
            &Key {
                access_key_id: ACCESS_KEY_ID,
                secret_access_key: SECRET_ACCESS_KEY,
                session_token: Some("FQoDYXdzE"),
            },
            &Request {
                method: "GET",
                target: "/",
                host: "sts.amazonaws.com",
                headers: &[],
                body: b"",
                service: "sts",
                region: "us-east-1",
                now: WHEN,
            },
        );
        assert_eq!(header(&signed, "x-amz-security-token"), "FQoDYXdzE");
        assert!(header(&signed, "authorization").contains("x-amz-security-token"));
    }

    #[test]
    fn the_framing_of_a_connection_that_will_be_rewritten_is_not_signed() {
        // reqwest sets its own `content-length` and may re-encode the body's
        // transfer. A signature over headers the client is about to replace
        // is a signature the service rejects, and the reason is invisible.
        let signed = sign(
            &key(),
            &Request {
                method: "PUT",
                target: "/thing",
                host: "s3.amazonaws.com",
                headers: &[
                    ("content-length".to_owned(), "5".to_owned()),
                    ("connection".to_owned(), "close".to_owned()),
                ],
                body: b"hello",
                service: "s3",
                region: "us-east-1",
                now: WHEN,
            },
        );
        let authorization = header(&signed, "authorization");
        assert!(!authorization.contains("content-length"), "{authorization}");
        assert!(!authorization.contains("connection"), "{authorization}");
        // S3 always wants the payload hash, and gets it.
        assert_eq!(
            header(&signed, "x-amz-content-sha256"),
            hex(&Sha256::digest(b"hello"))
        );
    }

    #[test]
    fn s3_signs_the_path_it_sends_and_everything_else_double_encodes() {
        assert_eq!(canonical_path("/a b/c", "s3"), "/a b/c");
        assert_eq!(canonical_path("/a b/c", "sts"), "/a%2520b/c");
        assert_eq!(canonical_path("", "sts"), "/");
        // A query is sorted and a bare flag gets its `=`.
        assert_eq!(canonical_query("b=2&a=1&flag"), "a=1&b=2&flag=");
        assert_eq!(canonical_query(""), "");
    }
}
