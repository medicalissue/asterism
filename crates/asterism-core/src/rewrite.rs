//! The rewrite engine: what an outbound request has to be before a secret is
//! put into it.
//!
//! This module is deliberately pure, and it is deliberately *small*. It parses
//! nothing, frames nothing and opens nothing — HTTP is [`http`] and hyper's
//! job, TLS is rustls's — and what is left is the one thing that is Asterism's
//! own: given a binding that came off an instance and headers that came off a
//! guest, *may this request be given the value, and where exactly does it go?*
//!
//! # The rule
//!
//! Substitution happens when **all** of these hold, and never otherwise:
//!
//! 1. The connection was opened to an authority some binding on this instance
//!    names, matched exactly — no suffix match, no wildcard.
//! 2. The request carries a credential at exactly the placement that binding
//!    describes, once and only once.
//! 3. That credential is byte-for-byte the opaque handle this instance was
//!    minted, compared in constant time.
//!
//! A request that carries no credential at all is forwarded untouched, which
//! is what makes a proxied guest work at all: an image's package manager and
//! its health checks talk to bound hosts too. A request that carries
//! *something else* is refused rather than forwarded, because a guest that
//! sent the wrong credential to a bound host is either confused or hostile
//! and neither wants its own key silently swapped in.
//!
//! # What never appears here
//!
//! Material. [`fill`] is the one function that takes any, it is called on the
//! source device immediately before the upstream connection, and it marks the
//! header it writes as sensitive — which is what makes `http`'s own `Debug`
//! print `Sensitive` instead of a key everywhere the daemon logs a request.

use std::net::IpAddr;

use http::header::{HeaderMap, HeaderName, HeaderValue};

use crate::secret::{Binding, Placement};

/// The most headers a bound request may carry, handed to hyper's
/// `http1::Builder::max_headers` rather than counted here.
///
/// Beyond this a request is either broken or trying to make header lookup
/// quadratic. The framing caps that go with it — head size, and what to do
/// with two `Content-Length`s — are hyper's, and are the reason none of that
/// is written in this file any more.
pub const MAX_HEADERS: usize = 96;

/// The largest request body carried through a bound connection.
///
/// Bound traffic is API calls, and the proxy buffers a body whole so that the
/// source device can be handed one frame rather than a stream. That buffering
/// is one reason for a cap; the other is that the frame then has to cross the
/// mesh, which refuses anything over
/// [`MESH_FRAME_LIMIT`](crate::protocol::MESH_FRAME_LIMIT) — so this is sized
/// to fit inside one with its base64 expansion and its headers, and
/// `protocol::egress` has the test that keeps the two honest.
///
/// It is enforced by `http_body_util::Limited`, not by anything here.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// The largest upstream response buffered on the way back. Same frame, same
/// reasoning.
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Why a request was not carried.
///
/// Each variant is a *category*, not a sentence about one request: the text a
/// guest is given says what rule it broke and never what it sent, because a
/// proxy that echoes a rejected credential back has just written it into the
/// guest's own logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Larger than this plane carries. `what` is `"body"` or `"head"`.
    TooLarge(&'static str),
    /// Something about the request contradicts the tunnel it arrived in.
    Malformed(&'static str),
    /// Nothing on this instance binds the authority the guest connected to.
    NotBound,
    /// The bound placement appears more than once. Two `Authorization`
    /// headers are a request-smuggling shape, and picking one of them is a
    /// guess about which end-to-end hop wins.
    Duplicated,
    /// A credential is there and it is not the handle this instance holds.
    HandleMismatch,
    /// The destination is not somewhere a guest is allowed to be sent.
    NotPublic(&'static str),
    /// The upstream could not be reached, or did not answer in time.
    Upstream(String),
}

impl Refusal {
    /// The status a guest sees.
    pub fn status(&self) -> u16 {
        match self {
            Self::TooLarge("body") => 413,
            Self::TooLarge(_) => 431,
            Self::Malformed(_) => 400,
            Self::NotBound | Self::NotPublic(_) => 403,
            Self::Duplicated | Self::HandleMismatch => 401,
            Self::Upstream(_) => 502,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge(what) => {
                write!(f, "the request {what} is larger than this proxy carries")
            }
            Self::Malformed(why) => write!(
                f,
                "the request does not match the tunnel it arrived in: {why}"
            ),
            Self::NotBound => f.write_str("no secret on this instance is bound to that authority"),
            Self::Duplicated => f.write_str("the bound credential header appears more than once"),
            Self::HandleMismatch => {
                f.write_str("that is not this instance's handle for the bound secret")
            }
            Self::NotPublic(what) => write!(f, "a guest may not be proxied to {what}"),
            Self::Upstream(why) => write!(f, "the upstream did not answer: {why}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// What the engine decided about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request presented this instance's handle at the bound placement.
    /// Strip it here and fill it on the source device.
    Substitute,
    /// No credential at the bound placement at all: carry it as it is.
    ///
    /// This is the common case for a bound host — a `GET /health`, a package
    /// index, a redirect being followed — and refusing it would mean binding
    /// a secret to a host broke every other use of that host.
    PassThrough,
}

/// The bindings one instance carries, as an allowlist.
///
/// A newtype rather than a bare slice so that "does this authority have a
/// binding" is one function with one definition of *match*. Suffix matching
/// is what turns `api.example.com` into `api.example.com.evil.test`, so
/// matching is equality on the normalised authority and nothing else.
pub struct Allowlist<'a>(pub &'a [Binding]);

impl<'a> Allowlist<'a> {
    /// The binding for a `host:port` authority as it arrived in a CONNECT
    /// line, or `None`.
    ///
    /// A binding written without a port means the default port for the
    /// scheme, which for an intercepted CONNECT is always 443; a binding
    /// written with one means only that port.
    pub fn find(&self, authority: &str) -> Option<&'a Binding> {
        let authority = authority.trim().to_ascii_lowercase();
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().ok()?),
            None => (authority.as_str(), 443),
        };
        self.0
            .iter()
            .find(|binding| match binding.authority.rsplit_once(':') {
                Some((bound_host, bound_port)) => {
                    bound_host == host && bound_port.parse() == Ok(port)
                }
                None => binding.authority == host && port == 443,
            })
    }
}

// ---- the rule --------------------------------------------------------------

/// Whether this request may be given the bound secret.
///
/// `authority` is what the guest asked for in its CONNECT line, not what DNS
/// said and not what the `Host` header claims — the certificate the guest
/// accepted was minted for the CONNECT authority, so that is the only name
/// the connection actually authenticated.
pub fn decide(
    binding: &Binding,
    authority: &str,
    uri: &http::Uri,
    headers: &HeaderMap,
) -> Result<Decision, Refusal> {
    if Allowlist(std::slice::from_ref(binding))
        .find(authority)
        .is_none()
    {
        return Err(Refusal::NotBound);
    }
    // Inside a terminated tunnel a request is in origin form. An absolute-form
    // target means the guest is asking one origin to fetch another's url, and
    // the authority in it would disagree with the one the certificate was
    // minted for.
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(Refusal::Malformed("the target names an origin of its own"));
    }
    // The `Host` header travels inside the tunnel and the guest chose it, so
    // a mismatch means the guest is trying to reach one origin through
    // another's certificate. It is refused rather than corrected.
    if let Some(host) = headers.get(http::header::HOST) {
        let Ok(host) = host.to_str() else {
            return Err(Refusal::Malformed("the Host header is not ascii"));
        };
        if !same_origin(host, authority) {
            return Err(Refusal::Malformed(
                "the Host header names a different origin",
            ));
        }
    }
    let header = header_name(&binding.placement)?;
    let mut present = headers.get_all(&header).iter();
    let Some(raw) = present.next() else {
        return Ok(Decision::PassThrough);
    };
    if present.next().is_some() {
        return Err(Refusal::Duplicated);
    }
    let Ok(raw) = raw.to_str() else {
        return Err(Refusal::HandleMismatch);
    };
    // A value shaped wrongly for the placement — `Basic …` where the binding
    // says `Bearer` — is not this binding's credential. Treated as a
    // mismatch, not a pass-through: forwarding it would send whatever it is
    // to a host the user considers sensitive enough to bind.
    //
    // `accept` widens the *shapes* and never the header: a credential part
    // declares the schemes its own tools actually use — `gh` sends
    // `Authorization: token …` to some endpoints and `Bearer …` to others —
    // and each of them still has to carry this instance's handle, compared in
    // constant time, to be substituted.
    let accepted = std::iter::once(&binding.placement).chain(binding.accept.iter());
    for placement in accepted {
        if let Some(candidate) = placement.extract(raw) {
            if binding.guest_handle.matches(candidate) {
                return Ok(Decision::Substitute);
            }
        }
    }
    Err(Refusal::HandleMismatch)
}

/// Take the handle out of a header map, leaving a blank where the source
/// device will put the value.
///
/// Called on the consumer device, which is the only one that knows the
/// handle. What crosses the mesh therefore carries neither the guest's
/// credential nor the secret: one end holds the handle, the other holds the
/// material, and the frame between them holds a header with nothing in it.
pub fn strip(binding: &Binding, headers: &mut HeaderMap) -> Result<(), Refusal> {
    let header = header_name(&binding.placement)?;
    if headers.remove(&header).is_some() {
        headers.insert(header, HeaderValue::from_static(""));
    }
    Ok(())
}

/// Put the material in, immediately before the upstream connection.
///
/// The last function to touch a request and the only one that sees plaintext.
/// It refuses a value that could not be a header — a newline in a secret
/// would end the header block and let everything after it be read as a
/// request of its own — and it marks what it writes as sensitive, which is
/// how `http`'s own `Debug` prints `Sensitive` in place of a key from here on.
pub fn fill(binding: &Binding, headers: &mut HeaderMap, value: &str) -> Result<(), Refusal> {
    if value.is_empty() {
        return Err(Refusal::Malformed("the bound secret is empty"));
    }
    let header = header_name(&binding.placement)?;
    let mut rendered = HeaderValue::try_from(binding.placement.render(value)).map_err(|_| {
        Refusal::Malformed(
            "the bound secret cannot be a header value — it holds a control character",
        )
    })?;
    rendered.set_sensitive(true);
    headers.insert(header, rendered);
    Ok(())
}

/// The binding's header, as `http` spells one.
///
/// A binding's header name is validated where the user typed it
/// ([`crate::secret::check_header_name`]), so this failing means a shard was
/// edited by hand; it is a refusal rather than a panic because a daemon
/// should not die of somebody else's bad JSON.
fn header_name(placement: &Placement) -> Result<HeaderName, Refusal> {
    HeaderName::try_from(placement.header())
        .map_err(|_| Refusal::Malformed("this binding's header name is not an HTTP token"))
}

/// Whether a `Host` header and a CONNECT authority name the same origin,
/// allowing for the port being implicit in one and not the other.
fn same_origin(host_header: &str, authority: &str) -> bool {
    let split = |s: &str| -> (String, u16) {
        match s.trim().to_ascii_lowercase().rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(443)),
            None => (s.trim().to_ascii_lowercase(), 443),
        }
    };
    split(host_header) == split(authority)
}

/// The headers a proxy must not carry between two connections.
///
/// Hop-by-hop by RFC 9110, plus the framing ones: this end buffered the body,
/// so the length and the encoding it arrived under describe a connection that
/// no longer exists.
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

// ---- where a guest may be sent ---------------------------------------------

/// Whether an address is somewhere a guest's traffic may be proxied to.
///
/// The proxy runs on the host, so it reaches everything the host reaches —
/// the loopback services the daemon itself listens on, the LAN the device
/// sits on, and the link-local address every cloud provider serves instance
/// credentials from. A guest reaching those *through* the proxy would be the
/// proxy handing out the host's network position, which is a strictly larger
/// authority than the guest's own NAT already gives it.
///
/// So: public unicast only, checked after resolution rather than on the name,
/// because a name is whatever DNS says it is at the moment it is asked. The
/// address that passes here is then the one handed to the client, so there is
/// no second lookup for a rebind to land in.
pub fn is_public(addr: IpAddr) -> Result<(), Refusal> {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return Err(Refusal::NotPublic("this device's loopback"));
            }
            if v4.is_link_local() {
                // 169.254.169.254 is the one every cloud serves instance
                // credentials from, and it is link-local like the rest.
                return Err(Refusal::NotPublic(
                    "a link-local address, where instance metadata lives",
                ));
            }
            if v4.is_private() {
                return Err(Refusal::NotPublic(
                    "a private address on this device's own network",
                ));
            }
            if v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
            {
                return Err(Refusal::NotPublic("an address that is not a host"));
            }
            // Carrier-grade NAT (100.64/10) and the benchmarking range are
            // neither private nor routable, and both reach infrastructure.
            let [a, b, ..] = v4.octets();
            if a == 100 && (64..128).contains(&b) {
                return Err(Refusal::NotPublic("a carrier-grade NAT address"));
            }
            if a == 198 && (b == 18 || b == 19) {
                return Err(Refusal::NotPublic("a benchmarking address"));
            }
            if a == 0 || a >= 240 {
                return Err(Refusal::NotPublic("a reserved address"));
            }
            Ok(())
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Err(Refusal::NotPublic("this device's loopback"));
            }
            if v6.is_unspecified() || v6.is_multicast() {
                return Err(Refusal::NotPublic("an address that is not a host"));
            }
            // A v4-mapped v6 address reaches exactly the v4 address inside
            // it, so it is judged as that address rather than as a v6 one.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            if segments[0] & 0xfe00 == 0xfc00 {
                return Err(Refusal::NotPublic("a unique-local address"));
            }
            if segments[0] & 0xffc0 == 0xfe80 {
                return Err(Refusal::NotPublic("a link-local address"));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{
        Binding, GuestHandle, HandleShape, Placement, Secret, SecretId, SourceDevice, ValueRevision,
    };

    fn binding(authority: &str, placement: Placement) -> Binding {
        Binding {
            id: "b1".into(),
            secret_id: SecretId::from_name("anthropic").unwrap(),
            secret: "anthropic".into(),
            authority: authority.into(),
            guest_handle: GuestHandle::mint(HandleShape::for_authority(authority)),
            placement,
            env: "ANTHROPIC_API_KEY".into(),
            source_device_id: "source-key".into(),
            source_device: "laptop".into(),
            version: 1,
            bound_at: 1,
            provider: None,
            accept: Vec::new(),
            rule: crate::credential::CredentialRule::Substitute,
        }
    }

    fn x_api_key() -> Placement {
        Placement::Header {
            name: "x-api-key".into(),
        }
    }

    fn bearer() -> Placement {
        Placement::Authorization {
            scheme: "Bearer".into(),
        }
    }

    /// A request as hyper would hand it over: an origin-form target and a
    /// header map, with whatever the test is about in it.
    fn request(host: &str, headers: &[(&str, &str)]) -> (http::Uri, HeaderMap) {
        let mut map = HeaderMap::new();
        map.insert(http::header::HOST, HeaderValue::from_str(host).unwrap());
        for (name, value) in headers {
            map.append(
                HeaderName::try_from(*name).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        ("/v1/messages".parse().unwrap(), map)
    }

    fn secret(version: u64, source_version: u64, revision: &ValueRevision) -> Secret {
        Secret {
            id: SecretId::from_name("anthropic").unwrap(),
            name: "anthropic".into(),
            version,
            created_at: 1,
            updated_at: version,
            sources: vec![SourceDevice {
                device_id: "source-key".into(),
                device: "laptop".into(),
                version: source_version,
                updated_at: source_version,
                origin: revision.clone(),
                revision: revision.clone(),
            }],
            kind: crate::credential::PartKind::Secret,
            provider: None,
        }
    }

    #[test]
    fn a_request_that_carries_no_credential_is_carried_untouched() {
        // The common case for a bound host, and the reason binding a secret
        // to `api.anthropic.com` does not break every other call to it.
        let binding = binding("api.anthropic.com", x_api_key());
        let (uri, mut headers) = request("api.anthropic.com", &[("accept", "application/json")]);
        let before = headers.clone();
        assert_eq!(
            decide(&binding, "api.anthropic.com:443", &uri, &headers),
            Ok(Decision::PassThrough)
        );
        strip(&binding, &mut headers).unwrap();
        assert_eq!(
            headers, before,
            "pass-through must not invent a blank header"
        );
    }

    #[test]
    fn the_exact_handle_is_replaced_by_the_value_and_nothing_else_is() {
        let binding = binding("api.anthropic.com", x_api_key());
        let (uri, mut headers) = request(
            "api.anthropic.com",
            &[("x-api-key", binding.guest_handle.as_str())],
        );
        assert_eq!(
            decide(&binding, "api.anthropic.com:443", &uri, &headers),
            Ok(Decision::Substitute)
        );

        // The consumer blanks it; what crosses the mesh has neither the
        // handle nor the value in it.
        strip(&binding, &mut headers).unwrap();
        assert_eq!(headers.get("x-api-key").unwrap().as_bytes(), b"");
        assert_eq!(headers.get_all("x-api-key").iter().count(), 1);

        // The source fills it, immediately before egress.
        fill(&binding, &mut headers, "sk-ant-REAL").unwrap();
        assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-REAL");
        assert_eq!(headers.get_all("x-api-key").iter().count(), 1);
        // Everything else is exactly as the guest sent it.
        assert_eq!(headers.get("host").unwrap(), "api.anthropic.com");
    }

    #[test]
    fn a_bearer_binding_reads_and_writes_the_scheme_rather_than_the_bare_value() {
        let binding = binding("api.openai.com", bearer());
        let handle = binding.guest_handle.as_str().to_owned();
        let at =
            |authorization: &str| request("api.openai.com", &[("authorization", authorization)]);

        // Bare, without the scheme, is not this binding's credential; nor is
        // another scheme carrying the same bytes.
        for wrong in [handle.clone(), format!("Basic {handle}")] {
            let (uri, headers) = at(&wrong);
            assert_eq!(
                decide(&binding, "api.openai.com:443", &uri, &headers),
                Err(Refusal::HandleMismatch)
            );
        }

        let (uri, mut headers) = at(&format!("Bearer {handle}"));
        assert_eq!(
            decide(&binding, "api.openai.com:443", &uri, &headers),
            Ok(Decision::Substitute)
        );
        strip(&binding, &mut headers).unwrap();
        fill(&binding, &mut headers, "sk-REAL").unwrap();
        assert_eq!(headers.get("authorization").unwrap(), "Bearer sk-REAL");
    }

    #[test]
    fn a_bound_secret_reaches_only_the_authority_it_was_bound_to() {
        let binding = binding("api.anthropic.com", x_api_key());
        let (uri, headers) = request(
            "api.anthropic.com",
            &[("x-api-key", binding.guest_handle.as_str())],
        );
        for wrong in [
            "api.openai.com:443",
            // The suffix attack an allowlist exists to refuse.
            "api.anthropic.com.evil.test:443",
            "evil.test:443",
            // Right host, wrong port: a binding without a port means 443.
            "api.anthropic.com:8443",
        ] {
            assert_eq!(
                decide(&binding, wrong, &uri, &headers),
                Err(Refusal::NotBound),
                "{wrong}"
            );
        }
        assert_eq!(
            decide(&binding, "API.Anthropic.com:443", &uri, &headers),
            Ok(Decision::Substitute)
        );
    }

    #[test]
    fn a_request_that_disagrees_with_its_own_tunnel_is_refused() {
        // The certificate was minted for the CONNECT authority, so a Host
        // header — or an absolute-form target — naming a different origin is
        // the guest trying to reach one service through another's identity.
        let binding = binding("api.anthropic.com", x_api_key());
        let handle = binding.guest_handle.as_str();

        let (uri, headers) = request("internal.corp", &[("x-api-key", handle)]);
        assert!(matches!(
            decide(&binding, "api.anthropic.com:443", &uri, &headers),
            Err(Refusal::Malformed(_))
        ));

        let (_, headers) = request("api.anthropic.com", &[("x-api-key", handle)]);
        let absolute: http::Uri = "https://internal.corp/v1/messages".parse().unwrap();
        assert!(matches!(
            decide(&binding, "api.anthropic.com:443", &absolute, &headers),
            Err(Refusal::Malformed(_))
        ));
    }

    #[test]
    fn a_credential_that_is_not_this_instances_handle_is_refused_rather_than_forwarded() {
        let binding = binding("api.anthropic.com", x_api_key());
        let other = GuestHandle::mint(HandleShape::Anthropic);
        for wrong in [
            other.as_str(),
            "sk-ant-a-real-looking-key",
            // A prefix of the real handle: the comparison is length-aware.
            &binding.guest_handle.as_str()[..8],
            "",
        ] {
            let (uri, headers) = request("api.anthropic.com", &[("x-api-key", wrong)]);
            assert_eq!(
                decide(&binding, "api.anthropic.com:443", &uri, &headers),
                Err(Refusal::HandleMismatch),
                "{wrong:?}"
            );
        }
    }

    #[test]
    fn the_bound_header_appearing_twice_is_refused_rather_than_resolved() {
        // Two credential headers is the shape a smuggled request wears, and
        // choosing one of them would be choosing which hop's request wins.
        let binding = binding("api.anthropic.com", x_api_key());
        let handle = binding.guest_handle.as_str();
        for pair in [[handle, handle], [handle, "something-else"]] {
            let (uri, headers) = request(
                "api.anthropic.com",
                &[("x-api-key", pair[0]), ("X-API-KEY", pair[1])],
            );
            assert_eq!(
                decide(&binding, "api.anthropic.com:443", &uri, &headers),
                Err(Refusal::Duplicated)
            );
        }
    }

    #[test]
    fn a_rotated_secret_is_refreshed_rather_than_redeemed_against_stale_bytes() {
        // The binding was made at version 1. A rotation to version 2 must
        // reach the next request: the source handle is selected per request,
        // so the refresh is reported and the request still goes.
        let binding = binding("api.anthropic.com", x_api_key());
        let lineage = ValueRevision::mint();

        let fresh = binding.refresh(&secret(1, 1, &lineage)).unwrap();
        assert_eq!(fresh.handle.version, 1);
        assert_eq!(fresh.rotated_from, None);

        let rotated = ValueRevision::mint();
        let refreshed = binding.refresh(&secret(2, 2, &rotated)).unwrap();
        assert_eq!(refreshed.handle.version, 2);
        assert_eq!(refreshed.rotated_from, Some(1));
        assert_eq!(refreshed.handle.source.revision, rotated);

        // A source that the rotation has not reached cannot serve the
        // current version, and says so instead of serving the old value.
        assert!(
            binding.refresh(&secret(2, 1, &lineage)).is_err(),
            "a lagging source must not serve a rotation"
        );

        // The guest's handle is not touched by any of it: rotation is a
        // host-side fact, and re-seeding a guest for one would be a reboot.
        let (uri, headers) = request(
            "api.anthropic.com",
            &[("x-api-key", binding.guest_handle.as_str())],
        );
        assert_eq!(
            decide(&binding, "api.anthropic.com:443", &uri, &headers),
            Ok(Decision::Substitute)
        );
    }

    #[test]
    fn the_caps_this_plane_hands_to_hyper_are_the_ones_it_says_it_has() {
        // The framing caps are enforced by hyper and http_body_util, and
        // these constants are what they are configured with. The test is here
        // so that a change to one is a change a reviewer sees — and so that
        // the *reason* the body caps are what they are is written down: a
        // frame has to cross the mesh, base64 costs four bytes for three, and
        // the headers ride along with it. `protocol::egress` serialises a
        // full-sized one and checks it for real.
        assert_eq!(MAX_HEADERS, 96);
        let limit = crate::protocol::MESH_FRAME_LIMIT;
        for cap in [MAX_BODY_BYTES, MAX_RESPONSE_BYTES] {
            assert!(
                cap.div_ceil(3) * 4 < limit,
                "a {cap}-byte body is {} base64 bytes, over the {limit} a frame carries",
                cap.div_ceil(3) * 4
            );
        }
        assert_eq!(Refusal::TooLarge("body").status(), 413);
        assert_eq!(Refusal::TooLarge("head").status(), 431);
        assert_eq!(Refusal::Upstream(String::new()).status(), 502);
        // The framing headers a proxy must not carry across two connections.
        for hop in [
            "connection",
            "content-length",
            "transfer-encoding",
            "te",
            "upgrade",
        ] {
            assert!(is_hop_by_hop(hop), "{hop}");
        }
        assert!(!is_hop_by_hop("x-api-key"));
        assert!(!is_hop_by_hop("authorization"));
    }

    #[test]
    fn a_secret_that_could_end_a_header_block_is_refused_rather_than_written() {
        // The one way a value could turn one request into two. `http` refuses
        // the bytes; this asserts that the refusal is ours to report and not
        // a panic, and that an empty value is caught before it gets there.
        let binding = binding("api.anthropic.com", x_api_key());
        let (_, mut headers) = request("api.anthropic.com", &[]);
        for hostile in ["a\r\nX-Injected: 1", "a\nb", "a\0b", ""] {
            assert!(
                matches!(
                    fill(&binding, &mut headers, hostile),
                    Err(Refusal::Malformed(_))
                ),
                "{hostile:?} was written into a header"
            );
        }
        assert!(fill(&binding, &mut headers, "sk-ant-fine").is_ok());
    }

    #[test]
    fn nothing_that_prints_a_request_or_a_handle_can_print_what_is_in_it() {
        let binding = binding("api.anthropic.com", x_api_key());
        let handle = binding.guest_handle.as_str().to_owned();
        let (_, mut headers) = request("api.anthropic.com", &[("x-api-key", &handle)]);
        fill(&binding, &mut headers, "sk-ant-REAL").unwrap();

        // `fill` marks the header sensitive, which is `http`'s own mechanism
        // for this: every Debug of that map from here on prints `Sensitive`.
        let debug = format!("{headers:?}");
        assert!(!debug.contains("sk-ant-REAL"), "{debug}");
        assert!(!debug.contains(handle.as_str()), "{debug}");
        assert!(debug.contains("Sensitive"), "{debug}");
        assert!(headers.get("x-api-key").unwrap().is_sensitive());

        assert_eq!(format!("{:?}", binding.guest_handle), "<guest handle>");
        // A whole binding is printed by `ast status` and by every error path
        // in the daemon.
        assert!(!format!("{binding:?}").contains(handle.as_str()));
        // The hint is short enough to be a prefix and long enough to name one
        // handle out of an instance's few.
        assert!(handle.starts_with(binding.guest_handle.hint().trim_end_matches('…')));
    }

    #[test]
    fn a_guest_is_not_proxied_onto_the_hosts_own_network() {
        // Everything the proxy could reach that the guest's NAT could not.
        for (addr, what) in [
            ("127.0.0.1", "loopback"),
            ("169.254.169.254", "cloud instance metadata"),
            ("10.1.2.3", "private"),
            ("192.168.1.1", "the LAN"),
            ("172.16.0.1", "private"),
            ("100.64.0.1", "carrier-grade NAT"),
            ("0.0.0.0", "unspecified"),
            ("224.0.0.1", "multicast"),
            ("::1", "v6 loopback"),
            ("fd00::1", "unique-local"),
            ("fe80::1", "v6 link-local"),
            ("::ffff:127.0.0.1", "loopback behind a v4-mapped v6 address"),
        ] {
            assert!(
                is_public(addr.parse().unwrap()).is_err(),
                "{what} ({addr}) was allowed"
            );
        }
        for public in ["1.1.1.1", "160.79.104.10", "2606:4700::1111"] {
            assert!(
                is_public(public.parse().unwrap()).is_ok(),
                "{public} was refused"
            );
        }
        assert_eq!(Refusal::NotPublic("x").status(), 403);
    }

    #[test]
    fn an_allowlist_matches_one_authority_and_never_a_neighbour_of_it() {
        let bindings = vec![
            binding("api.anthropic.com", x_api_key()),
            binding("internal.example.com:8443", bearer()),
        ];
        let list = Allowlist(&bindings);
        for (asked, expected) in [
            ("api.anthropic.com:443", 0),
            ("api.anthropic.com", 0),
            ("internal.example.com:8443", 1),
        ] {
            assert_eq!(
                list.find(asked).map(|b| &b.authority),
                Some(&bindings[expected].authority),
                "{asked}"
            );
        }
        for miss in [
            "internal.example.com:443",
            "internal.example.com",
            "api.anthropic.com:80",
            "notapi.anthropic.com:443",
            "",
        ] {
            assert!(list.find(miss).is_none(), "{miss} matched");
        }
    }
}
