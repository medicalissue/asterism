//! Orbit-scoped secret metadata.
//!
//! This module intentionally contains no secret material.  A [`Secret`] is
//! the orbit's description of a value, a [`Binding`] says which outbound
//! authority may eventually use it, and a [`Handle`] identifies one concrete
//! source device from which the daemon can resolve it.  The bytes themselves
//! live behind the daemon's `SecretStore` platform seam.
//!
//! What metadata does carry is a [`ValueRevision`]: a commitment to *which*
//! value a source holds, never to the value itself.  That distinction is the
//! whole design.  Without it, two devices that created the same name during a
//! partition described their two unrelated values identically, and a merge
//! could not tell them apart from one value replicated twice.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Immutable orbit identity of a secret.
///
/// Layer 0 deliberately derives this from the name.  That gives two devices
/// creating the same named secret during a partition the same identity, while
/// leaving a future rename as an explicit metadata migration rather than an
/// accidental identity change.  Sharing an identity is what makes the
/// collision visible; [`ValueRevision`] is what keeps it from being silently
/// merged away.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretId(String);

impl SecretId {
    pub fn from_name(name: &str) -> Result<Self> {
        check_name(name)?;
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Random, immutable identity of one concrete secret value.
///
/// A revision is minted at the instant a value is created or rotated, and it
/// reaches a second device only on the authenticated source-to-source path
/// that carries the bytes themselves.  Two revisions being equal therefore
/// proves shared provenance: the bytes were replicated, not retyped.
///
/// It is deliberately random rather than a digest of the value.  Metadata
/// replicates in the clear to every device in the orbit and rests unencrypted
/// in each catalog, so a digest would hand anyone who can read a catalog an
/// offline verifier — and against a short PIN, a passphrase, or any of the
/// low-entropy values people actually keep in a secret manager, an offline
/// verifier is the whole attack.  The cost of choosing randomness is that
/// equal plaintext reached by two independent paths looks different, which is
/// the safe direction to be wrong in: it raises a conflict a human resolves
/// instead of silently blessing two values as one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ValueRevision(uuid::Uuid);

impl ValueRevision {
    /// Mint a fresh revision.  Every call yields a distinct value, which is
    /// exactly what makes two partitioned creations of one name detectable.
    pub fn mint() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl std::fmt::Display for ValueRevision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for ValueRevision {
    type Error = anyhow::Error;

    /// Parsing is strict so that a peer cannot widen the type.  A revision
    /// that arrived as an empty string, or as a prefix of another, would
    /// compare equal to things it has no provenance with.
    fn try_from(text: String) -> Result<Self> {
        uuid::Uuid::parse_str(&text)
            .map(Self)
            .with_context(|| format!("{text:?} is not a secret value revision"))
    }
}

impl From<ValueRevision> for String {
    fn from(revision: ValueRevision) -> Self {
        revision.0.to_string()
    }
}

/// One device that independently holds the value.
///
/// `device_id` is the mesh public key and therefore the identity.  `device`
/// is only the current human-readable route hint and may change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDevice {
    pub device_id: String,
    pub device: String,
    pub version: u64,
    pub updated_at: u64,
    /// The lineage this source belongs to: the revision minted when the
    /// secret was first created, carried unchanged through every rotation and
    /// every copy to a further source.  Two devices that independently created
    /// one name hold different origins, and no later rotation can make them
    /// agree — which is correct, because their values were never related.
    pub origin: ValueRevision,
    /// The revision of the exact bytes this source holds at `version`.
    pub revision: ValueRevision,
}

/// Orbit-visible metadata for one secret.  There is no value field by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    pub id: SecretId,
    pub name: String,
    pub version: u64,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub sources: Vec<SourceDevice>,
}

/// Why a secret's sources cannot be treated as interchangeable.
///
/// This is derived from the source list rather than stored beside it, so a
/// conflict cannot be cleared by a peer that simply forgets to mention it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretConflict {
    /// The name was created independently more than once.  The values are
    /// unrelated, so no rotation reconciles them: a human has to say which
    /// lineage survives.
    Origin { origins: Vec<ValueRevision> },
    /// Sources within one lineage claim a single version while holding
    /// different values.  A partitioned rotation looks like this.
    Revision {
        version: u64,
        revisions: Vec<ValueRevision>,
    },
}

impl std::fmt::Display for SecretConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Origin { origins } => write!(
                f,
                "it was created independently on more than one device, so {} unrelated values \
                 share the name ({})",
                origins.len(),
                joined(origins)
            ),
            Self::Revision { version, revisions } => write!(
                f,
                "{} different values are claimed at version {version} ({})",
                revisions.len(),
                joined(revisions)
            ),
        }
    }
}

fn joined(revisions: &[ValueRevision]) -> String {
    revisions
        .iter()
        .map(ValueRevision::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Where a credential rides on an outbound request.
///
/// This is the whole of what a binding says about a request's *shape*, and
/// it is deliberately a closed set rather than a template string. A template
/// is a small language, and a small language in front of a secret is a place
/// for an injection to live; two named placements cover the two ways every
/// API in `SECRETS.md` carries a key, and a third is a change to this enum
/// that every match arm is then made to answer for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Placement {
    /// The value is the whole of one header: `x-api-key: <value>`.
    Header { name: String },
    /// The value follows a scheme in `Authorization`: `Bearer <value>`.
    Authorization { scheme: String },
}

impl Placement {
    /// `--as x-api-key`, `--as bearer`, `--as header:X-Token`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.eq_ignore_ascii_case("bearer") {
            return Ok(Self::Authorization {
                scheme: "Bearer".into(),
            });
        }
        let name = match spec.split_once(':') {
            Some((tag, name)) if tag.eq_ignore_ascii_case("header") => name.trim(),
            Some(_) => bail!(
                "{spec:?} is not a placement — write `bearer`, `x-api-key`, or `header:<Name>`"
            ),
            None => spec,
        };
        check_header_name(name)?;
        if name.eq_ignore_ascii_case("authorization") {
            bail!(
                "write `--as bearer` for an Authorization header, so the scheme is part of \
                 the binding rather than part of the value"
            );
        }
        Ok(Self::Header {
            name: name.to_ascii_lowercase(),
        })
    }

    /// The header this placement reads and writes, lowercased.
    pub fn header(&self) -> &str {
        match self {
            Self::Header { name } => name,
            Self::Authorization { .. } => "authorization",
        }
    }

    /// The header value that carries `credential`.
    pub fn render(&self, credential: &str) -> String {
        match self {
            Self::Header { .. } => credential.to_owned(),
            Self::Authorization { scheme } => format!("{scheme} {credential}"),
        }
    }

    /// The credential inside a header value, or `None` if this value is not
    /// shaped the way the placement says it should be.
    ///
    /// Strict about the scheme on purpose: a request that said `Basic` where
    /// the binding says `Bearer` is not a request this binding describes, and
    /// substituting into it would put an API key somewhere nobody asked for.
    pub fn extract<'v>(&self, value: &'v str) -> Option<&'v str> {
        match self {
            Self::Header { .. } => Some(value),
            Self::Authorization { scheme } => {
                let (got, rest) = value.split_once(' ')?;
                got.eq_ignore_ascii_case(scheme).then(|| rest.trim_start())
            }
        }
    }

    /// What to guess for an authority when the user did not say.
    pub fn for_authority(authority: &str) -> Self {
        match host_of(authority) {
            "api.anthropic.com" => Self::Header {
                name: "x-api-key".into(),
            },
            _ => Self::Authorization {
                scheme: "Bearer".into(),
            },
        }
    }
}

impl std::fmt::Display for Placement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header { name } => write!(f, "{name}"),
            Self::Authorization { scheme } => write!(f, "authorization: {scheme}"),
        }
    }
}

/// The prefix an opaque guest handle wears.
///
/// A handle is a random string that means nothing, but an SDK will often
/// reject one before it is ever sent — OpenAI's clients check for `sk-`,
/// Anthropic's for `sk-ant-` — so a handle that does not look like the
/// family it stands in for fails inside the guest, where there is no proxy
/// to explain why. The shape is cosmetic and the entropy is not: every
/// shape carries the same 240-odd random bits after its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleShape {
    /// `ast-…`, for anything with no house style to imitate.
    Opaque,
    /// `sk-ast-…`.
    OpenAi,
    /// `sk-ant-ast-…`.
    Anthropic,
}

impl HandleShape {
    pub fn for_authority(authority: &str) -> Self {
        match host_of(authority) {
            "api.anthropic.com" => Self::Anthropic,
            "api.openai.com" => Self::OpenAi,
            _ => Self::Opaque,
        }
    }

    /// The prefix, which always contains `ast` so that a handle found in a
    /// log somewhere is identifiable as one rather than mistaken for the
    /// real key it stands in for.
    fn prefix(self) -> &'static str {
        match self {
            Self::Opaque => "ast-",
            Self::OpenAi => "sk-ast-",
            Self::Anthropic => "sk-ant-ast-",
        }
    }
}

/// The opaque per-instance stand-in a guest is given instead of a secret.
///
/// It is not the secret and it is not derived from it: it is random, it is
/// meaningful only to the one proxy that minted it, and it is worth exactly
/// the reach of that proxy — one instance, one authority, one placement. It
/// is still a bearer credential, so `Debug` redacts it and comparison is
/// constant-time.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GuestHandle(String);

impl GuestHandle {
    /// Mint a fresh handle. Two v4 UUIDs' worth of randomness — 244 bits —
    /// base32'd, because a handle travels in a header and through a shell.
    pub fn mint(shape: HandleShape) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let mut out = String::from(shape.prefix());
        // Crockford-ish base32 without the ambiguous glyphs, so a handle can
        // be read off a terminal and typed back in.
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        let mut acc: u16 = 0;
        let mut bits = 0u32;
        for byte in bytes {
            acc = (acc << 8) | byte as u16;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
        }
        Self(out)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constant-time equality against a candidate off the wire.
    ///
    /// A handle is compared once per request against something an untrusted
    /// guest chose, which is the textbook shape for a timing oracle on a
    /// bearer token.
    pub fn matches(&self, candidate: &str) -> bool {
        let (ours, theirs) = (self.0.as_bytes(), candidate.as_bytes());
        let mut diff = (ours.len() ^ theirs.len()) as u8;
        for (i, ours) in ours.iter().enumerate() {
            diff |= ours ^ theirs.get(i).copied().unwrap_or(0);
        }
        diff == 0
    }

    /// The first few characters, for a message that has to identify *which*
    /// handle without reprinting it.
    pub fn hint(&self) -> String {
        format!("{}…", &self.0[..self.0.len().min(11)])
    }
}

impl std::fmt::Debug for GuestHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<guest handle>")
    }
}

/// One secret attached to one instance, as the instance records it.
///
/// Everything here is either public metadata or the opaque handle, and that
/// is the invariant the whole feature rests on: this struct is written into
/// `state.json`, printed by `ast status`, and carried across a cpu-part move,
/// so if material could reach it, material would reach all three.
///
/// `version` is a *note*, not a pin. The value it named may have been rotated
/// since; the source handle used at egress is re-selected from live metadata
/// every time (see [`Binding::refresh`]), and this field is what lets a
/// refresh be reported as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub id: String,
    pub secret_id: SecretId,
    /// The secret's orbit name, so `ast status` does not have to resolve one.
    pub secret: String,
    /// Host or `host:port` authority this binding applies to, lowercased.
    pub authority: String,
    /// Where the credential rides on a request to that authority.
    pub placement: Placement,
    /// What the guest is given instead of the value.
    pub guest_handle: GuestHandle,
    /// The environment variable the seed exports the handle as.
    pub env: String,
    /// The device whose store holds the value. Egress resolves there and
    /// nowhere else.
    pub source_device_id: String,
    /// That device's orbit name when the binding was made — a route hint,
    /// like [`SourceDevice::device`], and never the identity.
    pub source_device: String,
    /// The secret's version when the binding was made.
    pub version: u64,
    pub bound_at: u64,
}

/// A source handle selected for one request, and whether selecting it moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refreshed {
    pub handle: Handle,
    /// The version the binding was made at, when that is not the version
    /// this handle names. A rotation since the attach looks like this.
    pub rotated_from: Option<u64>,
}

impl Binding {
    /// The source handle to redeem for this binding, right now.
    ///
    /// Deliberately re-selected per request rather than persisted. A handle
    /// pins a version *and* the revision that version meant, so one written
    /// down at attach time is a promise about bytes that a later rotation
    /// makes false — and a stale promise in front of a secret fails at the
    /// far end, as an authentication error in somebody else's log, which is
    /// the least debuggable place for it to fail. Re-selecting means a
    /// rotation is picked up by the next request and a source that has
    /// genuinely gone (removed, conflicted, left behind by a rotation it
    /// never received) is refused here in words.
    pub fn refresh(&self, secret: &Secret) -> Result<Refreshed> {
        if secret.id != self.secret_id {
            bail!(
                "secret {:?} is not the secret {:?} is bound to",
                secret.name,
                self.secret
            );
        }
        let handle = secret.handle(&self.source_device_id).with_context(|| {
            format!(
                "the source for {:?} on {} cannot serve it",
                self.secret, self.source_device
            )
        })?;
        Ok(Refreshed {
            rotated_from: (handle.version != self.version).then_some(self.version),
            handle,
        })
    }
}

/// The `host` of a `host:port` authority, or the whole string when there is
/// no port. Not a parser: it exists so callers stop writing this twice.
fn host_of(authority: &str) -> &str {
    authority.split(':').next().unwrap_or(authority)
}

/// A header name, as HTTP defines one (RFC 9110 token).
///
/// Checked because a binding's header name is written into an outbound
/// request: a name carrying a colon, a newline or a space is a request
/// smuggling primitive, and it is refused where the user typed it rather
/// than where it would take effect.
pub fn check_header_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("a header name cannot be empty");
    }
    if name.len() > 64 {
        bail!("header name {name:?} is longer than 64 characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        bail!("header name {name:?} is not an HTTP token");
    }
    Ok(())
}

/// The authority a binding may name, normalised.
///
/// Three refusals, and each of them is a way this feature could be turned
/// into something other than what it is:
///
/// * A wildcard or a path would make one binding cover hosts the user never
///   read out loud, and the whole point of an allowlist is that they did.
/// * An IP literal cannot be intercepted honestly. A leaf certificate for an
///   address needs an IP SAN, clients that talk to addresses are the ones
///   that pin, and a guest that pins sees a handshake failure with no
///   explanation in it. Refusing is the honest answer; see the module note.
/// * `localhost` and friends are not a destination, they are this device —
///   see [`crate::rewrite::is_public`], which refuses the same thing at the
///   other end, after DNS, where it cannot be talked around.
pub fn check_authority(authority: &str) -> Result<String> {
    let authority = authority.trim();
    if authority.is_empty() {
        bail!("a bound authority cannot be empty");
    }
    if authority.len() > 255 {
        bail!("authority {authority:?} is longer than 255 characters");
    }
    if let Some(rest) = authority
        .strip_prefix("https://")
        .or_else(|| authority.strip_prefix("http://"))
    {
        bail!(
            "write the authority on its own, without a scheme: --to {}",
            rest.trim_end_matches('/')
        );
    }
    if authority.contains('/') || authority.contains('?') || authority.contains('*') {
        bail!(
            "a binding names one authority — a host, or `host:port` — not a url or a \
             pattern; a path is not something TLS can be told apart by"
        );
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .with_context(|| format!("{port:?} is not a port number"))?;
            if port == 0 {
                bail!("port 0 is not a destination");
            }
            (host, Some(port))
        }
        None => (authority, None),
    };
    if host.is_empty() {
        bail!("authority {authority:?} has no host in it");
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        bail!(
            "{host} is an address, not a name. A bound authority is intercepted with a \
             certificate this device mints, and a client that was given an address is a \
             client that pins — it would see a handshake failure with nothing in it to \
             explain the refusal, so the refusal is here instead"
        );
    }
    if !host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    }) {
        bail!("{host:?} is not a hostname");
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
        bail!(
            "{host} is this device, or something on its LAN — a bound authority is \
             somewhere the guest's traffic leaves for, and proxying a guest back onto \
             the host is the hole this refuses to open"
        );
    }
    Ok(match port {
        Some(port) => format!("{lower}:{port}"),
        None => lower,
    })
}

/// The environment variable name a seed exports a handle as.
pub fn check_env_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("an environment variable name cannot be empty");
    }
    if name.len() > 64 {
        bail!("environment variable {name:?} is longer than 64 characters");
    }
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        bail!("environment variable {name:?} starts with a digit");
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!("environment variable {name:?} may only contain letters, digits and '_'");
    }
    Ok(())
}

/// The variable a secret's handle lands in when the user did not pick one:
/// the name, shouted, with anything that is not a variable character turned
/// into an underscore.
pub fn default_env_name(secret: &str) -> String {
    let mut out: String = secret
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// A version-pinned reference to one source device.
///
/// This is the input to the mesh-routable source operation.  Pinning the
/// version prevents a request selected under one policy snapshot from silently
/// receiving a later rotation, and the source's revision pins *which* value
/// that version meant, so a snapshot taken during a partition cannot be
/// redeemed against a source that turned out to hold something else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handle {
    pub secret_id: SecretId,
    pub source: SourceDevice,
    pub version: u64,
}

impl Secret {
    /// The reason, if any, that this secret's sources are not interchangeable.
    ///
    /// Order matters: a divergent origin is reported first because it is the
    /// unrecoverable one.  Sources in different lineages are different
    /// secrets that collided on a name, and describing that as a version
    /// disagreement would invite someone to "fix" it with a rotation that
    /// quietly destroys one of the two values.
    pub fn conflict(&self) -> Option<SecretConflict> {
        let origins: BTreeSet<&ValueRevision> =
            self.sources.iter().map(|source| &source.origin).collect();
        if origins.len() > 1 {
            return Some(SecretConflict::Origin {
                origins: origins.into_iter().cloned().collect(),
            });
        }
        let mut by_version: BTreeMap<u64, BTreeSet<&ValueRevision>> = BTreeMap::new();
        for source in &self.sources {
            by_version
                .entry(source.version)
                .or_default()
                .insert(&source.revision);
        }
        by_version
            .into_iter()
            .find(|(_, revisions)| revisions.len() > 1)
            .map(|(version, revisions)| SecretConflict::Revision {
                version,
                revisions: revisions.into_iter().cloned().collect(),
            })
    }

    /// Construct a handle for one of this secret's advertised sources.
    ///
    /// A conflicted secret has no interchangeable source, so this refuses
    /// rather than picking one.  Picking would be worse than failing: the
    /// caller has no way to notice that the value it received is the other
    /// one, and the request it authenticates just fails somewhere far away.
    pub fn handle(&self, device_id: &str) -> Result<Handle> {
        if let Some(conflict) = self.conflict() {
            bail!(
                "secret {:?} is in conflict — {conflict}; resolve it before use",
                self.name
            );
        }
        self.sources
            .iter()
            .find(|source| source.device_id == device_id && source.version == self.version)
            .cloned()
            .map(|source| Handle {
                secret_id: self.id.clone(),
                version: self.version,
                source,
            })
            .ok_or_else(|| {
                anyhow!(
                    "no source on device {device_id:?} holds secret {:?} at version {}",
                    self.name,
                    self.version
                )
            })
    }
}

pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("a secret name cannot be empty");
    }
    if name.len() > 127 {
        bail!("secret name {name:?} is longer than 127 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("secret name {name:?} may only contain letters, digits, '-', '_' and '.'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(device_id: &str, version: u64, lineage: &ValueRevision) -> SourceDevice {
        SourceDevice {
            device_id: device_id.into(),
            device: device_id.into(),
            version,
            updated_at: version,
            origin: lineage.clone(),
            revision: lineage.clone(),
        }
    }

    fn secret(version: u64, sources: Vec<SourceDevice>) -> Secret {
        Secret {
            id: SecretId::from_name("api").unwrap(),
            name: "api".into(),
            version,
            created_at: 1,
            updated_at: version,
            sources,
        }
    }

    #[test]
    fn metadata_has_no_place_to_serialize_plaintext() {
        let lineage = ValueRevision::mint();
        let secret = secret(1, vec![source("public-key", 1, &lineage)]);
        let json = serde_json::to_string(&secret).unwrap();
        assert!(!json.contains("plaintext"));
        assert_eq!(serde_json::from_str::<Secret>(&json).unwrap(), secret);
    }

    #[test]
    fn a_revision_is_not_a_digest_so_a_catalog_is_not_an_offline_verifier() {
        // Two devices holding the same low-entropy value must not be able to
        // recognise each other from metadata alone, because anyone who reads
        // the catalog could then confirm a guess at that value offline.  The
        // price is that identical plaintext typed twice looks like two values,
        // which the merge reports rather than resolves.
        let first = ValueRevision::mint();
        let second = ValueRevision::mint();
        assert_ne!(first, second);
    }

    #[test]
    fn a_revision_that_did_not_come_from_a_mint_is_refused_on_the_wire() {
        // An empty or truncated revision from a peer would compare equal to
        // material it has no provenance with, which is the one way a source
        // could talk its way into being interchangeable.
        for forged in ["", "1", "not-a-revision"] {
            let wire = format!(
                r#"{{"device_id":"d","device":"d","version":1,"updated_at":1,"origin":"{forged}","revision":"{forged}"}}"#
            );
            assert!(serde_json::from_str::<SourceDevice>(&wire).is_err());
        }
        let honest = ValueRevision::mint();
        let round_tripped: ValueRevision =
            serde_json::from_str(&serde_json::to_string(&honest).unwrap()).unwrap();
        assert_eq!(round_tripped, honest);
    }

    #[test]
    fn a_handle_is_pinned_to_a_matching_source_version() {
        let lineage = ValueRevision::mint();
        let mut secret = secret(2, vec![source("source-key", 1, &lineage)]);
        assert!(secret.handle("source-key").is_err());
        secret.sources[0].version = 2;
        assert_eq!(secret.handle("source-key").unwrap().version, 2);
    }

    #[test]
    fn a_partitioned_create_of_one_name_is_a_conflict_not_a_wider_source_set() {
        // Both devices named the value `api` and both called it version 1.
        // Only the origin distinguishes two unrelated values from one value
        // held twice, and it is what stops a consumer from being handed
        // whichever source it happened to select.
        let here = ValueRevision::mint();
        let there = ValueRevision::mint();
        let secret = secret(
            1,
            vec![source("laptop", 1, &here), source("desktop", 1, &there)],
        );
        match secret.conflict() {
            Some(SecretConflict::Origin { origins }) => assert_eq!(origins.len(), 2),
            other => panic!("expected an origin conflict, got {other:?}"),
        }
        assert!(secret
            .handle("laptop")
            .unwrap_err()
            .to_string()
            .contains("conflict"));
        assert!(secret.handle("desktop").is_err());
    }

    #[test]
    fn sources_that_diverged_at_one_version_are_not_interchangeable() {
        // One lineage, rotated on both sides of a partition: the origins
        // agree, so only the per-version revision separates the two values.
        let lineage = ValueRevision::mint();
        let mut here = source("laptop", 2, &lineage);
        here.revision = ValueRevision::mint();
        let mut there = source("desktop", 2, &lineage);
        there.revision = ValueRevision::mint();
        let secret = secret(2, vec![here, there]);
        match secret.conflict() {
            Some(SecretConflict::Revision { version, revisions }) => {
                assert_eq!(version, 2);
                assert_eq!(revisions.len(), 2);
            }
            other => panic!("expected a revision conflict, got {other:?}"),
        }
        assert!(secret.handle("laptop").is_err());
    }

    #[test]
    fn a_copied_revision_leaves_two_sources_interchangeable() {
        // The valid shape: one lineage, one revision, replicated to a second
        // device by the path that also carried the bytes.  Either source may
        // serve the value, so both produce a handle.
        let lineage = ValueRevision::mint();
        let secret = secret(
            1,
            vec![
                source("laptop", 1, &lineage),
                source("desktop", 1, &lineage),
            ],
        );
        assert!(secret.conflict().is_none());
        assert_eq!(secret.handle("laptop").unwrap().source.revision, lineage);
        assert_eq!(secret.handle("desktop").unwrap().source.revision, lineage);
    }

    #[test]
    fn an_authority_is_one_name_a_user_read_out_loud_and_never_a_pattern() {
        assert_eq!(
            check_authority("API.Anthropic.Com").unwrap(),
            "api.anthropic.com"
        );
        assert_eq!(
            check_authority(" internal.example.com:8443 ").unwrap(),
            "internal.example.com:8443"
        );
        for (bad, why) in [
            ("", "empty"),
            ("*.anthropic.com", "a wildcard covers hosts nobody read"),
            ("api.anthropic.com/v1", "a path is not a TLS identity"),
            ("https://api.anthropic.com", "a scheme"),
            ("api.anthropic.com:0", "port 0"),
            ("api.anthropic.com:notaport", "a port that is not a number"),
            ("1.2.3.4", "an address cannot be intercepted honestly"),
            ("[::1]:443", "an address, in brackets"),
            ("localhost", "this device"),
            ("astd.local", "something on the LAN"),
            ("-lead.example.com", "not a hostname"),
        ] {
            assert!(
                check_authority(bad).is_err(),
                "{bad:?} was accepted ({why})"
            );
        }
    }

    #[test]
    fn a_placement_is_two_shapes_and_refuses_to_become_a_template_language() {
        assert_eq!(
            Placement::parse("bearer").unwrap(),
            Placement::Authorization {
                scheme: "Bearer".into()
            }
        );
        assert_eq!(
            Placement::parse("X-Api-Key").unwrap(),
            Placement::Header {
                name: "x-api-key".into()
            }
        );
        assert_eq!(
            Placement::parse("header:X-Token").unwrap(),
            Placement::Header {
                name: "x-token".into()
            }
        );
        // The two ways a placement could be turned into an injection.
        for bad in [
            "x-api-key: extra",
            "x api key",
            "auth\r\nX-Injected",
            "authorization",
            "",
        ] {
            assert!(Placement::parse(bad).is_err(), "{bad:?} was accepted");
        }
        // What each shape reads and writes.
        let bearer = Placement::parse("bearer").unwrap();
        assert_eq!(bearer.header(), "authorization");
        assert_eq!(bearer.render("v"), "Bearer v");
        assert_eq!(bearer.extract("Bearer v"), Some("v"));
        assert_eq!(bearer.extract("bearer v"), Some("v"));
        assert_eq!(bearer.extract("Basic v"), None);
        assert_eq!(bearer.extract("v"), None);
        let key = Placement::parse("x-api-key").unwrap();
        assert_eq!(key.render("v"), "v");
        assert_eq!(key.extract("v"), Some("v"));
        // The default for an authority is the family's own convention.
        assert_eq!(
            Placement::for_authority("api.anthropic.com").header(),
            "x-api-key"
        );
        assert_eq!(
            Placement::for_authority("api.openai.com").header(),
            "authorization"
        );
    }

    #[test]
    fn a_guest_handle_is_random_shaped_and_never_the_value() {
        // Shaped so an SDK's own prefix check passes inside the guest, where
        // there is no proxy to explain a rejection.
        assert!(
            GuestHandle::mint(HandleShape::for_authority("api.openai.com"))
                .as_str()
                .starts_with("sk-ast-")
        );
        assert!(
            GuestHandle::mint(HandleShape::for_authority("api.anthropic.com"))
                .as_str()
                .starts_with("sk-ant-ast-")
        );
        assert!(
            GuestHandle::mint(HandleShape::for_authority("example.test"))
                .as_str()
                .starts_with("ast-")
        );

        let handle = GuestHandle::mint(HandleShape::Opaque);
        // 32 random bytes is 52 base32 characters.
        assert_eq!(handle.as_str().len(), "ast-".len() + 52);
        assert_ne!(handle, GuestHandle::mint(HandleShape::Opaque));
        assert!(handle.matches(handle.as_str()));
        assert!(!handle.matches(&handle.as_str()[..10]));
        assert!(!handle.matches(&format!("{}X", handle.as_str())));
        assert!(!handle.matches(""));
        assert_eq!(format!("{handle:?}"), "<guest handle>");
        // It travels in a header and through a shell, so it must be plain.
        assert!(handle
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    }

    #[test]
    fn an_environment_variable_name_is_checked_where_it_is_typed() {
        assert_eq!(default_env_name("anthropic-api.key"), "ANTHROPIC_API_KEY");
        assert_eq!(default_env_name("9lives"), "_9LIVES");
        assert!(check_env_name("ANTHROPIC_API_KEY").is_ok());
        for bad in ["", "1ST", "HAS-DASH", "HAS SPACE", "A;rm -rf /"] {
            assert!(check_env_name(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_binding_carries_no_material_and_survives_a_round_trip() {
        // This struct is written into `state.json` and printed by
        // `ast status`, so what it can hold is the whole invariant.
        let binding = Binding {
            id: "b1".into(),
            secret_id: SecretId::from_name("api").unwrap(),
            secret: "api".into(),
            authority: "api.anthropic.com".into(),
            placement: Placement::parse("x-api-key").unwrap(),
            guest_handle: GuestHandle::mint(HandleShape::Anthropic),
            env: "ANTHROPIC_API_KEY".into(),
            source_device_id: "source-key".into(),
            source_device: "laptop".into(),
            version: 3,
            bound_at: 7,
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(!json.contains("value"));
        assert!(!json.contains("plaintext"));
        assert_eq!(serde_json::from_str::<Binding>(&json).unwrap(), binding);
        // The handle is in there — that is what it is for — and the Debug
        // that every daemon error path uses is not.
        assert!(json.contains(binding.guest_handle.as_str()));
        assert!(!format!("{binding:?}").contains(binding.guest_handle.as_str()));
    }

    #[test]
    fn a_binding_refuses_to_refresh_against_a_secret_that_is_not_its_own() {
        let lineage = ValueRevision::mint();
        let mut binding = Binding {
            id: "b1".into(),
            secret_id: SecretId::from_name("api").unwrap(),
            secret: "api".into(),
            authority: "api.anthropic.com".into(),
            placement: Placement::parse("x-api-key").unwrap(),
            guest_handle: GuestHandle::mint(HandleShape::Anthropic),
            env: "API".into(),
            source_device_id: "source-key".into(),
            source_device: "laptop".into(),
            version: 1,
            bound_at: 1,
        };
        let held = secret(1, vec![source("source-key", 1, &lineage)]);
        assert!(binding.refresh(&held).is_ok());

        // A conflicted secret has no interchangeable source, so a binding on
        // it stops working rather than picking a lineage.
        let mut conflicted = held.clone();
        conflicted
            .sources
            .push(source("desktop-key", 1, &ValueRevision::mint()));
        assert!(binding.refresh(&conflicted).is_err());

        // A binding whose source has left the secret entirely.
        binding.source_device_id = "gone-key".into();
        assert!(binding.refresh(&held).is_err());

        // And a secret that simply is not this one.
        binding.source_device_id = "source-key".into();
        let mut other = held.clone();
        other.id = SecretId::from_name("other").unwrap();
        other.name = "other".into();
        assert!(binding.refresh(&other).is_err());
    }

    #[test]
    fn a_source_still_catching_up_is_stale_rather_than_in_conflict() {
        // A rotation reaches sources one at a time.  Lagging behind is not
        // divergence, or every rotation would raise a conflict; the lagging
        // source simply cannot serve the current version.
        let lineage = ValueRevision::mint();
        let mut rotated = source("laptop", 2, &lineage);
        rotated.revision = ValueRevision::mint();
        let secret = secret(2, vec![rotated, source("desktop", 1, &lineage)]);
        assert!(secret.conflict().is_none());
        assert!(secret.handle("laptop").is_ok());
        assert!(secret.handle("desktop").is_err());
    }
}
