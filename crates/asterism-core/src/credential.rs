//! Credential parts: the secret plane, extended until an agent's tools are
//! already logged in.
//!
//! A [`crate::secret::Secret`] is a value with a name. That is enough for an
//! API key and not enough for anything else a person actually holds: a GitHub
//! token is a value *and* a set of hosts *and* a header scheme *and* the
//! environment variable `gh` reads; a Google grant is not a value at all but a
//! refresh token that buys one; an AWS credential is not something you send,
//! it is something you sign with.
//!
//! None of that is a new architecture. It is the same handle, the same store,
//! the same door, the same revocation — with the parts of "how this credential
//! is used" that were previously typed on the command line moved into a
//! declaration this repository carries. `ast attach bot --secret k --to
//! api.example.com --as bearer --env K` is four decisions a person makes.
//! `ast attach bot --credential gh` is the same four decisions, made once,
//! here, by someone who read GitHub's documentation.
//!
//! # The three rules
//!
//! What the door does with the material is a closed set, and it is closed for
//! the same reason [`crate::secret::Placement`] is: a template language in
//! front of a credential is a place for an injection to live.
//!
//! * **substitute** — the material is the credential. Take the handle out,
//!   put the value in. Every token-shaped provider.
//! * **refresh** — the material is a *grant*. The source device exchanges it
//!   for a short-lived access token immediately before the connection out,
//!   caches that token in memory until it expires, and substitutes it. The
//!   durable store never holds an access token, which is what keeps the
//!   revision commitment in [`crate::secret`] honest: the bytes on disk do
//!   not change when a token is refreshed, because no token is on disk.
//! * **sign** — the material is a key pair and the credential is a signature
//!   over the request. Computed on the source device, after the request is
//!   final and before it is sent. See [`crate::sigv4`].
//!
//! # What is *not* here
//!
//! Material, and any way to reach it. This module parses declarations and
//! shapes headers. The grant and key types below are the *schemas* the source
//! device reads its own store into; they are constructed on that device,
//! immediately before use, and they cross no wire.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::secret::{check_env_name, check_header_name, GuestHandle, Placement};

/// What kind of thing a part is, as `ast credential ls` prints it.
///
/// `Secret` is the pre-existing kind and is the serde default, so every
/// catalog written before this module existed reads back as what it was.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartKind {
    /// A raw value the user typed or piped in: `ast secret create`.
    #[default]
    Secret,
    /// A provider token this device signed in for: `ast login gh`.
    Login,
    /// An authorization grant with a refresh token: `ast oauth add google`.
    OAuth,
}

impl PartKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Login => "login",
            Self::OAuth => "oauth",
        }
    }
}

impl std::fmt::Display for PartKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for PartKind {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "secret" => Ok(Self::Secret),
            "login" => Ok(Self::Login),
            "oauth" => Ok(Self::OAuth),
            other => bail!("{other:?} is not a part kind — secret, login or oauth"),
        }
    }
}

// ---- what the door does ----------------------------------------------------

/// What the source device must do with the material it holds, carried on the
/// binding and on the egress frame.
///
/// It is on the *frame* rather than looked up from the provider name at the
/// far end for the same reason [`crate::secret::Placement`] is: the source
/// performs the operation the consumer authenticated, not one of its own
/// choosing. A source running an older build that does not know a provider
/// still knows what it was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialRule {
    /// The stored bytes are the credential.
    #[default]
    Substitute,
    /// The stored bytes are an [`OAuthGrant`]; exchange it for an access
    /// token at `token_url` and substitute that.
    Refresh {
        token_url: String,
        /// Mint a new access token this many seconds before the one in hand
        /// expires. A token that expires in flight fails in somebody else's
        /// log, which is the least debuggable place for it to fail.
        #[serde(default = "default_skew")]
        skew_secs: u64,
    },
    /// The stored bytes are a [`SigningKeys`]; sign the request with them.
    Sign {
        algorithm: SigningAlgorithm,
        service: String,
        region: String,
    },
}

fn default_skew() -> u64 {
    120
}

/// The signing schemes the door implements. A closed set, and each member is
/// a signer somebody wrote and tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningAlgorithm {
    /// AWS Signature Version 4. See [`crate::sigv4`].
    AwsSigv4,
}

impl CredentialRule {
    /// One word for `ast credential ls`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Substitute => "substitute",
            Self::Refresh { .. } => "refresh",
            Self::Sign { .. } => "sign",
        }
    }
}

// ---- what the source device reads its own store into -----------------------

/// An authorization grant, as it rests in this device's credential store.
///
/// Serialised as JSON with [`OAUTH_MARKER`] set, so the source device can tell
/// a grant from a raw token without being told which it should expect — a
/// distinction that matters because getting it wrong would put a refresh
/// token in an `Authorization` header.
///
/// There is no access token field. That is deliberate and it is the whole
/// reason a refresh happens per request rather than being written back: a
/// [`crate::secret::ValueRevision`] is a commitment to *which bytes* a source
/// holds, and a store that rewrote itself every hour would break that
/// commitment for every other device in the orbit. The access token lives in
/// memory on the source device and nowhere else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthGrant {
    /// Always [`OAUTH_MARKER`]. Present so this schema is self-identifying.
    #[serde(rename = "asterism_oauth")]
    pub marker: u32,
    pub provider: String,
    pub refresh_token: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub token_url: String,
    /// Who the grant belongs to, for `ast credential ls`. Never used to
    /// authenticate anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

pub const OAUTH_MARKER: u32 = 1;

impl OAuthGrant {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let grant: Self = serde_json::from_slice(bytes)
            .context("this part is not an authorization grant this build can read")?;
        if grant.marker != OAUTH_MARKER {
            bail!(
                "this grant says it is version {}, and this build reads version {OAUTH_MARKER}",
                grant.marker
            );
        }
        if grant.refresh_token.is_empty() {
            bail!("this grant carries no refresh token");
        }
        Ok(grant)
    }
}

impl std::fmt::Display for OAuthGrant {
    /// Never the token. This type is `Debug`-derived for the daemon's error
    /// paths, so the one place it could print is here, and here it does not.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} grant>", self.provider)
    }
}

/// A key pair a `sign` rule computes with.
///
/// Two lines of text or a JSON object, because the two ways a person has
/// these to hand are an `aws configure` block and a copy-paste out of a
/// console, and refusing one of them would be a riddle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKeys {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

impl SigningKeys {
    /// Read either shape.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("signing keys are not text")?;
        let trimmed = text.trim();
        if trimmed.starts_with('{') {
            return serde_json::from_str(trimmed).context("that is not a signing key object");
        }
        let mut lines = trimmed.lines().map(str::trim).filter(|l| !l.is_empty());
        let (Some(id), Some(key)) = (lines.next(), lines.next()) else {
            bail!(
                "signing keys are two lines — the access key id, then the secret access key — \
                 or a JSON object with those names"
            );
        };
        Ok(Self {
            access_key_id: strip_assignment(id).to_owned(),
            secret_access_key: strip_assignment(key).to_owned(),
            session_token: lines.next().map(|t| strip_assignment(t).to_owned()),
        })
    }
}

/// `AWS_ACCESS_KEY_ID=AKIA…` → `AKIA…`, so a pasted `aws configure` block
/// works as well as two bare lines.
fn strip_assignment(line: &str) -> &str {
    match line.split_once('=') {
        Some((_, value)) => value.trim().trim_matches('"'),
        None => line,
    }
}

// ---- the declaration -------------------------------------------------------

/// One provider, as `providers/<name>.toml` declares it.
///
/// Every field here is public configuration. If something in this struct
/// needed to be secret, it would be in the wrong file — a provider
/// declaration is compiled into the binary and printed by `ast credential
/// providers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub name: String,
    pub aliases: Vec<String>,
    pub kind: PartKind,
    pub summary: String,
    /// Declared but not proved against the real service. `ast login` and
    /// `ast oauth add` say so out loud rather than implying a test that was
    /// never run.
    pub experimental: bool,
    /// The prefix the guest's handle wears, so a tool that sniffs the shape
    /// of its own token is not surprised inside the guest.
    pub handle_prefix: String,
    pub authorities: Vec<String>,
    pub env: Vec<String>,
    /// Where the credential rides, upstream.
    pub placement: Placement,
    /// The placements a *guest* may present the handle at. A superset of
    /// `placement`: `gh` sends `Authorization: token …` to some endpoints and
    /// `Bearer …` to others, and a door that recognised only one of them
    /// would refuse the tool it exists to serve.
    pub accept: Vec<Placement>,
    pub rule: CredentialRule,
    /// Files the guest gets, for tools that read a config file rather than an
    /// environment variable. The content may name an environment variable but
    /// never carries a value: `${NPM_TOKEN}`, not the handle and certainly not
    /// the token.
    pub files: Vec<ProviderFile>,
    pub login: Option<LoginSpec>,
    pub oauth: Option<OAuthSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFile {
    pub path: String,
    pub mode: String,
    pub content: String,
}

/// How `ast login <provider>` gets a token on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSpec {
    /// A host command whose stdout is the token, tried first. Its absence,
    /// its failure, and its printing nothing are all "not signed in here",
    /// which is not an error — it is the reason to open a device flow.
    pub import: Vec<String>,
    /// Read the token from stdin instead. For providers with no device flow.
    pub paste: bool,
    pub paste_hint: String,
    pub device_authorization_url: String,
    pub token_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    /// An endpoint that names the account, so signing in can say who.
    pub identity_url: String,
    pub identity_field: String,
}

/// How `ast oauth add <provider>` obtains a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthSpec {
    pub device_authorization_url: String,
    pub authorize_url: String,
    pub token_url: String,
    /// The scopes the provider's device flow covers. A grant asking for
    /// anything outside it needs the loopback redirect flow.
    pub device_flow_scopes: Vec<String>,
    pub default_scopes: Vec<String>,
    /// Expanded in front of a scope that is not already a URL, so a person
    /// can type `gmail.readonly`.
    pub scope_prefix: String,
    pub client_id: String,
    pub client_id_required: bool,
    pub client_secret_required: bool,
}

impl OAuthSpec {
    /// A scope as the provider spells it.
    pub fn expand(&self, scope: &str) -> String {
        let scope = scope.trim();
        if scope.contains("://") || self.scope_prefix.is_empty() || scope.contains(':') {
            return scope.to_owned();
        }
        format!("{}{scope}", self.scope_prefix)
    }

    /// Whether every one of these can be granted by the device flow.
    pub fn device_flow_covers(&self, scopes: &[String]) -> bool {
        !self.device_flow_scopes.is_empty()
            && scopes.iter().all(|s| self.device_flow_scopes.contains(s))
    }
}

impl Provider {
    /// Whether this name or one of its aliases is what the user typed.
    pub fn answers_to(&self, name: &str) -> bool {
        let name = name.trim().to_ascii_lowercase();
        self.name == name || self.aliases.contains(&name)
    }

    /// A fresh opaque handle in this provider's shape.
    pub fn mint_handle(&self) -> GuestHandle {
        GuestHandle::mint_prefixed(&self.handle_prefix)
    }

    /// The default part name: the provider's short name, which is what the
    /// user typed and what they will type again to attach it.
    pub fn default_part_name(&self) -> &str {
        self.aliases.first().unwrap_or(&self.name)
    }
}

// ---- the catalog -----------------------------------------------------------

/// The declarations this build carries, parsed once.
///
/// `include_str!` rather than a directory read: a provider declaration is
/// part of the program's behaviour, and a program whose door rules could be
/// edited by dropping a file next to it is a program with a configuration
/// file in front of every credential its user owns.
pub fn catalog() -> &'static [Provider] {
    static CATALOG: OnceLock<Vec<Provider>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        DECLARATIONS
            .iter()
            .map(|(file, text)| {
                parse(text).unwrap_or_else(|e| panic!("provider declaration {file}: {e:#}"))
            })
            .collect()
    })
}

/// Every declaration, with the file it came from so a parse failure can name
/// it. The list is written out rather than globbed because `include_str!`
/// cannot glob and because a provider that is in the tree but not in this
/// list would silently not exist.
const DECLARATIONS: &[(&str, &str)] = &[
    ("aws.toml", include_str!("../providers/aws.toml")),
    ("docker.toml", include_str!("../providers/docker.toml")),
    ("github.toml", include_str!("../providers/github.toml")),
    ("google.toml", include_str!("../providers/google.toml")),
    ("linear.toml", include_str!("../providers/linear.toml")),
    ("notion.toml", include_str!("../providers/notion.toml")),
    ("npm.toml", include_str!("../providers/npm.toml")),
    ("slack.toml", include_str!("../providers/slack.toml")),
];

/// Look one up by name or alias.
pub fn find(name: &str) -> Option<&'static Provider> {
    catalog().iter().find(|p| p.answers_to(name))
}

/// The same, with a refusal that lists what there is.
pub fn require(name: &str) -> Result<&'static Provider> {
    find(name).ok_or_else(|| {
        anyhow!(
            "no provider called {name:?} — this build knows {}",
            catalog()
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

// ---- parsing ---------------------------------------------------------------

#[derive(Deserialize)]
struct RawProvider {
    name: String,
    #[serde(default)]
    aliases: Vec<String>,
    kind: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    experimental: bool,
    handle_prefix: String,
    #[serde(default)]
    authorities: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    rule: RawRule,
    #[serde(default)]
    files: Vec<RawFile>,
    login: Option<RawLogin>,
    oauth: Option<RawOAuth>,
}

#[derive(Deserialize)]
struct RawRule {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    placement: String,
    #[serde(default)]
    accept: Vec<String>,
    #[serde(default)]
    token_url: String,
    #[serde(default)]
    refresh_skew_secs: Option<u64>,
    #[serde(default)]
    algorithm: String,
    #[serde(default)]
    service: String,
    #[serde(default)]
    region: String,
}

#[derive(Deserialize)]
struct RawFile {
    path: String,
    #[serde(default = "default_mode")]
    mode: String,
    content: String,
}

fn default_mode() -> String {
    "0644".into()
}

#[derive(Deserialize)]
struct RawLogin {
    #[serde(default)]
    import: Vec<String>,
    #[serde(default)]
    paste: bool,
    #[serde(default)]
    paste_hint: String,
    #[serde(default)]
    device_authorization_url: String,
    #[serde(default)]
    token_url: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    identity_url: String,
    #[serde(default)]
    identity_field: String,
}

#[derive(Deserialize)]
struct RawOAuth {
    #[serde(default)]
    device_authorization_url: String,
    #[serde(default)]
    authorize_url: String,
    #[serde(default)]
    token_url: String,
    #[serde(default)]
    device_flow_scopes: Vec<String>,
    #[serde(default)]
    default_scopes: Vec<String>,
    #[serde(default)]
    scope_prefix: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_id_required: bool,
    #[serde(default)]
    client_secret_required: bool,
}

/// Parse one declaration, checking everything that could make a binding made
/// from it a lie.
///
/// Every refusal below is something that would otherwise fail inside a guest,
/// where there is nobody to read the message.
pub fn parse(text: &str) -> Result<Provider> {
    let raw: RawProvider = toml::from_str(text).context("this is not a provider declaration")?;
    let kind: PartKind = raw.kind.parse()?;
    crate::secret::check_name(&raw.name)?;
    for alias in &raw.aliases {
        crate::secret::check_name(alias)?;
    }
    check_handle_prefix(&raw.handle_prefix)?;
    let authorities = raw
        .authorities
        .iter()
        .map(|a| crate::secret::check_authority(a))
        .collect::<Result<Vec<_>>>()
        .with_context(|| {
            format!(
                "provider {:?} declares an authority it cannot bind",
                raw.name
            )
        })?;
    if raw.env.is_empty() {
        bail!(
            "provider {:?} names no environment variable, so nothing in a guest would find it",
            raw.name
        );
    }
    for env in &raw.env {
        check_env_name(env)?;
    }
    let placement = declared_placement(&raw.rule.placement)?;
    let mut accept = vec![placement.clone()];
    for spec in &raw.rule.accept {
        let extra = accept_placement(spec, &placement)?;
        if !accept.contains(&extra) {
            accept.push(extra);
        }
    }
    let rule = match raw.rule.kind.as_str() {
        "substitute" => CredentialRule::Substitute,
        "refresh" => {
            if raw.rule.token_url.is_empty() {
                bail!("provider {:?} refreshes but names no token_url", raw.name);
            }
            check_https(&raw.rule.token_url)?;
            CredentialRule::Refresh {
                token_url: raw.rule.token_url.clone(),
                skew_secs: raw.rule.refresh_skew_secs.unwrap_or_else(default_skew),
            }
        }
        "sign" => {
            let algorithm = match raw.rule.algorithm.as_str() {
                "aws-sigv4" => SigningAlgorithm::AwsSigv4,
                other => bail!("provider {:?} signs with unknown {other:?}", raw.name),
            };
            if raw.rule.service.is_empty() || raw.rule.region.is_empty() {
                bail!(
                    "provider {:?} signs but names no default service and region",
                    raw.name
                );
            }
            CredentialRule::Sign {
                algorithm,
                service: raw.rule.service.clone(),
                region: raw.rule.region.clone(),
            }
        }
        other => bail!("provider {:?} has unknown rule {other:?}", raw.name),
    };
    if matches!(rule, CredentialRule::Refresh { .. }) && kind != PartKind::OAuth {
        bail!(
            "provider {:?} refreshes, which only an oauth part can do",
            raw.name
        );
    }
    let files = raw
        .files
        .into_iter()
        .map(|file| {
            if !file.path.starts_with('/') {
                bail!(
                    "provider {:?} writes {:?}, which is not an absolute guest path",
                    raw.name,
                    file.path
                );
            }
            // A file's content may *name* a variable and may never carry a
            // value. Checked here because this string is written into a
            // guest's disk, which is the one place a credential part
            // promises never to be.
            Ok(ProviderFile {
                path: file.path,
                mode: file.mode,
                content: file.content,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let login = raw.login.map(|l| LoginSpec {
        import: l.import,
        paste: l.paste,
        paste_hint: l.paste_hint,
        device_authorization_url: l.device_authorization_url,
        token_url: l.token_url,
        client_id: l.client_id,
        scopes: l.scopes,
        identity_url: l.identity_url,
        identity_field: l.identity_field,
    });
    let oauth = raw.oauth.map(|o| OAuthSpec {
        device_authorization_url: o.device_authorization_url,
        authorize_url: o.authorize_url,
        token_url: o.token_url,
        device_flow_scopes: o.device_flow_scopes,
        default_scopes: o.default_scopes,
        scope_prefix: o.scope_prefix,
        client_id: o.client_id,
        client_id_required: o.client_id_required,
        client_secret_required: o.client_secret_required,
    });
    if kind == PartKind::OAuth && oauth.is_none() {
        bail!(
            "provider {:?} is an oauth part with no [oauth] section",
            raw.name
        );
    }
    if kind == PartKind::Login && login.is_none() {
        bail!(
            "provider {:?} is a login part with no [login] section",
            raw.name
        );
    }
    Ok(Provider {
        name: raw.name,
        aliases: raw.aliases,
        kind,
        summary: raw.summary,
        experimental: raw.experimental,
        handle_prefix: raw.handle_prefix,
        authorities,
        env: raw.env,
        placement,
        accept,
        rule,
        files,
        login,
        oauth,
    })
}

/// The placement a declaration may name.
///
/// Wider than [`Placement::parse`] by exactly one case: a declaration may put
/// the credential in `Authorization` with no scheme at all, which is how
/// Linear and a handful of others read their keys. `Placement::parse` refuses
/// that because a *person* typing `--as authorization` has almost certainly
/// meant `--as bearer`, and the ambiguity is worth a question. A declaration
/// is not a person and has already been read by someone with the provider's
/// documentation open.
pub fn declared_placement(spec: &str) -> Result<Placement> {
    if let Some(name) = spec.strip_prefix("header:") {
        let name = name.trim();
        check_header_name(name)?;
        return Ok(Placement::Header {
            name: name.to_ascii_lowercase(),
        });
    }
    Placement::parse(spec)
}

/// A placement a guest may present the handle at, relative to the one the
/// door writes.
fn accept_placement(spec: &str, canonical: &Placement) -> Result<Placement> {
    if spec == "raw" {
        return Ok(Placement::Header {
            name: canonical.header().to_owned(),
        });
    }
    match canonical {
        // A scheme name alone means "the same header, this scheme".
        Placement::Authorization { .. } => Ok(Placement::Authorization {
            scheme: scheme_word(spec)?.to_owned(),
        }),
        Placement::Header { .. } => declared_placement(spec),
    }
}

fn scheme_word(spec: &str) -> Result<&str> {
    let spec = spec.trim();
    if spec.is_empty() || !spec.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        bail!("{spec:?} is not an authorization scheme");
    }
    Ok(spec)
}

/// A handle prefix, as [`GuestHandle`] will wear it.
///
/// It must contain `ast`, for the same reason every built-in shape does: a
/// handle found in a log somewhere has to be identifiable as one, rather than
/// mistaken for the real key it stands in for and treated as a leak.
pub fn check_handle_prefix(prefix: &str) -> Result<()> {
    if !prefix.contains("ast") {
        bail!(
            "handle prefix {prefix:?} does not contain 'ast', so a handle wearing it could not \
             be told from the credential it stands in for"
        );
    }
    if prefix.len() > 24 {
        bail!("handle prefix {prefix:?} is longer than 24 characters");
    }
    if !prefix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("handle prefix {prefix:?} must be letters, digits, '-' and '_'");
    }
    Ok(())
}

fn check_https(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        bail!("{url:?} is not an https url, and a token endpoint has to be one");
    }
    Ok(())
}

/// The scopes a grant should ask for, from what the user typed.
pub fn resolve_scopes(spec: &OAuthSpec, asked: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let source = match asked.is_empty() {
        true => &spec.default_scopes,
        false => asked,
    };
    for scope in source {
        for part in scope.split(',') {
            let expanded = spec.expand(part);
            if !expanded.is_empty() && !out.contains(&expanded) {
                out.push(expanded);
            }
        }
    }
    out
}

/// The environment a credential part puts in a guest: every name the provider
/// declares, all carrying the one handle.
pub fn handle_environment(provider: &Provider, handle: &GuestHandle) -> Vec<(String, String)> {
    provider
        .env
        .iter()
        .map(|name| (name.clone(), handle.as_str().to_owned()))
        .collect()
}

/// A form body, `application/x-www-form-urlencoded`.
///
/// Written here rather than pulled in, because the only thing this needs from
/// a url crate is percent-encoding of a handful of token-endpoint fields, and
/// the encoding is eleven lines.
pub fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", percent(key), percent(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// One PKCE pair: the verifier this device keeps, and the challenge it sends.
///
/// RFC 7636, and it is not optional here. A loopback redirect is a redirect
/// to a port anything else on the machine could also have bound, so the
/// authorization code that lands on it is a code somebody else may have
/// caught. PKCE is what makes a caught code worthless: the token endpoint
/// will only exchange it for whoever can produce the verifier, and the
/// verifier never left this process.
#[derive(Debug, Clone)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// Mint one. Two v4 UUIDs of entropy, base64url'd, which is inside RFC 7636's
/// 43–128 character window.
pub fn pkce() -> Pkce {
    use sha2::{Digest, Sha256};
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    let verifier = data_encoding::BASE64URL_NOPAD.encode(&bytes);
    let challenge = data_encoding::BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
    }
}

/// An opaque one-time value, for an OAuth `state` or a device nonce.
pub fn nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// A query string, which is a form body in a different place.
pub fn query_encode(pairs: &[(&str, &str)]) -> String {
    form_encode(pairs)
}

/// What a token endpoint answers with, in the shape every provider here uses.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenGrant {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    /// RFC 6749 §5.2, and RFC 8628's `authorization_pending` / `slow_down`.
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

impl TokenGrant {
    /// The access token, or the provider's own reason there is none.
    ///
    /// A token endpoint answers 200 with an `error` field as often as it
    /// answers 4xx, so the status is not the verdict — this is.
    pub fn access(&self) -> Result<&str> {
        if let Some(error) = &self.error {
            let detail = self.error_description.as_deref().unwrap_or("");
            bail!(
                "the token endpoint refused: {error}{}{detail}",
                match detail.is_empty() {
                    true => "",
                    false => " — ",
                }
            );
        }
        if self.access_token.is_empty() {
            bail!("the token endpoint answered with no access token");
        }
        Ok(&self.access_token)
    }

    /// Some endpoints answer form-encoded rather than JSON — GitHub's does
    /// unless asked otherwise — so both shapes are read.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(body).context("the token endpoint answered in binary")?;
        let trimmed = text.trim_start();
        if trimmed.starts_with('{') {
            return serde_json::from_str(trimmed)
                .context("the token endpoint answered unreadable JSON");
        }
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        for pair in trimmed.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                fields.insert(key.to_owned(), percent_decode(value));
            }
        }
        Ok(Self {
            access_token: fields.remove("access_token").unwrap_or_default(),
            refresh_token: fields.remove("refresh_token").unwrap_or_default(),
            expires_in: fields.remove("expires_in").and_then(|v| v.parse().ok()),
            scope: fields.remove("scope"),
            token_type: fields.remove("token_type"),
            error: fields.remove("error"),
            error_description: fields.remove("error_description"),
        })
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16)
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declaration_this_build_carries_parses_and_binds() {
        // The catalog is `include_str!`d and parsed lazily, so a declaration
        // with a typo in it is a panic at first use — inside whatever command
        // the user ran. This test is where that panic is supposed to happen.
        let catalog = catalog();
        assert!(catalog.len() >= 6, "the catalog is suspiciously small");
        let mut seen: Vec<&str> = Vec::new();
        for provider in catalog {
            assert!(
                !provider.authorities.is_empty(),
                "{} binds nothing",
                provider.name
            );
            assert!(provider.handle_prefix.contains("ast"));
            // Names and aliases share one namespace, because that is the
            // namespace `ast login <name>` looks in.
            for name in std::iter::once(provider.name.as_str())
                .chain(provider.aliases.iter().map(String::as_str))
            {
                assert!(!seen.contains(&name), "{name:?} is declared twice");
                seen.push(name);
            }
            // Every accepted placement reads the same header the door writes,
            // or `strip` would leave the guest's handle on the request.
            for accept in &provider.accept {
                assert_eq!(
                    accept.header(),
                    provider.placement.header(),
                    "{} accepts a placement in another header",
                    provider.name
                );
            }
        }
    }

    #[test]
    fn the_two_providers_this_lane_proves_are_shaped_as_the_transcript_says() {
        let gh = require("gh").expect("gh resolves through its alias");
        assert_eq!(gh.name, "github");
        assert_eq!(gh.kind, PartKind::Login);
        assert!(gh.mint_handle().as_str().starts_with("sk-ast-gh-"));
        assert!(gh.env.contains(&"GH_TOKEN".to_owned()));
        assert_eq!(gh.rule, CredentialRule::Substitute);
        // A gh that sends the older `token` scheme is still presenting this
        // instance's handle, and the door has to see that.
        assert!(gh.accept.contains(&Placement::Authorization {
            scheme: "token".into()
        }));
        assert!(gh.authorities.contains(&"api.github.com".to_owned()));

        let google = require("google").unwrap();
        assert_eq!(google.kind, PartKind::OAuth);
        assert!(matches!(google.rule, CredentialRule::Refresh { .. }));
        assert!(google
            .env
            .contains(&"CLOUDSDK_AUTH_ACCESS_TOKEN".to_owned()));
    }

    #[test]
    fn a_declaration_that_would_fail_inside_a_guest_is_refused_here() {
        let base = |extra: &str| {
            format!(
                "name = \"x\"\nkind = \"login\"\nhandle_prefix = \"ast-x-\"\n\
                 authorities = [\"api.example.com\"]\nenv = [\"X\"]\n\
                 [rule]\ntype = \"substitute\"\nplacement = \"bearer\"\n\
                 [login]\npaste = true\n{extra}"
            )
        };
        assert!(parse(&base("")).is_ok());
        for (bad, why) in [
            (
                "name = \"x\"\nkind = \"login\"\nhandle_prefix = \"x-\"\nauthorities=[\"a.example.com\"]\nenv=[\"X\"]\n[rule]\ntype=\"substitute\"\nplacement=\"bearer\"\n[login]\npaste=true\n",
                "a prefix with no 'ast' in it cannot be told from a real key",
            ),
            (
                "name = \"x\"\nkind = \"login\"\nhandle_prefix = \"ast-x-\"\nauthorities=[\"*.example.com\"]\nenv=[\"X\"]\n[rule]\ntype=\"substitute\"\nplacement=\"bearer\"\n[login]\npaste=true\n",
                "a wildcard authority",
            ),
            (
                "name = \"x\"\nkind = \"login\"\nhandle_prefix = \"ast-x-\"\nauthorities=[\"a.example.com\"]\nenv=[]\n[rule]\ntype=\"substitute\"\nplacement=\"bearer\"\n[login]\npaste=true\n",
                "no environment variable, so nothing would find it",
            ),
            (
                "name = \"x\"\nkind = \"login\"\nhandle_prefix = \"ast-x-\"\nauthorities=[\"a.example.com\"]\nenv=[\"X\"]\n[rule]\ntype=\"refresh\"\nplacement=\"bearer\"\ntoken_url=\"https://t.example.com/t\"\n[login]\npaste=true\n",
                "a login part cannot refresh",
            ),
            (
                "name = \"x\"\nkind = \"oauth\"\nhandle_prefix = \"ast-x-\"\nauthorities=[\"a.example.com\"]\nenv=[\"X\"]\n[rule]\ntype=\"refresh\"\nplacement=\"bearer\"\ntoken_url=\"http://t.example.com/t\"\n[oauth]\n",
                "a token endpoint over plain http",
            ),
            (
                "name = \"x\"\nkind = \"oauth\"\nhandle_prefix = \"ast-x-\"\nauthorities=[\"a.example.com\"]\nenv=[\"X\"]\n[rule]\ntype=\"sign\"\nalgorithm=\"rot13\"\nservice=\"s\"\nregion=\"r\"\n[oauth]\n",
                "a signing algorithm nobody wrote",
            ),
        ] {
            assert!(parse(bad).is_err(), "accepted a declaration that {why}");
        }
    }

    #[test]
    fn a_declaration_may_put_a_credential_in_authorization_where_a_person_may_not() {
        // `--as authorization` from a person is almost always a mistyped
        // `--as bearer`, so it is refused there. Linear really does read the
        // bare header, and the declaration says so with the docs open.
        assert!(Placement::parse("authorization").is_err());
        assert_eq!(
            declared_placement("header:authorization").unwrap(),
            Placement::Header {
                name: "authorization".into()
            }
        );
        let linear = require("linear").unwrap();
        assert_eq!(linear.placement.header(), "authorization");
        assert_eq!(linear.placement.render("key"), "key");
    }

    #[test]
    fn a_grant_is_self_identifying_so_a_refresh_token_is_never_sent_as_one() {
        let grant = OAuthGrant {
            marker: OAUTH_MARKER,
            provider: "google".into(),
            refresh_token: "1//refresh".into(),
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".into()],
            client_id: "cid".into(),
            client_secret: Some("csecret".into()),
            token_url: "https://oauth2.googleapis.com/token".into(),
            account: Some("someone@example.com".into()),
        };
        let json = serde_json::to_vec(&grant).unwrap();
        let back = OAuthGrant::parse(&json).unwrap();
        assert_eq!(back.refresh_token, "1//refresh");
        // A raw token is not a grant, and is not mistaken for one.
        assert!(OAuthGrant::parse(b"ghp_arawtoken").is_err());
        // Nor is a grant from a version this build does not read.
        assert!(OAuthGrant::parse(br#"{"asterism_oauth":99,"provider":"g","refresh_token":"r","client_id":"c","token_url":"u"}"#).is_err());
        // And it never prints itself.
        assert_eq!(grant.to_string(), "<google grant>");
    }

    #[test]
    fn signing_keys_are_read_in_both_shapes_a_person_has_them_in() {
        // A prefix of the example pair AWS publishes in its own signing
        // documentation. Held in a variable rather than repeated inline so
        // that a secret scanner does not have to decide whether an assertion
        // about a parser is a leaked credential.
        let published = "wJalrXUtnFEMI/K7MDENG";
        let two_lines = SigningKeys::parse(format!("AKIDEXAMPLE\n{published}").as_bytes()).unwrap();
        assert_eq!(two_lines.access_key_id, "AKIDEXAMPLE");
        assert_eq!(two_lines.secret_access_key, published);
        let pasted = SigningKeys::parse(
            format!("AWS_ACCESS_KEY_ID=AKIDEXAMPLE\nAWS_SECRET_ACCESS_KEY=\"{published}\"")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(pasted.access_key_id, "AKIDEXAMPLE");
        assert_eq!(pasted.secret_access_key, published);
        let json = SigningKeys::parse(
            br#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"s","session_token":"t"}"#,
        )
        .unwrap();
        assert_eq!(json.session_token.as_deref(), Some("t"));
        assert!(SigningKeys::parse(b"only-one-line").is_err());
    }

    #[test]
    fn a_scope_a_person_can_type_becomes_the_one_the_provider_published() {
        let google = require("google").unwrap();
        let spec = google.oauth.as_ref().unwrap();
        assert_eq!(
            resolve_scopes(spec, &["gmail.readonly,calendar.readonly".to_owned()]),
            vec![
                "https://www.googleapis.com/auth/gmail.readonly".to_owned(),
                "https://www.googleapis.com/auth/calendar.readonly".to_owned(),
            ]
        );
        // A scope already spelled in full is left alone.
        assert_eq!(
            resolve_scopes(spec, &["https://www.googleapis.com/auth/drive".to_owned()]),
            vec!["https://www.googleapis.com/auth/drive".to_owned()]
        );
        // Nothing asked for is the declared default, never everything.
        assert_eq!(resolve_scopes(spec, &[]), spec.default_scopes);
        // Gmail is not in Google's device-flow set, so a grant for it needs
        // the redirect flow, and `ast oauth add` has to know that before it
        // sends a person to a screen that will refuse them.
        assert!(!spec.device_flow_covers(&resolve_scopes(spec, &["gmail.readonly".to_owned()])));
        assert!(spec.device_flow_covers(&resolve_scopes(spec, &["drive".to_owned()])));
    }

    #[test]
    fn a_token_endpoint_is_read_in_json_and_in_form_encoding() {
        // GitHub answers form-encoded unless asked for JSON, and an `error`
        // arrives with a 200 as often as with a 4xx.
        let form =
            TokenGrant::parse(b"access_token=gho_x&scope=repo%2Cgist&token_type=bearer").unwrap();
        assert_eq!(form.access().unwrap(), "gho_x");
        assert_eq!(form.scope.as_deref(), Some("repo,gist"));
        let pending = TokenGrant::parse(b"error=authorization_pending").unwrap();
        assert_eq!(pending.error.as_deref(), Some("authorization_pending"));
        assert!(pending.access().is_err());
        let json = TokenGrant::parse(br#"{"access_token":"ya29.x","expires_in":3599}"#).unwrap();
        assert_eq!(json.access().unwrap(), "ya29.x");
        assert_eq!(json.expires_in, Some(3599));
        // A refusal names the provider's own reason and does not invent one.
        let refused =
            TokenGrant::parse(br#"{"error":"invalid_grant","error_description":"expired"}"#)
                .unwrap();
        let message = refused.access().unwrap_err().to_string();
        assert!(message.contains("invalid_grant"), "{message}");
        assert!(message.contains("expired"), "{message}");
    }

    #[test]
    fn a_form_body_encodes_what_a_token_endpoint_would_otherwise_mis_split() {
        assert_eq!(
            form_encode(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", "1//a+b&c=d"),
            ]),
            "grant_type=refresh_token&refresh_token=1%2F%2Fa%2Bb%26c%3Dd"
        );
    }
}
