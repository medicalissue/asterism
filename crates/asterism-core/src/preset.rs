//! Agent presets: one file that says what an agent needs to be running.
//!
//! A [`crate::profile`] turns a general-purpose cloud image into a workspace
//! by installing things at first boot. A preset is the other half of that
//! idea, aimed at one job: *this named agent, ready to talk to, in about a
//! minute*. It names an image that already has the agent CLI in it, the
//! secrets the agent cannot work without, the command that starts it, and the
//! directory it works in. Nothing else.
//!
//! ## Why an image and not a bootstrap
//!
//! Installing a Node runtime and an npm package at every first boot costs a
//! minute of network for bytes that were identical last week, and it fails
//! differently on every distribution. An agent image is built once, pinned by
//! digest, and pulled once per device. The thing a golden image must never
//! contain — a credential — is the one thing a preset deliberately does not
//! carry: it names secrets, it never holds them.
//!
//! ## The secrets are names, not values
//!
//! `secrets` is a list of *bindings to make*, each naming an orbit secret
//! (`ast secret ls`), the one authority it may be spent against, where it
//! rides on a request, and the environment variable the guest finds its
//! opaque handle in. Creating an agent resolves those through
//! [`crate::secret`] exactly as `ast attach --secret` does, so the guest gets
//! `sk-ast-…` and the door swaps in the real value on its way out. A preset
//! whose required secret does not exist is refused *before* anything is
//! created — see [`Preset::missing_required`] — because a half-built instance
//! that cannot authenticate is worse than no instance.
//!
//! ## Where presets come from
//!
//! Two places, in this order: the ones Asterism ships (compiled in from
//! `presets/*.json` at the repository root) and the ones the user writes in
//! `~/.asterism/presets/*.json`. A user file with a shipped name replaces it,
//! which is how you pin your own build of an agent image without patching
//! Asterism.
//!
//! JSON rather than TOML on purpose: this crate already parses JSON for the
//! daemon protocol, the image config, and the registry manifest, and a
//! preset is not worth a new dependency in the boot path.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths;

/// Presets compiled into the binary, in catalog order.
const BUILTIN: &[(&str, &str)] = &[
    (
        "claude-code",
        include_str!("../../../presets/claude-code.json"),
    ),
    ("codex", include_str!("../../../presets/codex.json")),
];

/// One secret a preset wants bound to the instance it creates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresetSecret {
    /// The orbit secret's name, as `ast secret ls` shows it.
    pub name: String,
    /// The one authority the value may be spent against: `host` or
    /// `host:port`.
    pub authority: String,
    /// How the credential rides on a request: `bearer`, `x-api-key`, or
    /// `header:<Name>`. `None` lets the authority's own default decide.
    #[serde(default)]
    pub placement: Option<String>,
    /// The environment variable the guest finds its handle in. Defaults to
    /// the secret's name.
    #[serde(default)]
    pub env: Option<String>,
    /// Whether the agent is useless without it. A missing required secret is
    /// a refusal; a missing optional one is simply not bound.
    #[serde(default)]
    pub required: bool,
}

impl PresetSecret {
    /// The environment variable this binding lands in.
    pub fn env_var(&self) -> &str {
        self.env.as_deref().unwrap_or(&self.name)
    }
}

/// A directory an agent preset wants mounted, and what its bytes are for.
///
/// The workspace is where the agent *works*; these are the two other places
/// an agent box writes that the root disk is the wrong home for.
///
/// `memory` is the agent's own state — the conversation, the settings — and
/// the point of declaring it is that `ast rewind` puts the box back twenty
/// minutes and leaves this alone, so `claude --resume` continues the same
/// conversation across the rewind. `cache` is rebuildable bytes shared by
/// `key` with every agent box that asks for the same key, so three boxes
/// warm one cargo registry between them instead of three.
///
/// Like the workspace, these are host directories shared into the guest
/// rather than block volumes: the host can see them, a fork can copy one
/// with `cp`, and the rewind engine already knows how to clone a tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresetMount {
    /// Where it appears in the guest. Absolute.
    pub at: String,
    /// What the bytes are for. `instance` would be a mount a rewind rolls
    /// back with the box, which is what the workspace deliberately is not —
    /// so in practice this is `memory` or `cache`.
    pub lifecycle: crate::volume::Lifecycle,
    /// What a `cache` mount is shared by. Required on a cache — that is what
    /// makes the second box find the first one's bytes — and refused on
    /// anything else, where there is nothing to share.
    #[serde(default)]
    pub key: Option<String>,
}

impl PresetMount {
    /// The directory on this device that backs this mount.
    ///
    /// A memory mount belongs to one instance and is named after it. A cache
    /// belongs to its key, and that is the whole of how sharing works: two
    /// boxes asking for one key are handed one directory. One mount point per
    /// key, though — a preset that warms both `~/.npm` and `~/.cache` under
    /// one key gets two directories under that key, not one directory
    /// mounted twice with each guest path overwriting the other's contents.
    pub fn host_dir(&self, root: &Path, instance: &str) -> PathBuf {
        match (self.lifecycle, &self.key) {
            (crate::volume::Lifecycle::Cache, Some(key)) => {
                root.join("cache").join(safe(key)).join(safe(&self.at))
            }
            _ => root.join("memory").join(instance).join(safe(&self.at)),
        }
    }
}

/// Reduce a key to one path component. A key may be a repository URL; a
/// directory name may not be.
fn safe(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// A named, self-contained description of an agent that can be run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preset {
    /// What `--agent` names. ASCII lowercase, digits and `-`.
    pub name: String,
    /// One line, for `ast agents`.
    pub summary: String,
    /// The OCI image, written the way `--image` accepts it.
    pub image: String,
    /// The manifest digest that image must have, when it is pinned. A preset
    /// with a digest boots the same bytes on every device forever; one
    /// without follows its tag.
    #[serde(default)]
    pub digest: Option<String>,
    /// The command tmux runs. Not a shell script: one command line.
    pub start: String,
    /// Where the agent works, and where a cloned repository lands. This is
    /// the mount point of the instance's data volume, so it survives a
    /// snapshot and restore of the root disk.
    pub workdir: String,
    /// A command whose first line of output is the installed agent's
    /// version. Run in the guest once, to report what actually landed.
    pub version_probe: String,
    /// Where to read about the agent itself.
    pub docs: String,
    /// True for a preset that is shipped to be tried, not relied on.
    #[serde(default)]
    pub experimental: bool,
    /// The secrets to bind, required ones first in refusal order.
    #[serde(default)]
    pub secrets: Vec<PresetSecret>,
    /// Directories to mount past the workspace: the agent's memory and the
    /// caches it shares. Empty is a preset that keeps everything but its
    /// workspace on the root disk, which is what every preset meant before
    /// this field existed.
    #[serde(default)]
    pub mounts: Vec<PresetMount>,
}

impl Preset {
    /// Parse and validate one preset document.
    pub fn parse(text: &str) -> Result<Preset> {
        let preset: Preset = serde_json::from_str(text).context("unreadable preset")?;
        preset.validate()?;
        Ok(preset)
    }

    fn validate(&self) -> Result<()> {
        if !is_preset_name(&self.name) {
            bail!(
                "preset name {:?} is not usable — ascii lowercase, digits and `-`",
                self.name
            );
        }
        if crate::oci::parse(&self.image).is_none() {
            bail!(
                "preset {} names {:?}, which is not an OCI image reference",
                self.name,
                self.image
            );
        }
        if let Some(digest) = &self.digest {
            if !digest.starts_with("sha256:") && !digest.starts_with("sha512:") {
                bail!(
                    "preset {} pins {digest:?}, which is not a manifest digest",
                    self.name
                );
            }
        }
        if self.start.trim().is_empty() {
            bail!("preset {} has no start command", self.name);
        }
        if !self.workdir.starts_with('/') {
            bail!(
                "preset {} works in {:?}, which is not an absolute path",
                self.name,
                self.workdir
            );
        }
        if self.version_probe.trim().is_empty() {
            bail!("preset {} has no version probe", self.name);
        }
        for mount in &self.mounts {
            if !mount.at.starts_with('/') {
                bail!(
                    "preset {} mounts {:?}, which is not an absolute path",
                    self.name,
                    mount.at
                );
            }
            if mount.at == self.workdir {
                bail!(
                    "preset {} mounts {:?} on top of its own workdir",
                    self.name,
                    mount.at
                );
            }
            let is_cache = mount.lifecycle == crate::volume::Lifecycle::Cache;
            if is_cache != mount.key.is_some() {
                bail!(
                    "preset {} declares {:?} as a {} mount with{} a key — a cache is \
                     shared by key and nothing else is",
                    self.name,
                    mount.at,
                    mount.lifecycle,
                    if mount.key.is_some() { "" } else { "out" }
                );
            }
            if let Some(key) = &mount.key {
                crate::volume::check_key(key)
                    .with_context(|| format!("preset {} shares {:?}", self.name, mount.at))?;
            }
        }
        let mut seen: Vec<&str> = Vec::new();
        for mount in &self.mounts {
            if seen.contains(&mount.at.as_str()) {
                bail!(
                    "preset {} mounts {:?} twice — two directories at one guest path \
                     shadow each other",
                    self.name,
                    mount.at
                );
            }
            seen.push(&mount.at);
        }
        for secret in &self.secrets {
            if !is_env_name(secret.env_var()) {
                bail!(
                    "preset {} would put a handle in {:?}, which is not an \
                     environment variable name",
                    self.name,
                    secret.env_var()
                );
            }
            if secret.authority.trim().is_empty() {
                bail!(
                    "preset {} binds {} to no authority — a secret is always \
                     spendable against exactly one",
                    self.name,
                    secret.name
                );
            }
            if let Some(placement) = &secret.placement {
                crate::secret::Placement::parse(placement)
                    .with_context(|| format!("preset {} places {}", self.name, secret.name))?;
            }
        }
        Ok(())
    }

    /// The image reference to pull: pinned to the digest when the preset has
    /// one, so what boots is what was reviewed rather than what the tag
    /// points at today.
    pub fn image_reference(&self) -> String {
        match &self.digest {
            Some(digest) => format!("{}@{digest}", repository_of(&self.image)),
            None => self.image.clone(),
        }
    }

    /// The required secrets this orbit does not have, in preset order.
    ///
    /// `have` is the orbit's secret names, as `ast secret ls` reports them.
    /// The answer drives a refusal that happens before any mutation, so the
    /// caller must ask this first and create nothing when it is non-empty.
    pub fn missing_required<S: AsRef<str>>(&self, have: &[S]) -> Vec<&PresetSecret> {
        self.secrets
            .iter()
            .filter(|s| s.required)
            .filter(|s| !have.iter().any(|h| h.as_ref() == s.name))
            .collect()
    }

    /// The refusal, in the words the user can act on.
    pub fn missing_secret_refusal(&self, secret: &PresetSecret) -> String {
        format!(
            "preset {} needs secret {} — run `ast secret add {}` first",
            self.name, secret.name, secret.name
        )
    }
}

/// Whether an orbit already has every required secret, or the first refusal.
pub fn check_secrets<S: AsRef<str>>(preset: &Preset, have: &[S]) -> Result<(), String> {
    match preset.missing_required(have).first() {
        Some(missing) => Err(preset.missing_secret_refusal(missing)),
        None => Ok(()),
    }
}

/// Every preset this device knows, shipped ones first, user ones replacing a
/// shipped one of the same name.
pub fn catalog() -> Result<Vec<Preset>> {
    let mut presets = Vec::new();
    for (name, text) in BUILTIN {
        let preset = Preset::parse(text).with_context(|| format!("the built-in {name} preset"))?;
        presets.push(preset);
    }
    for preset in user_presets(&user_dir())? {
        match presets.iter().position(|p| p.name == preset.name) {
            Some(at) => presets[at] = preset,
            None => presets.push(preset),
        }
    }
    Ok(presets)
}

/// Where a user's own presets live.
pub fn user_dir() -> PathBuf {
    paths::home_dir().join("presets")
}

/// Read every `*.json` in a directory as a preset, in name order.
///
/// A directory that does not exist is not an error: most devices have none.
/// A file that does not parse *is*, and names itself — a preset silently
/// skipped is a preset that stops working for reasons nobody can see.
fn user_presets(dir: &Path) -> Result<Vec<Preset>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    let mut presets = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let preset = Preset::parse(&text).with_context(|| format!("in {}", path.display()))?;
        presets.push(preset);
    }
    Ok(presets)
}

/// Look one up by name, or say what there is instead.
pub fn get(name: &str) -> Result<Preset> {
    let catalog = catalog()?;
    if let Some(found) = catalog.iter().find(|p| p.name == name) {
        return Ok(found.clone());
    }
    let known = catalog
        .iter()
        .map(|p| p.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "no agent preset named {name:?} — this device knows {known}, and reads \
         your own from {}",
        user_dir().display()
    )
}

/// What the CLI records beside an instance so that `ast attach` and
/// `ast logs` know what they are looking at, and so a reboot restarts the
/// same session with the same command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRecord {
    /// The preset's name, for reporting.
    pub preset: String,
    /// The tmux session, which is the instance's name.
    pub session: String,
    /// The mount point of the data volume.
    pub workdir: String,
    /// Where the repository was cloned, when one was.
    #[serde(default)]
    pub repo_path: Option<String>,
    /// The repository's url, for a re-clone after the volume is emptied.
    #[serde(default)]
    pub repo_url: Option<String>,
    /// The command tmux runs.
    pub start: String,
    /// What the guest answered when asked its version.
    #[serde(default)]
    pub version: Option<String>,
}

impl AgentRecord {
    /// The directory the agent starts in.
    pub fn start_dir(&self) -> &str {
        self.repo_path.as_deref().unwrap_or(&self.workdir)
    }

    /// Where the pane capture is written inside the guest.
    pub fn log_path(&self) -> String {
        format!("{}/.asterism/agent.log", self.workdir)
    }

    /// The shell run in the guest to bring the session up, idempotently.
    ///
    /// Idempotent because it runs twice for the same reason `ast up` is
    /// idempotent: once when the agent is created, and again from the image's
    /// entrypoint after a reboot. `tmux has-session` is the whole guard —
    /// a second `new-session` would otherwise fail and take the boot with it.
    ///
    /// `pipe-pane` is how `ast logs` has anything to read. It appends, so a
    /// restarted session continues the same file rather than truncating what
    /// the last one said.
    pub fn start_script(&self) -> String {
        let log = self.log_path();
        format!(
            "set -e\n\
             mkdir -p {dir} {logdir}\n\
             cd {dir}\n\
             if tmux has-session -t {session} 2>/dev/null; then\n\
             \x20 echo 'asterism: session {session} already running'\n\
             \x20 exit 0\n\
             fi\n\
             tmux new-session -d -s {session} -c {dir} {start}\n\
             tmux pipe-pane -t {session} -o {pipe}\n\
             echo 'asterism: session {session} started'\n",
            dir = sh_quote(self.start_dir()),
            logdir = sh_quote(&format!("{}/.asterism", self.workdir)),
            session = self.session,
            start = sh_quote(&self.start),
            pipe = sh_quote(&format!("cat >> {}", sh_quote(&log))),
        )
    }

    /// What `ast attach` runs on the far side of ssh.
    ///
    /// `new-session -A` is attach-or-create in one word, so a session the
    /// guest lost — an agent that exited, a volume that was replaced — is not
    /// a dead end but a new one, started with the same command in the same
    /// directory.
    pub fn attach_command(&self) -> String {
        format!(
            "tmux new-session -A -s {session} -c {dir} {start}",
            session = self.session,
            dir = sh_quote(self.start_dir()),
            start = sh_quote(&self.start),
        )
    }
}

/// The repository directory `--repo <url>` clones into, under `workdir`.
///
/// The last path component with any `.git` taken off, which is what `git
/// clone` itself would have picked. A url that yields nothing usable is a
/// refusal rather than a directory called `""`.
pub fn repo_dir(workdir: &str, url: &str) -> Result<String> {
    let trimmed = url.trim_end_matches('/');
    let last = trimmed
        .rsplit(['/', ':'])
        .next()
        .unwrap_or_default()
        .trim_end_matches(".git");
    if last.is_empty() || last.starts_with('.') {
        bail!("cannot tell what directory {url:?} would clone into");
    }
    if !last
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("cannot tell what directory {url:?} would clone into");
    }
    Ok(format!("{}/{}", workdir.trim_end_matches('/'), last))
}

/// The repository part of an image reference, without its tag or digest.
fn repository_of(image: &str) -> String {
    match crate::oci::parse(image) {
        Some(reference) => format!("{}/{}", reference.registry, reference.repository),
        None => image.to_owned(),
    }
}

fn is_preset_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

fn is_env_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One shell word, safe whatever is in it.
fn sh_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claude() -> Preset {
        get_builtin("claude-code")
    }

    fn get_builtin(name: &str) -> Preset {
        let (_, text) = BUILTIN
            .iter()
            .find(|(n, _)| *n == name)
            .expect("a built-in preset");
        Preset::parse(text).expect("the built-in preset parses")
    }

    /// The scene, as data: every agent this device ships keeps its own state
    /// off the root disk and shares its caches with the others.
    #[test]
    fn every_agent_preset_keeps_its_memory_off_the_root_disk() {
        use crate::volume::Lifecycle;
        for (name, text) in BUILTIN {
            let preset = Preset::parse(text).expect("a built-in preset");
            let memory: Vec<&PresetMount> = preset
                .mounts
                .iter()
                .filter(|m| m.lifecycle == Lifecycle::Memory)
                .collect();
            assert_eq!(
                memory.len(),
                1,
                "{name} declares {} memory mounts",
                memory.len()
            );
            assert!(memory[0].at.starts_with('/'), "{name}: {:?}", memory[0].at);
            assert!(
                preset
                    .mounts
                    .iter()
                    .any(|m| m.lifecycle == Lifecycle::Cache),
                "{name} shares no cache"
            );
        }
    }

    /// Two boxes, one warm cache; two boxes, two separate memories. This is
    /// the whole of how sharing works, and it is a function of the directory
    /// names — so it is asserted on the directory names.
    #[test]
    fn a_cache_is_named_after_its_key_and_a_memory_after_its_instance() {
        use crate::volume::Lifecycle;
        let root = Path::new("/home/me/.asterism");
        let preset = claude();
        let dirs = |instance: &str| -> Vec<PathBuf> {
            preset
                .mounts
                .iter()
                .map(|m| m.host_dir(root, instance))
                .collect()
        };
        let bot = dirs("bot");
        let other = dirs("other");
        for (i, mount) in preset.mounts.iter().enumerate() {
            match mount.lifecycle {
                Lifecycle::Cache => {
                    assert_eq!(bot[i], other[i], "two boxes must share {:?}", mount.at)
                }
                _ => assert_ne!(bot[i], other[i], "two boxes must not share {:?}", mount.at),
            }
        }
        // And two cache mounts under one key are two directories, not one
        // directory mounted twice with each guest path eating the other.
        let caches: Vec<&PathBuf> = preset
            .mounts
            .iter()
            .enumerate()
            .filter(|(_, m)| m.lifecycle == Lifecycle::Cache)
            .map(|(i, _)| &bot[i])
            .collect();
        assert!(caches.len() > 1, "nothing to check");
        assert_eq!(
            caches.len(),
            caches
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
    }

    /// A cache is shared by key and nothing else is, so declaring a key on a
    /// memory mount — or leaving one off a cache — is refused rather than
    /// becoming a promise nothing keeps.
    #[test]
    fn a_mount_that_could_not_be_honoured_is_refused() {
        use crate::volume::Lifecycle;
        let mut preset = claude();

        preset.mounts = vec![PresetMount {
            at: "/root/.claude".into(),
            lifecycle: Lifecycle::Memory,
            key: Some("k".into()),
        }];
        assert!(preset.validate().unwrap_err().to_string().contains("key"));

        preset.mounts = vec![PresetMount {
            at: "/root/.cache".into(),
            lifecycle: Lifecycle::Cache,
            key: None,
        }];
        assert!(preset.validate().unwrap_err().to_string().contains("key"));

        preset.mounts = vec![PresetMount {
            at: "root/.claude".into(),
            lifecycle: Lifecycle::Memory,
            key: None,
        }];
        assert!(preset
            .validate()
            .unwrap_err()
            .to_string()
            .contains("absolute path"));

        // Two mounts at one guest path shadow each other, and the workspace
        // is a mount point too.
        preset.mounts = vec![
            PresetMount {
                at: "/root/.claude".into(),
                lifecycle: Lifecycle::Memory,
                key: None,
            },
            PresetMount {
                at: "/root/.claude".into(),
                lifecycle: Lifecycle::Cache,
                key: Some("k".into()),
            },
        ];
        assert!(preset.validate().unwrap_err().to_string().contains("twice"));

        preset.mounts = vec![PresetMount {
            at: preset.workdir.clone(),
            lifecycle: Lifecycle::Memory,
            key: None,
        }];
        assert!(preset
            .validate()
            .unwrap_err()
            .to_string()
            .contains("workdir"));
    }

    /// A preset written before mounts existed still parses, and declares
    /// none — the same instance it always described.
    #[test]
    fn a_preset_without_mounts_declares_none() {
        let text = r#"{"name":"old","summary":"s","image":"ghcr.io/x/y:1",
            "start":"y","workdir":"/work","version_probe":"y --version",
            "docs":"https://example.com"}"#;
        let preset = Preset::parse(text).unwrap();
        assert!(preset.mounts.is_empty());
    }

    #[test]
    fn every_shipped_preset_parses_and_validates() {
        for (name, text) in BUILTIN {
            let preset = Preset::parse(text)
                .unwrap_or_else(|e| panic!("the {name} preset does not parse: {e:#}"));
            assert_eq!(&preset.name, name);
            assert!(!preset.summary.is_empty());
            assert!(crate::oci::parse(&preset.image).is_some());
        }
    }

    #[test]
    fn the_two_shipped_agents_require_the_key_their_vendor_issues() {
        let claude = claude();
        let required: Vec<&str> = claude
            .secrets
            .iter()
            .filter(|s| s.required)
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(required, ["ANTHROPIC_API_KEY"]);

        let codex = get_builtin("codex");
        let required: Vec<&str> = codex
            .secrets
            .iter()
            .filter(|s| s.required)
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(required, ["OPENAI_API_KEY"]);
    }

    #[test]
    fn a_missing_required_secret_is_named_with_the_command_that_fixes_it() {
        let codex = get_builtin("codex");
        let missing = codex.missing_required::<&str>(&[]);
        assert_eq!(missing.len(), 1);
        assert_eq!(
            codex.missing_secret_refusal(missing[0]),
            "preset codex needs secret OPENAI_API_KEY — run `ast secret add OPENAI_API_KEY` first"
        );
        assert_eq!(
            check_secrets(&codex, &[] as &[&str]),
            Err(
                "preset codex needs secret OPENAI_API_KEY — run `ast secret add OPENAI_API_KEY` first"
                    .to_owned()
            )
        );
    }

    #[test]
    fn an_optional_secret_is_never_a_refusal() {
        let claude = claude();
        assert!(claude
            .secrets
            .iter()
            .any(|s| s.name == "GITHUB_TOKEN" && !s.required));
        assert!(check_secrets(&claude, &["ANTHROPIC_API_KEY"]).is_ok());
        assert!(claude
            .missing_required(&["ANTHROPIC_API_KEY".to_owned()])
            .is_empty());
    }

    #[test]
    fn a_pinned_preset_pulls_the_digest_and_not_the_tag() {
        let mut preset = claude();
        assert_eq!(preset.image_reference(), preset.image);
        preset.digest = Some(format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(
            preset.image_reference(),
            format!(
                "ghcr.io/medicalissue/agent-claude-code@sha256:{}",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn a_preset_that_is_not_an_image_reference_is_refused_before_it_is_used() {
        let mut preset = claude();
        preset.image = "not a reference".into();
        let text = serde_json::to_string(&preset).unwrap();
        let error = format!("{:#}", Preset::parse(&text).unwrap_err());
        assert!(error.contains("not an OCI image reference"), "{error}");
    }

    #[test]
    fn a_preset_cannot_route_a_handle_into_something_that_is_not_a_variable() {
        let mut preset = claude();
        preset.secrets[0].env = Some("2BAD-NAME".into());
        let text = serde_json::to_string(&preset).unwrap();
        let error = format!("{:#}", Preset::parse(&text).unwrap_err());
        assert!(error.contains("environment variable name"), "{error}");
    }

    #[test]
    fn a_preset_cannot_bind_a_secret_to_nothing() {
        let mut preset = claude();
        preset.secrets[0].authority = "  ".into();
        let text = serde_json::to_string(&preset).unwrap();
        let error = format!("{:#}", Preset::parse(&text).unwrap_err());
        assert!(error.contains("no authority"), "{error}");
    }

    #[test]
    fn a_relative_workdir_is_refused() {
        let mut preset = claude();
        preset.workdir = "work".into();
        let text = serde_json::to_string(&preset).unwrap();
        let error = format!("{:#}", Preset::parse(&text).unwrap_err());
        assert!(error.contains("not an absolute path"), "{error}");
    }

    #[test]
    fn a_user_preset_replaces_the_shipped_one_of_the_same_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut mine = claude();
        mine.image = "ghcr.io/me/my-claude:1".into();
        std::fs::write(
            dir.path().join("claude-code.json"),
            serde_json::to_string(&mine).unwrap(),
        )
        .unwrap();
        let read = user_presets(dir.path()).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].image, "ghcr.io/me/my-claude:1");
    }

    #[test]
    fn a_user_preset_that_does_not_parse_names_its_own_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.json"), "{ not json").unwrap();
        let error = format!("{:#}", user_presets(dir.path()).unwrap_err());
        assert!(error.contains("broken.json"), "{error}");
    }

    #[test]
    fn a_directory_with_no_presets_in_it_is_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        assert!(user_presets(dir.path()).unwrap().is_empty());
        assert!(user_presets(&dir.path().join("nope")).unwrap().is_empty());
    }

    #[test]
    fn a_clone_lands_under_the_workdir_named_the_way_git_would_name_it() {
        assert_eq!(
            repo_dir("/work", "https://github.com/me/app.git").unwrap(),
            "/work/app"
        );
        assert_eq!(
            repo_dir("/work/", "https://github.com/me/app/").unwrap(),
            "/work/app"
        );
        assert_eq!(
            repo_dir("/work", "git@github.com:me/app.git").unwrap(),
            "/work/app"
        );
        assert!(repo_dir("/work", "https://github.com/me/..").is_err());
        assert!(repo_dir("/work", "https://github.com/me/a b").is_err());
        assert!(repo_dir("/work", "").is_err());
    }

    fn record() -> AgentRecord {
        AgentRecord {
            preset: "claude-code".into(),
            session: "bot".into(),
            workdir: "/work".into(),
            repo_path: Some("/work/app".into()),
            repo_url: Some("https://github.com/me/app.git".into()),
            start: "claude".into(),
            version: Some("2.1".into()),
        }
    }

    #[test]
    fn starting_a_session_twice_is_not_an_error() {
        let script = record().start_script();
        assert!(script.contains("tmux has-session -t bot"), "{script}");
        assert!(
            script.find("has-session").unwrap() < script.find("new-session").unwrap(),
            "{script}"
        );
        assert!(script.contains("tmux new-session -d -s bot -c '/work/app' 'claude'"));
        assert!(script.contains("pipe-pane -t bot -o"));
    }

    #[test]
    fn attaching_creates_the_session_when_the_guest_has_lost_it() {
        assert_eq!(
            record().attach_command(),
            "tmux new-session -A -s bot -c '/work/app' 'claude'"
        );
    }

    #[test]
    fn an_agent_with_no_repository_works_in_the_volume_root() {
        let mut record = record();
        record.repo_path = None;
        assert_eq!(record.start_dir(), "/work");
        assert_eq!(
            record.attach_command(),
            "tmux new-session -A -s bot -c '/work' 'claude'"
        );
    }

    #[test]
    fn a_start_command_with_a_quote_in_it_stays_one_word() {
        let mut record = record();
        record.start = "sh -c 'echo hi'".into();
        assert!(record.start_script().contains(r#"'sh -c '\''echo hi'\'''"#));
    }

    #[test]
    fn the_pane_capture_lives_on_the_volume_that_survives_a_restore() {
        assert_eq!(record().log_path(), "/work/.asterism/agent.log");
    }
}
