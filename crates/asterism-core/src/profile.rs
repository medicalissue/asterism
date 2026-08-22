//! Bootstrap profiles: what a guest is, past the operating system on it.
//!
//! A cloud image boots a machine. An agent needs a place to work: a shell it
//! can come back to after the wifi drops, git, a Node runtime, and the agent
//! CLI itself. Doing that by hand once per instance is the admin work this
//! module deletes — and doing it by baking a golden image is the thing it
//! exists to avoid, because an image with a runtime in it is out of date the
//! week after it is built, and an image with a *credential* in it is one that
//! must never be copied anywhere.
//!
//! So a profile is neither. It is a versioned list of things to install and
//! things to check, applied inside the guest from the same cloud-init seed
//! that already carries the mounts and the host-key insurance. The base
//! instance stays whatever image the user asked for; profiles are additive,
//! they name what they need (`claude` is nothing without `node`), and every
//! one of them ends in checks, because "it installed" and "it works" are two
//! claims and only the second one is worth having.
//!
//! ## The version is the whole point of the word
//!
//! Each profile carries a [`Profile::version`], and the set an instance was
//! created with is folded into the seed's fingerprint. Bump one and the seed
//! is reissued, the guest's cloud-init treats the next boot as a first boot,
//! and the work is applied again — the same mechanism that already lands a
//! newly attached volume on a guest that has been running for a month. The
//! guest keeps the stamp it last finished in `/var/lib/asterism/bootstrap.done`,
//! so a boot that has nothing to do costs one `cat` and a comparison.
//!
//! ## Where the credential is not
//!
//! No profile writes a key and none of them asks for one. An agent gets its
//! credential the way [`crate::secret`] hands one over: the guest holds an
//! opaque handle, the value is swapped in on its way out through this
//! device's egress proxy, and the value never reaches the guest's disk — so
//! it is not in a snapshot of that disk, and not in anything the guest could
//! attach to a bug report. That is a claim about an *absence*, and an
//! absence is only worth stating if something looks for the presence: the
//! last section of the generated `asterism-check` is exactly that search.
//!
//! ## Why nothing here is piped into a shell
//!
//! Every install goes through the distribution's own package manager, or
//! through npm for the two CLIs published there and nowhere else. No profile
//! downloads a script and runs it. [`crate::verify`] exists because a byte
//! nobody checked is a byte nobody should boot, and `curl … | sh` inside a
//! bootstrap is that same trade one layer up.

use anyhow::{bail, Result};

/// Package names for one thing, spelled for each package manager Asterism's
/// image catalog can put in front of it.
///
/// Three fields rather than one, because the name is genuinely different per
/// distribution often enough that a single string would be a lie somewhere.
/// An empty field means "this manager has nothing to install for this" and
/// is not a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packages {
    /// Debian and Ubuntu.
    pub apt: &'static str,
    /// Fedora.
    pub dnf: &'static str,
    /// Alpine.
    pub apk: &'static str,
}

/// A file a profile puts in the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestFile {
    pub path: &'static str,
    /// Octal, as cloud-init's `permissions:` wants it.
    pub mode: &'static str,
    pub content: &'static str,
}

/// One thing `asterism-check` confirms about a guest.
///
/// `probe` is a shell command whose exit status is the verdict and whose
/// first line of output is the evidence — `git --version` prints the version
/// it found, which is what a person reading the report actually wants.
/// `remedy` is what to do when it fails, and it is a required field: a check
/// that can only say "no" leaves the user exactly where they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Check {
    pub what: &'static str,
    pub probe: &'static str,
    pub remedy: &'static str,
}

/// A named, versioned set of bootstrap work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    pub name: &'static str,
    /// Bumped when what this profile does changes. Folded into the seed, so
    /// a bump reaches instances that already exist.
    pub version: u32,
    /// One line, for `ast profiles`.
    pub summary: &'static str,
    /// Profiles this one is meaningless without. Pulled in automatically and
    /// always applied first; see [`resolve`].
    pub requires: &'static [&'static str],
    pub packages: &'static [Packages],
    pub files: &'static [GuestFile],
    /// Shell run as root in the guest after this profile's packages are in.
    /// One fragment per step, each run under `set -e`.
    pub steps: &'static [&'static str],
    pub checks: &'static [Check],
}

/// Every profile Asterism ships, in the order they are applied.
///
/// Order is the array's order and not the order the user typed, because
/// `claude` needs `node` whichever way round they were asked for.
pub const CATALOG: &[Profile] = &[BASE, NODE, CLAUDE, CODEX];

/// Look one up by name.
pub fn get(name: &str) -> Option<&'static Profile> {
    CATALOG.iter().find(|p| p.name == name)
}

/// Resolve names into profiles: unknown ones refused, required ones pulled
/// in, duplicates dropped, and the result in catalog order.
///
/// The refusal lists the catalog, because the whole set fits on one line and
/// a user who mistyped `cladue` wants to see `claude` rather than be told to
/// go and look it up.
pub fn resolve(names: &[String]) -> Result<Vec<&'static Profile>> {
    let mut wanted: Vec<&'static str> = Vec::new();
    for name in names {
        let Some(profile) = get(name) else {
            bail!(
                "no bootstrap profile called {name:?} — Asterism ships {}",
                CATALOG
                    .iter()
                    .map(|p| p.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        };
        // A `requires` naming something absent would be a bug in this file,
        // not in what the user typed, so it is an assertion rather than a
        // message: the catalog is a constant and the test below walks it.
        for required in profile.requires {
            debug_assert!(get(required).is_some(), "unknown requirement {required:?}");
            wanted.push(required);
        }
        wanted.push(profile.name);
    }
    Ok(CATALOG
        .iter()
        .filter(|p| wanted.contains(&p.name))
        .collect())
}

/// The resolved set of profiles for one instance, and everything the seed
/// needs to carry them into its guest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bootstrap {
    profiles: Vec<&'static Profile>,
}

impl Bootstrap {
    /// Resolve an instance's recorded profile names.
    pub fn resolve(names: &[String]) -> Result<Self> {
        Ok(Bootstrap {
            profiles: resolve(names)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    pub fn profiles(&self) -> &[&'static Profile] {
        &self.profiles
    }

    /// What this set *is*, as one short string: names and versions.
    ///
    /// It is the guest's idea of "already done" and it is folded into the
    /// seed's fingerprint, so bumping a version changes both at once — a
    /// guest cannot end up believing it has applied work that has since been
    /// rewritten under the same name.
    pub fn stamp(&self) -> String {
        self.profiles
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The files this bootstrap writes into the guest: `(path, mode,
    /// content)`, in the order they should be written.
    ///
    /// Rendering them as cloud-config is the seed's job and not this
    /// module's — this one knows what a guest needs, that one knows what
    /// YAML will survive the trip.
    pub fn files(&self) -> Vec<(String, &'static str, String)> {
        if self.is_empty() {
            return Vec::new();
        }
        let mut out = vec![
            (
                "/etc/asterism/bootstrap.stamp".to_owned(),
                "0644",
                format!("{}\n", self.stamp()),
            ),
            (
                "/usr/local/lib/asterism/pkg".to_owned(),
                "0755",
                PKG.to_owned(),
            ),
            (
                "/usr/local/sbin/asterism-bootstrap".to_owned(),
                "0755",
                DRIVER.to_owned(),
            ),
            (
                "/usr/local/sbin/asterism-check".to_owned(),
                "0755",
                self.check_script(),
            ),
            (
                "/etc/systemd/system/asterism-bootstrap.service".to_owned(),
                "0644",
                UNIT.to_owned(),
            ),
        ];
        for (i, profile) in self.profiles.iter().enumerate() {
            for file in profile.files {
                out.push((file.path.to_owned(), file.mode, file.content.to_owned()));
            }
            out.push((
                format!(
                    "/usr/local/lib/asterism/bootstrap.d/{:02}-{}",
                    (i + 1) * 10,
                    profile.name
                ),
                "0755",
                profile.apply_script(),
            ));
        }
        out
    }

    /// The `runcmd` shell that puts the bootstrap in motion.
    ///
    /// It starts a unit rather than doing the work: package installs and two
    /// npm downloads are minutes, `runcmd` is cloud-init's last stage, and a
    /// guest whose ssh is waiting on an `apt-get` is a guest the user thinks
    /// has failed to boot. Starting it `--no-block` from inside cloud-final
    /// also puts it *after* cloud-init's own package work, which is what
    /// keeps the two of them off the same dpkg lock.
    ///
    /// The unit is enabled, so a guest that was powered off mid-install
    /// finishes the job at its next boot instead of staying half-built.
    pub fn runcmd(&self) -> String {
        if self.is_empty() {
            return String::new();
        }
        String::from(RUNCMD)
    }

    /// The verifier, generated from every check in the set.
    ///
    /// Generated rather than shipped whole because the checks belong to the
    /// profiles: adding a profile adds its lines here, and an instance is
    /// never asked whether it has a `claude` nobody installed.
    fn check_script(&self) -> String {
        let mut out = String::from(CHECK_HEAD);
        out.push_str(&format!("want={}\n\n", quote(&self.stamp())));
        out.push_str(CHECK_STATE);
        for profile in &self.profiles {
            out.push_str(&format!("\nsection {}\n", quote(profile.name)));
            for check in profile.checks {
                out.push_str(&format!(
                    "check {} {} {}\n",
                    quote(check.what),
                    quote(check.probe),
                    quote(check.remedy)
                ));
            }
        }
        out.push_str(CHECK_CREDENTIALS);
        out.push_str(CHECK_TAIL);
        out
    }
}

impl Profile {
    /// The script that applies this one profile in the guest.
    fn apply_script(&self) -> String {
        let mut out = format!(
            "#!/bin/sh\n\
             # Asterism bootstrap profile {}, version {}.\n\
             # Regenerated from the seed at every boot — edits here are lost.\n\
             set -e\n",
            self.name, self.version
        );
        for packages in self.packages {
            out.push_str(&format!(
                "/usr/local/lib/asterism/pkg {} {} {}\n",
                quote(packages.apt),
                quote(packages.dnf),
                quote(packages.apk)
            ));
        }
        for step in self.steps {
            out.push_str(step.trim_end());
            out.push('\n');
        }
        out
    }
}

/// Single-quote for `sh`. Every string this module puts into a generated
/// script goes through here, because a remedy is English prose and English
/// prose contains apostrophes.
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

// ---- the catalog -----------------------------------------------------------

/// Everything a person needs before they can do anything at all, and the one
/// thing an agent needs that a person does not: a session that outlives the
/// connection it was started on.
///
/// `tmux` is the answer to the acceptance criterion nobody writes down —
/// close the laptop, come back tomorrow, and the thing you left running is
/// still running. `agent` is `tmux new-session -A`, spelled as a word,
/// because "attach or create" is the only tmux invocation an agent's home
/// ever needs and nobody should have to remember its flags.
const BASE: Profile = Profile {
    name: "base",
    version: 1,
    summary: "git, tmux, curl, jq — and a session that survives a dropped connection",
    requires: &[],
    packages: &[Packages {
        apt: "git tmux curl ca-certificates jq rsync less unzip",
        dnf: "git tmux curl ca-certificates jq rsync less unzip",
        apk: "git tmux curl ca-certificates jq rsync less unzip bash",
    }],
    files: &[
        GuestFile {
            path: "/usr/local/bin/agent",
            mode: "0755",
            content: "#!/bin/sh\n\
                      # Attach to this instance's long-running session, or start it.\n\
                      # The session outlives the ssh connection it started on, so a\n\
                      # dropped wifi is a reconnect and not a lost afternoon.\n\
                      #\n\
                      # With a terminal — ast ssh <instance>, then agent — this attaches.\n\
                      # Without one — ast ssh <instance> -- agent — there is no terminal\n\
                      # to attach to, so the session is started in the background and\n\
                      # where to find it is printed, rather than tmux refusing.\n\
                      if [ -t 1 ]; then\n\
                      \x20 exec tmux new-session -A -s agent \"$@\"\n\
                      fi\n\
                      tmux new-session -A -d -s agent \"$@\"\n\
                      echo 'asterism: the agent session is running — attach to it with \
                      ast ssh <instance>, then agent'\n",
        },
        GuestFile {
            path: "/etc/tmux.conf",
            mode: "0644",
            content: "# Written by Asterism's base profile.\n\
                      set -g history-limit 50000\n\
                      set -g mouse on\n\
                      set -g escape-time 10\n",
        },
        // sshd's own keepalive, which is what notices that a client is gone
        // rather than leaving a session pinned to a laptop that closed. The
        // count is generous on purpose: a phone changing networks should
        // find its session where it left it.
        GuestFile {
            path: "/etc/ssh/sshd_config.d/50-asterism-agent.conf",
            mode: "0644",
            content: "# Written by Asterism's base profile.\n\
                      ClientAliveInterval 30\n\
                      ClientAliveCountMax 20\n\
                      TCPKeepAlive yes\n",
        },
    ],
    steps: &[
        // A drop-in directory is only a directory until the main config
        // includes it, and an image that does not is a setting silently not
        // applied. Say so rather than believing the file was enough.
        "if sshd -T 2>/dev/null | grep -q '^clientaliveinterval 30$'; then\n\
         \x20 systemctl try-restart ssh sshd >/dev/null 2>&1 || true\n\
         else\n\
         \x20 echo 'asterism: this image does not read /etc/ssh/sshd_config.d, so the \
         keepalive was not applied — add ClientAliveInterval 30 to /etc/ssh/sshd_config' >&2\n\
         fi",
    ],
    checks: &[
        Check {
            what: "git",
            probe: "git --version",
            remedy: "the base profile did not install git — journalctl -u asterism-bootstrap",
        },
        Check {
            what: "tmux",
            probe: "tmux -V",
            remedy: "the base profile did not install tmux — journalctl -u asterism-bootstrap",
        },
        Check {
            what: "jq",
            probe: "jq --version",
            remedy: "the base profile did not install jq — journalctl -u asterism-bootstrap",
        },
        Check {
            what: "agent session",
            probe: "test -x /usr/local/bin/agent && echo '/usr/local/bin/agent'",
            remedy: "the tmux helper is missing — reboot to reapply the seed",
        },
        Check {
            what: "ssh keepalive",
            probe: "sshd -T 2>/dev/null | grep '^clientaliveinterval'",
            remedy: "sshd is not reading /etc/ssh/sshd_config.d — a dropped connection may \
                     take an hour to be noticed; add ClientAliveInterval 30 to \
                     /etc/ssh/sshd_config",
        },
    ],
};

/// The runtime both agent CLIs are written in.
///
/// From the distribution's own repositories and nowhere else. Every one of
/// them ships a Node new enough for both CLIs today, and the alternative on
/// offer — a vendor's install script, fetched over https and piped into a
/// root shell — is precisely the unpinned fetch the rest of this tree
/// refuses. When a distribution's Node really is too old, that is a fact the
/// check states, with the version it found, rather than something a
/// bootstrap papers over.
const NODE: Profile = Profile {
    name: "node",
    version: 1,
    summary: "Node.js and npm from the distribution, the runtime both agent CLIs need",
    requires: &["base"],
    packages: &[Packages {
        apt: "nodejs npm",
        dnf: "nodejs npm",
        apk: "nodejs npm",
    }],
    files: &[],
    steps: &[
        "major=$(node --version 2>/dev/null | sed 's/^v//; s/\\..*//')\n\
         if [ -z \"$major\" ] || [ \"$major\" -lt 18 ]; then\n\
         \x20 echo \"asterism: this image's node is ${major:-missing} and the agent CLIs \
         need 18 or newer — install a newer node, then: asterism-check\" >&2\n\
         fi",
    ],
    checks: &[
        Check {
            what: "node",
            probe: "node --version",
            remedy: "no node on this guest — journalctl -u asterism-bootstrap",
        },
        Check {
            what: "node >= 18",
            probe: "test \"$(node --version | sed 's/^v//; s/\\..*//')\" -ge 18 && node --version",
            remedy: "this distribution's node is older than the agent CLIs support (18) — \
                     boot a newer image, or install a newer node and re-run asterism-check",
        },
        Check {
            what: "npm",
            probe: "npm --version",
            remedy: "no npm on this guest — journalctl -u asterism-bootstrap",
        },
    ],
};

/// Claude Code, from the registry its publisher publishes it to.
///
/// Unpinned on purpose, and it is the one place in this tree where that is
/// the right answer: the profile's version governs *how* the CLI is
/// installed, not which release of somebody else's software a user gets, and
/// pinning a patch here would mean an instance created next year installs a
/// year-old agent. What is installed is recorded in the guest, so
/// `asterism-check` can say which version answered.
const CLAUDE: Profile = Profile {
    name: "claude",
    version: 1,
    summary: "Claude Code, with its credential arriving as a handle rather than a key",
    requires: &["base", "node"],
    packages: &[],
    files: &[],
    steps: &["npm install -g --no-fund --no-audit @anthropic-ai/claude-code"],
    checks: &[Check {
        what: "claude",
        probe: "claude --version",
        remedy: "Claude Code is not installed — journalctl -u asterism-bootstrap, then \
                 npm install -g @anthropic-ai/claude-code",
    }],
};

/// Codex, on the same terms as Claude Code above.
const CODEX: Profile = Profile {
    name: "codex",
    version: 1,
    summary: "the Codex CLI, with its credential arriving as a handle rather than a key",
    requires: &["base", "node"],
    packages: &[],
    files: &[],
    steps: &["npm install -g --no-fund --no-audit @openai/codex"],
    checks: &[Check {
        what: "codex",
        probe: "codex --version",
        remedy: "the Codex CLI is not installed — journalctl -u asterism-bootstrap, then \
                 npm install -g @openai/codex",
    }],
};

// ---- what runs in the guest ------------------------------------------------

/// Install packages, whichever package manager this image has.
///
/// Retries rather than failing at the first refusal, because the two things
/// that go wrong on a first boot are both temporary: cloud-init's own
/// package run still holding the lock, and a network that is not up yet. An
/// image with none of the three managers is a different thing entirely — it
/// is a fact about the image — so it says so and stops.
const PKG: &str = "#!/bin/sh\n\
    # usage: pkg '<apt names>' '<dnf names>' '<apk names>'\n\
    # Written by Asterism. Regenerated from the seed at every boot.\n\
    apt=$1\n\
    dnf=$2\n\
    apk=$3\n\
    attempt=1\n\
    while :; do\n\
    \x20 if command -v apt-get >/dev/null 2>&1; then\n\
    \x20   [ -n \"$apt\" ] || exit 0\n\
    \x20   DEBIAN_FRONTEND=noninteractive apt-get update -qq \\\n\
    \x20     && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $apt && exit 0\n\
    \x20 elif command -v dnf >/dev/null 2>&1; then\n\
    \x20   [ -n \"$dnf\" ] || exit 0\n\
    \x20   dnf install -y -q $dnf && exit 0\n\
    \x20 elif command -v apk >/dev/null 2>&1; then\n\
    \x20   [ -n \"$apk\" ] || exit 0\n\
    \x20   apk add --no-cache $apk && exit 0\n\
    \x20 else\n\
    \x20   echo \"asterism: this image has no apt-get, dnf or apk, so nothing can be \
    installed for you — install these by hand: $apt\" >&2\n\
    \x20   exit 1\n\
    \x20 fi\n\
    \x20 if [ \"$attempt\" -ge 6 ]; then\n\
    \x20   echo \"asterism: giving up on: $apt$dnf$apk\" >&2\n\
    \x20   exit 1\n\
    \x20 fi\n\
    \x20 echo \"asterism: package manager busy or offline, retrying in 15s \
    ($attempt/6)\" >&2\n\
    \x20 attempt=$((attempt + 1))\n\
    \x20 sleep 15\n\
    done\n";

/// Run every profile's script, in order, and record what finished.
///
/// The stamp comparison at the top is what makes this cheap on every boot
/// after the first, and what makes a version bump reapply: the seed writes
/// what the instance *should* have, the guest writes what it *does* have,
/// and they are compared rather than assumed.
const DRIVER: &str = "#!/bin/sh\n\
    # Written by Asterism. Applies this instance's bootstrap profiles.\n\
    set -u\n\
    state=/var/lib/asterism/bootstrap.done\n\
    want=$(cat /etc/asterism/bootstrap.stamp 2>/dev/null || echo none)\n\
    have=$(cat \"$state\" 2>/dev/null || echo none)\n\
    if [ \"$have\" = \"$want\" ]; then\n\
    \x20 echo \"asterism: bootstrap already applied ($want)\"\n\
    \x20 exit 0\n\
    fi\n\
    echo \"asterism: applying bootstrap profiles: $want\"\n\
    mkdir -p /var/lib/asterism\n\
    failed=\n\
    for step in /usr/local/lib/asterism/bootstrap.d/*; do\n\
    \x20 [ -x \"$step\" ] || continue\n\
    \x20 echo \"asterism: ${step##*/}\"\n\
    \x20 \"$step\" || { failed=1; echo \"asterism: ${step##*/} did not finish\" >&2; }\n\
    done\n\
    if [ -n \"$failed\" ]; then\n\
    \x20 echo 'asterism: bootstrap incomplete — the guest is usable, and \
    asterism-check says what is missing' >&2\n\
    \x20 exit 1\n\
    fi\n\
    printf '%s\\n' \"$want\" >\"$state\"\n\
    sync\n\
    echo 'asterism: bootstrap applied — verify it with asterism-check'\n";

/// The unit that runs the driver, at this boot and at every boot after.
///
/// The ordering is `cloud-config.service` and not `cloud-final.service`, and
/// the difference is the whole unit working or silently never running again.
/// cloud-init's own package work happens in cloud-config, which is what this
/// wants to stay off the dpkg lock of — but the unit that *starts* this one
/// is cloud-final, and cloud-final is itself `After=multi-user.target`.
/// Ordering after it while being `WantedBy=multi-user.target` is a cycle, and
/// systemd breaks a cycle by deleting a job: the first boot still ran this,
/// because cloud-init starts it by hand, and every boot after it was dropped
/// with one line in the journal. cloud-config is ordered *before*
/// multi-user.target, so it gives the same protection and closes nothing.
///
/// Found by `scripts/e2e-profile.sh`, which reboots the guest and asks.
const UNIT: &str = "[Unit]\n\
    Description=Asterism: apply this instance's bootstrap profiles\n\
    Wants=network-online.target\n\
    After=network-online.target cloud-config.service\n\
    [Service]\n\
    Type=oneshot\n\
    RemainAfterExit=yes\n\
    ExecStart=/usr/local/sbin/asterism-bootstrap\n\
    [Install]\n\
    WantedBy=multi-user.target\n";

/// The `runcmd` half: enable the unit and let go of it.
const RUNCMD: &str = "if command -v systemctl >/dev/null 2>&1; then\n\
    \x20 systemctl daemon-reload\n\
    \x20 systemctl enable asterism-bootstrap.service >/dev/null 2>&1 || true\n\
    \x20 systemctl start --no-block asterism-bootstrap.service >/dev/null 2>&1 \\\n\
    \x20   || echo 'asterism: could not start asterism-bootstrap — run it by hand' >&2\n\
    else\n\
    \x20 # No systemd here, so this boot gets the bootstrap and later boots do\n\
    \x20 # not. asterism-check reports the stamp either way, which is how a\n\
    \x20 # guest in that state is told apart from one that finished.\n\
    \x20 setsid /usr/local/sbin/asterism-bootstrap >/var/log/asterism-bootstrap.log 2>&1 &\n\
    fi\n\
    exit 0";

/// The head of the generated verifier: how a check reports, and nothing else.
const CHECK_HEAD: &str = "#!/bin/sh\n\
    # Written by Asterism. Confirms this guest is what its profiles said it\n\
    # would be — run it whenever you want to know, not just after a boot.\n\
    # Regenerated from the seed at every boot; edits here are lost.\n\
    fails=0\n\
    section() { printf '\\n%s\\n' \"$1\"; }\n\
    check() {\n\
    \x20 if out=$(eval \"$2\" 2>&1); then\n\
    \x20   printf '  ok    %-16s %s\\n' \"$1\" \"$(printf '%s' \"$out\" | head -1)\"\n\
    \x20 else\n\
    \x20   printf '  FAIL  %-16s %s\\n' \"$1\" \"$3\"\n\
    \x20   fails=$((fails + 1))\n\
    \x20 fi\n\
    }\n";

/// Whether the bootstrap finished, which every other check is conditional on.
///
/// A guest three minutes into its first boot fails half the checks below and
/// is perfectly healthy, so this section says which of the two it is instead
/// of leaving a person to guess from a wall of red.
const CHECK_STATE: &str = "\
    section 'bootstrap'\n\
    have=$(cat /var/lib/asterism/bootstrap.done 2>/dev/null || echo none)\n\
    if [ \"$have\" = \"$want\" ]; then\n\
    \x20 printf '  ok    %-16s %s\\n' 'applied' \"$want\"\n\
    else\n\
    \x20 printf '  FAIL  %-16s %s\\n' 'applied' \"this guest is at ${have}, not ${want} — \
    it may still be running: systemctl status asterism-bootstrap\"\n\
    \x20 fails=$((fails + 1))\n\
    fi\n";

/// The section that looks for the thing that should not be there.
///
/// Two searches, and between them they are the whole of what "the credential
/// is not on this disk" can be checked to mean from inside the guest. One:
/// no agent CLI has written a key into a dotfile, which is what happens when
/// somebody pastes one in and is exactly what a snapshot of this disk would
/// then carry. Two: every credential-shaped environment variable holds an
/// Asterism handle — every handle contains `ast-`, by construction, so that a
/// value found in a log is identifiable as a stand-in rather than mistaken
/// for the key it stands in for.
const CHECK_CREDENTIALS: &str = "\
    \nsection 'credentials'\n\
    found=\n\
    for f in /root/.claude/.credentials.json /home/*/.claude/.credentials.json \\\n\
    \x20        /root/.codex/auth.json /home/*/.codex/auth.json \\\n\
    \x20        /root/.netrc /home/*/.netrc; do\n\
    \x20 [ -s \"$f\" ] && found=\"$found $f\"\n\
    done\n\
    if [ -z \"$found\" ]; then\n\
    \x20 printf '  ok    %-16s %s\\n' 'none on disk' 'no agent credential file on this guest'\n\
    else\n\
    \x20 printf '  FAIL  %-16s %s\\n' 'none on disk' \"a credential is on this disk, so it \
    is in every snapshot of it:$found — remove it and bind the secret instead: ast attach \
    <instance> --secret <name> --to <authority>\"\n\
    \x20 fails=$((fails + 1))\n\
    fi\n\
    if [ -r /etc/profile.d/asterism-egress.sh ]; then\n\
    \x20 while IFS= read -r line; do\n\
    \x20   case $line in export\\ *KEY=*|export\\ *TOKEN=*|export\\ *SECRET=*) ;; *) continue ;; esac\n\
    \x20   name=${line#export }\n\
    \x20   value=${name#*=}\n\
    \x20   name=${name%%=*}\n\
    \x20   case $value in *ast-*)\n\
    \x20     printf '  ok    %-16s %s\\n' \"$name\" 'an Asterism handle, not a credential' ;;\n\
    \x20   *)\n\
    \x20     printf '  FAIL  %-16s %s\\n' \"$name\" 'this looks like a real credential rather \
    than a handle — the value should never enter the guest'\n\
    \x20     fails=$((fails + 1)) ;;\n\
    \x20   esac\n\
    \x20 done </etc/profile.d/asterism-egress.sh\n\
    fi\n";

/// The verdict.
const CHECK_TAIL: &str = "\
    \nif [ \"$fails\" -eq 0 ]; then\n\
    \x20 echo\n\
    \x20 echo \"asterism: this guest is ready ($want)\"\n\
    else\n\
    \x20 echo\n\
    \x20 echo \"asterism: $fails check(s) failed\" >&2\n\
    \x20 exit 1\n\
    fi\n";

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Every requirement names a profile that exists, and nothing requires
    /// something later in the catalog than itself — the order the array is
    /// written in is the order things are applied in, so a forward reference
    /// would be work done before what it depends on.
    #[test]
    fn the_catalog_is_internally_consistent() {
        for (i, profile) in CATALOG.iter().enumerate() {
            for required in profile.requires {
                let at = CATALOG.iter().position(|p| p.name == *required);
                let at =
                    at.unwrap_or_else(|| panic!("{} requires unknown {required:?}", profile.name));
                assert!(
                    at < i,
                    "{} requires {required:?}, which is applied after it",
                    profile.name
                );
            }
            assert!(profile.version > 0, "{} has no version", profile.name);
            assert!(
                !profile.checks.is_empty(),
                "{} promises nothing checkable",
                profile.name
            );
        }
    }

    /// Asking for `claude` gets you the runtime it needs, in the order it
    /// needs it, whether or not you knew to ask.
    #[test]
    fn requirements_arrive_with_what_asked_for_them() {
        let resolved = Bootstrap::resolve(&names(&["claude"])).unwrap();
        let got: Vec<&str> = resolved.profiles().iter().map(|p| p.name).collect();
        assert_eq!(got, vec!["base", "node", "claude"]);

        // Typed in any order, listed twice, or with a requirement spelled
        // out: one set, in catalog order.
        let resolved = Bootstrap::resolve(&names(&["codex", "claude", "node", "codex"])).unwrap();
        let got: Vec<&str> = resolved.profiles().iter().map(|p| p.name).collect();
        assert_eq!(got, vec!["base", "node", "claude", "codex"]);
    }

    #[test]
    fn an_unknown_profile_is_refused_with_the_catalog() {
        let err = Bootstrap::resolve(&names(&["cladue"]))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no bootstrap profile called \"cladue\""),
            "{err}"
        );
        assert!(err.contains("base, node, claude, codex"), "{err}");
        // Nothing asked for is nothing to apply, and that is not an error.
        assert!(Bootstrap::resolve(&[]).unwrap().is_empty());
    }

    /// The stamp is what the guest compares itself against, so it has to
    /// move when a profile's version does and stay put otherwise.
    #[test]
    fn the_stamp_names_every_profile_and_its_version() {
        let resolved = Bootstrap::resolve(&names(&["claude"])).unwrap();
        assert_eq!(resolved.stamp(), "base@1 node@1 claude@1");
        assert_eq!(
            Bootstrap::resolve(&names(&["base"])).unwrap().stamp(),
            "base@1"
        );
        // Two sets that differ only in what was asked for still differ here.
        assert_ne!(
            Bootstrap::resolve(&names(&["claude"])).unwrap().stamp(),
            Bootstrap::resolve(&names(&["codex"])).unwrap().stamp()
        );
    }

    /// An empty set writes nothing and runs nothing: an instance created
    /// without `--profile` is exactly the instance it was before profiles
    /// existed, down to the seed's fingerprint.
    #[test]
    fn no_profiles_is_no_bootstrap_at_all() {
        let none = Bootstrap::default();
        assert!(none.files().is_empty());
        assert!(none.runcmd().is_empty());
    }

    #[test]
    fn the_guest_gets_a_driver_a_unit_and_one_script_per_profile() {
        let resolved = Bootstrap::resolve(&names(&["claude"])).unwrap();
        let files = resolved.files();
        let paths: Vec<&str> = files.iter().map(|(p, _, _)| p.as_str()).collect();
        assert!(paths.contains(&"/usr/local/sbin/asterism-bootstrap"));
        assert!(paths.contains(&"/usr/local/sbin/asterism-check"));
        assert!(paths.contains(&"/etc/systemd/system/asterism-bootstrap.service"));
        assert!(paths.contains(&"/usr/local/lib/asterism/bootstrap.d/10-base"));
        assert!(paths.contains(&"/usr/local/lib/asterism/bootstrap.d/20-node"));
        assert!(paths.contains(&"/usr/local/lib/asterism/bootstrap.d/30-claude"));
        // The base profile's own files come along with it.
        assert!(paths.contains(&"/usr/local/bin/agent"));

        // Everything that is run is executable, and everything that is read
        // is not — a driver written 0644 is a bootstrap that never runs.
        for (path, mode, _) in &files {
            let executable = matches!(
                path.as_str(),
                "/usr/local/lib/asterism/pkg"
                    | "/usr/local/sbin/asterism-bootstrap"
                    | "/usr/local/sbin/asterism-check"
                    | "/usr/local/bin/agent"
            ) || path.starts_with("/usr/local/lib/asterism/bootstrap.d/");
            assert_eq!(*mode, if executable { "0755" } else { "0644" }, "{path}");
        }

        // The stamp the guest compares against is written where the driver
        // reads it, and says the same thing the seed hashed.
        let (_, _, stamp) = files
            .iter()
            .find(|(p, _, _)| p == "/etc/asterism/bootstrap.stamp")
            .expect("stamp file");
        assert_eq!(stamp.trim(), resolved.stamp());
    }

    /// The one thing a profile script must never do is silently install
    /// nothing: the package line names all three managers, so an image that
    /// is not Debian still gets what it was promised.
    #[test]
    fn a_profile_script_installs_on_every_package_manager() {
        let script = BASE.apply_script();
        assert!(script.starts_with("#!/bin/sh\n"), "{script}");
        assert!(
            script.contains("/usr/local/lib/asterism/pkg 'git tmux"),
            "{script}"
        );
        // Three quoted arguments on that line, one per manager.
        let line = script
            .lines()
            .find(|l| l.starts_with("/usr/local/lib/asterism/pkg"))
            .unwrap();
        assert_eq!(line.matches('\'').count(), 6, "{line}");
        assert!(PKG.contains("apt-get install"));
        assert!(PKG.contains("dnf install"));
        assert!(PKG.contains("apk add"));
        // And an image with none of them says so instead of appearing to work.
        assert!(PKG.contains("has no apt-get, dnf or apk"));
    }

    /// Prose in a remedy reaches a shell, and English prose has apostrophes
    /// in it. Counting quotes proves nothing here — `'\\''` is how an
    /// apostrophe is spelled inside a quoted string, and it is odd on
    /// purpose — so a real shell is asked how many arguments each generated
    /// line has. Three is right; anything else is a remedy that has become
    /// a command.
    #[test]
    fn generated_shell_survives_an_apostrophe() {
        assert_eq!(quote("it's fine"), "'it'\\''s fine'");
        let script = Bootstrap::resolve(&names(&["claude", "codex"]))
            .unwrap()
            .check_script();
        for line in script
            .lines()
            .filter(|l| l.starts_with("check ") || l.starts_with("section "))
        {
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!(
                    "check() {{ echo $#; }}; section() {{ echo $#; }}; {line}"
                ))
                .output()
                .expect("running /bin/sh");
            let argc = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            let want = if line.starts_with("section ") {
                "1"
            } else {
                "3"
            };
            assert_eq!(argc, want, "{line}");
        }
    }

    /// The verifier asks about every check every profile declares, and about
    /// the two things no profile declares because they are true of all of
    /// them: that the bootstrap finished, and that no credential is on the
    /// disk.
    #[test]
    fn the_verifier_asks_about_everything_in_the_set() {
        let resolved = Bootstrap::resolve(&names(&["claude", "codex"])).unwrap();
        let script = resolved.check_script();
        for profile in resolved.profiles() {
            assert!(
                script.contains(&format!("section '{}'", profile.name)),
                "{script}"
            );
            for check in profile.checks {
                assert!(
                    script.contains(&format!("check '{}'", check.what)),
                    "{script}"
                );
            }
        }
        assert!(script.contains(&format!("want='{}'", resolved.stamp())));
        assert!(script.contains("section 'credentials'"));
        assert!(script.contains(".credentials.json"));
        assert!(script.contains("*ast-*"));
        // A guest that has not finished is told that, rather than being told
        // it is broken.
        assert!(script.contains("systemctl status asterism-bootstrap"));
        // Nothing a profile did not ask for: no codex line without codex.
        let claude_only = Bootstrap::resolve(&names(&["claude"]))
            .unwrap()
            .check_script();
        assert!(!claude_only.contains("check 'codex'"), "{claude_only}");
    }

    /// Every script this module writes into a guest parses as `sh`.
    ///
    /// A syntax error here is invisible from the host and fatal in the
    /// guest: the file lands, the unit runs it, it dies on line one, and the
    /// only evidence is a journal nobody is reading yet. `sh -n` is the
    /// cheapest possible version of the boot that would have found it.
    #[test]
    fn every_generated_script_parses_as_sh() {
        let resolved = Bootstrap::resolve(&names(&["claude", "codex"])).unwrap();
        let mut scripts: Vec<(String, String)> = resolved
            .files()
            .into_iter()
            .filter(|(_, mode, _)| *mode == "0755")
            .map(|(path, _, content)| (path, content))
            .collect();
        scripts.push(("runcmd".to_owned(), resolved.runcmd()));
        assert!(scripts.len() > 5, "nothing was checked: {scripts:?}");
        for (path, script) in scripts {
            let mut child = std::process::Command::new("/bin/sh")
                .arg("-n")
                .stdin(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("running /bin/sh");
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "{path} is not valid sh: {}\n{script}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// The bootstrap is started, not run, from cloud-init's last stage —
    /// minutes of package installs must not be minutes of a guest that
    /// cannot be reached.
    #[test]
    fn the_runcmd_starts_a_unit_rather_than_doing_the_work() {
        let runcmd = Bootstrap::resolve(&names(&["base"])).unwrap().runcmd();
        assert!(runcmd.contains("systemctl start --no-block asterism-bootstrap.service"));
        assert!(runcmd.contains("systemctl enable asterism-bootstrap.service"));
        assert!(!runcmd.contains("apt-get"));
        // Enabled, so a guest cut off mid-install finishes at the next boot.
        assert!(UNIT.contains("WantedBy=multi-user.target"));
        assert!(UNIT.contains("After=network-online.target cloud-config.service"));
        // The regression: a unit wanted by multi-user.target must not be
        // ordered after anything that is itself after multi-user.target.
        // cloud-final is, and ordering after it cost every boot but the
        // first — systemd breaks the cycle by deleting this unit's job.
        assert!(!UNIT.contains("cloud-final"), "{UNIT}");
        // And the driver does nothing at all when the guest is already there.
        assert!(DRIVER.contains("bootstrap already applied"));
    }
}
