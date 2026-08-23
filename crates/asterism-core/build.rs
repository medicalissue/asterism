//! Stamps one immutable build id into every binary in this tree.
//!
//! Two different questions get asked about a binary that is misbehaving, and
//! only one of them is "what version is it". The other is "is this the exact
//! thing we shipped" — which a version number cannot answer, because every
//! build between two tags reports the same one. So the id stamped here names
//! the *source* the artifact was built from, and it is fixed at compile time:
//! nothing at runtime can change what a binary says it is.
//!
//! Shape: `<version>+<source>`, where source is
//!
//!   * `ASTERISM_BUILD_ID` verbatim, when the build was told what to call
//!     itself (the release workflow sets it to the commit being released), or
//!   * the short commit of the checkout being built, suffixed `.dirty` when
//!     the worktree has uncommitted changes, or
//!   * `unknown`, when neither is available — a source tarball with no `.git`
//!     is a legitimate way to build this, and it must not fail the build. It
//!     is honest about not knowing rather than inventing a plausible id.
//!
//! Every public binary in this tree links `asterism-core`, so stamping it in
//! one place makes `ast` and `astd` agree. The separately released Desktop
//! checks that same identity at its signed manifest boundary.

use std::process::Command;

fn main() {
    // A commit is not a file, so cargo has no way to know this went stale.
    // The two inputs it *can* watch are named here; the rest is handled by
    // rebuilding whenever the crate itself does.
    println!("cargo:rerun-if-env-changed=ASTERISM_BUILD_ID");
    println!("cargo:rerun-if-changed=build.rs");

    let source = explicit()
        .or_else(git)
        .unwrap_or_else(|| "unknown".to_owned());
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_owned());
    println!("cargo:rustc-env=ASTERISM_BUILD_ID={version}+{source}");
}

/// What the build was told to call itself, if anything. Sanitised, because
/// this string ends up in `ast version`, in a bug report and in a menu: a
/// newline in it would make one line of output look like two.
fn explicit() -> Option<String> {
    let raw = std::env::var("ASTERISM_BUILD_ID").ok()?;
    let cleaned = sanitise(&raw);
    if cleaned.is_empty() {
        return None;
    }
    Some(cleaned)
}

/// The commit this was built from, marked when the tree it was built from
/// did not match that commit.
fn git() -> Option<String> {
    // Cargo runs this with the crate directory as its cwd, and git searches
    // upward from there. That is the right answer when this crate is being
    // built from its own checkout and the wrong one when it has been vendored
    // inside somebody else's repository, where the commit found would name
    // their tree. Asking git whether it tracks this crate's manifest settles
    // which of the two it is.
    run(&["ls-files", "--error-unmatch", "Cargo.toml"])?;
    let commit = run(&["rev-parse", "--short=12", "HEAD"])?;
    if commit.is_empty() {
        return None;
    }
    // An empty `status --porcelain` is a clean tree. A *failed* status is not
    // evidence of cleanliness, so it is treated as dirty: overstating drift
    // costs a suffix, understating it hides the reason a binary misbehaves.
    let dirty = match run(&["status", "--porcelain", "--untracked-files=no"]) {
        Some(out) => !out.is_empty(),
        None => true,
    };
    Some(if dirty {
        format!("{commit}.dirty")
    } else {
        commit
    })
}

fn run(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(sanitise(&String::from_utf8_lossy(&out.stdout)))
}

/// Keep it to the characters an id is allowed to be made of, so the stamp
/// stays one word on one line however it got here.
fn sanitise(s: &str) -> String {
    s.trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
        .take(64)
        .collect()
}
