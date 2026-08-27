//! One namespace for everything an orbit is addressed by.
//!
//! An orbit holds two kinds of thing a user types the name of: **devices**,
//! the machines that supply compute, and **instances**, the guests that run
//! on them. They share a single namespace, and that is a product decision
//! rather than an implementation convenience:
//!
//! ```text
//! ast ssh bot      # bot's session, wherever in the orbit it runs
//! ast ssh studio   # the host shell on the device called studio
//! ```
//!
//! Both are `ast ssh <name>` because a person holding a laptop does not think
//! of "the instance namespace" and "the device namespace" — they think of
//! things they can reach. The price of that is that a name means exactly one
//! thing, which is what this module is: the refusal when someone tries to
//! make it mean two, and the sentence that lists what the names actually are.
//!
//! In `asterism-core` because both binaries need the same words. The daemon
//! composes the refusals — it is the half that can see the whole orbit — and
//! the CLI prints them; a sentence worded twice is two builds that disagree
//! about what happened.

/// What a name in an orbit turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameKind {
    /// A guest: `ast ssh` opens a shell inside it.
    Instance,
    /// A machine in this orbit: `ast ssh` opens its host shell, if its owner
    /// enabled one.
    Device,
}

impl std::fmt::Display for NameKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NameKind::Instance => "instance",
            NameKind::Device => "device",
        })
    }
}

/// Refusing to create an instance called what a device is already called.
///
/// Carries the remedy on a second line, because "pick another name" is not
/// advice — the user already knows they have to. The line to type is.
///
/// A plain string rather than a [`crate::fix::Fixable`]: this refusal is
/// composed by the daemon, which is the half that can see the orbit, and
/// crosses the unix socket as a `Response::Error` message. A remedy carried
/// beside the sentence in a Rust type would be dropped at that boundary and
/// the user would read half the answer, so it is *in* the sentence.
pub fn instance_name_is_a_device(name: &str, create_line: &str) -> String {
    format!(
        "{name:?} is already a device in this orbit — Instance and device \
         names share one namespace\n  fix: {create_line}"
    )
}

/// The `ast create` line that a refused name suggests instead.
///
/// `studio` becomes `studio-bot`: the device is still recognisable in it, so
/// the user can see the suggestion is about their machine without reading the
/// sentence above it twice.
pub fn suggested_instance_name(name: &str) -> String {
    format!("{name}-bot")
}

/// Refusing to let a device answer to a name an instance already has.
///
/// Reached at pairing and at `ast device rename`. Unlike the create direction
/// there is no single line to type — which name gives way is the user's
/// call — so both remedies are named in the sentence.
pub fn device_name_is_an_instance(name: &str, compute_device: &str) -> String {
    format!(
        "{name:?} is already an instance in this orbit (compute on {compute_device}) \
         — Instance and device names share one namespace: pair with \
         `ast device add <ticket> --name {name}-host`, or rename the instance \
         first with `ast rename {name} <new-name>`"
    )
}

/// The refusal for a name that is neither an instance nor a device.
///
/// Lists both halves of the namespace, because the user's next question is
/// "then what *is* here", and because a name that turns out to be a device
/// when they expected an instance is a thing they can see from this line
/// alone.
pub fn unknown_name(name: &str, devices: &[String], instances: &[String]) -> String {
    let mut parts = Vec::new();
    if !devices.is_empty() {
        parts.push(format!("devices: {}", devices.join(", ")));
    }
    if !instances.is_empty() {
        parts.push(format!("instances: {}", instances.join(", ")));
    }
    if parts.is_empty() {
        return format!("unknown name {name:?} (this orbit has no devices or instances)");
    }
    format!("unknown name {name:?} (orbit has {})", parts.join("; "))
}

/// What `--device` says now that it is gone.
///
/// A flag that is removed outright reads as a typo; one that answers with the
/// form that replaced it is the last thing it ever has to do. Hidden from
/// `--help`, so nobody meets this sentence except the people who already had
/// the old one in their fingers or their scripts.
pub fn device_flag_retired(name: &str) -> String {
    format!(
        "--device is gone: an orbit has one namespace, so a bare name is enough \
         — `ast ssh {name}` for that device's host shell, `ast ssh <instance>` \
         and every other instance command by bare name from any device, and \
         `--on {name}` for the few commands that really are about one device's \
         own storage or images"
    )
}

/// What `ast ssh --host <device>` says now that the bare name does it.
///
/// `--host` was the device half of `ast ssh` back when a device and an
/// instance were addressed differently. They are not any more, so the flag
/// has nothing left to disambiguate.
pub fn host_flag_retired(name: &str) -> String {
    format!("--host is gone: say `ast ssh {name}` — one orbit, one namespace")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal and its remedy are two lines of one string, because they
    /// have to survive the socket between the daemon that composed them and
    /// the terminal that prints them.
    #[test]
    fn creating_an_instance_named_after_a_device_says_so_and_offers_a_name() {
        let name = "studio";
        let refusal = instance_name_is_a_device(
            name,
            &format!(
                "ast create {} --image nginx:alpine",
                suggested_instance_name(name)
            ),
        );
        assert_eq!(
            refusal,
            "\"studio\" is already a device in this orbit — Instance and device \
             names share one namespace\n  fix: ast create studio-bot --image nginx:alpine"
        );
    }

    #[test]
    fn pairing_a_device_named_after_an_instance_names_both_remedies() {
        let refusal = device_name_is_an_instance("bot", "studio");
        assert!(refusal.contains("already an instance in this orbit (compute on studio)"));
        assert!(refusal.contains("--name bot-host"));
        assert!(refusal.contains("ast rename bot <new-name>"));
    }

    #[test]
    fn the_unknown_name_refusal_lists_both_halves_of_the_namespace() {
        let devices = ["macbook".to_owned(), "studio".to_owned(), "dev5".to_owned()];
        let instances = ["bot".to_owned(), "web".to_owned()];
        assert_eq!(
            unknown_name("nope", &devices, &instances),
            "unknown name \"nope\" (orbit has devices: macbook, studio, dev5; instances: bot, web)"
        );
    }

    /// A one-device orbit with nothing on it still has a device — itself — so
    /// the empty-half case is the one worth spelling out separately.
    #[test]
    fn a_half_empty_namespace_lists_only_the_half_that_has_names() {
        assert_eq!(
            unknown_name("nope", &["studio".to_owned()], &[]),
            "unknown name \"nope\" (orbit has devices: studio)"
        );
        assert_eq!(
            unknown_name("nope", &[], &[]),
            "unknown name \"nope\" (this orbit has no devices or instances)"
        );
    }

    #[test]
    fn the_retired_flags_name_the_bare_name_forms_that_replaced_them() {
        let said = device_flag_retired("studio");
        assert!(said.contains("ast ssh studio"), "{said}");
        assert!(said.contains("--on studio"), "{said}");
        assert_eq!(
            host_flag_retired("studio"),
            "--host is gone: say `ast ssh studio` — one orbit, one namespace"
        );
    }
}
