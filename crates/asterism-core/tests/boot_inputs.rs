//! What a boot input has to carry before Asterism will touch it, from
//! outside the crate.
//!
//! These are deliberately integration tests rather than unit tests, for one
//! reason: the claim being made is about the *public* surface. `ast pull`,
//! `ast create` and the daemon's boot path all reach an image through
//! [`asterism_core::image::resolve`], and the guarantee is that a source
//! nothing can vouch for dies there — not in some caller that remembered to
//! check first. A test living inside `image.rs` could reach past that
//! surface; this one cannot, which is the point.
//!
//! The other half of the claim is negative and needs a whole-store view:
//! that a refusal changes *nothing*. So `ASTERISM_HOME` points at a
//! directory that is never created, and every test asserts it still is not
//! there afterwards. A single stray `create_dir_all` on a refusal path fails
//! these tests, whichever function did it.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use asterism_core::verify::{self, Algo, Digest, Source};
use asterism_core::{image, paths};

/// A store that does not exist, and must still not exist when a test ends.
///
/// Set once for the whole test binary. `ASTERISM_HOME` is process-wide, so
/// pointing it somewhere harmless once is the only safe way to use it: no
/// test here creates the directory, and none of them may.
fn absent_store() -> &'static Path {
    static STORE: OnceLock<PathBuf> = OnceLock::new();
    STORE.get_or_init(|| {
        let dir = tempfile::tempdir().expect("a temp dir");
        let store = dir.path().join("store-that-should-stay-absent");
        std::env::set_var("ASTERISM_HOME", &store);
        // The temp dir must outlive every test in this binary; leaking it is
        // how a `OnceLock` value gets a `'static` lifetime, and the OS
        // reclaims it when the process ends.
        std::mem::forget(dir);
        store
    })
}

/// Nothing was created, anywhere the store would be.
fn assert_store_untouched(what: &str) {
    let store = absent_store();
    assert!(
        !store.exists(),
        "{what} created something under {} — a refusal must not mutate the store",
        store.display()
    );
    // And the paths the store is made of are the ones under it, so a caller
    // that built a path and wrote to it would show up above.
    assert!(paths::images_dir().starts_with(store));
}

/// The url an attacker would like you to type: reachable, well-formed,
/// serving whatever they please, and carrying no claim about its own bytes.
const UNPINNED: &[&str] = &[
    "https://mirror.example.invalid/ubuntu-24.04-server-cloudimg-arm64.img",
    "https://cdn.example.invalid/images/debian-13.qcow2?token=abc",
    "https://example.invalid/x.raw#anchor",
    "http://plaintext.example.invalid/x.qcow2",
];

#[test]
fn an_unpinned_url_is_refused_before_anything_is_downloaded_or_written() {
    absent_store();
    for reference in UNPINNED {
        let text = match image::resolve(reference) {
            Err(e) => format!("{e:#}"),
            Ok(r) => panic!(
                "{reference} resolved to {} instead of being refused",
                r.name
            ),
        };

        // Refused, and the refusal is one somebody can act on: it says what
        // is missing, that nothing happened, and exactly what to type.
        assert!(
            text.contains("nothing publishes a digest"),
            "{reference}: {text}"
        );
        assert!(
            text.contains("nothing was downloaded"),
            "{reference}: {text}"
        );
        assert!(text.contains("#sha256:<hex>"), "{reference}: {text}");
        assert!(text.contains("sha512"), "{reference}: {text}");
        assert!(text.contains("blake3"), "{reference}: {text}");
        // And it points at the sources that do come with a digest.
        assert!(text.contains("ast images"), "{reference}: {text}");

        assert_store_untouched(reference);
    }
}

/// A pin in an algorithm this build cannot compute is not a weaker check, it
/// is no check — so it is refused on the same terms, and just as early.
#[test]
fn only_the_digest_algorithms_asterism_can_compute_are_accepted() {
    absent_store();
    let unsupported = [
        ("md5", "d41d8cd98f00b204e9800998ecf8427e"),
        ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("crc32", "00000000"),
    ];
    for (algo, hex) in unsupported {
        let reference = format!("https://mirror.example.invalid/x.qcow2#{algo}:{hex}");
        let text = match image::resolve(&reference) {
            Err(e) => format!("{e:#}"),
            Ok(r) => panic!("{algo} was accepted, resolving to {}", r.name),
        };
        assert!(
            text.contains("unsupported digest algorithm"),
            "{algo}: {text}"
        );
        assert!(text.contains("nothing was pulled"), "{algo}: {text}");
        assert_store_untouched(algo);
    }

    // A supported algorithm with a digest that is not one — truncated,
    // over-long, not hex — is refused too, and as an error about the pin
    // rather than "unknown image".
    for bad in [
        "sha256:abc",
        "sha256:zzzz",
        &format!("sha256:{}", "a".repeat(63)),
        &format!("sha512:{}", "a".repeat(64)),
        &format!("blake3:{}", "a".repeat(128)),
    ] {
        let reference = format!("https://mirror.example.invalid/x.qcow2#{bad}");
        let text = match image::resolve(&reference) {
            Err(e) => format!("{e:#}"),
            Ok(r) => panic!("{bad} was accepted, resolving to {}", r.name),
        };
        assert!(
            text.contains("pins a digest Asterism will not accept"),
            "{bad}: {text}"
        );
        assert_store_untouched(bad);
    }
}

/// The three algorithms that are accepted, each carried end to end: the
/// reference resolves with something to check against, honest bytes are
/// adopted, and substituted bytes are refused.
#[test]
fn a_supported_pin_resolves_and_then_governs_the_adoption() {
    absent_store();
    // Somewhere of its own, so this test can adopt without the store — which
    // every test in this binary insists does not exist — being involved.
    let dir = tempfile::tempdir().unwrap();
    let bytes = b"the image the publisher actually serves";

    for algo in [Algo::Sha256, Algo::Sha512, Algo::Blake3] {
        let digest = Digest::of_bytes(algo, bytes);
        let url = "https://mirror.example.invalid/x.qcow2";
        let resolved = image::resolve(&format!("{url}#{digest}")).unwrap();

        assert_eq!(resolved.url.as_deref(), Some(url), "{algo}");
        assert_eq!(resolved.name, url, "the pin is not part of the name");
        let expected = resolved
            .expected
            .as_ref()
            .expect("a pinned url carries its digest");
        assert_eq!(expected, &digest, "{algo}");
        assert_eq!(expected.algo(), algo);
        assert!(
            resolved.staging.is_some(),
            "a url is downloaded, not used in place"
        );
        assert_store_untouched(algo.name());

        // What `ast pull` does with it once curl has written the `.part`.
        let staged = dir.path().join(format!("{}.part", algo.name()));
        let dest = dir.path().join(format!("{}.raw", algo.name()));
        std::fs::write(&staged, bytes).unwrap();
        let record =
            verify::adopt(&staged, &dest, Some(expected), Source::new("download", url)).unwrap();
        assert_eq!(record.content, digest, "{algo}");
        assert_eq!(record.source, url);
        verify::check(&dest, verify::Depth::Full).unwrap();

        // And the same pin against what an attacker would have served
        // instead: refused, with the store and the destination untouched.
        let poisoned = dir.path().join(format!("{}-bad.part", algo.name()));
        let elsewhere = dir.path().join(format!("{}-bad.raw", algo.name()));
        std::fs::write(&poisoned, b"a backdoored image of the same shape").unwrap();
        let text = format!(
            "{:#}",
            verify::adopt(
                &poisoned,
                &elsewhere,
                Some(expected),
                Source::new("download", url)
            )
            .unwrap_err()
        );
        assert!(
            text.contains("does not match its published digest"),
            "{algo}: {text}"
        );
        assert!(!elsewhere.exists(), "{algo}");
        assert!(
            !poisoned.exists(),
            "{algo}: left where a retry would resume it"
        );
        assert_store_untouched(algo.name());
    }
}

/// Two pins on one url name one file in the store — that is deliberate, so
/// that re-pinning is not a second gigabyte — which makes "is it already
/// pulled" and "is the *right* thing already pulled" different questions.
/// Answering only the first would let a device that holds one image report
/// success for a request naming another.
#[test]
fn a_url_pinned_to_different_bytes_is_not_answered_with_what_is_already_there() {
    absent_store();
    let dir = tempfile::tempdir().unwrap();
    let url = "https://mirror.example.invalid/x.qcow2";
    let served = b"what the mirror served the first time";
    let published = Digest::of_bytes(Algo::Sha256, served);
    let other = Digest::of_bytes(Algo::Sha256, b"the build the user actually wants");

    // Pull once, the way `ast pull` does: download, verify against the pin,
    // adopt, and record the pin as what it came from.
    let first = image::resolve(&format!("{url}#{published}")).unwrap();
    let staged = dir.path().join("x.part");
    let dest = dir.path().join("x.raw");
    std::fs::write(&staged, served).unwrap();
    verify::adopt(
        &staged,
        &dest,
        first.expected.as_ref(),
        Source::new("download", url).derived_from([published.to_string()]),
    )
    .unwrap();

    // The store now holds one file, and both references name it.
    let second = image::resolve(&format!("{url}#{other}")).unwrap();
    assert_eq!(first.path, second.path, "re-pinning is not a second copy");

    // Same file, and it is perfectly sound — but it is not what the second
    // reference asked for, and saying "already pulled" would make the digest
    // the user typed do nothing at all.
    verify::check(&dest, verify::Depth::Full).unwrap();
    let record = verify::provenance(&dest).unwrap();
    assert!(record.derived_from.contains(&published.to_string()));
    assert!(!record.derived_from.contains(&other.to_string()));

    assert_store_untouched("re-pinning");
}

/// The sources that *do* come with a digest still resolve, so the refusal
/// above is about the unverifiable case and not about urls in general.
#[test]
fn the_sources_that_publish_a_digest_are_unaffected() {
    absent_store();
    for entry in image::CATALOG {
        let r = image::resolve(entry.alias).unwrap();
        assert!(
            r.expected.is_some(),
            "{} resolved with nothing to check against",
            entry.alias
        );
        assert!(r.url.is_some(), "{}", entry.alias);
    }
    // A registry reference is checked against the digests in its manifest
    // rather than against a pin, so it resolves without one.
    let oci = image::resolve("docker.io/library/nginx:latest").unwrap();
    assert_eq!(oci.kind(), asterism_core::hv::ImageKind::OciRootfs);
    assert!(oci.url.is_none());
    assert_store_untouched("the sources that publish a digest");
}

/// A file on this disk is not a download and is not refused: the bytes are
/// already here, and what is recorded is that they are the ones the user
/// pointed at. It may still carry a pin.
#[test]
fn a_local_file_is_not_a_url_and_is_not_refused() {
    absent_store();
    let dir = tempfile::tempdir().unwrap();
    let theirs = dir.path().join("mine.raw");
    std::fs::write(&theirs, b"the user's own image").unwrap();

    let r = image::resolve(&theirs.display().to_string()).unwrap();
    assert!(r.url.is_none());
    assert!(r.staging.is_none(), "the user's file is never staged");
    assert!(r.expected.is_none());

    let digest = Digest::of_bytes(Algo::Blake3, b"the user's own image");
    let pinned = image::resolve(&format!("{}#{digest}", theirs.display())).unwrap();
    assert_eq!(pinned.expected.as_ref(), Some(&digest));

    // Resolving is a lookup, so even the local path did not make the store.
    assert_store_untouched("a local file");
}
