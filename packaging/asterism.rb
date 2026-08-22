# Asterism — Homebrew formula.
#
# Homebrew is the distributor of record here. `depends_on "qemu"` asks
# Homebrew to install QEMU under its own terms; Asterism never ships a QEMU
# binary and never links QEMU code. See docs/LICENSING.md §2.
#
# Homebrew only installs formulae that live in a tap — a loose .rb path or a
# raw URL is rejected — so this file is the source of truth and the tap
# medicalissue/homebrew-asterism carries a copy.
#
# This copy is HEAD-only on purpose: `head` is a moving branch and nobody
# should be installed onto it by accident, so it is never what a plain
# `brew install` resolves to. The tap's copy is the same file with a stable
# block rendered into it at release time:
#
#   scripts/render-formula.sh v0.1.0 > Formula/asterism.rb
#
# which pins one tag and one source-tarball digest. The release workflow
# renders it and attaches it to the release. See packaging/README.md.
#
class Asterism < Formula
  desc "Run your AI agents 24/7 on hardware you already own"
  homepage "https://asterism.run"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/medicalissue/asterism.git", branch: "main"

  # scripts/render-formula.sh replaces the next line with the `stable` and
  # `livecheck` blocks for one tag. A tagged tarball is what `brew audit
  # --strict` wants; a HEAD-only formula cannot pass it, which is why the
  # tap's copy is rendered and this one is not.
  # release:stable-block

  depends_on "rust" => :build
  depends_on "minisign"
  depends_on "qemu"

  def install
    # `brew style` wants `cargo install *std_cargo_args` here, and this is a
    # deliberate departure: two `cargo install --path` runs would compile the
    # shared dependency graph twice, since each gets its own target directory.
    # One `cargo build` naming every package is a single pass. Swap to
    #
    #   system "cargo", "install", *std_cargo_args(path: "crates/asterism-cli")
    #   system "cargo", "install", *std_cargo_args(path: "crates/asterism-daemon")
    #
    # if the tap's CI ever enforces FormulaAudit/Text.
    #
    # --locked: Cargo.lock is committed, so this resolves to exactly the
    # dependency graph CI tested. Only the shipped binaries are named; the
    # library crates come along as their dependencies. `asterism-vz` is
    # named here rather than left to the signing script so that it shares
    # this one pass — and only on macOS, where its guest is the only thing
    # it can run.
    packages = ["--package", "asterism-cli", "--package", "asterism-daemon"]
    packages += ["--package", "asterism-vz"] if OS.mac?
    system "cargo", "build", "--release", "--locked", *packages

    # `ast` looks for `astd` as a sibling before falling back to PATH, so both
    # belong in the same bin.
    bin.install "target/release/ast"
    bin.install "target/release/astd"
    # Homebrew owns these binaries, so the updater only reports that lane and
    # sends activation back to `brew upgrade`. Shipping the same checker still
    # gives the app and CLI one signed-channel/status implementation.
    (libexec/"asterism").install "packaging/update.sh" => "asterism-update"

    # `astd` finds `astd-vz` the same way, and without it every guest runs
    # on QEMU no matter what the machine could do. Building it is not
    # enough: Virtualization.framework refuses to create a machine in a
    # process that does not carry com.apple.security.virtualization, and
    # cargo emits unsigned binaries — so the tree's own signing script signs
    # what the build above produced, which is the same recipe, and the same
    # --sign-only invocation, that the release workflow runs. Homebrew
    # re-signs binaries it relocates with `--preserve-metadata=entitlements`,
    # so the entitlement survives the trip into the Cellar.
    return unless OS.mac?

    system "scripts/sign-vz.sh", "--release", "--sign-only"
    bin.install "target/release/astd-vz"
  end

  def caveats
    <<~EOS
      Asterism runs virtual machines with QEMU, installed here as a dependency.
      Asterism does not distribute QEMU.

      `ast` starts the `astd` daemon on demand; there is nothing to launch by
      hand. State lives in ~/.asterism (override with ASTERISM_HOME).

        ast images
        ast create dev --image debian:13
        ast up dev && ast ssh dev
    EOS
  end

  test do
    assert_match "ast", shell_output("#{bin}/ast --version")

    # The image catalog is compiled in: no daemon, no network, no state.
    images = shell_output("#{bin}/ast images")
    assert_match "ubuntu:24.04", images
    assert_match "debian:13", images

    # The daemon ships alongside the CLI, which is how `ast` finds it, and
    # the vz helper ships alongside the daemon for the same reason.
    assert_predicate bin/"astd", :executable?
    assert_predicate bin/"astd-vz", :executable? if OS.mac?

    # QEMU is a hard runtime dependency, not a suggestion.
    assert_path_exists formula_opt_bin("qemu")/"qemu-img"
  end
end
