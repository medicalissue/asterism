# Asterism — Homebrew formula.
#
# Homebrew is the distributor of record here. `depends_on "qemu"` asks
# Homebrew to install QEMU under its own terms; Asterism never ships a QEMU
# binary and never links QEMU code. See docs/LICENSING.md §2.
#
# Homebrew only installs formulae that live in a tap — a loose .rb path or a
# raw URL is rejected — so this file is the source of truth and the tap
# medicalissue/homebrew-asterism carries a copy. Until the first tag it is
# HEAD-only:
#
#   brew install --HEAD medicalissue/asterism/asterism
#
# See packaging/README.md for the local-tap workflow.
#
class Asterism < Formula
  desc "Run your AI agents 24/7 on hardware you already own"
  homepage "https://asterism.run"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/medicalissue/asterism.git", branch: "main"

  # TODO: first tagged release. When v0.1.0 is cut, add above the `head` line:
  #
  #   stable do
  #     url "https://github.com/medicalissue/asterism/archive/refs/tags/v0.1.0.tar.gz"
  #     sha256 "<shasum -a 256 of that tarball>"
  #   end
  #
  #   livecheck do
  #     url :stable
  #     strategy :github_latest
  #   end
  #
  # and add a bottle block once CI publishes bottles. A tagged tarball is also
  # what `brew audit --strict` wants; a HEAD-only formula cannot pass it.

  depends_on "rust" => :build
  depends_on "qemu"

  def install
    # `brew style` wants `cargo install *std_cargo_args` here, and this is a
    # deliberate departure: two `cargo install --path` runs would compile the
    # shared dependency graph twice, since each gets its own target directory.
    # One `cargo build` naming both packages is a single pass. Swap to
    #
    #   system "cargo", "install", *std_cargo_args(path: "crates/asterism-cli")
    #   system "cargo", "install", *std_cargo_args(path: "crates/asterism-daemon")
    #
    # if the tap's CI ever enforces FormulaAudit/Text.
    #
    # --locked: Cargo.lock is committed, so this resolves to exactly the
    # dependency graph CI tested. Only the two shipped binaries are named;
    # the library crates come along as their dependencies.
    system "cargo", "build", "--release", "--locked",
           "--package", "asterism-cli", "--package", "asterism-daemon"

    # `ast` looks for `astd` as a sibling before falling back to PATH, so both
    # belong in the same bin.
    bin.install "target/release/ast"
    bin.install "target/release/astd"
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

    # The daemon ships alongside the CLI, which is how `ast` finds it.
    assert_predicate bin/"astd", :executable?

    # QEMU is a hard runtime dependency, not a suggestion.
    assert_path_exists formula_opt_bin("qemu")/"qemu-img"
  end
end
