#!/usr/bin/env bash
# The installer's test suite, run against a fake release served off disk.
#
# Everything here is hermetic: no network, no GitHub, no writes outside one
# temp directory. A release is a tarball plus a SHA256SUMS file under a
# version directory, so a directory of those files reached through file://
# is the same release the installer sees over https — which is the point.
# `uname`, `git` and `cargo` are shimmed on PATH where a test needs the
# machine to be a machine it is not.
#
# What it proves, one test per line of the acceptance criteria: default
# install, explicit version, upgrade, reinstall, uninstall, a tampered
# tarball refused, an offline machine refused, an unsupported architecture
# refused, and the source escape hatch building the ref it was told to.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="${ROOT}/packaging/install.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/asterism-install-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAKE_RELEASES="${WORK}/releases"
SHIMS="${WORK}/shims"
mkdir -p "$FAKE_RELEASES" "$SHIMS"

pass=0
fail() {
	echo "INSTALL-TEST FAIL: $*" >&2
	exit 1
}
ok() {
	pass=$((pass + 1))
	echo "ok: $*"
}

# ---- a release that never existed ------------------------------------------

# Two tiny scripts standing in for the real binaries: the installer never
# executes what it installs, it only checksums and places it, so a script
# that prints its version tests the placement exactly as well as 40MB of
# Mach-O would.
make_release() {
	local version="$1" target="${2:-darwin-arm64}" helper="${3:-vz}"
	local dir="${FAKE_RELEASES}/${version}"
	local stage="${WORK}/stage-${version}-${target}"
	rm -rf "$stage"
	mkdir -p "$dir" "$stage"
	cat >"${stage}/ast" <<EOF
#!/bin/sh
echo "ast ${version#v}"
EOF
	cat >"${stage}/astd" <<EOF
#!/bin/sh
echo "astd ${version#v}"
EOF
	chmod +x "${stage}/ast" "${stage}/astd"
	# Releases cut before the vz helper existed carry two binaries, and this
	# script still has to install them — pass `novz` for one of those.
	local members=(ast astd)
	if [ "$helper" = vz ]; then
		cat >"${stage}/astd-vz" <<EOF
#!/bin/sh
echo "astd-vz ${version#v}"
EOF
		chmod +x "${stage}/astd-vz"
		members=(ast astd astd-vz)
	elif [ "$helper" = linux ]; then
		for bin in cloud-hypervisor virtiofsd; do
			printf '#!/bin/sh\necho "%s v53.0"\n' "$bin" >"${stage}/${bin}"
			chmod +x "${stage}/${bin}"
		done
		mkdir -p "${stage}/share/asterism/licenses"
		cp "${ROOT}/packaging/linux-components.env" "${stage}/share/asterism/"
		cp "${ROOT}/packaging/asterism-nbd" "${stage}/share/asterism/"
		for license in cloud-hypervisor-Apache-2.0 cloud-hypervisor-BSD-3-Clause \
			virtiofsd-Apache-2.0 virtiofsd-BSD-3-Clause; do
			printf 'test license\n' >"${stage}/share/asterism/licenses/${license}.txt"
		done
		cp "${ROOT}/LICENSE-APACHE" "${stage}/share/asterism/licenses/LICENSE-APACHE"
		cp "${ROOT}/LICENSE-MIT" "${stage}/share/asterism/licenses/LICENSE-MIT"
		if [ -f "${ROOT}/NOTICE" ]; then
			cp "${ROOT}/NOTICE" "${stage}/share/asterism/licenses/NOTICE"
		else
			printf 'NOTICE\n' >"${stage}/share/asterism/licenses/NOTICE"
		fi
		members=(ast astd cloud-hypervisor virtiofsd share)
	fi
	# The first release predates self-update; current releases ship the updater
	# that `ast update` keeps alive while replacing ast itself.
	if [ "$version" != v0.0.9 ]; then
		cp "${ROOT}/packaging/update.sh" "${stage}/asterism-update"
		chmod +x "${stage}/asterism-update"
		members+=(asterism-update)
	fi
	tar -czf "${dir}/asterism-${version}-${target}.tar.gz" -C "$stage" "${members[@]}"
	# A release also publishes the rendered Homebrew formula, and it is
	# listed in SHA256SUMS like everything else — the installer checks it
	# before pointing Homebrew at a local tap.
	"${ROOT}/scripts/render-formula.sh" "$version" \
		0000000000000000000000000000000000000000000000000000000000000000 \
		>"${dir}/asterism.rb"
	(cd "$dir" && sha256_lines "asterism-${version}-${target}.tar.gz" asterism.rb >SHA256SUMS)
}

sha256_lines() {
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$@"
	else
		sha256sum "$@"
	fi
}

# ---- shims -----------------------------------------------------------------

# uname reads two files rather than baking a machine in, so a test can move
# the host between architectures between runs.
cat >"${SHIMS}/uname" <<EOF
#!/bin/sh
case "\$1" in
-s) cat "${WORK}/uname-s" ;;
-m) cat "${WORK}/uname-m" ;;
*) cat "${WORK}/uname-s" ;;
esac
EOF
chmod +x "${SHIMS}/uname"

set_host() {
	printf '%s' "$1" >"${WORK}/uname-s"
	printf '%s' "$2" >"${WORK}/uname-m"
}
set_host Darwin arm64

# git and cargo, for the source path: the clone records the ref it was asked
# for so a test can assert which ref that was, and the build drops two
# binaries where cargo would have.
cat >"${SHIMS}/git" <<EOF
#!/bin/sh
# git clone --depth 1 --branch <ref> <url> <dst>
if [ "\$1" = "clone" ]; then
	ref=""; dst=""
	while [ \$# -gt 0 ]; do
		case "\$1" in
		--branch) shift; ref="\$1" ;;
		http*|git@*) : ;;
		--*) : ;;
		*) dst="\$1" ;;
		esac
		shift
	done
	mkdir -p "\$dst/.git"
	# A clone carries the repository's scripts, and the source path signs
	# the vz helper with one of them.
	mkdir -p "\$dst/scripts" "\$dst/crates/asterism-vz" "\$dst/packaging"
	cp "${ROOT}/scripts/sign-vz.sh" "\$dst/scripts/sign-vz.sh"
	cp "${ROOT}/crates/asterism-vz/vz.entitlements" "\$dst/crates/asterism-vz/vz.entitlements"
	cp "${ROOT}/packaging/update.sh" "\$dst/packaging/update.sh"
	cp "${ROOT}/packaging/linux-components.env" "\$dst/packaging/linux-components.env"
	cp "${ROOT}/packaging/asterism-nbd" "\$dst/packaging/asterism-nbd"
	printf '%s' "\$ref" >"${WORK}/cloned-ref"
	exit 0
fi
exit 0
EOF
chmod +x "${SHIMS}/git"

cat >"${SHIMS}/cargo" <<EOF
#!/bin/sh
# The build runs inside the clone, so target/ lands beside it.
mkdir -p target/release
printf '#!/bin/sh\necho "ast source-build"\n' >target/release/ast
printf '#!/bin/sh\necho "astd source-build"\n' >target/release/astd
printf '#!/bin/sh\necho "astd-vz source-build"\n' >target/release/astd-vz
chmod +x target/release/ast target/release/astd target/release/astd-vz
printf '%s\n' "\$*" >>"${WORK}/cargo-args"
exit 0
EOF
chmod +x "${SHIMS}/cargo"

cat >"${SHIMS}/setcap" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"${SHIMS}/nbd-client" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"${SHIMS}/modprobe" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"${WORK}/modprobe-args"
EOF
cat >"${SHIMS}/visudo" <<'EOF'
#!/bin/sh
[ "$1" = "-cf" ] && [ -s "$2" ]
EOF
cat >"${SHIMS}/sudo" <<'EOF'
#!/bin/sh
exec "$@"
EOF
cat >"${SHIMS}/chown" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "${SHIMS}/setcap" "${SHIMS}/nbd-client" "${SHIMS}/modprobe" \
	"${SHIMS}/visudo" "${SHIMS}/sudo" "${SHIMS}/chown"

# codesign, for the vz helper. Enough of one to answer the three questions
# asked of it: sign this, does it carry the entitlement, does the signature
# verify. A path listed in ${WORK}/unsigned answers as an unsigned binary,
# which is how the "installed but not entitled" branch gets tested without
# a real Mach-O to mangle.
cat >"${SHIMS}/codesign" <<EOF
#!/bin/sh
mode=sign
last=""
for a in "\$@"; do
	case "\$a" in
	-d) mode=display ;;
	--verify) mode=verify ;;
	esac
	last="\$a"
done
if grep -qxF "\$last" "${WORK}/unsigned" 2>/dev/null; then
	echo "\${last}: code object is not signed at all" >&2
	exit 1
fi
case "\$mode" in
display)
	cat <<'PLIST'
[Dict]
	[Key] com.apple.security.network.client
	[Value]
		[Bool] true
	[Key] com.apple.security.virtualization
	[Value]
		[Bool] true
PLIST
	;;
verify) ;;
sign) printf '%s\n' "\$*" >>"${WORK}/codesign-args" ;;
esac
exit 0
EOF
chmod +x "${SHIMS}/codesign"

# brew, for the Homebrew path. Enough of a Homebrew to be a real test: it
# keeps more than one tap, remembers what is installed, and what it installs
# is whatever version the formula in the named tap pins — which is the only
# way a test can catch a tap quietly serving a version nobody asked for.
cat >"${SHIMS}/brew" <<EOF
#!/bin/sh
taps="${WORK}/taps"
installed="${WORK}/brew-installed"

# Tap names have slashes and so would collide as directory names; each tap
# directory carries its own name instead of encoding it in the path.
tapdir_for() {
	for d in "\$taps"/*; do
		[ -f "\$d/.tapname" ] || continue
		[ "\$(cat "\$d/.tapname")" = "\$1" ] && { printf '%s' "\$d"; return 0; }
	done
	printf '%s/tap%s' "\$taps" "\$(ls "\$taps" 2>/dev/null | wc -l | tr -d ' ')"
}

case "\$1" in
tap)
	if [ \$# -eq 1 ]; then
		# One name per line: the installer matches whole lines, and the
		# name files carry no trailing newline of their own.
		for d in "\$taps"/*; do
			[ -f "\$d/.tapname" ] || continue
			printf '%s\n' "\$(cat "\$d/.tapname")"
		done
		exit 0
	fi
	# No tap this test did not create is published.
	exit 1
	;;
untap) exit 0 ;;
tap-new)
	shift
	for a in "\$@"; do
		case "\$a" in --*) ;; *) t="\$a" ;; esac
	done
	d="\$(tapdir_for "\$t")"
	mkdir -p "\$d/Formula"
	printf '%s' "\$t" >"\$d/.tapname"
	exit 0
	;;
--repository)
	tapdir_for "\$2"
	printf '\n'
	exit 0
	;;
list)
	[ -f "\$installed" ] || exit 1
	printf 'asterism %s\n' "\$(cat "\$installed")"
	exit 0
	;;
uninstall)
	rm -f "\$installed"
	exit 0
	;;
install | reinstall)
	printf '%s\n' "\$*" >>"${WORK}/brew-args"
	for a in "\$@"; do fq="\$a"; done
	d="\$(tapdir_for "\${fq%/*}")"
	formula="\$d/Formula/asterism.rb"
	case " \$* " in
	*" --HEAD "*)
		printf 'HEAD' >"\$installed"
		exit 0
		;;
	esac
	# What Homebrew installs is the version the formula pins, so read it
	# back out of the stable url rather than being told.
	v="\$(sed -n 's|.*/tags/v\(.*\)\.tar\.gz.*|\1|p' "\$formula" | head -n 1)"
	[ -n "\$v" ] || { echo "shim: no stable version in \$formula" >&2; exit 1; }
	printf '%s' "\$v" >"\$installed"
	exit 0
	;;
esac
exit 0
EOF
chmod +x "${SHIMS}/brew"

# The tap directory the shim would hand Homebrew for a given tap name.
tapdir() {
	local d
	for d in "${WORK}/taps"/*; do
		[ -f "$d/.tapname" ] || continue
		[ "$(cat "$d/.tapname")" = "$1" ] && { printf '%s' "$d"; return 0; }
	done
	return 1
}

brew_installed() { cat "${WORK}/brew-installed"; }
reset_brew() { rm -rf "${WORK}/taps" "${WORK}/brew-args" "${WORK}/brew-installed"; }

# ---- running the installer -------------------------------------------------

PREFIX=""
fresh_prefix() {
	PREFIX="${WORK}/prefix-$1"
	rm -rf "$PREFIX"
	mkdir -p "${PREFIX}/bin"
}

# run_install <ok|refused> [VAR=value ...] [-- <installer args>]
run_install() {
	local mode="$1"
	shift
	local envs=() args=()
	while [ $# -gt 0 ]; do
		if [ "$1" = "--" ]; then
			shift
			args=("$@")
			break
		fi
		envs+=("$1")
		shift
	done
	local out status=0
	# bash 3.2 is what macOS ships, and there an empty array under `set -u`
	# is an error rather than nothing — hence the ${a[@]+"${a[@]}"} guards.
	out="$(env PATH="${SHIMS}:${PATH}" \
		HOME="${WORK}/home" \
		ASTERISM_YES=1 \
		ASTERISM_PREFIX="$PREFIX" \
		ASTERISM_SYSTEM_ROOT="${WORK}/system-root" \
		ASTERISM_BASE_URL="file://${FAKE_RELEASES}" \
		ASTERISM_INDEX_URL="file://${WORK}/latest.json" \
		${envs[@]+"${envs[@]}"} sh "$INSTALL" ${args[@]+"${args[@]}"} 2>&1)" || status=$?
	OUT="$out"
	case "$mode" in
	ok) [ "$status" -eq 0 ] || fail "expected success, got ${status}:"$'\n'"$out" ;;
	refused) [ "$status" -ne 0 ] || fail "expected a refusal, got success:"$'\n'"$out" ;;
	esac
}

# `--` because the needles include things like --HEAD, which grep would
# otherwise read as one of its own options and fail on.
says() { grep -qF -- "$1" <<<"$OUT" || fail "expected \"$1\" in:"$'\n'"$OUT"; }
never_says() { grep -qF -- "$1" <<<"$OUT" && fail "did not expect \"$1\" in:"$'\n'"$OUT"; return 0; }
installed_version() { "${PREFIX}/bin/ast" --version; }
receipt() { cat "${PREFIX}/share/asterism/install-receipt.env"; }

mkdir -p "${WORK}/home"
# v0.0.9 stands in for a release cut before the vz helper shipped; v0.1.0
# and everything after it carries one.
make_release v0.0.9 darwin-arm64 novz
make_release v0.1.0
make_release v0.1.1 linux-x86_64 linux
printf '{"tag_name": "v0.1.0", "name": "v0.1.0"}\n' >"${WORK}/latest.json"

# ---- 1. the script itself --------------------------------------------------

sh -n "$INSTALL" || fail "install.sh is not valid POSIX sh"
sh -n "${ROOT}/packaging/asterism-nbd" || fail "asterism-nbd is not valid POSIX sh"
bash -n "${ROOT}/scripts/package-linux.sh" || fail "package-linux.sh is not valid bash"
if command -v shellcheck >/dev/null 2>&1; then
	shellcheck -s sh "$INSTALL" "${ROOT}/packaging/asterism-nbd" || fail "shellcheck found problems in install.sh"
	ok "sh -n and shellcheck are clean"
else
	ok "sh -n is clean (shellcheck not installed)"
fi

if grep -n 'master' "$INSTALL"; then
	fail "install.sh still names the master branch"
fi
ok "no reference to a master branch anywhere in the installer"

# Every privileged command goes through run_root, which prints it and asks
# first. One `sudo` in the whole file, and it is that one.
sudo_calls="$(grep -cE '^[[:space:]]*sudo ' "$INSTALL" || true)"
[ "$sudo_calls" = "1" ] || fail "expected exactly one sudo call (inside run_root), found ${sudo_calls}"
grep -qE '^[[:space:]]*sudo "\$@"$' "$INSTALL" || fail "the one sudo call is not run_root's"
ok "the only privileged command is run_root's, which prints it and asks first"

# ---- 2. default install ----------------------------------------------------

fresh_prefix default
run_install ok
says "release v0.1.0 for darwin-arm64"
says "sha256 ok:"
says "installed ${PREFIX}/bin/ast"
says "installed ${PREFIX}/bin/astd"
[ -x "${PREFIX}/bin/ast" ] || fail "ast was not installed"
[ -x "${PREFIX}/bin/astd" ] || fail "astd was not installed"
[ "$(installed_version)" = "ast 0.1.0" ] || fail "wrong version installed: $(installed_version)"
grep -q '^version=v0.1.0$' <<<"$(receipt)" || fail "receipt does not record the version:"$'\n'"$(receipt)"
grep -q '^method=release$' <<<"$(receipt)" || fail "receipt does not record the method"
[ -x "${PREFIX}/libexec/asterism/asterism-update" ] || fail "the signed updater was not installed"
ok "the default install resolves the latest tag and verifies it"

# The helper is the difference between a machine that can run
# Virtualization.framework guests and one that can only run QEMU, so it is
# installed, recorded, and the same build as the rest.
says "installed ${PREFIX}/bin/astd-vz"
[ -x "${PREFIX}/bin/astd-vz" ] || fail "astd-vz was not installed"
[ "$("${PREFIX}/bin/astd-vz" --version)" = "astd-vz 0.1.0" ] \
	|| fail "astd-vz is not the version that was installed: $("${PREFIX}/bin/astd-vz" --version)"
grep -q '^files=bin/ast bin/astd bin/astd-vz libexec/asterism/asterism-update$' <<<"$(receipt)" \
	|| fail "the receipt does not record the helper:"$'\n'"$(receipt)"
never_says "does not carry the virtualization"
ok "the vz helper is installed beside the daemon and recorded in the receipt"

# ---- 3. reinstall is a no-op, and FORCE overrides it -----------------------

run_install ok
says "already installed: v0.1.0"
never_says "downloading"
ok "re-running on an up-to-date machine downloads nothing"

run_install ok ASTERISM_FORCE=1
says "downloading"
says "sha256 ok:"
[ "$(installed_version)" = "ast 0.1.0" ] || fail "force reinstall changed the version"
ok "ASTERISM_FORCE=1 reinstalls the same version"

# An entitled helper is the whole point of shipping one, so a helper that
# lost its signature is said out loud at install time rather than found by
# `ast create --backend vz` later.
fresh_prefix unentitled
printf '%s\n' "${PREFIX}/bin/astd-vz" >"${WORK}/unsigned"
run_install ok
says "does not carry the virtualization"
says "QEMU backend"
: >"${WORK}/unsigned"
ok "a helper whose signature carries no entitlement is called out at install time"

# ---- 4. an explicit version, and upgrading off it --------------------------

fresh_prefix pinned
run_install ok ASTERISM_VERSION=v0.0.9
says "release v0.0.9 for darwin-arm64"
[ "$(installed_version)" = "ast 0.0.9" ] || fail "explicit version was not honoured"
ok "ASTERISM_VERSION installs exactly that tag"

# A release with no helper in it installs, rather than being refused as a
# partial release: this script installs any tag it is pointed at, including
# the ones cut before the helper existed. What it does not do is stay quiet
# about what that costs.
[ ! -e "${PREFIX}/bin/astd-vz" ] || fail "a release with no helper installed one anyway"
says "This release ships no astd-vz"
grep -q '^files=bin/ast bin/astd$' <<<"$(receipt)" \
	|| fail "the receipt claims files the release did not carry:"$'\n'"$(receipt)"
ok "a release cut before the helper existed installs, and says what is missing"

# The pinned digest is the offline-verifiable path: no SHA256SUMS fetched.
DIGEST="$(sha256_lines "${FAKE_RELEASES}/v0.0.9/asterism-v0.0.9-darwin-arm64.tar.gz" | cut -d' ' -f1)"
run_install ok ASTERISM_VERSION=v0.0.9 ASTERISM_FORCE=1 ASTERISM_SHA256="$DIGEST"
says "digest pinned by ASTERISM_SHA256"
never_says "downloading file://${FAKE_RELEASES}/v0.0.9/SHA256SUMS"
ok "ASTERISM_SHA256 pins the digest without fetching SHA256SUMS"

run_install ok
says "upgraded v0.0.9 -> v0.1.0"
[ "$(installed_version)" = "ast 0.1.0" ] || fail "upgrade did not replace the binary"
grep -q '^version=v0.1.0$' <<<"$(receipt)" || fail "upgrade did not update the receipt"
[ -x "${PREFIX}/bin/astd-vz" ] || fail "the upgrade did not install the helper the new release carries"
ok "an upgrade replaces every binary, adds one the old release lacked, and rewrites the receipt"

# Downgrading is the same machinery pointed the other way — and it takes the
# helper with it. `astd` spawns whatever astd-vz sits beside it, so a helper
# left over from a newer build would be a v0.1.0 helper answering a v0.0.9
# daemon.
run_install ok ASTERISM_VERSION=v0.0.9
[ "$(installed_version)" = "ast 0.0.9" ] || fail "downgrade did not take"
says "removed ${PREFIX}/bin/astd-vz"
[ ! -e "${PREFIX}/bin/astd-vz" ] || fail "a helper from the newer build survived the downgrade"
grep -q '^files=bin/ast bin/astd$' <<<"$(receipt)" || fail "the receipt still claims a helper"
ok "naming an older tag moves back to it, and removes a helper that release never had"

# Re-running on that machine is still a no-op: "already installed" is a
# claim about the files the receipt names, and it names two here.
run_install ok ASTERISM_VERSION=v0.0.9
says "already installed: v0.0.9"
never_says "downloading"
ok "a release with no helper is not reinstalled on every run looking for one"

# ---- 5. uninstall ----------------------------------------------------------

fresh_prefix uninstall
run_install ok
: >"${PREFIX}/bin/somebody-elses-tool"
run_install ok -- --uninstall
[ ! -e "${PREFIX}/bin/ast" ] || fail "ast survived the uninstall"
[ ! -e "${PREFIX}/bin/astd" ] || fail "astd survived the uninstall"
[ ! -e "${PREFIX}/bin/astd-vz" ] || fail "astd-vz survived the uninstall"
[ ! -e "${PREFIX}/libexec/asterism/asterism-update" ] || fail "asterism-update survived the uninstall"
[ ! -e "${PREFIX}/share/asterism/install-receipt.env" ] || fail "the receipt survived the uninstall"
[ -e "${PREFIX}/bin/somebody-elses-tool" ] || fail "uninstall deleted a file it did not install"
says "left alone"
ok "uninstall removes what the receipt names and nothing else"

run_install refused -- --uninstall
says "no install receipt"
ok "uninstalling twice refuses rather than guessing"

# ---- 6. a tampered tarball -------------------------------------------------

fresh_prefix tampered
make_release v0.2.0
printf 'not the release you were promised' >>"${FAKE_RELEASES}/v0.2.0/asterism-v0.2.0-darwin-arm64.tar.gz"
run_install refused ASTERISM_VERSION=v0.2.0
says "checksum mismatch"
says "Nothing was written."
[ ! -e "${PREFIX}/bin/ast" ] || fail "a tampered tarball still got installed"
ok "a tarball that does not match SHA256SUMS is refused, and nothing is written"

# An artifact absent from SHA256SUMS is refused for the same reason.
fresh_prefix unlisted
mkdir -p "${FAKE_RELEASES}/v0.3.0"
cp "${FAKE_RELEASES}/v0.1.0/asterism-v0.1.0-darwin-arm64.tar.gz" \
	"${FAKE_RELEASES}/v0.3.0/asterism-v0.3.0-darwin-arm64.tar.gz"
: >"${FAKE_RELEASES}/v0.3.0/SHA256SUMS"
run_install refused ASTERISM_VERSION=v0.3.0
says "SHA256SUMS does not list"
ok "an artifact missing from SHA256SUMS is refused"

# A tarball that verifies but holds half a release is refused too: a
# checksum says the bytes are the ones published, not that they are all of
# them.
fresh_prefix partial
mkdir -p "${FAKE_RELEASES}/v0.4.0" "${WORK}/stage-partial"
printf '#!/bin/sh\necho "ast 0.4.0"\n' >"${WORK}/stage-partial/ast"
chmod +x "${WORK}/stage-partial/ast"
tar -czf "${FAKE_RELEASES}/v0.4.0/asterism-v0.4.0-darwin-arm64.tar.gz" \
	-C "${WORK}/stage-partial" ast
"${ROOT}/scripts/render-formula.sh" v0.4.0 \
	0000000000000000000000000000000000000000000000000000000000000000 \
	>"${FAKE_RELEASES}/v0.4.0/asterism.rb"
(cd "${FAKE_RELEASES}/v0.4.0" && sha256_lines "asterism-v0.4.0-darwin-arm64.tar.gz" asterism.rb >SHA256SUMS)
run_install refused ASTERISM_VERSION=v0.4.0
says "has no astd in it"
says "Refusing to install a partial release"
[ ! -e "${PREFIX}/bin/ast" ] || fail "a tarball missing a binary installed the rest of itself"
ok "a tarball missing one of the binaries is refused before anything is written"

# So is a release with no SHA256SUMS at all.
fresh_prefix nosums
rm -f "${FAKE_RELEASES}/v0.3.0/SHA256SUMS"
run_install refused ASTERISM_VERSION=v0.3.0
says "Refusing to install unverified bytes"
ok "a release with no SHA256SUMS is refused"

# ---- 7. offline ------------------------------------------------------------

fresh_prefix offline
run_install refused ASTERISM_INDEX_URL="file://${WORK}/there-is-no-such-file"
says "could not reach"
says "ASTERISM_VERSION"
[ ! -e "${PREFIX}/bin/ast" ] || fail "an unreachable index still installed something"
ok "an unreachable release index refuses and says how to install offline"

fresh_prefix offline-assets
run_install refused ASTERISM_BASE_URL="file://${WORK}/no-releases-here"
says "could not download"
says "Nothing was installed."
ok "unreachable release assets refuse without touching the prefix"

# ---- 8. unsupported architectures ------------------------------------------

for host in "Darwin x86_64" "Linux riscv64" "FreeBSD amd64"; do
	# shellcheck disable=SC2086
	set -- $host
	fresh_prefix "arch-$1-$2"
	set_host "$1" "$2"
	run_install refused
	says "no binary release for $1 $2"
	says "ASTERISM_METHOD=source"
	[ ! -e "${PREFIX}/bin/ast" ] || fail "$host installed a binary that cannot run on it"
done
set_host Darwin arm64
ok "every host without a binary release is refused by name, pointing at source"

# ---- 8b. Linux exact-artifact install --------------------------------------

fresh_prefix linux-release
set_host Linux x86_64
rm -rf "${WORK}/system-root" "${WORK}/modprobe-args"
run_install ok ASTERISM_VERSION=v0.1.1
says "release v0.1.1 for linux-x86_64"
says "installed ${PREFIX}/bin/cloud-hypervisor"
says "installed ${PREFIX}/bin/virtiofsd"
says "Linux instances default to bundled Cloud Hypervisor v53.0 over KVM."
says "loginctl enable-linger"
[ -x "${PREFIX}/bin/cloud-hypervisor" ] || fail "Cloud Hypervisor was not installed"
[ -x "${PREFIX}/bin/virtiofsd" ] || fail "virtiofsd was not installed"
[ -f "${PREFIX}/share/asterism/linux-components.env" ] || fail "component lock was not installed"
[ -x "${PREFIX}/libexec/asterism/asterism-update" ] || fail "the Linux updater was not installed"
[ -x "${WORK}/system-root/usr/local/libexec/asterism/asterism-nbd" ] \
	|| fail "the root-owned NBD argument boundary was not installed"
grep -qxF 'nbd' "${WORK}/system-root/etc/modules-load.d/asterism-nbd.conf" \
	|| fail "the nbd module is not enabled at boot"
grep -qxF 'options nbd nbds_max=64' "${WORK}/system-root/etc/modprobe.d/asterism-nbd.conf" \
	|| fail "the installed nbd module options do not expose the supported device pool"
grep -qxF 'nbd nbds_max=64' "${WORK}/modprobe-args" \
	|| fail "the installer did not load the nbd module for immediate use"
policy="${WORK}/system-root/etc/sudoers.d/asterism-nbd-$(id -u)"
grep -qF 'NOPASSWD:' "$policy" || fail "the NBD helper policy is not non-interactive"
grep -qF "${WORK}/system-root/usr/local/libexec/asterism/asterism-nbd" "$policy" \
	|| fail "sudoers grants something other than the root-owned argument boundary"
[ -e "${WORK}/system-root/run/lock/asterism-nbd.lock" ] \
	|| fail "the NBD flock inode was not created"

# A live foreign claim must refuse uninstall and keep cleanup authority.
mkdir -p "${WORK}/system-root/run/asterism-nbd/nbd0"
printf '2000:2000\n' >"${WORK}/system-root/run/asterism-nbd/nbd0/owner"
printf '1\n' >"${WORK}/system-root/run/asterism-nbd/nbd0/helper-pid"
run_install refused -- --uninstall
says "live NBD claims remain"
says "cleanup authority were kept"
[ -x "${WORK}/system-root/usr/local/libexec/asterism/asterism-nbd" ] \
	|| fail "uninstall removed the NBD helper while a live claim existed"
[ -e "$policy" ] || fail "uninstall removed sudoers cleanup authority while a live claim existed"
[ -x "${PREFIX}/bin/cloud-hypervisor" ] || fail "refused uninstall still removed prefix files"
rm -rf "${WORK}/system-root/run/asterism-nbd/nbd0"
run_install ok -- --uninstall
[ ! -e "${PREFIX}/bin/cloud-hypervisor" ] || fail "uninstall left Cloud Hypervisor behind"
[ ! -e "${PREFIX}/share/asterism/linux-components.env" ] || fail "uninstall left component metadata behind"
[ ! -e "$policy" ] || fail "uninstall left the account's NBD sudo policy behind"

# The shared artifact lock is exclusive across install/update/uninstall.
fresh_prefix linux-lock
set_host Linux x86_64
mkdir -p "${PREFIX}/share/asterism/artifact.lock"
sleep 30 &
lock_pid=$!
printf '%s\n' "$lock_pid" >"${PREFIX}/share/asterism/artifact.lock/owner"
run_install refused ASTERISM_VERSION=v0.1.1
says "artifact lock"
kill "$lock_pid" >/dev/null 2>&1 || true
wait "$lock_pid" >/dev/null 2>&1 || true
rm -rf "${PREFIX}/share/asterism/artifact.lock"
ok "a Linux release installs pinned CHV/virtiofsd, NBD policy, and uninstalls exactly"

set_host Darwin arm64

# ---- 9. the source escape hatch --------------------------------------------

fresh_prefix source
rm -f "${WORK}/cloned-ref" "${WORK}/cargo-args"
run_install ok ASTERISM_METHOD=source XDG_CACHE_HOME="${WORK}/cache"
says "building from v0.1.0"
[ "$(cat "${WORK}/cloned-ref")" = "v0.1.0" ] \
	|| fail "the source build cloned $(cat "${WORK}/cloned-ref") instead of the release tag"
grep -q -- "--locked" "${WORK}/cargo-args" || fail "the source build did not pass --locked"
[ "$(installed_version)" = "ast source-build" ] || fail "the source build did not install its binaries"
grep -q '^method=source$' <<<"$(receipt)" || fail "receipt does not record the source method"
ok "ASTERISM_METHOD=source builds the release tag, not a branch"

# Building the helper is not enough — an unsigned one carries no
# virtualization entitlement and VZ will not create a machine in it. The
# source path therefore runs the tree's own signing script, which is the
# same one a release build runs.
says "building and signing astd-vz"
[ -x "${PREFIX}/bin/astd-vz" ] || fail "the source build installed no vz helper"
grep -q -- "--entitlements" "${WORK}/codesign-args" \
	|| fail "the helper was installed without being signed with its entitlements"
grep -q '^files=bin/ast bin/astd bin/astd-vz libexec/asterism/asterism-update$' <<<"$(receipt)" \
	|| fail "the receipt does not record the helper the source build installed:"$'\n'"$(receipt)"
ok "a source install signs the vz helper and lands it beside the daemon"

fresh_prefix source-ref
rm -f "${WORK}/cloned-ref"
run_install ok ASTERISM_METHOD=source ASTERISM_REF=main XDG_CACHE_HOME="${WORK}/cache-main"
says "a git ref, not a release"
[ "$(cat "${WORK}/cloned-ref")" = "main" ] || fail "ASTERISM_REF=main did not clone main"
ok "main is built only when it is asked for by name, and is called out when it is"

# ---- 10. the Homebrew path -------------------------------------------------

fresh_prefix brew
reset_brew
run_install ok ASTERISM_METHOD=brew
says "fetching file://${FAKE_RELEASES}/v0.1.0/asterism.rb"
says "sha256 ok:"
says "brew install medicalissue/asterism/asterism"
never_says "--HEAD"
LOCAL_TAP="$(tapdir medicalissue/asterism)" || fail "no local tap was built"
cmp -s "${LOCAL_TAP}/Formula/asterism.rb" "${FAKE_RELEASES}/v0.1.0/asterism.rb" \
	|| fail "the tap got a formula other than the release's"
grep -q '^install medicalissue/asterism/asterism$' "${WORK}/brew-args" \
	|| fail "brew was handed something other than a plain stable install: $(cat "${WORK}/brew-args")"
[ "$(brew_installed)" = "0.1.0" ] || fail "brew installed $(brew_installed), not 0.1.0"
ok "the brew path installs the release's rendered formula, not the moving branch"

run_install ok ASTERISM_METHOD=brew
says "already installed by Homebrew: asterism 0.1.0"
never_says "brew uninstall"
ok "re-running the brew path on an up-to-date machine hands Homebrew nothing"

# Two releases, both directions. A local tap built for one release and left
# alone is the whole bug: Homebrew resolves what the formula in the tap
# says, so a tap that still holds v0.1.0 installs v0.1.0 no matter which
# version this script resolved. Each step below asserts on the version the
# tap's formula actually pinned, not on what the script said it would do.
fresh_prefix brew-downgrade
run_install ok ASTERISM_METHOD=brew ASTERISM_VERSION=v0.0.9
says "medicalissue/asterism holds v0.1.0 — refreshing it for v0.0.9"
says "moving 0.1.0 -> 0.0.9"
says "brew uninstall asterism"
cmp -s "${LOCAL_TAP}/Formula/asterism.rb" "${FAKE_RELEASES}/v0.0.9/asterism.rb" \
	|| fail "the tap still holds the old release's formula"
[ "$(brew_installed)" = "0.0.9" ] || fail "downgrade left brew on $(brew_installed)"
ok "the brew path downgrades: the tap is refreshed and Homebrew lands on the older tag"

fresh_prefix brew-upgrade
run_install ok ASTERISM_METHOD=brew
says "medicalissue/asterism holds v0.0.9 — refreshing it for v0.1.0"
says "moving 0.0.9 -> 0.1.0"
cmp -s "${LOCAL_TAP}/Formula/asterism.rb" "${FAKE_RELEASES}/v0.1.0/asterism.rb" \
	|| fail "the tap still holds the old release's formula"
[ "$(brew_installed)" = "0.1.0" ] || fail "upgrade left brew on $(brew_installed)"
ok "the brew path upgrades back: a stale tap is refreshed across every version change"

# ---- 11. a published tap, and a version it does not pin --------------------

# A published tap is the distributor of record and this script does not write
# to it. It also pins exactly one version, so a user who names a different one
# has to get that version from somewhere else — and "somewhere else" must not
# be "quietly, the published tap's version".
publish_tap() {
	reset_brew
	mkdir -p "${WORK}/taps/published/Formula"
	printf 'medicalissue/asterism' >"${WORK}/taps/published/.tapname"
	cp "${FAKE_RELEASES}/$1/asterism.rb" "${WORK}/taps/published/Formula/asterism.rb"
	printf '# a published tap, not ours\n' >>"${WORK}/taps/published/Formula/asterism.rb"
	PUBLISHED_SHA="$(sha256_lines "${WORK}/taps/published/Formula/asterism.rb" | cut -d' ' -f1)"
}

fresh_prefix brew-published
publish_tap v0.1.0
run_install ok ASTERISM_METHOD=brew
says "medicalissue/asterism is a published tap and pins v0.1.0"
never_says "refreshing it for"
never_says "fetching"
[ "$(brew_installed)" = "0.1.0" ] || fail "brew installed $(brew_installed) from the published tap"
[ "$(sha256_lines "${WORK}/taps/published/Formula/asterism.rb" | cut -d' ' -f1)" = "$PUBLISHED_SHA" ] \
	|| fail "the published tap's formula was rewritten"
ok "a published tap that pins the resolved version is used as it stands"

# The regression: the published tap pins v0.1.0 and the user asks for v0.0.9.
fresh_prefix brew-published-pin
publish_tap v0.1.0
run_install ok ASTERISM_METHOD=brew ASTERISM_VERSION=v0.1.0
[ "$(brew_installed)" = "0.1.0" ] || fail "setup: expected 0.1.0 installed from the published tap"

run_install ok ASTERISM_METHOD=brew ASTERISM_VERSION=v0.0.9 ASTERISM_FORCE=1
says "medicalissue/asterism is a published tap and does not pin v0.0.9 — leaving it untouched"
says "installing v0.0.9 from medicalissue/asterism-pin instead"
says "sha256 ok:"
says "moving 0.1.0 -> 0.0.9"
says "brew install medicalissue/asterism-pin/asterism"
[ "$(brew_installed)" = "0.0.9" ] \
	|| fail "an explicit ASTERISM_VERSION got $(brew_installed) from the published tap instead"
[ "$(sha256_lines "${WORK}/taps/published/Formula/asterism.rb" | cut -d' ' -f1)" = "$PUBLISHED_SHA" ] \
	|| fail "the published tap's formula was rewritten to serve the pinned version"
[ ! -e "${WORK}/taps/published/.asterism-local-tap" ] \
	|| fail "the published tap was claimed with a stamp"
PIN_TAP_DIR="$(tapdir medicalissue/asterism-pin)" || fail "no pin tap was built"
cmp -s "${PIN_TAP_DIR}/Formula/asterism.rb" "${FAKE_RELEASES}/v0.0.9/asterism.rb" \
	|| fail "the pin tap does not hold the requested release's formula"
[ "$(cat "${PIN_TAP_DIR}/.asterism-local-tap")" = "v0.0.9" ] \
	|| fail "the pin tap is not stamped for the version it was built for"
ok "a version the published tap does not pin comes from a tap this script owns, and the published tap is untouched"

# Coming back to the version the published tap does pin uses it again.
fresh_prefix brew-published-back
run_install ok ASTERISM_METHOD=brew ASTERISM_VERSION=v0.1.0
says "medicalissue/asterism is a published tap and pins v0.1.0"
says "brew install medicalissue/asterism/asterism"
[ "$(brew_installed)" = "0.1.0" ] || fail "did not come back to the published tap's version"
ok "and moving back to the published version uses the published tap again"

# A tap this script did not stamp is never written to, even under a name it
# would otherwise treat as its own.
fresh_prefix brew-pin-owned
publish_tap v0.1.0
mkdir -p "${WORK}/taps/pinsquat/Formula"
printf 'medicalissue/asterism-pin' >"${WORK}/taps/pinsquat/.tapname"
printf '# someone else got here first\n' >"${WORK}/taps/pinsquat/Formula/asterism.rb"
run_install refused ASTERISM_METHOD=brew ASTERISM_VERSION=v0.0.9
says "was not written by this script"
grep -q '^# someone else got here first$' "${WORK}/taps/pinsquat/Formula/asterism.rb" \
	|| fail "an unstamped formula in the pin tap was overwritten"
ok "an unstamped formula is refused rather than overwritten, whichever tap it is in"

fresh_prefix brew-tampered
reset_brew
mkdir -p "${WORK}/brew-tampered/v0.1.0"
cp "${FAKE_RELEASES}/v0.1.0/"* "${WORK}/brew-tampered/v0.1.0/"
printf '\n# tampered\n' >>"${WORK}/brew-tampered/v0.1.0/asterism.rb"
run_install refused ASTERISM_METHOD=brew ASTERISM_BASE_URL="file://${WORK}/brew-tampered"
says "checksum mismatch on asterism.rb"
[ ! -e "${WORK}/brew-args" ] || fail "brew was run despite a tampered formula"
ok "a tampered formula is refused before Homebrew ever sees it"

# ---- 12. a prefix the user does not own ------------------------------------

if [ "$(id -u)" != "0" ]; then
	fresh_prefix readonly
	chmod 500 "${PREFIX}/bin"
	run_install refused
	says "not writable"
	says "ASTERISM_PREFIX"
	chmod 700 "${PREFIX}/bin"
	ok "an unwritable prefix is refused in words, without reaching for root"
else
	ok "unwritable-prefix test skipped (running as root)"
fi

# ---- 13. arguments ---------------------------------------------------------

fresh_prefix args
run_install refused ASTERISM_METHOD=nonsense
says "unknown ASTERISM_METHOD"
ok "an unknown method is refused"

fresh_prefix args2
run_install refused -- --frobnicate
says "unknown argument"
ok "an unknown argument is refused"

echo "INSTALL-TEST GREEN (${pass} checks)"
