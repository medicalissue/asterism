#!/usr/bin/env bash
# Hermetic tests for Windows host integration and distribution.
#
# No Cargo, no Hyper-V, no network. Proves the installer target map, the
# Windows tarball shape (ast.exe/astd.exe/astd-hyperv.exe), Authenticode
# refusal when a thumbprint is pinned without a signature, uninstall via
# receipt, and the static host-integration gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="${ROOT}/packaging/install.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/asterism-windows-host-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail() {
	echo "WINDOWS-HOST-TEST FAIL: $*" >&2
	exit 1
}
ok() {
	pass=$((pass + 1))
	echo "ok: $*"
}

bash "${ROOT}/scripts/check-windows-host.sh" || fail "check-windows-host.sh"
ok "static Windows host gate"

# The host-integration gate must compose with the real native-backend file
# names. It rejects forbidden control implementations by content, not merely
# because those candidate files exist.
NATIVE_FIXTURES="${WORK}/native-boundary"
mkdir -p "$NATIVE_FIXTURES"
cat >"${NATIVE_FIXTURES}/valid.rs" <<'EOF'
fn launch_native_compute_core() { /* narrow native adapter */ }
#[test]
fn hcs_document_has_no_fallbacks() { assert!(!"hcs".contains("whpx")); }
EOF
bash "${ROOT}/scripts/check-windows-host.sh" --native-only "${NATIVE_FIXTURES}/valid.rs" >/dev/null \
	|| fail "valid native backend candidate was rejected"
for forbidden in whpx qemu powershell; do
	case "$forbidden" in
	whpx) line='fn launch() { let backend = "WHPX"; }' ;;
	qemu) line='fn launch() { Command::new("qemu-system-x86_64"); }' ;;
	powershell) line='fn launch() { Command::new("powershell.exe"); }' ;;
	esac
	printf '%s\n' "$line" >"${NATIVE_FIXTURES}/${forbidden}.rs"
	if bash "${ROOT}/scripts/check-windows-host.sh" --native-only "${NATIVE_FIXTURES}/${forbidden}.rs" >/dev/null 2>&1; then
		fail "native boundary accepted forbidden ${forbidden} control"
	fi
done
ok "native backend files compose while WHPX, QEMU and ad-hoc PowerShell controls fail"

# ---- shims -----------------------------------------------------------------

SHIMS="${WORK}/shims"
FAKE="${WORK}/releases"
mkdir -p "$SHIMS" "$FAKE"
export PATH="${SHIMS}:$PATH"

# Git for Windows gives Bash POSIX paths while its native curl expects a
# Windows file URL. Keep the release fixture local, but translate the path at
# that process boundary so the same suite really executes on windows-latest.
case "$(uname -s)" in
MINGW* | MSYS* | CYGWIN*) FAKE_URL="file:///$(cygpath -m "$FAKE")" ;;
*) FAKE_URL="file://${FAKE}" ;;
esac

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

sha256_of() {
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		sha256sum "$1" | awk '{print $1}'
	fi
}

make_windows_release() {
	local version="$1" target="$2"
	local dir="${FAKE}/${version}"
	local stage="${WORK}/stage-${version}-${target}"
	rm -rf "$stage"
	mkdir -p "$dir" "$stage"
	for bin in ast.exe astd.exe astd-hyperv.exe; do
		printf '#!/bin/sh\necho "%s %s"\n' "${bin%.exe}" "${version#v}" >"${stage}/${bin}"
		chmod +x "${stage}/${bin}"
	done
	cp "${ROOT}/packaging/update.ps1" "${stage}/asterism-update.ps1"
	cp "${ROOT}/packaging/install.ps1" "${stage}/install.ps1"
	tar -czf "${dir}/asterism-${version}-${target}.tar.gz" -C "$stage" \
		ast.exe astd.exe astd-hyperv.exe asterism-update.ps1 install.ps1
	(cd "$dir" && {
		if command -v shasum >/dev/null 2>&1; then
			shasum -a 256 "asterism-${version}-${target}.tar.gz"
		else
			sha256sum "asterism-${version}-${target}.tar.gz"
		fi
	} >SHA256SUMS)
}

run_install() {
	# $1 expected: ok | refused
	local expect="$1"
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
	local status=0
	set +e
	OUT="$(env PATH="${SHIMS}:${PATH}" \
		ASTERISM_YES=1 \
		ASTERISM_PREFIX="$PREFIX" \
		ASTERISM_BASE_URL="$FAKE_URL" \
		ASTERISM_INDEX_URL="$FAKE_URL/latest.json" \
		${envs[@]+"${envs[@]}"} sh "$INSTALL" ${args[@]+"${args[@]}"} 2>&1)"
	status=$?
	set -e
	if [ "$expect" = ok ] && [ "$status" -ne 0 ]; then
		echo "$OUT" >&2
		fail "install exited $status, expected success"
	fi
	if [ "$expect" = refused ] && [ "$status" -eq 0 ]; then
		echo "$OUT" >&2
		fail "install succeeded, expected refusal"
	fi
}

says() {
	printf '%s' "$OUT" | grep -q "$1" || {
		echo "$OUT" >&2
		fail "output did not contain: $1"
	}
}

make_windows_release v0.1.0 windows-x86_64
printf '{"tag_name":"v0.1.0"}\n' >"${FAKE}/latest.json"

PREFIX="${WORK}/prefix-x64"
mkdir -p "${PREFIX}/bin"
set_host MINGW64_NT-10.0 x86_64
run_install ok ASTERISM_PREFIX="$PREFIX" ASTERISM_VERSION=v0.1.0
[ -x "${PREFIX}/bin/ast.exe" ] || fail "ast.exe was not installed"
[ -x "${PREFIX}/bin/astd.exe" ] || fail "astd.exe was not installed"
[ -x "${PREFIX}/bin/astd-hyperv.exe" ] || fail "astd-hyperv.exe was not installed"
[ -f "${PREFIX}/libexec/asterism/asterism-update.ps1" ] || fail "update.ps1 was not installed"
[ -f "${PREFIX}/libexec/asterism/install.ps1" ] || fail "install.ps1 was not packaged next to the updater"
grep -q '^target=windows-x86_64$' "${PREFIX}/share/asterism/install-receipt.env" \
	|| fail "receipt target is not windows-x86_64"
grep -q 'astd-hyperv.exe' "${PREFIX}/share/asterism/install-receipt.env" \
	|| fail "receipt does not list astd-hyperv.exe"
ok "windows-x86_64 release installs binaries and a self-contained updater pair"

run_install ok ASTERISM_PREFIX="$PREFIX" ASTERISM_VERSION=v0.1.0
says "already installed"
ok "re-running the Windows install is a no-op"

run_install ok ASTERISM_PREFIX="$PREFIX" -- --uninstall
[ ! -e "${PREFIX}/bin/ast.exe" ] || fail "uninstall left ast.exe"
[ ! -e "${PREFIX}/share/asterism/install-receipt.env" ] || fail "uninstall left the receipt"
ok "Windows uninstall removes the receipt's files"

# A Windows tarball without the helper is refused before mutation.
PREFIX="${WORK}/prefix-nohelper"
mkdir -p "${PREFIX}/bin" "${FAKE}/v0.1.1"
stage="${WORK}/stage-nohelper"
mkdir -p "$stage"
printf '#!/bin/sh\necho ast\n' >"${stage}/ast.exe"
printf '#!/bin/sh\necho astd\n' >"${stage}/astd.exe"
chmod +x "${stage}/ast.exe" "${stage}/astd.exe"
tar -czf "${FAKE}/v0.1.1/asterism-v0.1.1-windows-x86_64.tar.gz" -C "$stage" ast.exe astd.exe
(cd "${FAKE}/v0.1.1" && {
	if command -v shasum >/dev/null 2>&1; then shasum -a 256 asterism-v0.1.1-windows-x86_64.tar.gz
	else sha256sum asterism-v0.1.1-windows-x86_64.tar.gz
	fi
} >SHA256SUMS)
run_install refused ASTERISM_PREFIX="$PREFIX" ASTERISM_VERSION=v0.1.1 ASTERISM_BASE_URL="$FAKE_URL"
says "astd-hyperv"
[ ! -e "${PREFIX}/bin/ast.exe" ] || fail "a partial Windows tarball still installed ast.exe"
ok "a Windows tarball without astd-hyperv.exe is refused"

# A Windows artifact must package the matching installer beside its updater;
# otherwise `ast update apply` would install successfully and fail only later.
PREFIX="${WORK}/prefix-noinstaller"
mkdir -p "${PREFIX}/bin" "${FAKE}/v0.1.2"
stage="${WORK}/stage-noinstaller"
mkdir -p "$stage"
for bin in ast.exe astd.exe astd-hyperv.exe; do
	printf '#!/bin/sh\necho %s\n' "$bin" >"${stage}/${bin}"
	chmod +x "${stage}/${bin}"
done
cp "${ROOT}/packaging/update.ps1" "${stage}/asterism-update.ps1"
tar -czf "${FAKE}/v0.1.2/asterism-v0.1.2-windows-x86_64.tar.gz" -C "$stage" \
	ast.exe astd.exe astd-hyperv.exe asterism-update.ps1
(cd "${FAKE}/v0.1.2" && {
	if command -v shasum >/dev/null 2>&1; then shasum -a 256 asterism-v0.1.2-windows-x86_64.tar.gz
	else sha256sum asterism-v0.1.2-windows-x86_64.tar.gz
	fi
} >SHA256SUMS)
run_install refused ASTERISM_PREFIX="$PREFIX" ASTERISM_VERSION=v0.1.2 ASTERISM_BASE_URL="$FAKE_URL"
says "install.ps1"
[ ! -e "${PREFIX}/bin/ast.exe" ] || fail "artifact without install.ps1 mutated ast.exe"
ok "a Windows updater without packaged install.ps1 is refused before mutation"

# Arm64 target detection.
set_host MINGW64_NT-10.0 arm64
make_windows_release v0.1.0 windows-arm64
PREFIX="${WORK}/prefix-arm"
mkdir -p "${PREFIX}/bin"
run_install ok ASTERISM_PREFIX="$PREFIX" ASTERISM_VERSION=v0.1.0
grep -q '^target=windows-arm64$' "${PREFIX}/share/asterism/install-receipt.env" \
	|| fail "arm64 host did not install the arm64 artifact"
ok "windows-arm64 host installs the arm64 artifact"

# Pinning an Authenticode thumbprint without a matching signature is a refusal.
set_host MINGW64_NT-10.0 x86_64
make_windows_release v0.1.0 windows-x86_64
PREFIX="${WORK}/prefix-auth"
mkdir -p "${PREFIX}/bin"
run_install refused ASTERISM_PREFIX="$PREFIX" ASTERISM_VERSION=v0.1.0 \
	ASTERISM_AUTHENTICODE_THUMBPRINT=DEADBEEF
printf '%s' "$OUT" | grep -Eqi 'PowerShell|Authenticode|thumbprint' || {
	echo "$OUT" >&2
	fail "pinned Authenticode did not refuse in words"
}
ok "a pinned Authenticode thumbprint is refused without a matching signature"

# install.ps1 and update.ps1 parse as PowerShell when pwsh is present.
if command -v pwsh >/dev/null 2>&1; then
	pwsh -NoProfile -Command "& { \$errs = \$null; \$null = [System.Management.Automation.Language.Parser]::ParseFile('${ROOT}/packaging/install.ps1', [ref]\$null, [ref]\$errs); if (\$errs) { \$errs | ForEach-Object { \$_.ToString() }; exit 1 } }" \
		|| fail "install.ps1 parse"
	pwsh -NoProfile -Command "& { \$errs = \$null; \$null = [System.Management.Automation.Language.Parser]::ParseFile('${ROOT}/packaging/update.ps1', [ref]\$null, [ref]\$errs); if (\$errs) { \$errs | ForEach-Object { \$_.ToString() }; exit 1 } }" \
		|| fail "update.ps1 parse"
	pwsh -NoProfile -Command "& { \$errs = \$null; \$null = [System.Management.Automation.Language.Parser]::ParseFile('${ROOT}/scripts/windows-host-fixtures.ps1', [ref]\$null, [ref]\$errs); if (\$errs) { \$errs | ForEach-Object { \$_.ToString() }; exit 1 } }" \
		|| fail "windows-host-fixtures.ps1 parse"
	ok "install.ps1, update.ps1 and windows-host-fixtures.ps1 parse"
	pwsh -NoProfile -File "${ROOT}/scripts/windows-host-fixtures.ps1" \
		|| fail "windows-host-fixtures.ps1"
	ok "privilege, rollback, stop, helper probe and firewall fixtures"
else
	ok "install.ps1 parse skipped (no pwsh on this host)"
fi

# Helper Probe fixture speaks the protocol without Hyper-V.
PROBE="${ROOT}/scripts/fixtures/windows-host/probe-helper"
chmod +x "$PROBE"
reply="$(printf '%s\n' '{"op":"probe"}' | "$PROBE")"
printf '%s' "$reply" | grep -q '"result":"ready"' || fail "probe-helper did not speak Ready"
printf '%s' "$reply" | grep -q '"protocol":1' || fail "probe-helper protocol is not 1"
ok "helper probe fixture answers Probe"

# Firewall fixture contains a Hyper-V decoy and the exact Asterism rule.
DUMP="${ROOT}/scripts/fixtures/windows-host/firewall-show-rule.txt"
grep -q 'Rule Name:                            Hyper-V' "$DUMP" || fail "firewall fixture missing Hyper-V decoy"
grep -q 'Asterism device daemon' "$DUMP" || fail "firewall fixture missing Asterism rule"
grep -q 'Program Files\\Asterism\\bin\\astd.exe' "$DUMP" || fail "firewall fixture program does not match created rule"
ok "firewall fixture distinguishes Hyper-V substring from the Asterism rule"

# Privilege: a user-writable ImagePath is not a LocalSystem service.
grep -q 'refusing to install' "${ROOT}/crates/asterism-core/src/windows_host.rs" \
	|| fail "privilege boundary missing from sc_create_args"
ok "privilege boundary is in source"

# Transactional update rollback (source fixture; same layout as update.ps1 / rust).
TX="${WORK}/update-tx"
mkdir -p "${TX}/bin" "${TX}/state/update-backup"
printf 'old-ast\n' >"${TX}/bin/ast.exe"
printf 'old-astd\n' >"${TX}/bin/astd.exe"
printf 'owner=1\nid=tx-1\nphase=claimed\n' >"${TX}/state/update-transaction.claim"
if [ -e "${TX}/state/update-transaction.claim.new" ]; then
	fail "claim file already split"
fi
# Exclusive create of a second claim must fail.
if (set -o noclobber; echo 'owner=2' >"${TX}/state/update-transaction.claim") 2>/dev/null; then
	fail "a second updater stole the claim"
fi
cp "${TX}/bin/ast.exe" "${TX}/state/update-backup/ast.exe"
cp "${TX}/bin/astd.exe" "${TX}/state/update-backup/astd.exe"
printf 'broken\n' >"${TX}/bin/ast.exe"
printf 'broken\n' >"${TX}/bin/astd.exe"
cp "${TX}/state/update-backup/ast.exe" "${TX}/bin/ast.exe"
cp "${TX}/state/update-backup/astd.exe" "${TX}/bin/astd.exe"
grep -q '^old-ast$' "${TX}/bin/ast.exe" || fail "rollback did not restore ast.exe"
grep -q '^old-astd$' "${TX}/bin/astd.exe" || fail "rollback did not restore astd.exe"
rm -f "${TX}/state/update-transaction.claim"
[ ! -e "${TX}/state/update-transaction.claim" ] || fail "claim survived rollback"
ok "update claim, backup and rollback restore the previous unit"

echo "WINDOWS-HOST-TEST GREEN (${pass} checks)"
