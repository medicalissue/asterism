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

# ---- shims -----------------------------------------------------------------

SHIMS="${WORK}/shims"
FAKE="${WORK}/releases"
mkdir -p "$SHIMS" "$FAKE"
export PATH="${SHIMS}:$PATH"

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
	tar -czf "${dir}/asterism-${version}-${target}.tar.gz" -C "$stage" \
		ast.exe astd.exe astd-hyperv.exe asterism-update.ps1
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
		ASTERISM_BASE_URL="file://${FAKE}" \
		ASTERISM_INDEX_URL="file://${FAKE}/latest.json" \
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
grep -q '^target=windows-x86_64$' "${PREFIX}/share/asterism/install-receipt.env" \
	|| fail "receipt target is not windows-x86_64"
grep -q 'astd-hyperv.exe' "${PREFIX}/share/asterism/install-receipt.env" \
	|| fail "receipt does not list astd-hyperv.exe"
ok "windows-x86_64 release installs ast.exe, astd.exe, astd-hyperv.exe and a receipt"

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
run_install refused ASTERISM_PREFIX="$PREFIX" ASTERISM_VERSION=v0.1.1 ASTERISM_BASE_URL="file://${FAKE}"
says "astd-hyperv"
[ ! -e "${PREFIX}/bin/ast.exe" ] || fail "a partial Windows tarball still installed ast.exe"
ok "a Windows tarball without astd-hyperv.exe is refused"

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
	pwsh -NoProfile -Command "& { \$null = [System.Management.Automation.Language.Parser]::ParseFile('${ROOT}/packaging/install.ps1', [ref]\$null, [ref]\$errs); if (\$errs) { \$errs | ForEach-Object { \$_.ToString() }; exit 1 } }" \
		|| fail "install.ps1 parse"
	pwsh -NoProfile -Command "& { \$null = [System.Management.Automation.Language.Parser]::ParseFile('${ROOT}/packaging/update.ps1', [ref]\$null, [ref]\$errs); if (\$errs) { \$errs | ForEach-Object { \$_.ToString() }; exit 1 } }" \
		|| fail "update.ps1 parse"
	ok "install.ps1 and update.ps1 parse"
else
	ok "install.ps1 parse skipped (no pwsh on this host)"
fi

echo "WINDOWS-HOST-TEST GREEN (${pass} checks)"
