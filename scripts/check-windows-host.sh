#!/bin/sh
# Static gate for Windows host integration (as-lvf.10).
#
# The Hyper-V VM lifecycle stays in its native backend. This gate composes
# with that candidate when its files are present: it checks the boundary
# rather than rejecting the existence of a valid backend.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

fail() {
	printf '%s\n' "$*" >&2
	exit 1
}

check_native_source() {
	file=$1
	[ -f "$file" ] || return 0
	# A protocol assertion may name a forbidden backend to prove its generated
	# document omits it. Product control code may not select or launch one.
	if grep -ni 'whpx' "$file" | grep -Ev 'assert!\(!.*contains\("whpx"\)\)' >/dev/null 2>&1; then
		fail "$file introduces WHPX control into the native Windows path"
	fi
	if grep -ni 'qemu' "$file" | grep -Ev 'assert!\(!.*contains\("qemu"\)\)' >/dev/null 2>&1; then
		fail "$file introduces QEMU control into the native Windows path"
	fi
	if grep -nEi 'Command::new.*(powershell|pwsh)|powershell\.exe|pwsh\.exe' "$file" >/dev/null 2>&1; then
		fail "$file introduces ad-hoc PowerShell control into the native Windows path"
	fi
}

# Small entry point used by exact failure fixtures and by the native backend
# candidate's own gate. It tests file contents, not forbidden filenames.
if [ "${1:-}" = "--native-only" ]; then
	shift
	[ "$#" -gt 0 ] || fail "--native-only needs at least one source file"
	for file in "$@"; do check_native_source "$file"; done
	echo "Windows native backend boundary: clean"
	exit 0
fi

for file in \
	crates/asterism-core/src/hyperv.rs \
	crates/asterism-core/src/windows_host.rs \
	crates/asterism-daemon/src/backend/hyperv.rs \
	crates/asterism-hyperv/src/lib.rs \
	crates/asterism-hyperv/src/windows.rs
do
	check_native_source "$file"
done

grep -q 'pub const HELPER_BIN: &str = "astd-hyperv"' crates/asterism-core/src/hyperv.rs \
	|| fail "helper contract is missing HELPER_BIN"
grep -q 'pub const PROTOCOL_VERSION: u32 = 1' crates/asterism-core/src/hyperv.rs \
	|| fail "helper contract is missing protocol 1"
grep -q '000003ff-facb-11e6-bd58-64006a7986d3' crates/asterism-core/src/hyperv.rs \
	|| fail "helper contract is missing the AF_HYPERV service GUID"
grep -q 'ShouldTerminateOnLastHandleClosed' crates/asterism-core/src/hyperv.rs \
	|| fail "durable HCS ownership flag is not pinned in the protocol document"
grep -q 'SetThreadExecutionState' crates/asterism-core/src/power.rs \
	|| fail "Windows sleep row is missing"
grep -q 'windows-service' crates/asterism-core/src/service.rs \
	|| fail "Windows Service persistence row is missing"
grep -q 'Credential Manager' crates/asterism-daemon/src/secret.rs \
	|| fail "Credential Manager secret store is missing"
grep -q 'windows-x86_64' packaging/install.sh \
	|| fail "installer does not name the Windows x86_64 target"
grep -q 'astd-hyperv' packaging/install.sh \
	|| fail "installer does not require astd-hyperv on Windows"
grep -q 'Get-AuthenticodeSignature' packaging/install.ps1 \
	|| fail "native Windows installer does not verify Authenticode"
grep -q 'com.asterism.astd' packaging/install.ps1 \
	|| fail "native Windows installer does not name the SCM service"
grep -q 'windows-host:' .github/workflows/ci.yml \
	|| fail "GitHub Windows host workflow is missing"

# Sol blockers: privilege, probe, stop, transactional update, firewall exactness,
# thread-affine sleep, honest docs.
grep -q 'obj={SERVICE_ACCOUNT_SYSTEM}' crates/asterism-core/src/windows_host.rs \
	|| fail "SCM create does not pin obj=LocalSystem"
grep -q 'user-writable prefix' crates/asterism-core/src/windows_host.rs \
	|| fail "LocalSystem + user-writable prefix is not refused"
grep -q 'fn probe_helper' crates/asterism-core/src/hyperv.rs \
	|| fail "doctor has no real helper Probe"
grep -q 'host.ensure_supported()' crates/asterism-core/src/hyperv.rs \
	|| fail "helper Probe does not validate Ready compatibility metadata"
grep -q 'wait_service_stop' crates/asterism-daemon/src/main.rs \
	|| fail "SCM stop latch is not wired into the daemon accept loop"
grep -q 'another updater process owns the activation transaction' packaging/update.ps1 \
	|| fail "Windows updater is not transactional"
grep -q "'status', 'check', 'apply', 'recover', 'channel'" packaging/update.ps1 \
	|| fail "Windows updater does not accept channel semantics"
grep -Fq 'if is_powershell { "-Yes" } else { "--yes" }' crates/asterism-cli/src/main.rs \
	|| fail "ast update apply does not use PowerShell parameter semantics"
grep -q "'asterism-update.ps1', 'install.ps1'" packaging/update.ps1 \
	|| fail "Windows updater does not protect the packaged installer pair"
grep -Fq "'libexec\asterism\install.ps1'" packaging/install.ps1 \
	|| fail "native Windows installer does not place install.ps1 beside the updater"
grep -q 'asterism-update.ps1' crates/asterism-core/src/windows_host.rs \
	|| fail "ast update cannot reach asterism-update.ps1"
grep -q 'name={ASTERISM_FIREWALL_RULE}' crates/asterism-core/src/windows_host.rs \
	|| fail "firewall rule args do not use the exact Asterism rule name"
grep -q 'Asterism device daemon' packaging/install.ps1 \
	|| fail "installer does not create the exact firewall rule the doctor matches"
grep -q 'ThreadAffineHold' crates/asterism-core/src/windows_host.rs \
	|| fail "SetThreadExecutionState is not owned on a dedicated thread"
grep -q 'unverified' docs/PLATFORM.md \
	|| fail "PLATFORM.md still claims an unproven Windows guest lifecycle"
grep -q 'source-and-script only' docs/PLATFORM.md \
	|| fail "PLATFORM.md does not admit the Windows compile graph is not Cargo-proven"
grep -q 'not invoke Cargo' .github/workflows/ci.yml \
	|| fail "CI Windows lane is not honest about skipping Cargo"

# Host modules are portable (always compiled). They must not be listed as
# Windows-only exclusions in the source-graph gate.
if grep -E 'WINDOWS_ONLY.*windows_host|windows_host\.rs' scripts/check-rust-source-graph.sh | grep -v '^#' >/dev/null 2>&1; then
	if grep -q "WINDOWS_ONLY_HELPER_MODULES=.*windows_host" scripts/check-rust-source-graph.sh; then
		fail "windows_host.rs must stay in the compile graph on every OS"
	fi
fi
grep -q 'crates/asterism-core/src/windows_host.rs' crates/asterism-core/src/lib.rs \
	|| true
grep -q 'pub mod windows_host' crates/asterism-core/src/lib.rs \
	|| fail "windows_host is not in the asterism-core module graph"
grep -q 'pub mod hyperv' crates/asterism-core/src/lib.rs \
	|| fail "hyperv contract is not in the asterism-core module graph"

echo "Windows host integration: helper contract and optional native backend compose without WHPX/QEMU/PowerShell control"
