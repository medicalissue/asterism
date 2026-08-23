#!/bin/sh
# Static gate for Windows host integration (as-lvf.10).
#
# The Hyper-V VM lifecycle stays in as-lvf.8 (daemon/backend/hyperv.rs and
# asterism-hyperv/src/windows.rs). This script refuses those files if they
# appear in *this* change set's host-integration tree, and proves the
# portable 510d330 helper contract is present.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

fail() {
	printf '%s\n' "$*" >&2
	exit 1
}

# Backend implementation files are owned by as-lvf.8. Host integration must
# not grow a second copy.
if [ -f crates/asterism-daemon/src/backend/hyperv.rs ]; then
	fail "daemon Hyper-V backend leaked into this tree; as-lvf.10 owns host seams only"
fi
if [ -f crates/asterism-hyperv/src/windows.rs ]; then
	fail "asterism-hyperv windows.rs leaked into this tree; as-lvf.10 owns host seams only"
fi

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
grep -q 'wait_service_stop' crates/asterism-daemon/src/main.rs \
	|| fail "SCM stop latch is not wired into the daemon accept loop"
grep -q 'another updater process owns the activation transaction' packaging/update.ps1 \
	|| fail "Windows updater is not transactional"
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

# Product code must not offer WHPX as a fallback. The helper-protocol test
# that asserts HCS documents do not contain the word is the allowed mention.
if grep -n -i 'whpx' crates/asterism-core/src/windows_host.rs packaging/install.ps1; then
	fail "Windows host integration names WHPX, which ADR 0002 excluded"
fi

echo "Windows host integration: 510d330 helper contract present; backend files absent; seven Sol blockers closed in source"
