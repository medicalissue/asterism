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

# Product code must not offer WHPX as a fallback. The helper-protocol test
# that asserts HCS documents do not contain the word is the allowed mention.
if grep -n -i 'whpx' crates/asterism-core/src/windows_host.rs packaging/install.ps1; then
	fail "Windows host integration names WHPX, which ADR 0002 excluded"
fi

echo "Windows host integration: 510d330 helper contract present; backend files absent; installer/doctor/service seams in place"
