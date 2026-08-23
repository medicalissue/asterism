#!/bin/sh
# Static architecture gate for the Windows backend. Runtime/conformance tests
# prove behaviour; this prevents host mechanisms leaking across the helper
# protocol in a way a mock would happily accept.
#
# Intentionally rg-free: GitHub hosted Windows runners and a POSIX operator
# shell both have python3. The PowerShell twin is
# scripts/check-hyperv-boundary.ps1.
set -eu

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

if [ "${1:-}" != "" ]; then
  echo "usage: $0" >&2
  exit 2
fi

helper=crates/asterism-hyperv/src/windows.rs
daemon=crates/asterism-daemon/src/backend/hyperv.rs
protocol=crates/asterism-hyperv/src/lib.rs
ipc_harness=scripts/windows-local-system-ipc.ps1

python3 - "$helper" "$daemon" "$protocol" "$ipc_harness" <<'PY'
import pathlib
import re
import sys

helper, daemon, protocol, ipc_harness = (pathlib.Path(p) for p in sys.argv[1:5])
errors = []

def read(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        errors.append(f"missing {path}")
        return ""

helper_text = read(helper)
daemon_text = read(daemon)
protocol_text = read(protocol)
ipc_harness_text = read(ipc_harness)

required = [
    "HcsCreateComputeSystem",
    "HcsOpenComputeSystem",
    "HcsStartComputeSystem",
    "HcsShutDownComputeSystem",
    "HcsTerminateComputeSystem",
    "HcsSaveComputeSystem",
    "HcnCreateNetwork",
    "HcnCreateEndpoint",
    "HcnDeleteNetwork",
    "CreateVirtualDisk",
    "AttachVirtualDisk",
    "AF_HYPERV",
    "SOCKADDR_HV",
    "HV_PROTOCOL_RAW",
]
for symbol in required:
    if not re.search(rf"\b{re.escape(symbol)}\b", helper_text):
        errors.append(f"native Hyper-V helper is missing direct API seam {symbol}")

forbidden = re.compile(r"\b(qemu|whpx|powershell|pwsh|wmic\.exe)\b", re.I)
hits = [
    f"{helper}:{i}: {line.rstrip()}"
    for i, line in enumerate(helper_text.splitlines(), 1)
    if forbidden.search(line)
]
if hits:
    errors.append("native Hyper-V helper contains a forbidden wrapper/runtime path")
    errors.extend(hits)

if re.search(r"asterism_vz", daemon_text):
    errors.append("daemon Hyper-V backend imports asterism_vz Unix APIs")

leak = re.compile(
    r"windows_sys|Hcs[A-Z]|Hcn[A-Z]|CreateVirtualDisk|AF_HYPERV|SOCKADDR_HV"
)
leaks = [
    f"{daemon}:{i}: {line.rstrip()}"
    for i, line in enumerate(daemon_text.splitlines(), 1)
    if leak.search(line)
]
if leaks:
    errors.append("Windows implementation details leaked above the helper protocol")
    errors.extend(leaks)

if not re.search(r"ShouldTerminateOnLastHandleClosed.*false", protocol_text):
    errors.append("durable HCS ownership flag is not pinned in the protocol document")

if re.search(r"\$home\b", ipc_harness_text, re.I):
    errors.append("LocalSystem IPC harness repurposes PowerShell's reserved HOME variable")

if errors:
    sys.stderr.write("\n".join(errors) + "\n")
    sys.exit(1)

print("Hyper-V boundary: direct helper APIs present; daemon seam clean")
PY
