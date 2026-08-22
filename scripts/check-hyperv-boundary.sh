#!/bin/sh
# Static architecture gate for the Windows backend. Runtime/conformance tests
# prove behaviour; this prevents host mechanisms leaking across the helper
# protocol in a way a mock would happily accept.
set -eu

helper=crates/asterism-hyperv/src/windows.rs
daemon=crates/asterism-daemon/src/backend/hyperv.rs

# Git for Windows ships grep but not ripgrep. Spell Rust identifier boundaries
# with POSIX character classes so a longer lookalike cannot satisfy the gate.
for symbol in \
  HcsCreateComputeSystem HcsOpenComputeSystem HcsStartComputeSystem \
  HcsShutDownComputeSystem HcsTerminateComputeSystem HcsSaveComputeSystem \
  HcnCreateNetwork HcnCreateEndpoint CreateVirtualDisk AttachVirtualDisk \
  AF_HYPERV SOCKADDR_HV HV_PROTOCOL_RAW
do
  grep -Eq "(^|[^[:alnum:]_])${symbol}([^[:alnum:]_]|$)" "$helper" || {
    echo "native Hyper-V helper is missing direct API seam ${symbol}" >&2
    exit 1
  }
done

if grep -Eni '(^|[^[:alnum:]_])(qemu|whpx|powershell|pwsh|wmic\.exe)([^[:alnum:]_]|$)' "$helper"; then
  echo "native Hyper-V helper contains a forbidden wrapper/runtime path" >&2
  exit 1
fi

if grep -En 'windows_sys|Hcs[A-Z]|Hcn[A-Z]|CreateVirtualDisk|AF_HYPERV|SOCKADDR_HV' "$daemon"; then
  echo "Windows implementation details leaked above the helper protocol" >&2
  exit 1
fi

grep -Eq '"ShouldTerminateOnLastHandleClosed"[[:space:]]*:[[:space:]]*false' crates/asterism-hyperv/src/lib.rs || {
  echo "durable HCS ownership flag is not pinned in the protocol document" >&2
  exit 1
}

echo "Hyper-V boundary: direct helper APIs present; daemon seam clean"
