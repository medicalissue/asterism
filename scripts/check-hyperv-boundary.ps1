# Native Windows twin of scripts/check-hyperv-boundary.sh.
# Source-only: no Hyper-V, no Cargo, no mutation.
$ErrorActionPreference = "Stop"

Set-Location (Split-Path -Parent $PSScriptRoot)

$Helper = "crates/asterism-hyperv/src/windows.rs"
$Daemon = "crates/asterism-daemon/src/backend/hyperv.rs"
$Protocol = "crates/asterism-hyperv/src/lib.rs"
$Errors = New-Object System.Collections.Generic.List[string]

function Read-Required([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        $script:Errors.Add("missing $Path") | Out-Null
        return ""
    }
    return [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path))
}

$helperText = Read-Required $Helper
$daemonText = Read-Required $Daemon
$protocolText = Read-Required $Protocol

$required = @(
    "HcsCreateComputeSystem",
    "HcsOpenComputeSystem",
    "HcsStartComputeSystem",
    "HcsShutDownComputeSystem",
    "HcsTerminateComputeSystem",
    "HcsSaveComputeSystem",
    "HcnCreateNetwork",
    "HcnCreateEndpoint",
    "CreateVirtualDisk",
    "AttachVirtualDisk",
    "AF_HYPERV",
    "SOCKADDR_HV",
    "HV_PROTOCOL_RAW"
)
foreach ($symbol in $required) {
    if ($helperText -notmatch [regex]::Escape($symbol)) {
        $Errors.Add("native Hyper-V helper is missing direct API seam $symbol") | Out-Null
    }
}

$forbidden = [regex]::new('\b(qemu|whpx|powershell|pwsh|wmic\.exe)\b', 'IgnoreCase')
$forbiddenHit = $false
$n = 0
foreach ($line in ($helperText -split "`n")) {
    $n++
    if ($forbidden.IsMatch($line)) {
        if (-not $forbiddenHit) {
            $Errors.Add("native Hyper-V helper contains a forbidden wrapper/runtime path") | Out-Null
            $forbiddenHit = $true
        }
        $Errors.Add("${Helper}:${n}: $($line.TrimEnd())") | Out-Null
    }
}

$leak = [regex]::new('windows_sys|Hcs[A-Z]|Hcn[A-Z]|CreateVirtualDisk|AF_HYPERV|SOCKADDR_HV')
$leaked = $false
$n = 0
foreach ($line in ($daemonText -split "`n")) {
    $n++
    if ($leak.IsMatch($line)) {
        if (-not $leaked) {
            $Errors.Add("Windows implementation details leaked above the helper protocol") | Out-Null
            $leaked = $true
        }
        $Errors.Add("${Daemon}:${n}: $($line.TrimEnd())") | Out-Null
    }
}

if ($protocolText -notmatch 'ShouldTerminateOnLastHandleClosed.*false') {
    $Errors.Add("durable HCS ownership flag is not pinned in the protocol document") | Out-Null
}

if ($Errors.Count -gt 0) {
    [Console]::Error.WriteLine(($Errors -join [Environment]::NewLine))
    exit 1
}

Write-Output "Hyper-V boundary: direct helper APIs present; daemon seam clean"
