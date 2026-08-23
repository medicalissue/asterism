# Opt-in Windows 11 Pro/Enterprise real-host harness for the native Hyper-V
# backend. GitHub hosted runners cannot satisfy this: they are Windows Server
# images without nested Hyper-V and without a Windows 11 Pro/Enterprise
# product edition.
#
# Usage:
#   ./scripts/hyperv-real-host-harness.ps1 -ExplainOnly
#   $env:ASTERISM_HYPERV_REAL_HOST = "1"
#   ./scripts/hyperv-real-host-harness.ps1
#
# Operations, in order, once the pre-mutation gates pass:
#   probe, create, boot, control, snapshot, stop, restart, adoption, stop.
param(
    [switch]$ExplainOnly,
    [string]$Instance = "asterism-hyperv-harness",
    [string]$Image = "ubuntu:24.04",
    [string]$EvidenceDir = ""
)

$ErrorActionPreference = "Stop"

function Write-Gap {
    param([string]$Text)
    Write-Output $Text
}

$GithubHostedGaps = @(
    "GitHub hosted windows-latest is Windows Server Datacenter, not Windows 11 Pro or Enterprise",
    "GitHub hosted runners do not expose nested Hyper-V / HCS compute-system mutation",
    "vmcompute/hns may exist as services without a usable HCS v2.1 VM partition",
    "VirtDisk VHDX create/attach against a real compute system cannot be proven",
    "AF_HYPERV/AF_VSOCK guest-agent readiness cannot be proven",
    "create/boot/control/snapshot/restart/adoption/stop of a Linux guest cannot be proven",
    "live guest survival across astd restart cannot be proven"
)

if ($ExplainOnly) {
    Write-Gap "Hyper-V real-host harness: EXPLAIN ONLY"
    Write-Gap "Opt-in: set ASTERISM_HYPERV_REAL_HOST=1 on an elevated Windows 11 Pro/Enterprise host with Hyper-V enabled."
    Write-Gap "GitHub hosted runner gaps (impossible here):"
    foreach ($gap in $GithubHostedGaps) {
        Write-Gap "  - $gap"
    }
    Write-Gap "Unverified until this harness records evidence on a real host: every lifecycle claim above."
    exit 0
}

if ($env:ASTERISM_HYPERV_REAL_HOST -ne "1") {
    Write-Gap "refusing to mutate this host: set ASTERISM_HYPERV_REAL_HOST=1 after reading ADR 0002"
    Write-Gap "Use -ExplainOnly to print the GitHub hosted runner gap without mutation."
    exit 2
}

if ($env:OS -ne "Windows_NT") {
    throw "this harness runs only on Windows 11 Pro or Enterprise"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "the native Hyper-V backend needs an elevated administrator token"
}

$product = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
$build = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
if ($product -notmatch "Pro|Enterprise") {
    throw "the native Hyper-V backend needs Windows 11 Pro or Enterprise; this is $product"
}
if ($build -lt 22000) {
    throw "the native Hyper-V backend needs Windows 11 build 22000 or newer; this is $build"
}

function Assert-ServiceRunning([string]$Name) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne "Running") {
        throw "Hyper-V is disabled or awaiting a reboot ($Name is not running)"
    }
}
Assert-ServiceRunning "vmcompute"
Assert-ServiceRunning "hns"

$ast = Get-Command ast -ErrorAction SilentlyContinue
$helper = Get-Command astd-hyperv -ErrorAction SilentlyContinue
if (-not $EvidenceDir) {
    $EvidenceDir = Join-Path $env:TEMP "asterism-hyperv-evidence"
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$log = Join-Path $EvidenceDir "harness.log"

function Record([string]$Step, [string]$Result) {
    $line = "{0:o} {1} {2}" -f (Get-Date).ToUniversalTime(), $Step, $Result
    Add-Content -LiteralPath $log -Value $line
    Write-Output $line
}

Record "host" "$product build $build elevated=true vmcompute=running hns=running"

if (-not $ast -or -not $helper) {
    Record "binaries" "MISSING ast=$([bool]$ast) astd-hyperv=$([bool]$helper)"
    throw "astd-hyperv and ast must be on PATH; real lifecycle remains unverified"
}

function Invoke-Ast([string[]]$Args) {
    & $ast.Source @Args
    if ($LASTEXITCODE -ne 0) {
        throw "ast $($Args -join ' ') failed with $LASTEXITCODE"
    }
}

Record "probe" "pre-mutation gates passed; mutating $Instance"
try {
    Invoke-Ast @("create", $Instance, "--image", $Image, "--backend", "hyperv")
    Record "create" "ok"
    Invoke-Ast @("up", $Instance)
    Record "boot" "ok"
    Invoke-Ast @("status", $Instance)
    Record "control" "ok"
    Invoke-Ast @("snapshot", $Instance, "harness")
    Record "snapshot" "ok"
    Invoke-Ast @("down", $Instance)
    Record "stop" "ok"
    Invoke-Ast @("up", $Instance)
    Record "restart" "ok"
    Get-Process astd -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    Invoke-Ast @("status", $Instance)
    Record "adoption" "ok (guest still visible after astd restart)"
    Invoke-Ast @("down", $Instance)
    Record "stop-final" "ok"
}
finally {
    try { Invoke-Ast @("rm", $Instance) } catch { Record "cleanup" $_.Exception.Message }
}

Write-Output "evidence: $log"
