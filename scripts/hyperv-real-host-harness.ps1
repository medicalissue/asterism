# Opt-in Windows real-host harness for the native Hyper-V backend. Pro and
# Enterprise are the supported Microsoft path. Home is an explicitly labelled
# experiment and reaches mutation only when the same real service/API probes
# pass. GitHub hosted runners cannot satisfy this: they are Windows Server
# images without nested Hyper-V.
#
# Usage:
#   ./scripts/hyperv-real-host-harness.ps1 -ExplainOnly
#   $env:ASTERISM_HYPERV_REAL_HOST = "1"
#   ./scripts/hyperv-real-host-harness.ps1
#
# Daemon disk snapshots copy a closed VHDX. The sequence therefore stops the
# guest before snapshot, then proves restart, adoption across an astd
# restart, and a final stop. Helper build identity and leftover HCS/HCN
# objects are recorded independently of `ast`.
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
    "GitHub hosted windows-latest is Windows Server Datacenter, not a client Hyper-V host",
    "GitHub hosted runners do not expose nested Hyper-V / HCS compute-system mutation",
    "vmcompute/hns may exist as services without a usable HCS v2.1 VM partition",
    "VirtDisk VHDX create/attach against a real compute system cannot be proven",
    "AF_HYPERV/AF_VSOCK guest-agent readiness cannot be proven",
    "create/boot/control/stop/snapshot/restart/adoption/final-stop of a Linux guest cannot be proven",
    "live guest survival across astd restart cannot be proven",
    "independent HCS compute-system and HCN network cleanup cannot be proven"
)

if ($ExplainOnly) {
    Write-Gap "Hyper-V real-host harness: EXPLAIN ONLY"
    Write-Gap "Opt-in: set ASTERISM_HYPERV_REAL_HOST=1 on an elevated Windows host with Hyper-V enabled. Home is experimental and must be labelled in the evidence."
    Write-Gap "Lifecycle once opted in: probe, create, boot, control, stop, snapshot, restart, adoption, final-stop, independent HCS/HCN cleanup."
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
    throw "this harness runs only on Windows"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "the native Hyper-V backend needs an elevated administrator token"
}

$currentVersion = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$product = $currentVersion.ProductName
$edition = $currentVersion.EditionID
$build = [int]$currentVersion.CurrentBuildNumber
$support = if ($product -match "Pro|Enterprise") { "microsoft-supported" } else { "experimental-unsupported-sku" }
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
Assert-ServiceRunning "vmms"

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

function Invoke-Helper([string]$Json) {
    $helperPath = $helper.Source
    $reply = $Json | & $helperPath
    if ($LASTEXITCODE -ne 0) {
        throw "astd-hyperv failed with $LASTEXITCODE"
    }
    return $reply
}

function Get-HcsSystems {
    $hcsdiag = Get-Command hcsdiag -ErrorAction SilentlyContinue
    if (-not $hcsdiag) {
        throw "hcsdiag is required for independent HCS cleanup evidence"
    }
    return (& $hcsdiag.Source list 2>$null | Out-String)
}

function Get-HcnNetworks {
    try {
        $nets = Get-HnsNetwork -ErrorAction Stop | ConvertTo-Json -Depth 6
        if ($nets) { return $nets }
        return "[]"
    } catch {
        throw "Get-HnsNetwork is required for independent HCN cleanup evidence: $($_.Exception.Message)"
    }
}

function Get-HcnEndpoints {
    try {
        $eps = Get-HnsEndpoint -ErrorAction Stop | ConvertTo-Json -Depth 6
        if ($eps) { return $eps }
        return "[]"
    } catch {
        throw "Get-HnsEndpoint is required for independent HCN cleanup evidence: $($_.Exception.Message)"
    }
}

Record "host" "$product edition=$edition build=$build support=$support elevated=true vmcompute=running hns=running vmms=running"

if (-not $ast -or -not $helper) {
    Record "binaries" "MISSING ast=$([bool]$ast) astd-hyperv=$([bool]$helper)"
    throw "astd-hyperv and ast must be on PATH; real lifecycle remains unverified"
}

$probeJson = Invoke-Helper '{"op":"probe"}'
Record "helper-build" $probeJson
$probe = $probeJson | ConvertFrom-Json
if (-not $probe.host.build) {
    throw "astd-hyperv probe did not return host.build"
}
Record "helper-build-id" $probe.host.build

function Invoke-Ast([string[]]$CommandArgs) {
    & $ast.Source @CommandArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ast $($CommandArgs -join ' ') failed with $LASTEXITCODE"
    }
}

$asterismHome = if ($env:ASTERISM_HOME) { $env:ASTERISM_HOME } elseif ($env:USERPROFILE) { Join-Path $env:USERPROFILE ".asterism" } else { Join-Path $env:HOME ".asterism" }
$createdHarnessHome = -not (Test-Path -LiteralPath $asterismHome)
if ($createdHarnessHome) {
    New-Item -ItemType Directory -Path $asterismHome | Out-Null
    # An elevated token defaults new directories to BUILTIN\Administrators as
    # owner. The named-pipe contract intentionally admits the interactive
    # account plus LocalSystem, so make that identity explicit just as the
    # Windows installer and conformance fixture do.
    $account = (& whoami.exe).Trim()
    & icacls.exe $asterismHome /setowner $account /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "failed to set ASTERISM_HOME owner to $account" }
    $accountAce = "${account}:(OI)(CI)(F)"
    & icacls.exe $asterismHome /inheritance:r /grant:r $accountAce "*S-1-5-18:(OI)(CI)(F)" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "failed to protect ASTERISM_HOME for $account and LocalSystem" }
}
$configPath = Join-Path $asterismHome "instances\$Instance\hyperv.json"
$daemonPidPath = Join-Path $asterismHome "astd.pid"
$systemId = $null
$networkId = $null
$endpointId = $null

Record "probe" "pre-mutation gates passed; mutating $Instance"
try {
    Invoke-Ast @("create", $Instance, "--image", $Image, "--backend", "hyperv")
    Record "create" "ok"
    Invoke-Ast @("up", $Instance)
    Record "boot" "ok"
    Invoke-Ast @("status", $Instance)
    Record "control" "ok"

    if (Test-Path -LiteralPath $configPath) {
        $cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        $systemId = $cfg.system_id
        $networkId = $cfg.network_id
        $endpointId = $cfg.endpoint_id
        Record "handle" "system_id=$systemId network_id=$networkId endpoint_id=$endpointId"
    } else {
        throw "expected durable helper config at $configPath"
    }

    Invoke-Ast @("down", $Instance)
    Record "stop-before-snapshot" "ok"
    Invoke-Ast @("snapshot", $Instance, "harness")
    Record "snapshot" "ok (guest was stopped)"
    Invoke-Ast @("up", $Instance)
    Record "restart" "ok"
    if (-not (Test-Path -LiteralPath $daemonPidPath)) {
        throw "expected astd pid evidence at $daemonPidPath"
    }
    $daemonPidText = (Get-Content -LiteralPath $daemonPidPath -Raw).Trim()
    $daemonPid = [int]$daemonPidText
    $daemon = Get-Process -Id $daemonPid -ErrorAction Stop
    if ($daemon.ProcessName -ne "astd") {
        throw "$daemonPidPath names $($daemon.ProcessName), not astd"
    }
    Stop-Process -Id $daemonPid -Force
    Record "daemon-stop" "pid=$daemonPid"
    Start-Sleep -Seconds 2
    Invoke-Ast @("status", $Instance)
    Record "adoption" "ok (guest still visible after astd restart)"
    Invoke-Ast @("down", $Instance)
    Record "stop-final" "ok"
}
finally {
    $cleanupError = $null
    try { Invoke-Ast @("rm", $Instance) } catch {
        $cleanupError = $_.Exception.Message
        Record "cleanup-ast" $cleanupError
    }
    Start-Sleep -Seconds 2
    $hcs = Get-HcsSystems
    Set-Content -LiteralPath (Join-Path $EvidenceDir "hcsdiag-list.txt") -Value $hcs
    $hcnNets = Get-HcnNetworks
    Set-Content -LiteralPath (Join-Path $EvidenceDir "hcn-networks.json") -Value $hcnNets
    $hcnEps = Get-HcnEndpoints
    Set-Content -LiteralPath (Join-Path $EvidenceDir "hcn-endpoints.json") -Value $hcnEps

    $leftover = @()
    if ($cleanupError) {
        $leftover += "ast rm failed: $cleanupError"
    }
    if ($systemId -and $hcs -match [regex]::Escape($systemId)) {
        $leftover += "HCS compute system $systemId still listed"
    }
    if ($networkId -and $hcnNets -match [regex]::Escape($networkId)) {
        $leftover += "HCN network $networkId still present"
    }
    if ($endpointId -and $hcnEps -match [regex]::Escape($endpointId)) {
        $leftover += "HCN endpoint $endpointId still present"
    }
    if ($leftover.Count -gt 0) {
        $msg = $leftover -join "; "
        Record "cleanup-independent" "FAILED $msg"
        throw "independent HCS/HCN cleanup failed: $msg"
    }
    Record "cleanup-independent" "ok (no leftover HCS system or HCN endpoint/network for this instance)"
}

Write-Output "evidence: $log"
Write-Output "helper-build-id: $($probe.host.build)"
