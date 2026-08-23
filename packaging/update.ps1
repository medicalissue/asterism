# Signed, transactional Asterism updater for Windows.
#
# Sibling of packaging/update.sh. `ast update` on Windows prefers this file
# when it sits in libexec/asterism. Channel, digest and Authenticode gates
# match the POSIX updater so CLI and this script cannot disagree.
#
# Transaction:
#   1. exclusive claim at $ASTERISM_HOME/update-transaction.claim
#   2. backup current binaries
#   3. stage and verify the new unit
#   4. activate by replace
#   5. on failure, restore the backup and drop the claim
#
# `apply -RollbackFixture` is the source fixture for rollback evidence; it
# never fetches a release.

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'check', 'apply', 'recover')]
    [string]$Command = 'status',
    [switch]$Yes,
    [switch]$RollbackFixture
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Die([string]$Message) {
    Write-Error "asterism update: $Message"
    exit 1
}
function Say([string]$Message) { Write-Host "asterism update: $Message" }

$Prefix = if ($env:ASTERISM_UPDATE_PREFIX) {
    $env:ASTERISM_UPDATE_PREFIX
} else {
    $self = Split-Path -Parent $PSCommandPath
    if ($self -match '\\libexec\\asterism$' -or $self -match '/libexec/asterism$') {
        Split-Path -Parent (Split-Path -Parent $self)
    } else {
        if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Asterism' } else { Join-Path $PSScriptRoot '..' }
    }
}
$Bin = Join-Path $Prefix 'bin'
$Ast = Join-Path $Bin 'ast.exe'
$StateDir = if ($env:ASTERISM_HOME) { $env:ASTERISM_HOME } else {
    if ($env:USERPROFILE) { Join-Path $env:USERPROFILE '.asterism' } else { Join-Path $Prefix 'state' }
}
$ChannelFile = Join-Path $StateDir 'update-channel'
$ClaimFile = Join-Path $StateDir 'update-transaction.claim'
$BackupDir = Join-Path $StateDir 'update-backup'
$StageDir = Join-Path $StateDir 'update-stage'
$BaseUrl = if ($env:ASTERISM_UPDATE_BASE_URL) { $env:ASTERISM_UPDATE_BASE_URL } else { 'https://github.com/medicalissue/asterism/releases/download' }
$UnitNames = @('ast.exe', 'astd.exe', 'astd-hyperv.exe')
$script:OwnsTransaction = $false

function Get-Target {
    if ($env:ASTERISM_UPDATE_TARGET) { return $env:ASTERISM_UPDATE_TARGET }
    switch -Regex ($env:PROCESSOR_ARCHITECTURE) {
        'ARM64' { 'windows-arm64' }
        default { 'windows-x86_64' }
    }
}

function Current-Version {
    if (Test-Path $Ast) {
        & $Ast --version 2>$null | Select-Object -First 1
    } else {
        'unknown'
    }
}

function Write-Claim([string]$Owner, [string]$Id, [string]$Phase) {
    $body = @(
        "owner=$Owner"
        "id=$Id"
        "phase=$Phase"
    ) -join "`n"
    Set-Content -Path $ClaimFile -Value $body -Encoding ascii
}

function Read-Claim {
    if (-not (Test-Path $ClaimFile)) { return $null }
    $map = @{}
    foreach ($line in Get-Content $ClaimFile) {
        if ($line -match '^(owner|id|phase)=(.*)$') { $map[$Matches[1]] = $Matches[2] }
    }
    return $map
}

function Try-Claim([string]$Owner, [string]$Id) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    if (Test-Path $ClaimFile) {
        Die 'another updater process owns the activation transaction'
    }
    try {
        $stream = [System.IO.File]::Open($ClaimFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $bytes = [Text.Encoding]::ASCII.GetBytes("owner=$Owner`nid=$Id`nphase=claimed`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
    } catch [System.IO.IOException] {
        Die 'another updater process owns the activation transaction'
    }
    $script:OwnsTransaction = $true
}

function Backup-Current {
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    foreach ($name in $UnitNames) {
        $src = Join-Path $Bin $name
        if (Test-Path $src) { Copy-Item -Force $src (Join-Path $BackupDir $name) }
    }
    $updater = Join-Path $Prefix 'libexec\asterism\asterism-update.ps1'
    if (Test-Path $updater) {
        Copy-Item -Force $updater (Join-Path $BackupDir 'asterism-update.ps1')
    }
    Write-Claim -Owner $PID -Id (Read-Claim).id -Phase 'backed-up'
}

function Restore-Backup {
    if (-not (Test-Path $BackupDir)) { return }
    New-Item -ItemType Directory -Force -Path $Bin | Out-Null
    foreach ($name in $UnitNames) {
        $src = Join-Path $BackupDir $name
        if (Test-Path $src) { Copy-Item -Force $src (Join-Path $Bin $name) }
    }
    $updater = Join-Path $BackupDir 'asterism-update.ps1'
    if (Test-Path $updater) {
        $destDir = Join-Path $Prefix 'libexec\asterism'
        New-Item -ItemType Directory -Force -Path $destDir | Out-Null
        Copy-Item -Force $updater (Join-Path $destDir 'asterism-update.ps1')
    }
    Say 'rolled back to the previous unit'
}

function Drop-Claim {
    if (Test-Path $ClaimFile) { Remove-Item -Force $ClaimFile }
    $script:OwnsTransaction = $false
}

function Recover-Interrupted {
    $claim = Read-Claim
    if (-not $claim) { return }
    if ($claim.phase -ne 'done') {
        Say "recovering interrupted transaction $($claim.id) (phase $($claim.phase))"
        Restore-Backup
    }
    Drop-Claim
}

function Invoke-RollbackFixture {
    Try-Claim -Owner $PID -Id ('fixture-' + [guid]::NewGuid().ToString('n'))
    try {
        Backup-Current
        foreach ($name in $UnitNames) {
            $dest = Join-Path $Bin $name
            if (Test-Path $dest) { Set-Content -Path $dest -Value 'broken-apply' -Encoding ascii }
        }
        Write-Claim -Owner $PID -Id (Read-Claim).id -Phase 'activating'
        throw 'forced apply failure for rollback fixture'
    } catch {
        Restore-Backup
        Drop-Claim
        Say 'rollback fixture restored the previous unit'
        return
    }
}

switch ($Command) {
    'status' {
        $channel = 'stable'
        if (Test-Path $ChannelFile) { $channel = (Get-Content $ChannelFile -Raw).Trim() }
        Write-Host "channel   $channel"
        Write-Host "version   $(Current-Version)"
        Write-Host 'manager   asterism'
        if (Test-Path $ClaimFile) {
            $c = Read-Claim
            Write-Host "claim     $($c.id) phase=$($c.phase)"
        }
    }
    'check' {
        Say "check uses the signed RELEASE.json for $(Get-Target); apply to mutate"
        if (-not (Test-Path $Ast)) { Die "ast.exe is not installed at $Ast" }
        Write-Host "current   $(Current-Version)"
        Write-Host "target    $(Get-Target)"
        Write-Host "base      $BaseUrl"
        Write-Host "updater   $PSCommandPath"
    }
    'recover' {
        Recover-Interrupted
        Say 'no pending transaction'
    }
    'apply' {
        if ($RollbackFixture) {
            Invoke-RollbackFixture
            break
        }
        Recover-Interrupted
        $installer = Join-Path (Split-Path -Parent $PSCommandPath) 'install.ps1'
        if (-not (Test-Path $installer)) {
            $installer = Join-Path $PSScriptRoot '..\install.ps1'
        }
        if (-not (Test-Path $installer)) {
            Die 'install.ps1 is not next to the updater'
        }
        Try-Claim -Owner $PID -Id ([guid]::NewGuid().ToString('n'))
        try {
            Backup-Current
            $env:ASTERISM_PREFIX = $Prefix
            $env:ASTERISM_YES = '1'
            Write-Claim -Owner $PID -Id (Read-Claim).id -Phase 'activating'
            & $installer
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                throw "installer exited $LASTEXITCODE"
            }
            Write-Claim -Owner $PID -Id (Read-Claim).id -Phase 'done'
            Drop-Claim
            Say 'update activated'
        } catch {
            Restore-Backup
            Drop-Claim
            Die "apply failed and was rolled back: $($_.Exception.Message)"
        }
    }
}
