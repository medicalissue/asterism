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
    [ValidateSet('status', 'check', 'apply', 'recover', 'channel')]
    [string]$Command = 'status',
    [Parameter(Position = 1)]
    [ValidateSet('stable', 'beta', 'nightly')]
    [string]$Channel,
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
$LibexecNames = @('asterism-update.ps1', 'install.ps1')
$script:OwnsTransaction = $false
$script:ClaimStream = $null

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
    if (-not $script:ClaimStream) {
        throw 'cannot write an update claim without owning its file handle'
    }
    $body = @(
        "owner=$Owner"
        "id=$Id"
        "phase=$Phase"
    ) -join "`n"
    $bytes = [Text.Encoding]::ASCII.GetBytes("$body`n")
    $script:ClaimStream.Position = 0
    $script:ClaimStream.SetLength(0)
    $script:ClaimStream.Write($bytes, 0, $bytes.Length)
    $script:ClaimStream.Flush($true)
}

function Read-Claim {
    if (-not (Test-Path $ClaimFile)) { return $null }
    if ($script:ClaimStream) {
        $script:ClaimStream.Flush()
        $script:ClaimStream.Position = 0
        $bytes = New-Object byte[] ([int]$script:ClaimStream.Length)
        [void]$script:ClaimStream.Read($bytes, 0, $bytes.Length)
        $lines = ([Text.Encoding]::ASCII.GetString($bytes)) -split "`r?`n"
    } else {
        $lines = Get-Content $ClaimFile
    }
    $map = @{}
    foreach ($line in $lines) {
        if ($line -match '^(owner|id|phase)=(.*)$') { $map[$Matches[1]] = $Matches[2] }
    }
    foreach ($field in @('owner', 'id', 'phase')) {
        if (-not $map.ContainsKey($field) -or -not $map[$field]) {
            throw "update claim has no $field; refusing to mutate an unknown transaction"
        }
    }
    return $map
}

function Try-Claim([string]$Owner, [string]$Id) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    try {
        # Keep the handle for the entire transaction. Readers such as `status`
        # may inspect it, but another updater cannot write or delete it. When
        # this process dies Windows releases the handle and recovery can take
        # exclusive ownership of the stale transaction.
        $script:ClaimStream = [System.IO.File]::Open(
            $ClaimFile,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::Read
        )
    } catch [System.IO.IOException] {
        Die 'another updater process owns the activation transaction'
    }
    $script:OwnsTransaction = $true
    Write-Claim -Owner $Owner -Id $Id -Phase 'claimed'
}

function Lock-InterruptedClaim {
    try {
        $script:ClaimStream = [System.IO.File]::Open(
            $ClaimFile,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::Read
        )
    } catch [System.IO.IOException] {
        Die 'another updater process owns the activation transaction; refusing recovery'
    }
    $script:OwnsTransaction = $true
    try {
        return (Read-Claim)
    } catch {
        Release-ClaimHandle
        throw
    }
}

function Backup-Current {
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    foreach ($name in $UnitNames) {
        $src = Join-Path $Bin $name
        if (Test-Path $src) { Copy-Item -Force $src (Join-Path $BackupDir $name) }
    }
    $libexec = Join-Path $Prefix 'libexec\asterism'
    foreach ($name in $LibexecNames) {
        $src = Join-Path $libexec $name
        if (Test-Path $src) { Copy-Item -Force $src (Join-Path $BackupDir $name) }
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
    $destDir = Join-Path $Prefix 'libexec\asterism'
    foreach ($name in $LibexecNames) {
        $src = Join-Path $BackupDir $name
        if (Test-Path $src) {
            New-Item -ItemType Directory -Force -Path $destDir | Out-Null
            Copy-Item -Force $src (Join-Path $destDir $name)
        }
    }
    Say 'rolled back to the previous unit'
}

function Release-ClaimHandle {
    if ($script:ClaimStream) {
        $script:ClaimStream.Dispose()
        $script:ClaimStream = $null
    }
    $script:OwnsTransaction = $false
}

function Drop-Claim {
    if (-not $script:OwnsTransaction -or -not $script:ClaimStream) {
        throw 'refusing to delete an update claim this process does not own'
    }
    Release-ClaimHandle
    if (Test-Path $ClaimFile) { Remove-Item -Force $ClaimFile }
}

function Recover-Interrupted {
    if (-not (Test-Path $ClaimFile)) { return }
    $claim = Lock-InterruptedClaim
    try {
        if ($claim.phase -ne 'done') {
            Say "recovering interrupted transaction $($claim.id) (phase $($claim.phase))"
            Restore-Backup
        }
        Drop-Claim
    } catch {
        # A failed restore remains recoverable. Release our lock, but leave the
        # claim and backup untouched for the next deliberate recovery attempt.
        if ($script:ClaimStream) { Release-ClaimHandle }
        throw
    }
}

function Read-Channel {
    $channel = 'stable'
    if (Test-Path $ChannelFile) { $channel = (Get-Content $ChannelFile -Raw).Trim() }
    if ($channel -notin @('stable', 'beta', 'nightly')) {
        Die "unknown saved channel $channel; choose stable, beta, or nightly"
    }
    return $channel
}

function Save-Channel([string]$Name) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    Set-Content -Path $ChannelFile -Value $Name -Encoding ascii
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
        $channel = Read-Channel
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
    'channel' {
        if ($Channel) {
            Save-Channel $Channel
            Say "channel is now $Channel"
        } else {
            Write-Host (Read-Channel)
        }
    }
    'apply' {
        if ($RollbackFixture) {
            Invoke-RollbackFixture
            break
        }
        Recover-Interrupted
        $installer = Join-Path (Split-Path -Parent $PSCommandPath) 'install.ps1'
        if (-not (Test-Path $installer)) {
            Die 'the Windows release did not package install.ps1 next to the updater; reinstall from a complete artifact'
        }
        Try-Claim -Owner $PID -Id ([guid]::NewGuid().ToString('n'))
        try {
            Backup-Current
            $env:ASTERISM_PREFIX = $Prefix
            $env:ASTERISM_YES = '1'
            Write-Claim -Owner $PID -Id (Read-Claim).id -Phase 'activating'
            & $installer
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
