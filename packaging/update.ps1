# Signed, transactional Asterism updater for Windows.
#
# Sibling of packaging/update.sh. `ast update` on Windows prefers this file
# when it sits next to the installed binaries; the POSIX updater remains the
# Git Bash path. Channel, digest, Authenticode and downgrade gates match the
# POSIX updater so CLI and this script cannot disagree.

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'check', 'apply')]
    [string]$Command = 'status'
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
    if ($self -match '\\libexec\\asterism$') {
        Split-Path -Parent (Split-Path -Parent $self)
    } else {
        Join-Path $env:LOCALAPPDATA 'Asterism'
    }
}
$Bin = Join-Path $Prefix 'bin'
$Ast = Join-Path $Bin 'ast.exe'
$StateDir = if ($env:ASTERISM_HOME) { $env:ASTERISM_HOME } else { Join-Path $env:USERPROFILE '.asterism' }
$ChannelFile = Join-Path $StateDir 'update-channel'
$BaseUrl = if ($env:ASTERISM_UPDATE_BASE_URL) { $env:ASTERISM_UPDATE_BASE_URL } else { 'https://github.com/medicalissue/asterism/releases/download' }

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

switch ($Command) {
    'status' {
        $channel = 'stable'
        if (Test-Path $ChannelFile) { $channel = (Get-Content $ChannelFile -Raw).Trim() }
        Write-Host "channel   $channel"
        Write-Host "version   $(Current-Version)"
        Write-Host 'manager   asterism'
    }
    'check' {
        Say "check uses the signed RELEASE.json for $(Get-Target); apply to mutate"
        if (-not (Test-Path $Ast)) { Die "ast.exe is not installed at $Ast" }
        Write-Host "current   $(Current-Version)"
        Write-Host "target    $(Get-Target)"
        Write-Host "base      $BaseUrl"
    }
    'apply' {
        $installer = Join-Path (Split-Path -Parent $PSCommandPath) 'install.ps1'
        if (-not (Test-Path $installer)) {
            $installer = Join-Path $PSScriptRoot '..\install.ps1'
        }
        if (-not (Test-Path $installer)) {
            Die 'install.ps1 is not next to the updater'
        }
        $env:ASTERISM_PREFIX = $Prefix
        $env:ASTERISM_YES = '1'
        & $installer
    }
}
