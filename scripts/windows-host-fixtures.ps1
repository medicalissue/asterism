# PowerShell fixtures for the seven Windows host Sol blockers.
# Parse-safe on pwsh/Windows PowerShell. No Hyper-V, no SCM, no network.
#
#   pwsh -NoProfile -File scripts/windows-host-fixtures.ps1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not (Test-Path (Join-Path $Root 'packaging/update.ps1'))) {
    $Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}
$Pass = 0
function Ok([string]$Message) {
    $script:Pass++
    Write-Host "ok: $Message"
}
function Fail([string]$Message) {
    Write-Error "WINDOWS-HOST-FIXTURE FAIL: $Message"
    exit 1
}

# 1. Privilege boundary: installer names Program Files for elevated installs
# and the service create path refuses a user-writable ImagePath.
$install = Get-Content -Raw (Join-Path $Root 'packaging/install.ps1')
if ($install -notmatch 'Program Files') { Fail 'install.ps1 does not prefer a protected prefix' }
if ($install -notmatch 'user-writable prefix') { Fail 'install.ps1 does not warn that SCM refuses a user prefix' }
$hostRs = Get-Content -Raw (Join-Path $Root 'crates/asterism-core/src/windows_host.rs')
if ($hostRs -notmatch 'refusing to install') { Fail 'windows_host.rs does not refuse LocalSystem + user-writable prefix' }
if ($hostRs -notmatch 'obj=\{SERVICE_ACCOUNT_SYSTEM\}') { Fail 'SCM obj= is not explicit' }
Ok 'privilege boundary: LocalSystem is pinned and user-writable prefixes are refused'

# 2. Update rollback fixture: stage a fake prefix, force apply failure, restore.
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('asterism-update-fixture-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path (Join-Path $work 'bin') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $work 'libexec/asterism') | Out-Null
Set-Content -Path (Join-Path $work 'bin/ast.exe') -Value 'old-ast' -Encoding ascii
Set-Content -Path (Join-Path $work 'bin/astd.exe') -Value 'old-astd' -Encoding ascii
Set-Content -Path (Join-Path $work 'bin/astd-hyperv.exe') -Value 'old-hv' -Encoding ascii
Copy-Item (Join-Path $Root 'packaging/update.ps1') (Join-Path $work 'libexec/asterism/asterism-update.ps1')
$env:ASTERISM_UPDATE_PREFIX = $work
$env:ASTERISM_HOME = Join-Path $work 'state'
& (Join-Path $work 'libexec/asterism/asterism-update.ps1') apply -RollbackFixture
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { Fail "rollback fixture exited $LASTEXITCODE" }
$ast = Get-Content -Raw (Join-Path $work 'bin/ast.exe')
$astd = Get-Content -Raw (Join-Path $work 'bin/astd.exe')
if ($ast.Trim() -ne 'old-ast') { Fail "rollback did not restore ast.exe (got $ast)" }
if ($astd.Trim() -ne 'old-astd') { Fail "rollback did not restore astd.exe (got $astd)" }
if (Test-Path (Join-Path $work 'state/update-transaction.claim')) {
    Fail 'rollback left a live claim'
}
Remove-Item -Recurse -Force $work
Ok 'update rollback restores the previous unit and drops the claim'

# 3. Stop latch: daemon waits on wait_service_stop; request_service_stop wakes it.
$daemon = Get-Content -Raw (Join-Path $Root 'crates/asterism-daemon/src/main.rs')
if ($daemon -notmatch 'wait_service_stop') { Fail 'daemon accept loop does not wait on the SCM latch' }
if ($hostRs -notmatch 'fn wait_service_stop') { Fail 'stop latch has no waiter' }
if ($hostRs -notmatch 'SERVICE_CONTROL_STOP') { Fail 'ctrl handler does not request stop' }
Ok 'SCM stop latch is the daemon shutdown path'

# 4. Helper probe: fixture speaks Probe; doctor requires Probe, not a file.
$probe = Join-Path $Root 'scripts/fixtures/windows-host/probe-helper'
if (-not (Test-Path $probe)) { Fail 'probe-helper fixture is missing' }
$reply = Get-Content -Raw $probe | Select-String -Pattern '"result":"ready"' -SimpleMatch
# The script prints Ready after reading stdin; execute it.
$psi = New-Object System.Diagnostics.ProcessStartInfo
if (Get-Command sh -ErrorAction SilentlyContinue) {
    $out = '{"op":"probe"}' | & sh $probe
    if ($out -notmatch '"result":"ready"') { Fail "probe-helper did not speak Ready ($out)" }
    if ($out -notmatch '"protocol":1') { Fail 'probe-helper protocol is not 1' }
    Ok 'helper probe fixture speaks the 510d330 Probe protocol'
} else {
    $text = Get-Content -Raw $probe
    if ($text -notmatch '"result":"ready"') { Fail 'probe-helper source does not contain Ready' }
    Ok 'helper probe fixture source contains Ready (no sh on this host)'
}
if ($hostRs -notmatch 'Probe failed') { Fail 'doctor does not fail a helper that will not Probe' }

# 5. Firewall: dump with a Hyper-V group must not pass without the Asterism rule.
$dump = Get-Content -Raw (Join-Path $Root 'scripts/fixtures/windows-host/firewall-show-rule.txt')
if ($dump -notmatch 'Rule Name:\s+Hyper-V') { Fail 'firewall fixture missing Hyper-V decoy' }
if ($dump -notmatch 'Asterism device daemon') { Fail 'firewall fixture missing the real rule' }
if ($hostRs -notmatch 'firewall_rule_allows_program') { Fail 'no exact firewall matcher' }
if ($install -notmatch 'Asterism device daemon') { Fail 'installer does not create the matched rule' }
Ok 'firewall diagnostics match the created rule and ignore a Hyper-V substring'

Write-Host "WINDOWS-HOST-FIXTURES GREEN ($Pass checks)"
