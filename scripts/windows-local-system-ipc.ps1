param(
    [Parameter(Mandatory = $true)]
    [string]$Ast,
    [Parameter(Mandatory = $true)]
    [string]$Astd
)

$ErrorActionPreference = 'Stop'
$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$service = "com.asterism.astd.test.localsystem-$suffix"
$installRoot = Join-Path $env:ProgramData "Asterism\ci-$suffix"
$testHome = Join-Path $env:RUNNER_TEMP "asterism-home-$suffix"
$probeRoot = Join-Path $installRoot 'probe'
$task = "AsterismPipeRefusal-$suffix"
$installedAst = Join-Path $installRoot 'ast.exe'
$installedAstd = Join-Path $installRoot 'astd.exe'
$servicePid = 0
$pipeName = $null
$interactiveIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$interactiveSid = $interactiveIdentity.User.Value

function Get-AsterismPipes {
    @(Get-ChildItem -LiteralPath '\\.\pipe\' -ErrorAction Stop |
        Where-Object { $_.Name -like 'asterism-*' } |
        ForEach-Object { $_.Name })
}

function Wait-ServiceState([string]$Name, [string]$State, [int]$Seconds = 30) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $lastRow = $null
    do {
        $row = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
        $lastRow = $row
        if ($null -ne $row -and $row.State -eq $State) {
            return $row
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    $observed = if ($null -eq $lastRow) {
        'missing from SCM'
    } else {
        "state=$($lastRow.State) exit=$($lastRow.ExitCode) service_exit=$($lastRow.ServiceSpecificExitCode)"
    }
    $daemonLog = Join-Path $script:testHome 'astd.log'
    if (Test-Path -LiteralPath $daemonLog) {
        Write-Host '--- temporary LocalSystem astd log ---'
        Get-Content -LiteralPath $daemonLog | ForEach-Object { Write-Host $_ }
    }
    throw "service $Name did not reach $State ($observed)"
}

$beforePipes = Get-AsterismPipes
New-Item -ItemType Directory -Path $installRoot, $testHome, $probeRoot -Force | Out-Null
Copy-Item -LiteralPath $Ast -Destination $installedAst
Copy-Item -LiteralPath $Astd -Destination $installedAstd

# The LocalSystem ImagePath is read-only to ordinary authenticated users.
& icacls.exe $installRoot '/inheritance:r' '/grant:r' `
    '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-11:(OI)(CI)(RX)' | Out-Null
# LocalService can traverse the home and read its owner SID, but cannot write
# it. Its probe therefore reaches the pipe DACL instead of failing on a parent
# directory lookup, and cannot win the daemon election as a fallback.
& icacls.exe $testHome '/setowner' "*$interactiveSid" '/Q' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "could not assign ASTERISM_HOME to interactive SID $interactiveSid"
}
& icacls.exe $testHome '/inheritance:r' '/grant:r' `
    "*${interactiveSid}:(OI)(CI)(F)" '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-19:(OI)(CI)(RX)' '/Q' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'could not protect the user-owned ASTERISM_HOME'
}
& icacls.exe $probeRoot '/grant:r' '*S-1-5-19:(OI)(CI)(M)' | Out-Null

$env:ASTERISM_HOME = $testHome
$env:ASTERISM_TEST_SERVICE_LABEL = $service

try {
    & $installedAst service install
    if ($LASTEXITCODE -ne 0) {
        throw "ast service install exited $LASTEXITCODE"
    }

    $row = Wait-ServiceState -Name $service -State 'Running'
    if ($row.StartName -notin @('LocalSystem', 'Local System')) {
        throw "temporary astd account was $($row.StartName), not LocalSystem"
    }
    if ([int]$row.ProcessId -le 0) {
        throw 'SCM did not report the LocalSystem astd pid'
    }
    $servicePid = [int]$row.ProcessId

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $newPipes = @(Get-AsterismPipes | Where-Object { $_ -notin $beforePipes })
        if ($newPipes.Count -eq 1) {
            $pipeName = $newPipes[0]
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $pipeName) {
        throw "the LocalSystem service did not publish exactly one Asterism pipe"
    }

    # This is a real protocol request from the hosted runner's interactive
    # token to the LocalSystem daemon, not a same-account transport fixture.
    & $installedAst ls --local
    if ($LASTEXITCODE -ne 0) {
        throw "interactive ast could not roundtrip to LocalSystem astd"
    }

    $probeScript = Join-Path $probeRoot 'refuse.ps1'
    $probeResult = Join-Path $probeRoot 'result.txt'
    $probeLog = Join-Path $probeRoot 'output.txt'
    $probeConfig = Join-Path $probeRoot 'probe.json'
    @{
        HomePath = $testHome
        AstPath = $installedAst
        ResultPath = $probeResult
        LogPath = $probeLog
    } | ConvertTo-Json | Set-Content -LiteralPath $probeConfig -Encoding utf8
    @'
$config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'probe.json') -Raw | ConvertFrom-Json
$env:ASTERISM_HOME = $config.HomePath
& $config.AstPath ls --local *> $config.LogPath
Set-Content -LiteralPath $config.ResultPath -Value $LASTEXITCODE -Encoding ascii
'@ | Set-Content -LiteralPath $probeScript -Encoding utf8

    # schtasks.exe rejects a /TR command longer than 261 characters. Keep the
    # action itself short and let the root-owned JSON beside the script carry
    # the long GitHub-runner paths into the LocalService probe.
    $action = "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$probeScript`""
    & schtasks.exe /Create /TN $task /SC ONCE /ST 23:59 /RU 'NT AUTHORITY\LOCAL SERVICE' /RL LIMITED /TR $action /F | Out-Null
    & schtasks.exe /Run /TN $task | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath $probeResult)) {
        if ([DateTime]::UtcNow -ge $deadline) {
            throw 'LocalService refusal probe timed out'
        }
        Start-Sleep -Milliseconds 250
    }
    $probeExit = [int](Get-Content -LiteralPath $probeResult -Raw).Trim()
    if ($probeExit -eq 0) {
        throw 'the pipe admitted NT AUTHORITY\LOCAL SERVICE'
    }

    & $installedAst service uninstall
    if ($LASTEXITCODE -ne 0) {
        throw "ast service uninstall exited $LASTEXITCODE"
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ((Get-AsterismPipes) -contains $pipeName) {
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "named pipe $pipeName survived service stop"
        }
        Start-Sleep -Milliseconds 250
    }
    if (Get-Process -Id $servicePid -ErrorAction SilentlyContinue) {
        throw "LocalSystem astd pid $servicePid survived service stop"
    }

    Write-Host "LocalSystem service IPC PASS: service=$service pid=$servicePid pipe=$pipeName owner=$interactiveSid"
}
finally {
    & schtasks.exe /Delete /TN $task /F 2>$null | Out-Null
    & sc.exe stop $service 2>$null | Out-Null
    & sc.exe delete $service 2>$null | Out-Null
    Remove-Item Env:ASTERISM_TEST_SERVICE_LABEL -ErrorAction SilentlyContinue
}

# Expected idempotent cleanup failures above leave a non-zero native
# LASTEXITCODE even after every asserted lifecycle step passed. A thrown
# assertion never reaches this line; reaching it is the gate's success.
exit 0
