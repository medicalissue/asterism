<#
.SYNOPSIS
Build one self-contained Windows release archive.

.DESCRIPTION
packaging/install.ps1 unpacks this tarball flat and refuses it unless every one
of `ast.exe`, `astd.exe`, `astd-hyperv.exe`, `asterism-update.ps1` and
`install.ps1` is at the top level — a partial Windows release is not installed
at all, because `astd-hyperv.exe` is the only product virtualization path on
Windows and there is no WHPX/QEMU fallback to degrade to. So the manifest of
required names lives here, next to the code that produces them.

The updater is packaged under the name the installer places it as
(`asterism-update.ps1`), and `install.ps1` travels with it because
`asterism-update.ps1 apply` re-invokes the installer from beside itself.

    scripts/package-windows.ps1 -Version v0.1.0 -Dist dist/v0.1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Dist
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }

$target = switch -Regex ($env:PROCESSOR_ARCHITECTURE) {
    'ARM64' { 'windows-arm64' }
    default { 'windows-x86_64' }
}

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
$work = Join-Path ([IO.Path]::GetTempPath()) ("asterism-windows-package-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $work | Out-Null

try {
    # One cargo pass over the whole product graph: three separate builds would
    # recompile the shared dependency tree three times, and — worse — could
    # produce binaries from three different resolutions of it.
    Push-Location $root
    try {
        cargo build --release --locked --bin ast --bin astd --bin astd-hyperv
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with $LASTEXITCODE" }
    } finally {
        Pop-Location
    }

    foreach ($exe in @('ast.exe', 'astd.exe', 'astd-hyperv.exe')) {
        $src = Join-Path $targetDir "release\$exe"
        if (-not (Test-Path $src)) { throw "the build produced no $src" }
        Copy-Item -Force $src (Join-Path $work $exe)
    }

    Copy-Item -Force (Join-Path $root 'packaging\update.ps1') (Join-Path $work 'asterism-update.ps1')
    Copy-Item -Force (Join-Path $root 'packaging\install.ps1') (Join-Path $work 'install.ps1')
    foreach ($notice in @('LICENSE-APACHE', 'LICENSE-MIT', 'NOTICE')) {
        Copy-Item -Force (Join-Path $root $notice) (Join-Path $work $notice)
    }

    # The same list packaging/install.ps1 checks for. Fail here, where the
    # message can say which file the build did not produce, rather than on a
    # user's machine halfway through an install.
    foreach ($required in @('ast.exe', 'astd.exe', 'astd-hyperv.exe', 'asterism-update.ps1', 'install.ps1')) {
        if (-not (Test-Path (Join-Path $work $required))) {
            throw "refusing to package a Windows release with no $required"
        }
    }

    $archive = "asterism-$Version-$target.tar.gz"
    $out = Join-Path (Resolve-Path $Dist) $archive
    tar -czf $out -C $work ast.exe astd.exe astd-hyperv.exe asterism-update.ps1 install.ps1 LICENSE-APACHE LICENSE-MIT NOTICE
    if ($LASTEXITCODE -ne 0) { throw "tar failed with $LASTEXITCODE" }

    # SHA256SUMS is read by install.ps1 with an exact basename lookup, so the
    # name in it must be the bare archive name and never a path.
    #
    # LF, written explicitly: Set-Content would use CRLF here, and the publish
    # job concatenates this file into the release-wide SHA256SUMS that `shasum
    # -c` and install.sh read on other platforms. A trailing CR becomes part
    # of the filename token there and the artifact stops being verifiable.
    $digest = (Get-FileHash -Algorithm SHA256 $out).Hash.ToLowerInvariant()
    $line = "$digest  $archive`n"
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path (Resolve-Path $Dist) "SHA256SUMS.$target"), $line, $utf8)
    [IO.File]::WriteAllText((Join-Path (Resolve-Path $Dist) 'SHA256SUMS'), $line, $utf8)
    Write-Host $line.TrimEnd()
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
