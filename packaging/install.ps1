# Asterism Windows installer.
#
#   irm https://asterism.run/install.ps1 | iex
#
# Native PowerShell sibling of packaging/install.sh. It installs one tagged
# release: ast.exe, astd.exe, astd-hyperv.exe, and the updater. Bytes are
# checksummed against SHA256SUMS before anything is written. Authenticode is
# checked when a thumbprint is pinned or when ASTERISM_REQUIRE_SIGNATURE=1.
# Uninstall reads the receipt and removes only those files; ~/.asterism and
# instance disks stay.
#
# Environment:
#   ASTERISM_VERSION              tag (default: latest)
#   ASTERISM_PREFIX               install prefix (default: $env:LOCALAPPDATA\Asterism)
#   ASTERISM_YES=1                no prompts
#   ASTERISM_FORCE=1              reinstall
#   ASTERISM_SHA256               pin the tarball digest
#   ASTERISM_REQUIRE_SIGNATURE=1  refuse unsigned Authenticode
#   ASTERISM_AUTHENTICODE_THUMBPRINT  pin the signer
#   ASTERISM_BASE_URL / ASTERISM_INDEX_URL   mirrors / tests
#   --uninstall                   remove the receipt's files and the Windows Service

[CmdletBinding()]
param(
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo = 'medicalissue/asterism'
$Version = $env:ASTERISM_VERSION
$Prefix = if ($env:ASTERISM_PREFIX) { $env:ASTERISM_PREFIX } else { Join-Path $env:LOCALAPPDATA 'Asterism' }
$Force = $env:ASTERISM_FORCE -eq '1'
$RequireSig = $env:ASTERISM_REQUIRE_SIGNATURE -eq '1'
$PinnedSha = $env:ASTERISM_SHA256
$Thumbprint = $env:ASTERISM_AUTHENTICODE_THUMBPRINT
$BaseUrl = if ($env:ASTERISM_BASE_URL) { $env:ASTERISM_BASE_URL } else { "https://github.com/$Repo/releases/download" }
$IndexUrl = if ($env:ASTERISM_INDEX_URL) { $env:ASTERISM_INDEX_URL } else { "https://api.github.com/repos/$Repo/releases/latest" }
$ReceiptRel = 'share\asterism\install-receipt.env'
$ServiceName = 'com.asterism.astd'

function Say([string]$Message) { Write-Host "asterism: $Message" }
function Die([string]$Message) {
    Write-Error "asterism: $Message"
    exit 1
}

function Get-Target {
    switch -Regex ($env:PROCESSOR_ARCHITECTURE) {
        'ARM64' { return 'windows-arm64' }
        'AMD64' { return 'windows-x86_64' }
        default { Die "no binary release for Windows $($env:PROCESSOR_ARCHITECTURE). Use windows-x86_64 or windows-arm64." }
    }
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

function ReceiptPath { Join-Path $Prefix $ReceiptRel }

function Read-ReceiptField([string]$Name) {
    $path = ReceiptPath
    if (-not (Test-Path $path)) { return $null }
    foreach ($line in Get-Content $path) {
        if ($line -match "^$Name=(.*)$") { return $Matches[1] }
    }
    return $null
}

function Write-Receipt {
    param($Version, $Target, $Method, $Digest, [string[]]$Files)
    $dir = Split-Path (ReceiptPath) -Parent
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $body = @(
        "version=$Version"
        "target=$Target"
        "method=$Method"
        "digest=$Digest"
        "files=$($Files -join ' ')"
    ) -join "`n"
    Set-Content -Path (ReceiptPath) -Value $body -Encoding ascii
}

function Test-Authenticode([string]$Path) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($RequireSig -or $Thumbprint) {
        if ($sig.Status -ne 'Valid') {
            Die "$Path Authenticode status is $($sig.Status), not Valid. Refusing to install."
        }
        if ($Thumbprint) {
            $got = $sig.SignerCertificate.Thumbprint
            if ($got.ToLowerInvariant() -ne $Thumbprint.ToLowerInvariant()) {
                Die "$Path is signed by $got, not the pinned thumbprint."
            }
        }
        Say "authenticode ok: $Path"
        return
    }
    if ($sig.Status -eq 'NotSigned') {
        Say "$Path is not Authenticode-signed; checksum already verified. Pin ASTERISM_AUTHENTICODE_THUMBPRINT to require a signer."
        return
    }
    if ($sig.Status -ne 'Valid') {
        Die "$Path Authenticode status is $($sig.Status). Refusing to install."
    }
}

function Place-File([string]$Source, [string]$Rel) {
    $dest = Join-Path $Prefix $Rel
    $dir = Split-Path $dest -Parent
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $staged = Join-Path $dir ('.' + [IO.Path]::GetFileName($dest) + '.new')
    Copy-Item -Force $Source $staged
    Move-Item -Force $staged $dest
    Say "installed $dest"
}

function Uninstall-Service {
    $sc = Get-Command sc.exe -ErrorAction SilentlyContinue
    if (-not $sc) { return }
    & sc.exe stop $ServiceName 2>$null | Out-Null
    & sc.exe delete $ServiceName 2>$null | Out-Null
}

function Install-Release {
    $target = Get-Target
    if (-not $Version) {
        try {
            $index = Invoke-WebRequest -UseBasicParsing -Uri $IndexUrl
            if ($index.Content -match '"tag_name"\s*:\s*"([^"]+)"') {
                $script:Version = $Matches[1]
            }
        } catch {
            Die "could not reach $IndexUrl to find the latest release. Pass ASTERISM_VERSION."
        }
    }
    if (-not $Version) { Die "no release tag in the answer from $IndexUrl." }
    Say "release $Version for $target"

    $installed = Read-ReceiptField 'version'
    if ($installed -eq $Version -and -not $Force -and (Test-Path (ReceiptPath))) {
        Say "already installed: $Version in $(Join-Path $Prefix 'bin')"
        return
    }

    $artifact = "asterism-$Version-$target.tar.gz"
    $url = "$BaseUrl/$Version/$artifact"
    $work = Join-Path $env:TEMP ("asterism-install-" + [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        $tarball = Join-Path $work $artifact
        Say "downloading $url"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tarball
        } catch {
            Die "could not download $url. Nothing was installed."
        }
        if ($PinnedSha) {
            $want = $PinnedSha.ToLowerInvariant()
            Say 'digest pinned by ASTERISM_SHA256'
        } else {
            $sums = Join-Path $work 'SHA256SUMS'
            Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$Version/SHA256SUMS" -OutFile $sums
            $want = $null
            foreach ($line in Get-Content $sums) {
                $parts = $line.Split(@(' ', "`t"), [StringSplitOptions]::RemoveEmptyEntries)
                if ($parts.Count -ge 2 -and ($parts[1] -eq $artifact -or $parts[1] -eq "*$artifact")) {
                    $want = $parts[0].ToLowerInvariant()
                    break
                }
            }
            if (-not $want) { Die "SHA256SUMS does not list $artifact. Refusing to install an unlisted artifact." }
        }
        $got = Get-Sha256 $tarball
        if ($got -ne $want) {
            Die "checksum mismatch on $artifact:`n    expected $want`n    got      $got`nrefusing to install. Nothing was written."
        }
        Say "sha256 ok: $got"

        $unpack = Join-Path $work 'unpack'
        New-Item -ItemType Directory -Path $unpack | Out-Null
        tar -xzf $tarball -C $unpack
        foreach ($bin in @('ast.exe', 'astd.exe', 'astd-hyperv.exe')) {
            if (-not (Test-Path (Join-Path $unpack $bin))) {
                Die "$artifact has no $bin. Refusing to install a partial Windows release."
            }
        }
        $binDir = Join-Path $Prefix 'bin'
        if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Force -Path $binDir | Out-Null }
        if (-not (Test-Path $binDir -PathType Container) -or -not (Get-Item $binDir).Attributes) {
            Die "cannot create $binDir"
        }

        Place-File (Join-Path $unpack 'ast.exe') 'bin\ast.exe'
        Place-File (Join-Path $unpack 'astd.exe') 'bin\astd.exe'
        Place-File (Join-Path $unpack 'astd-hyperv.exe') 'bin\astd-hyperv.exe'
        $files = @('bin\ast.exe', 'bin\astd.exe', 'bin\astd-hyperv.exe')
        if (Test-Path (Join-Path $unpack 'asterism-update.ps1')) {
            Place-File (Join-Path $unpack 'asterism-update.ps1') 'libexec\asterism\asterism-update.ps1'
            $files += 'libexec\asterism\asterism-update.ps1'
        }
        if (Test-Path (Join-Path $unpack 'asterism-update')) {
            Place-File (Join-Path $unpack 'asterism-update') 'libexec\asterism\asterism-update'
            $files += 'libexec\asterism\asterism-update'
        }
        foreach ($rel in @('bin\ast.exe', 'bin\astd.exe', 'bin\astd-hyperv.exe')) {
            Test-Authenticode (Join-Path $Prefix $rel)
        }
        Write-Receipt $Version $target 'release' $got $files
        if ($installed -and $installed -ne $Version) {
            Say "upgraded $installed -> $Version"
        }
        Say ''
        Say 'Windows persistence is a Windows Service. After install:'
        Say '    ast doctor'
        Say '    ast service install'
        $binPath = Join-Path $Prefix 'bin'
        if (-not ($env:Path -split ';' | Where-Object { $_ -eq $binPath })) {
            Say ''
            Say "$binPath is not on PATH. Add it for this session:"
            Say "    `$env:Path += ';$binPath'"
        }
    } finally {
        Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    }
}

function Uninstall-Release {
    $r = ReceiptPath
    if (-not (Test-Path $r)) {
        Die "no install receipt at $r — nothing to uninstall."
    }
    Uninstall-Service
    $files = Read-ReceiptField 'files'
    foreach ($rel in ($files -split ' ')) {
        $f = Join-Path $Prefix $rel
        if (Test-Path $f) {
            Remove-Item -Force $f
            Say "removed $f"
        } else {
            Say "already gone: $f"
        }
    }
    Remove-Item -Force $r
    Say "removed $r"
    $home = if ($env:ASTERISM_HOME) { $env:ASTERISM_HOME } else { Join-Path $env:USERPROFILE '.asterism' }
    Say "instance state in $home was left alone."
    Say 'delete it by hand if you want it gone.'
}

if ($Uninstall -or $env:ASTERISM_UNINSTALL -eq '1') {
    Uninstall-Release
} else {
    Install-Release
}
