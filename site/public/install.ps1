# Talyx installer  -- Windows.
#
#   irm https://<install-url>/install.ps1 | iex
#
# Downloads the talyx + talyx-shim release binaries and installs them to
# $HOME\.talyx\bin. Does NOT run `talyx init` -- that requires a license,
# which doesn't exist yet at install time (see install.sh's header comment
# for the full rationale; this script mirrors it) -- same "no shell-profile
# edits without asking" rule applies here via -ModifyPath for the User PATH
# environment variable.
#
# $Repo points at the real repo, but no release has been tagged yet (see
# .github/workflows/release.yml, which is what produces the archive this
# script downloads). Until then this fails at the download step with a
# clear error, on purpose.
#
# v0 covers x86_64 Windows only (matches the release workflow's matrix)  --
# Windows on ARM isn't built yet.

param(
    [string]$Repo = $(if ($env:TALYX_REPO) { $env:TALYX_REPO } else { "rynald0cst0ltziam/talyx" }),
    [string]$Version = $(if ($env:TALYX_VERSION) { $env:TALYX_VERSION } else { "latest" }),
    [string]$InstallDir = $(if ($env:TALYX_INSTALL_DIR) { $env:TALYX_INSTALL_DIR } else { "$HOME\.talyx\bin" }),
    [switch]$ModifyPath
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host $msg }
# `throw`, not `exit` -- this script is meant to run via `irm ... | iex`,
# and `exit` inside an invoked expression terminates the HOST PowerShell
# process, closing the user's whole terminal window on any failure. A
# terminating error via `throw` only ends this script.
function Fail($msg) { throw "talyx-install: $msg" }

$arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
if ($arch -ne "X64") {
    Fail "unsupported architecture: $arch (v0 only ships x86_64-pc-windows-msvc)"
}
$target = "x86_64-pc-windows-msvc"

if ($Version -eq "latest") {
    $url = "https://github.com/$Repo/releases/latest/download/talyx-$target.zip"
    $sumsUrl = "https://github.com/$Repo/releases/latest/download/SHA256SUMS"
} else {
    $url = "https://github.com/$Repo/releases/download/$Version/talyx-$target.zip"
    $sumsUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS"
}

Write-Info "Talyx installer"
Write-Info "  target:  $target"
Write-Info "  version: $Version"
Write-Info "  from:    $url"
Write-Info "  to:      $InstallDir"
Write-Info ""

$tmpDir = Join-Path $env:TEMP "talyx-install-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $tmpDir | Out-Null
try {
    $zipPath = Join-Path $tmpDir "talyx.zip"
    try {
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    } catch {
        Fail "download failed ($url)  -- is $Repo a real repo with a published release yet? If you're testing this script before any release exists, that's expected. ($($_.Exception.Message))"
    }

    # Verify the download against the SHA256SUMS published with the
    # release before unpacking or running anything out of it. Fails
    # closed on a mismatch; a release published without a SHA256SUMS
    # (only possible by pinning an old -Version) warns and continues
    # rather than refusing something that never had a checksum to check.
    $archiveName = "talyx-$target.zip"
    $sumsPath = Join-Path $tmpDir "SHA256SUMS"
    $haveSums = $true
    try {
        Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsPath -UseBasicParsing
    } catch {
        $haveSums = $false
        Write-Info "  ! no SHA256SUMS published for this release -- skipping checksum verification"
    }
    if ($haveSums) {
        $expected = $null
        foreach ($line in Get-Content $sumsPath) {
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $archiveName) {
                $expected = $parts[0]
                break
            }
        }
        if (-not $expected) {
            Write-Info "  ! SHA256SUMS has no entry for $archiveName -- skipping checksum verification"
        } else {
            $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
            if ($actual -ne $expected.ToLower()) {
                Fail "checksum mismatch for $archiveName`n  expected: $expected`n  actual:   $actual`n  Refusing to install. This means the download did not match what the release published."
            }
            Write-Info "  checksum verified (sha256)"
        }
    }

    Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force
    $extracted = Get-ChildItem -Path $tmpDir -Directory -Filter "talyx-*" | Select-Object -First 1
    if (-not $extracted) { Fail "unexpected archive layout" }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $extracted.FullName "talyx.exe") $InstallDir -Force
    Copy-Item (Join-Path $extracted.FullName "talyx-shim.exe") $InstallDir -Force
    # Ship the license + third-party notices next to the binaries.
    foreach ($f in "LICENSE", "THIRD-PARTY-LICENSES.txt") {
        $src = Join-Path $extracted.FullName $f
        if (Test-Path $src) { Copy-Item $src (Join-Path $InstallDir "talyx-$f") -Force }
    }

    Write-Info "Installed:"
    Write-Info "  $InstallDir\talyx.exe"
    Write-Info "  $InstallDir\talyx-shim.exe"
    Write-Info ""

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$InstallDir*") {
        if ($ModifyPath) {
            [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
            Write-Info "Added $InstallDir to your User PATH  -- restart your terminal to pick this up."
        } else {
            Write-Info "NOTE: $InstallDir is not on your PATH."
            Write-Info "Add it yourself, or re-run with -ModifyPath to have it added to your User PATH automatically."
            Write-Info ('  $env:Path = "' + $InstallDir + ';$env:Path"')
        }
    }
    Write-Info ""
    Write-Info "Next steps (PATH changes only take effect in a NEW terminal, so this"
    Write-Info "session still needs the full path):"
    Write-Info "  $InstallDir\talyx.exe activate <YOUR-LICENSE-KEY>   # from your purchase email"
    Write-Info "  $InstallDir\talyx.exe scan --project .              # free, read-only, no license needed"
    Write-Info "  $InstallDir\talyx.exe init --project .              # after activating, turns on enforcement"
} finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}
