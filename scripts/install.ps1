# Talyx installer  -- Windows.
#
#   irm https://<install-url>/install.ps1 | iex
#
# Downloads the talyx + talyx-shim release binaries, installs
# them to $HOME\.talyx\bin, and runs `talyx init` against $HOME
# so every MCP server config it can find gets routed through the
# enforcement shim. See install.sh's header comment for the full rationale
# (this script mirrors it)  -- same "no shell-profile edits without asking"
# rule applies here via -ModifyPath for the User PATH environment variable.
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
    [switch]$ModifyPath,
    [switch]$NoInit
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host $msg }
function Fail($msg) { Write-Error "talyx-install: $msg"; exit 1 }

$arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
if ($arch -ne "X64") {
    Fail "unsupported architecture: $arch (v0 only ships x86_64-pc-windows-msvc)"
}
$target = "x86_64-pc-windows-msvc"

if ($Version -eq "latest") {
    $url = "https://github.com/$Repo/releases/latest/download/talyx-$target.zip"
} else {
    $url = "https://github.com/$Repo/releases/download/$Version/talyx-$target.zip"
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

    if (-not $NoInit) {
        Write-Info "Activating protection for every Claude Code MCP server config under `$HOME..."
        & "$InstallDir\talyx.exe" init --project $HOME
    } else {
        Write-Info "Skipped activation (-NoInit passed). Run this yourself when ready:"
        Write-Info "  $InstallDir\talyx.exe init --project `$HOME"
    }
} finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}
