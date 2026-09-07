# AgentGuard installer  -- Windows.
#
#   irm https://<install-url>/install.ps1 | iex
#
# Downloads the agentguard + agentguard-shim release binaries, installs
# them to $HOME\.agentguard\bin, and runs `agentguard init` against $HOME
# so every MCP server config it can find gets routed through the
# enforcement shim. See install.sh's header comment for the full rationale
# (this script mirrors it)  -- same "no shell-profile edits without asking"
# rule applies here via -ModifyPath for the User PATH environment variable.
#
# NOT wired to a real download yet: $Repo below is a placeholder until a
# real release exists (see .github/workflows/release.yml, which is what
# produces the archive this script downloads). Until then this fails at
# the download step with a clear error, on purpose.
#
# v0 covers x86_64 Windows only (matches the release workflow's matrix)  --
# Windows on ARM isn't built yet.

param(
    [string]$Repo = $(if ($env:AGENTGUARD_REPO) { $env:AGENTGUARD_REPO } else { "your-org/agentguard" }), # TODO: real repo
    [string]$Version = $(if ($env:AGENTGUARD_VERSION) { $env:AGENTGUARD_VERSION } else { "latest" }),
    [string]$InstallDir = $(if ($env:AGENTGUARD_INSTALL_DIR) { $env:AGENTGUARD_INSTALL_DIR } else { "$HOME\.agentguard\bin" }),
    [switch]$ModifyPath,
    [switch]$NoInit
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host $msg }
function Fail($msg) { Write-Error "agentguard-install: $msg"; exit 1 }

$arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
if ($arch -ne "X64") {
    Fail "unsupported architecture: $arch (v0 only ships x86_64-pc-windows-msvc)"
}
$target = "x86_64-pc-windows-msvc"

if ($Version -eq "latest") {
    $url = "https://github.com/$Repo/releases/latest/download/agentguard-$target.zip"
} else {
    $url = "https://github.com/$Repo/releases/download/$Version/agentguard-$target.zip"
}

Write-Info "AgentGuard installer"
Write-Info "  target:  $target"
Write-Info "  version: $Version"
Write-Info "  from:    $url"
Write-Info "  to:      $InstallDir"
Write-Info ""

$tmpDir = Join-Path $env:TEMP "agentguard-install-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $tmpDir | Out-Null
try {
    $zipPath = Join-Path $tmpDir "agentguard.zip"
    try {
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    } catch {
        Fail "download failed ($url)  -- is $Repo a real repo with a published release yet? If you're testing this script before any release exists, that's expected. ($($_.Exception.Message))"
    }

    Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force
    $extracted = Get-ChildItem -Path $tmpDir -Directory -Filter "agentguard-*" | Select-Object -First 1
    if (-not $extracted) { Fail "unexpected archive layout" }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $extracted.FullName "agentguard.exe") $InstallDir -Force
    Copy-Item (Join-Path $extracted.FullName "agentguard-shim.exe") $InstallDir -Force
    # Ship the license + third-party notices next to the binaries.
    foreach ($f in "LICENSE", "THIRD-PARTY-LICENSES.txt") {
        $src = Join-Path $extracted.FullName $f
        if (Test-Path $src) { Copy-Item $src (Join-Path $InstallDir "agentguard-$f") -Force }
    }

    Write-Info "Installed:"
    Write-Info "  $InstallDir\agentguard.exe"
    Write-Info "  $InstallDir\agentguard-shim.exe"
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
        & "$InstallDir\agentguard.exe" init --project $HOME
    } else {
        Write-Info "Skipped activation (-NoInit passed). Run this yourself when ready:"
        Write-Info "  $InstallDir\agentguard.exe init --project `$HOME"
    }
} finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}
