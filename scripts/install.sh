#!/usr/bin/env bash
# AgentGuard installer — macOS / Linux.
#
#   curl -fsSL https://<install-url>/install.sh | sh
#
# Downloads the agentguard + agentguard-shim release binaries for this
# machine, installs them to ~/.agentguard/bin, and runs `agentguard init`
# against the user's home directory so every MCP server config it can find
# (project-level ones aren't touched — only what's reachable from $HOME,
# which is where Claude Code's own user-scope config lives) gets routed
# through the enforcement shim. That last step is what "install once,
# forget it exists" (BUILD_PLAN.md's product philosophy) actually requires
# — a binary that's merely present but never activated protects nothing.
#
# NOT wired to a real download yet: AGENTGUARD_REPO below is a placeholder
# until a real release exists (see .github/workflows/release.yml — this
# script downloads exactly what that workflow publishes). Until then this
# script will fail at the download step with a clear error, on purpose,
# rather than silently doing nothing.
#
# Does NOT modify your shell profile (.bashrc/.zshrc/etc.) unless you pass
# --modify-path — a standing edit to your shell config is a bigger, more
# persistent change than installing a binary, and deserves to be something
# you asked for explicitly, not a default side effect of piping a script
# into your shell.

set -euo pipefail

AGENTGUARD_REPO="${AGENTGUARD_REPO:-your-org/agentguard}" # TODO: set to the real repo once one exists
AGENTGUARD_VERSION="${AGENTGUARD_VERSION:-latest}"
INSTALL_DIR="${AGENTGUARD_INSTALL_DIR:-$HOME/.agentguard/bin}"
MODIFY_PATH=0
RUN_INIT=1

for arg in "$@"; do
  case "$arg" in
    --modify-path) MODIFY_PATH=1 ;;
    --no-init) RUN_INIT=0 ;;
    *)
      echo "agentguard-install: unknown option '$arg'" >&2
      exit 1
      ;;
  esac
done

say() { printf '%s\n' "$*"; }
err() { printf 'agentguard-install: %s\n' "$*" >&2; exit 1; }

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin) os_part="apple-darwin" ;;
    Linux) os_part="unknown-linux-gnu" ;;
    *) err "unsupported OS: $os (AgentGuard v0 supports macOS and Linux via this script; Windows via install.ps1)" ;;
  esac

  case "$arch" in
    x86_64 | amd64) arch_part="x86_64" ;;
    arm64 | aarch64) arch_part="aarch64" ;;
    *) err "unsupported architecture: $arch" ;;
  esac

  printf '%s-%s\n' "$arch_part" "$os_part"
}

main() {
  command -v curl >/dev/null 2>&1 || err "curl is required"
  command -v tar >/dev/null 2>&1 || err "tar is required"

  local target url tmpdir
  target="$(detect_target)"
  if [ "$AGENTGUARD_VERSION" = "latest" ]; then
    url="https://github.com/${AGENTGUARD_REPO}/releases/latest/download/agentguard-${target}.tar.gz"
  else
    url="https://github.com/${AGENTGUARD_REPO}/releases/download/${AGENTGUARD_VERSION}/agentguard-${target}.tar.gz"
  fi

  say "AgentGuard installer"
  say "  target:  $target"
  say "  version: $AGENTGUARD_VERSION"
  say "  from:    $url"
  say "  to:      $INSTALL_DIR"
  say ""

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  if ! curl -fsSL "$url" -o "$tmpdir/agentguard.tar.gz"; then
    err "download failed ($url) — is $AGENTGUARD_REPO a real repo with a published release yet? If you're testing this script before any release exists, that's expected."
  fi

  mkdir -p "$INSTALL_DIR"
  tar xzf "$tmpdir/agentguard.tar.gz" -C "$tmpdir"
  # The archive extracts to a directory named agentguard-<target>/ (see the
  # release workflow's packaging step) containing both binaries.
  local extracted
  extracted="$(find "$tmpdir" -maxdepth 1 -type d -name 'agentguard-*')"
  [ -n "$extracted" ] || err "unexpected archive layout"

  cp "$extracted/agentguard" "$INSTALL_DIR/agentguard"
  cp "$extracted/agentguard-shim" "$INSTALL_DIR/agentguard-shim"
  chmod +x "$INSTALL_DIR/agentguard" "$INSTALL_DIR/agentguard-shim"

  say "Installed:"
  say "  $INSTALL_DIR/agentguard"
  say "  $INSTALL_DIR/agentguard-shim"
  say ""

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      if [ "$MODIFY_PATH" = "1" ]; then
        local profile
        profile="$(detect_profile)"
        if [ -n "$profile" ]; then
          printf '\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$profile"
          say "Added $INSTALL_DIR to PATH in $profile — restart your shell (or source it) to pick this up."
        fi
      else
        say "NOTE: $INSTALL_DIR is not on your PATH."
        say "Add it yourself, or re-run this installer with --modify-path to have it appended to your shell profile automatically."
        say "  export PATH=\"$INSTALL_DIR:\$PATH\""
      fi
      ;;
  esac
  say ""

  if [ "$RUN_INIT" = "1" ]; then
    say "Activating protection for every Claude Code MCP server config under \$HOME..."
    "$INSTALL_DIR/agentguard" init --project "$HOME"
  else
    say "Skipped activation (--no-init passed). Run this yourself when ready:"
    say "  $INSTALL_DIR/agentguard init --project \"\$HOME\""
  fi
}

detect_profile() {
  case "${SHELL:-}" in
    */zsh) printf '%s' "$HOME/.zshrc" ;;
    */bash) printf '%s' "$HOME/.bashrc" ;;
    *) printf '%s' "" ;;
  esac
}

main "$@"
