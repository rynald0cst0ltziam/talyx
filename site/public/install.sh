#!/usr/bin/env bash
# Talyx installer — macOS / Linux.
#
#   curl -fsSL https://<install-url>/install.sh | sh
#
# Downloads the talyx + talyx-shim release binaries for this machine and
# installs them to ~/.talyx/bin. Does NOT run `talyx init` — that requires
# a license, which doesn't exist yet at install time (see docs#activate).
# Running init unlicensed here used to print a scary error as the very
# last step of a fresh install; now the script just prints the next two
# commands (activate, then init) and stops.
#
# TALYX_REPO points at the real repo, but no release has been tagged yet
# (see .github/workflows/release.yml — this script downloads exactly what
# that workflow publishes). Until then this script will fail at the
# download step with a clear error, on purpose,
# rather than silently doing nothing.
#
# `sh` here is whatever /bin/sh is on this system — on Debian/Ubuntu
# that's dash, which does NOT support `set -o pipefail` (confirmed live:
# it aborts on the very first line with "Illegal option -o pipefail"
# before printing anything). The script has no internal pipeline that
# needs it, so it's simply not turned on — `set -eu` alone is POSIX and
# portable to every /bin/sh this is documented to run under.
#
# Does NOT modify your shell profile (.bashrc/.zshrc/etc.) unless you pass
# --modify-path — a standing edit to your shell config is a bigger, more
# persistent change than installing a binary, and deserves to be something
# you asked for explicitly, not a default side effect of piping a script
# into your shell.

set -eu

TALYX_REPO="${TALYX_REPO:-rynald0cst0ltziam/talyx}"
TALYX_VERSION="${TALYX_VERSION:-latest}"
INSTALL_DIR="${TALYX_INSTALL_DIR:-$HOME/.talyx/bin}"
MODIFY_PATH=0

for arg in "$@"; do
  case "$arg" in
    --modify-path) MODIFY_PATH=1 ;;
    *)
      echo "talyx-install: unknown option '$arg'" >&2
      exit 1
      ;;
  esac
done

say() { printf '%s\n' "$*"; }
err() { printf 'talyx-install: %s\n' "$*" >&2; exit 1; }

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin) os_part="apple-darwin" ;;
    Linux) os_part="unknown-linux-gnu" ;;
    *) err "unsupported OS: $os (Talyx v0 supports macOS and Linux via this script; Windows via install.ps1)" ;;
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

  # tmpdir is deliberately NOT `local`: the `trap ... EXIT` below fires at
  # the SCRIPT's exit, not when main() returns, and a `local` variable is
  # already out of scope by then — under `set -u` that's a hard error
  # ("tmpdir: parameter not set"), confirmed live: the script otherwise
  # completed successfully (binaries installed, next-steps printed) and
  # then failed anyway, on exit, for a customer who'd already succeeded.
  local target url
  target="$(detect_target)"
  if [ "$TALYX_VERSION" = "latest" ]; then
    url="https://github.com/${TALYX_REPO}/releases/latest/download/talyx-${target}.tar.gz"
  else
    url="https://github.com/${TALYX_REPO}/releases/download/${TALYX_VERSION}/talyx-${target}.tar.gz"
  fi

  say "Talyx installer"
  say "  target:  $target"
  say "  version: $TALYX_VERSION"
  say "  from:    $url"
  say "  to:      $INSTALL_DIR"
  say ""

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  if ! curl -fsSL "$url" -o "$tmpdir/talyx.tar.gz"; then
    err "download failed ($url) — is $TALYX_REPO a real repo with a published release yet? If you're testing this script before any release exists, that's expected."
  fi

  mkdir -p "$INSTALL_DIR"
  tar xzf "$tmpdir/talyx.tar.gz" -C "$tmpdir"
  # The archive extracts to a directory named talyx-<target>/ (see the
  # release workflow's packaging step) containing both binaries.
  local extracted
  extracted="$(find "$tmpdir" -maxdepth 1 -type d -name 'talyx-*')"
  [ -n "$extracted" ] || err "unexpected archive layout"

  cp "$extracted/talyx" "$INSTALL_DIR/talyx"
  cp "$extracted/talyx-shim" "$INSTALL_DIR/talyx-shim"
  chmod +x "$INSTALL_DIR/talyx" "$INSTALL_DIR/talyx-shim"
  # Ship the license + third-party notices next to the binaries (the
  # bundled MIT/BSD/Apache crates require their notices to travel along).
  for f in LICENSE THIRD-PARTY-LICENSES.txt; do
    [ -f "$extracted/$f" ] && cp "$extracted/$f" "$INSTALL_DIR/talyx-$f" || true
  done

  say "Installed:"
  say "  $INSTALL_DIR/talyx"
  say "  $INSTALL_DIR/talyx-shim"
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
  say "Next steps (PATH changes only take effect in a NEW shell, so this"
  say "session still needs the full path):"
  say "  $INSTALL_DIR/talyx activate <YOUR-LICENSE-KEY>   # from your purchase email"
  say "  $INSTALL_DIR/talyx scan --project .              # free, read-only, no license needed"
  say "  $INSTALL_DIR/talyx init --project .              # after activating, turns on enforcement"
}

detect_profile() {
  case "${SHELL:-}" in
    */zsh) printf '%s' "$HOME/.zshrc" ;;
    */bash) printf '%s' "$HOME/.bashrc" ;;
    *) printf '%s' "" ;;
  esac
}

main "$@"
