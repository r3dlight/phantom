#!/bin/sh
# Phantom one-shot installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/r3dlight/phantom/main/install.sh | sh
#
# Environment overrides:
#   PHANTOM_VERSION       Tag to install (default: latest GitHub release)
#   PHANTOM_INSTALL_DIR   Target dir (default: $HOME/.local/bin if writable, else /usr/local/bin)
#   PHANTOM_NO_VERIFY     Set non-empty to skip SHA256 checking
#   PHANTOM_REPO          Repo slug (default: r3dlight/phantom)
#
# Supported platforms: Linux x86_64/aarch64, macOS Intel/Apple-Silicon.
# Windows users: download the .zip from the release page directly.

set -eu

REPO="${PHANTOM_REPO:-r3dlight/phantom}"
NAME="phantom"

err()  { printf 'install: error: %s\n' "$*" >&2; exit 1; }
note() { printf 'install: %s\n' "$*"; }

# ─── Downloader ─────────────────────────────────────────────────────────────
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O - "$1"; }
else
    err "need curl or wget on PATH"
fi

# ─── Platform detection ─────────────────────────────────────────────────────
os="$(uname -s)"
arch="$(uname -m)"
case "$os/$arch" in
    Linux/x86_64)              target="x86_64-unknown-linux-gnu" ;;
    Linux/aarch64|Linux/arm64) target="aarch64-unknown-linux-gnu" ;;
    Darwin/x86_64)             target="x86_64-apple-darwin" ;;
    Darwin/arm64)              target="aarch64-apple-darwin" ;;
    *) err "unsupported platform $os/$arch — download manually from https://github.com/$REPO/releases" ;;
esac

# ─── Tag resolution ─────────────────────────────────────────────────────────
tag="${PHANTOM_VERSION:-}"
if [ -z "$tag" ]; then
    note "resolving latest release tag..."
    tag="$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
           | grep '"tag_name"' \
           | head -n1 \
           | sed 's/.*: *"\([^"]*\)".*/\1/')"
    [ -n "$tag" ] || err "could not resolve latest tag (rate-limited? set PHANTOM_VERSION explicitly)"
fi
note "installing $NAME $tag for $target"

# ─── Install dir ────────────────────────────────────────────────────────────
install_dir="${PHANTOM_INSTALL_DIR:-}"
if [ -z "$install_dir" ]; then
    if mkdir -p "$HOME/.local/bin" 2>/dev/null && [ -w "$HOME/.local/bin" ]; then
        install_dir="$HOME/.local/bin"
    else
        install_dir="/usr/local/bin"
    fi
fi
note "install dir: $install_dir"

# ─── Download ───────────────────────────────────────────────────────────────
tmp="$(mktemp -d 2>/dev/null || mktemp -d -t phantom-install)"
trap 'rm -rf "$tmp"' EXIT INT TERM

archive="$NAME-$tag-$target.tar.gz"
url="https://github.com/$REPO/releases/download/$tag/$archive"
note "downloading $archive..."
fetch "$url" > "$tmp/$archive" || err "download failed: $url"

# ─── Verify SHA256 ──────────────────────────────────────────────────────────
if [ -z "${PHANTOM_NO_VERIFY:-}" ]; then
    note "verifying SHA256..."
    fetch "https://github.com/$REPO/releases/download/$tag/SHA256SUMS" > "$tmp/SHA256SUMS" \
        || err "could not fetch SHA256SUMS (set PHANTOM_NO_VERIFY=1 to skip — not recommended)"
    expected="$(grep -F " $archive" "$tmp/SHA256SUMS" | head -n1 | awk '{print $1}')"
    [ -n "$expected" ] || err "no SHA256 entry for $archive in SHA256SUMS"
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
    else
        err "need sha256sum or shasum (or set PHANTOM_NO_VERIFY=1)"
    fi
    [ "$actual" = "$expected" ] || err "checksum mismatch: got $actual, expected $expected"
    note "checksum OK"
fi

# ─── Extract and install ────────────────────────────────────────────────────
note "extracting..."
tar -xzf "$tmp/$archive" -C "$tmp"
src="$tmp/$NAME-$tag-$target/$NAME"
[ -f "$src" ] || err "binary missing at $src after extraction"
chmod +x "$src" 2>/dev/null || true

if [ -w "$install_dir" ]; then
    cp "$src" "$install_dir/$NAME"
elif command -v sudo >/dev/null 2>&1; then
    note "no write permission on $install_dir; escalating with sudo"
    sudo cp "$src" "$install_dir/$NAME"
else
    err "$install_dir is not writable and sudo is unavailable; set PHANTOM_INSTALL_DIR to a writable directory"
fi

note "installed: $install_dir/$NAME"

# ─── PATH advice ────────────────────────────────────────────────────────────
case ":$PATH:" in
    *":$install_dir:"*) ;;
    *)
        note "note: $install_dir is not on \$PATH"
        note '      add this to your shell rc:  export PATH="'"$install_dir"':$PATH"'
        ;;
esac

"$install_dir/$NAME" --version
