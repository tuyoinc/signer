#!/bin/sh
# Installs tuyo-signer from GitHub Releases.
#
#   curl -fsSL https://github.com/tuyoinc/signer/releases/latest/download/install.sh | sh
#
# TUYO_SIGNER_VERSION      Release tag to install, such as v0.1.0 (default: latest)
# TUYO_SIGNER_INSTALL_DIR  Where to put the binary (default: ~/.tuyo/bin)
#
# Needs only sh, uname, curl or wget, and sha256sum or shasum. Never needs root.
set -eu

repo="tuyoinc/signer"
version="${TUYO_SIGNER_VERSION:-latest}"
install_dir="${TUYO_SIGNER_INSTALL_DIR:-$HOME/.tuyo/bin}"

fail() {
  echo "tuyo-signer install: $*" >&2
  exit 1
}

case "$(uname -s)" in
  Linux) os=unknown-linux-musl ;;
  Darwin) os=apple-darwin ;;
  *) fail "unsupported OS $(uname -s). On Windows, download tuyo-signer-x86_64-pc-windows-msvc.exe from https://github.com/$repo/releases." ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) fail "unsupported CPU $(uname -m)." ;;
esac
if [ "$os" = apple-darwin ]; then
  asset="tuyo-signer-universal-apple-darwin"
else
  asset="tuyo-signer-$arch-$os"
fi

if [ "$version" = latest ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    fail "needs curl or wget."
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    fail "needs sha256sum or shasum to verify the download."
  fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $asset ($version)..."
fetch "$base/$asset" "$tmp/tuyo-signer" || fail "download failed: $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "download failed: $base/SHA256SUMS"

expected="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || fail "SHA256SUMS has no entry for $asset."
[ "$(sha256 "$tmp/tuyo-signer")" = "$expected" ] || fail "checksum mismatch for $asset."

chmod 755 "$tmp/tuyo-signer"
"$tmp/tuyo-signer" --version >/dev/null 2>&1 || fail "the downloaded binary does not run on this machine."

mkdir -p "$install_dir"
mv -f "$tmp/tuyo-signer" "$install_dir/tuyo-signer"
echo "Installed $("$install_dir/tuyo-signer" --version) to $install_dir/tuyo-signer"

case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "Add it to your PATH:  export PATH=\"$install_dir:\$PATH\"" ;;
esac
