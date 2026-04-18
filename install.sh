#!/bin/sh
set -e

REPO="PoHsuanLai/jip"
BIN="jip"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Prefer musl (static) unless glibc explicitly requested
LIBC="${LIBC:-musl}"
TARGET="${ARCH}-unknown-linux-${LIBC}"

# Resolve latest release tag
TAG=$(curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$TAG" ]; then
    echo "error: could not determine latest release tag" >&2
    exit 1
fi

URL="https://github.com/${REPO}/releases/download/${TAG}/${BIN}-${TAG}-${TARGET}.tar.gz"

echo "Installing ${BIN} ${TAG} (${TARGET}) → ${INSTALL_DIR}/${BIN}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -sSfL "$URL" | tar -xz -C "$TMP"

# Install — try sudo if target dir isn't writable
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP/$BIN" "$INSTALL_DIR/$BIN"
else
    sudo mv "$TMP/$BIN" "$INSTALL_DIR/$BIN"
fi

echo "Done. Run: ${BIN} --version"
