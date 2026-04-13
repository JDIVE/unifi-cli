#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
OUT_DIR="${2:-release}"

if [[ -z "$VERSION" ]]; then
  echo "usage: $0 <version-tag> [out-dir]" >&2
  exit 1
fi

PYTHON="${PYTHON:-python3}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/pyinstaller-build"
RELEASE_DIR="$ROOT_DIR/$OUT_DIR"

case "$(uname -s)" in
  Linux) OS_NAME="linux" ;;
  Darwin) OS_NAME="macos" ;;
  *) echo "unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH_NAME="x86_64" ;;
  arm64|aarch64) ARCH_NAME="arm64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

cd "$ROOT_DIR"
mkdir -p "$RELEASE_DIR"

"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -e ".[dev]"
"$PYTHON" -m PyInstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name unifi \
  --distpath "$DIST_DIR" \
  --workpath "$ROOT_DIR/pyinstaller-build/work" \
  --specpath "$ROOT_DIR/pyinstaller-build/spec" \
  scripts/pyinstaller_entry.py

ASSET_BASENAME="unifi-${VERSION}-${OS_NAME}-${ARCH_NAME}"
PACKAGE_DIR="$RELEASE_DIR/$ASSET_BASENAME"
mkdir -p "$PACKAGE_DIR"

cp "$DIST_DIR/unifi" "$PACKAGE_DIR/unifi"
cp README.md LICENSE "$PACKAGE_DIR/"

tar -C "$RELEASE_DIR" -czf "$RELEASE_DIR/${ASSET_BASENAME}.tar.gz" "$ASSET_BASENAME"
rm -rf "$PACKAGE_DIR"

echo "built $RELEASE_DIR/${ASSET_BASENAME}.tar.gz"
