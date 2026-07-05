#!/usr/bin/env bash
#
# scripts/build_binary.sh
#
# Build pkgd standalone binary using PyInstaller.
# Also generates a SHA256 checksum file.
#
# Usage:
#   ./scripts/build_binary.sh                    # build for current platform
#   ./scripts/build_binary.sh --name pkgd-custom  # custom binary name
#
# Requires:
#   - pyinstaller (pip install pyinstaller)
#
# Output:
#   dist/<name>          — standalone binary
#   dist/<name>.sha256   — SHA256 checksum
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="pkgd"

# ── Parse arguments ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
    --name)
        BINARY_NAME="$2"
        shift 2
        ;;
    --help)
        echo "Usage: $(basename "$0") [--name BINARY_NAME]"
        exit 0
        ;;
    *)
        echo "Error: Unknown option: $1"
        echo "Usage: $(basename "$0") [--name BINARY_NAME]"
        exit 1
        ;;
    esac
done

# ── Verify prerequisites ─────────────────────────────────────────────────────

if ! command -v pyinstaller &>/dev/null; then
    echo "Error: pyinstaller is not installed."
    echo "Install with: pip install pyinstaller"
    exit 1
fi

# ── Build binary ─────────────────────────────────────────────────────────────

cd "$PROJECT_DIR"

echo "==> Building binary: ${BINARY_NAME}"
echo "==> PyInstaller version: $(pyinstaller --version 2>/dev/null || echo 'unknown')"

pyinstaller \
    --onefile \
    --name "$BINARY_NAME" \
    --clean \
    --noconfirm \
    src/pkg_defender/__pkgd_entry__.py

echo ""
echo "==> Binary built: dist/${BINARY_NAME}"
echo "==> Size: $(du -h "dist/${BINARY_NAME}" | cut -f1)"

# ── Generate SHA256 checksum ─────────────────────────────────────────────────

if command -v shasum &>/dev/null; then
    shasum -a 256 "dist/${BINARY_NAME}" >"dist/${BINARY_NAME}.sha256"
elif command -v sha256sum &>/dev/null; then
    sha256sum "dist/${BINARY_NAME}" >"dist/${BINARY_NAME}.sha256"
else
    python -c "
import hashlib
data = open('dist/${BINARY_NAME}', 'rb').read()
h = hashlib.sha256(data).hexdigest()
with open('dist/${BINARY_NAME}.sha256', 'w') as f:
    f.write(f'{h}  ${BINARY_NAME}\n')
"
fi

echo "==> SHA256: $(cat "dist/${BINARY_NAME}.sha256")"
echo "==> Done."
