#!/usr/bin/env bash
# Fetch the vendored pywebview/pyobjc native deps for your Python so the macdbg
# GUI opens a real native window with no `pip install`. run.sh then finds them
# automatically. Good for offline / air-gapped machines.
#
#   ./get-native-deps.sh                       # download the matching asset
#   ./get-native-deps.sh ./pywebview-…tar.gz   # install a tarball copied over (offline)
#   MACDBG_PYTHON=/path/to/python3 ./get-native-deps.sh
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
SLUG="MZHeader/macdbg"
TAG="native-deps"
ARCH="$(uname -m)"

PY="${MACDBG_PYTHON:-$(command -v python3 || true)}"
[ -n "$PY" ] && [ -x "$PY" ] || { echo "no python3 found; set MACDBG_PYTHON" >&2; exit 1; }
CPTAG="$("$PY" -c 'import sys;print("cp%d%d"%sys.version_info[:2])')"
VER="$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
ASSET="pywebview-macos-${ARCH}-${CPTAG}.tar.gz"
DEST="$DIR/vendor-${CPTAG}"

if [ "${1:-}" ]; then
    TARBALL="$1"
    [ -f "$TARBALL" ] || { echo "no such file: $TARBALL" >&2; exit 1; }
    CLEANUP=""
else
    TARBALL="$(mktemp -t macdbg-native).tgz"; CLEANUP="$TARBALL"
    URL="https://github.com/${SLUG}/releases/download/${TAG}/${ASSET}"
    echo "Downloading ${ASSET}…"
    curl -fL --progress-bar "$URL" -o "$TARBALL" || {
        echo "No prebuilt bundle for Python ${VER} (${ARCH})." >&2
        echo "Try a supported Python, or just: pip install pywebview" >&2
        rm -f "$CLEANUP"; exit 1; }
fi

rm -rf "$DEST"; mkdir -p "$DEST"
tar xzf "$TARBALL" -C "$DEST"
[ -n "$CLEANUP" ] && rm -f "$CLEANUP"

if PYTHONPATH="$DEST" PYTHONNOUSERSITE=1 "$PY" -S -c "import objc, webview" 2>/dev/null; then
    echo "Installed native deps for Python ${VER} -> ${DEST}"
    echo "Launch it:  ${DIR}/run.sh /path/to/binary"
else
    echo "Extracted but the bundle failed to import (version/arch mismatch)." >&2
    rm -rf "$DEST"; exit 1
fi
