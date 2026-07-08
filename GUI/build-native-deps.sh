#!/usr/bin/env bash
# Build a native-deps tarball (pywebview + its pyobjc backend) for ONE Python
# version, to upload as a GitHub Release asset. It repackages what
# `pip install --target` produces so run.sh / get-native-deps.sh can load it
# over PYTHONPATH with no network and no pip.
#
# pyobjc's C extensions are ABI-locked to each CPython minor version, so build
# one tarball per version:
#
#   ./build-native-deps.sh 3.13            # uv installs the interpreter
#   ./build-native-deps.sh /path/to/python3
#
# Prints the path to the tarball it wrote.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
ARG="${1:-3.13}"
ARCH="$(uname -m)"
OUT="$(mktemp -d)"

if [[ "$ARG" =~ ^3\.[0-9]+$ ]] && command -v uv >/dev/null 2>&1; then
    uv python install "$ARG" >/dev/null 2>&1 || true
    PY="$(uv python find "$ARG")"
else
    PY="$ARG"
fi
[ -x "$PY" ] || { echo "no usable interpreter: $ARG" >&2; exit 1; }
CPTAG="$("$PY" -c 'import sys;print("cp%d%d"%sys.version_info[:2])')"

echo "Building pywebview for $("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])') ($ARCH)…" >&2
if command -v uv >/dev/null 2>&1; then
    uv pip install --python "$PY" --target "$OUT" pywebview >&2
else
    "$PY" -m pip install --target "$OUT" pywebview >&2
fi

# sanity-check it imports in isolation before shipping it. -B so the check
# doesn't write .pyc files back into the tree we're about to strip.
PYTHONPATH="$OUT" PYTHONNOUSERSITE=1 "$PY" -SB -c "import objc, webview" \
    || { echo "built bundle failed to import objc+webview" >&2; rm -rf "$OUT"; exit 1; }

# Drop anything not needed at runtime that could carry build-machine paths:
#   bin/         console scripts whose shebang is this interpreter's abs path
#                (leaks the build user's home); pywebview imports the modules,
#                never these scripts.
#   __pycache__  .pyc files embed compile-time source paths.
#   .lock        uv's install lock.
rm -rf "$OUT/bin" "$OUT/.lock"
find "$OUT" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$OUT" -name '*.pyc' -delete 2>/dev/null || true

# Anonymise tar ownership so the headers carry no username/uid from this machine.
ASSET="pywebview-macos-${ARCH}-${CPTAG}.tar.gz"
tar --uid 0 --gid 0 --uname '' --gname '' -czf "$DIR/$ASSET" -C "$OUT" .
rm -rf "$OUT"
echo "$DIR/$ASSET"
