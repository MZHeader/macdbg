#!/usr/bin/env bash
# Launcher for the macdbg GUI.
#
# Prefers a native window (pywebview). Vendored deps in vendor313 make that work
# with no pip install (offline / air-gapped VMs). Falls back to the browser UI.
#
# Two macOS-launch quirks are handled here so double-clicking works like a
# terminal launch:
#   * arch: LaunchServices runs a script-based .app as x86_64 (Rosetta) by
#     default; that mismatches an arm64 target and lldb reports "the platform is
#     not currently connected". We force the native arch.
#   * SDK: outside a terminal lldb can't locate the macOS SDK, which also breaks
#     the host platform; we set DEVELOPER_DIR / SDKROOT.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/.." && pwd)"
VENDOR="$DIR/vendor313"

if sysctl -n hw.optional.arm64 2>/dev/null | grep -q 1; then NATIVE=arm64; else NATIVE=x86_64; fi

export DEVELOPER_DIR="${DEVELOPER_DIR:-$(/usr/bin/xcode-select -p 2>/dev/null || true)}"
if [ -z "${SDKROOT:-}" ]; then
    SDKROOT="$(/usr/bin/xcrun --show-sdk-path 2>/dev/null || true)"
    [ -z "$SDKROOT" ] && [ -n "$DEVELOPER_DIR" ] && SDKROOT="$DEVELOPER_DIR/SDKs/MacOSX.sdk"
    [ -n "$SDKROOT" ] && export SDKROOT
fi

CANDIDATES=(
    "$(command -v python3 2>/dev/null || true)"
    "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3"
    "/opt/homebrew/bin/python3"
    "/usr/local/bin/python3"
)
# -S + a clean PYTHONPATH make the front-end use ONLY the vendored deps and
# ignore any user/system site-packages. A duplicate pyobjc in the user's
# site-packages otherwise gets mixed with the vendored one and fails to import
# ("cannot import _objc / circular import") when launched from Finder.
# The vendored pyobjc is built for CPython 3.13, so the interpreter must be able
# to actually load it — test `import objc`, not just `import webview` (pywebview
# is pure Python and imports fine even under the system 3.9, which then can't
# load the 3.13 pyobjc .so). Finder's minimal PATH makes `python3` resolve to
# 3.9, so this check is what steers us to a compatible 3.13.
for c in "${CANDIDATES[@]}"; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    if PYTHONPATH="$VENDOR" PYTHONNOUSERSITE=1 "$c" -S -c "import objc, webview" >/dev/null 2>&1; then
        export PYTHONPATH="$VENDOR"
        export PYTHONNOUSERSITE=1
        exec /usr/bin/arch -"$NATIVE" "$c" -S "$DIR/gui.py" "$@"
    fi
done

# Fallback: browser UI under system python (needs lldb bindings).
export PYTHONPATH="$(/usr/bin/lldb -P):$REPO${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/arch -"$NATIVE" /usr/bin/python3 "$DIR/main.py" "$@"
