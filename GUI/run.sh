#!/usr/bin/env bash
# Launcher for the macdbg GUI.
#
# Prefers a native window (pywebview); install it with `pip install pywebview`.
# Falls back to a chromeless browser window when pywebview isn't available.
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
# Use the first interpreter that can import pywebview. Test `import objc` (not
# just webview): pywebview is pure Python and imports even where its pyobjc
# backend can't run, and pyobjc's native extensions are built per CPython minor
# version — so this picks a Python whose installed pywebview/pyobjc match it.
for c in "${CANDIDATES[@]}"; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    if "$c" -c "import objc, webview" >/dev/null 2>&1; then
        exec /usr/bin/arch -"$NATIVE" "$c" "$DIR/gui.py" "$@"
    fi
done

# Fallback: no pywebview -> browser UI under system python (needs lldb bindings).
# Nudge the user toward the nicer native window. This self-limits: once pywebview
# is installed we take the native path above and never reach here. Backgrounded
# so the dialog doesn't hold up the launch.
osascript -e 'display dialog "macdbg is running in a browser window.

For the full native app — its own window, menu bar, and dock icon — install pywebview, then relaunch:

    python3 -m pip install pywebview" buttons {"OK"} default button "OK" with title "macdbg" with icon note' >/dev/null 2>&1 &
export PYTHONPATH="$(/usr/bin/lldb -P):$REPO${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/arch -"$NATIVE" /usr/bin/python3 "$DIR/main.py" "$@"
