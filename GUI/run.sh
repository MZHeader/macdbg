#!/usr/bin/env bash
# Launcher for the macdbg GUI.
#
# Prefers a native window (pywebview). Get it however suits you:
#   * ./get-native-deps.sh  — download a prebuilt offline bundle for your Python
#   * pip install pywebview — into a venv at ~/.macdbg/venv (auto-detected) when
#     a global install is blocked by an externally-managed Python (PEP 668)
#   * $MACDBG_PYTHON        — point at any interpreter that already has it
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

# A Finder / double-click launch inherits a minimal PATH, so `command -v python3`
# misses the pyenv/conda/venv Python the user set up in their shell — the very
# one that has pywebview and that run.sh finds fine from a Terminal. Recover the
# login shell's PATH (marker-delimited so a chatty rc file can't corrupt it) and
# take its python3, so a double-click discovers the same interpreter a terminal
# launch does.
LOGIN_PY=""
_login_raw="$("${SHELL:-/bin/zsh}" -ilc 'printf "__MACDBGPATH__%s__END__" "$PATH"' 2>/dev/null </dev/null || true)"
LOGIN_PATH="$(printf '%s' "$_login_raw" | sed -n 's/.*__MACDBGPATH__\(.*\)__END__.*/\1/p')"
if [ -n "$LOGIN_PATH" ]; then
    LOGIN_PY="$(PATH="$LOGIN_PATH" command -v python3 2>/dev/null || true)"
fi

# Interpreters to try for the native window, best first. $MACDBG_PYTHON is an
# explicit override; the venv paths are the easy answer when a global
# `pip install` is blocked by an externally-managed Python (PEP 668) — put
# pywebview in a venv here and it's found even from the double-clicked .app,
# which has no activated shell. LOGIN_PY and the version-manager spots recover a
# user's active Python from a Finder launch; then whatever's on PATH / usual spots.
CANDIDATES=(
    "${MACDBG_PYTHON:-}"
    "$HOME/.macdbg/venv/bin/python3"
    "$REPO/.venv/bin/python3"
    "$DIR/.venv/bin/python3"
    "${LOGIN_PY:-}"
    "$(command -v python3 2>/dev/null || true)"
    "$HOME/.pyenv/shims/python3"
    "$HOME/miniforge3/bin/python3"
    "$HOME/miniconda3/bin/python3"
    "$HOME/anaconda3/bin/python3"
    "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3"
    "/opt/homebrew/bin/python3"
    "/usr/local/bin/python3"
)
# Use the first interpreter that can reach pywebview. Test `import objc` (not
# just webview): pywebview is pure Python and imports even where its pyobjc
# backend can't run, and pyobjc's native extensions are ABI-locked per CPython
# minor version — so this matches a Python to deps built for it. For each
# candidate we try, in order:
#   1. an offline bundle downloaded by get-native-deps.sh into vendor-cp<XY>/
#      (loaded isolated with -S so it can't clash with a site-packages pyobjc),
#   2. a pip/venv-installed pywebview in that interpreter's own environment.
# Probe each candidate for pywebview (its pyobjc backend must import too). When a
# candidate can't, capture WHY — so if we fall through to the browser we can tell
# the user where we looked and what went wrong instead of silently opening Safari.
# Each line also goes to ~/.macdbg/launch.log via stderr.
PROBE=""
for c in "${CANDIDATES[@]}"; do
    [ -n "$c" ] || continue
    if [ ! -x "$c" ]; then
        echo "[pywebview] not found: $c" >&2
        continue
    fi
    ver="$("$c" -c 'import sys;print(".".join(map(str,sys.version_info[:3])))' 2>/dev/null || echo '?')"
    tag="$("$c" -c 'import sys;print("cp%d%d"%sys.version_info[:2])' 2>/dev/null || true)"
    vd="$DIR/vendor-$tag"

    # 1) offline vendored bundle for this exact Python version (isolated with -S)
    if [ -n "$tag" ] && [ -d "$vd" ]; then
        err="$(PYTHONPATH="$vd" PYTHONNOUSERSITE=1 "$c" -S -c 'import objc, webview' 2>&1)" && ok=1 || ok=0
        if [ "$ok" = 1 ]; then
            echo "[pywebview] $c via offline bundle $vd" >&2
            export PYTHONPATH="$vd"; export PYTHONNOUSERSITE=1
            exec /usr/bin/arch -"$NATIVE" "$c" -S "$DIR/gui.py" "$@"
        fi
        echo "[pywebview] $c + $vd -> $(printf '%s' "$err" | tail -n1)" >&2
    fi

    # 2) pywebview installed in the interpreter's own environment
    err="$("$c" -c 'import objc, webview' 2>&1)" && ok=1 || ok=0
    if [ "$ok" = 1 ]; then
        echo "[pywebview] $c (has pywebview)" >&2
        exec /usr/bin/arch -"$NATIVE" "$c" "$DIR/gui.py" "$@"
    fi
    last="$(printf '%s' "$err" | tail -n1)"
    echo "[pywebview] $c (Python $ver) -> $last" >&2
    PROBE="${PROBE}• ${c} (Python ${ver})
      ${last}
"
done
[ -n "$PROBE" ] || PROBE="(no usable Python interpreter was found)
"

# Fallback: no pywebview anywhere -> browser UI under system python (needs lldb
# bindings). Tell the user where we looked, why each Python failed, and how to
# fix it. Backgrounded so the dialog doesn't hold up the launch.
MSG="macdbg is running in a browser window because it couldn't load pywebview (its native-window toolkit) in any Python it found.

Where it looked:
${PROBE}
Fix — do ONE of these, then relaunch:

1)  Install it in a venv (run.sh finds this automatically):
       python3 -m venv ~/.macdbg/venv
       ~/.macdbg/venv/bin/pip install pywebview

2)  Offline machine — grab the bundle for your Python from the native-deps
     release, then install it locally:
       GUI/get-native-deps.sh <bundle>.tar.gz

3)  Already have pywebview somewhere — point macdbg at that interpreter:
       export MACDBG_PYTHON=/path/to/python3

Details are in ~/.macdbg/launch.log"
ESC="$(printf '%s' "$MSG" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
osascript -e "display dialog \"$ESC\" buttons {\"OK\"} default button \"OK\" with title \"macdbg — no native window\" with icon caution" >/dev/null 2>&1 &
export PYTHONPATH="$(/usr/bin/lldb -P):$REPO${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/arch -"$NATIVE" /usr/bin/python3 "$DIR/main.py" "$@"
