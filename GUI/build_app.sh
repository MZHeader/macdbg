#!/usr/bin/env bash
# Build macdbg.app (at the repo root) — the double-clickable entry point.
#
# The bundle is a thin launcher: it hard-codes this checkout's path, sets
# PYTHONPATH to the system LLDB Python bindings, and execs GUI/main.py under
# /usr/bin/python3 (the only interpreter that can `import lldb` AND has tkinter).
# It runs unsigned for local use — launch + attach work because LLDB spawns
# Apple-signed debugserver.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/.." && pwd)"
APP="$REPO/macdbg.app"
CONTENTS="$APP/Contents"

rm -rf "$APP"
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources"

cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>            <string>macdbg</string>
    <key>CFBundleDisplayName</key>     <string>macdbg</string>
    <key>CFBundleExecutable</key>      <string>macdbg</string>
    <key>CFBundleIdentifier</key>      <string>tech.mzheader.macdbg.gui</string>
    <key>CFBundleVersion</key>         <string>1.1.0</string>
    <key>CFBundleShortVersionString</key> <string>1.1.0</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>LSMinimumSystemVersion</key>  <string>11.0</string>
    <key>NSHighResolutionCapable</key> <true/>
    <key>LSUIElement</key>             <false/>
    <key>CFBundleIconFile</key>        <string>macdbg.icns</string>
</dict>
</plist>
PLIST

# Launcher delegates to run.sh. The repo path is resolved from the bundle's own
# location at runtime (not baked in) so nothing about the build user is embedded
# in the bundle. Keep macdbg.app at the repo root for this to resolve. All output
# is appended to ~/.macdbg/launch.log so a failed launch leaves a trace.
cat > "$CONTENTS/MacOS/macdbg" <<'LAUNCH'
#!/bin/bash
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
mkdir -p "$HOME/.macdbg" 2>/dev/null
exec >> "$HOME/.macdbg/launch.log" 2>&1
echo "=== launch $(date '+%F %T') uname=$(uname -m) ==="
exec "$REPO/GUI/run.sh" "$@"
LAUNCH
chmod +x "$CONTENTS/MacOS/macdbg"

# App icon (generated, ships in the repo as GUI/macdbg.icns).
if [ -f "$DIR/macdbg.icns" ]; then
    cp "$DIR/macdbg.icns" "$CONTENTS/Resources/macdbg.icns"
fi

# Deliberately NOT code-signed: an ad-hoc signature makes Gatekeeper (spctl)
# *reject* the bundle on Finder double-click (bounce + vanish), whereas an
# unsigned, locally-built app is allowed to run. Strip any stale signature and
# the quarantine flag so a rebuilt bundle launches cleanly from Finder.
codesign --remove-signature "$APP" >/dev/null 2>&1 || true
xattr -dr com.apple.quarantine "$APP" >/dev/null 2>&1 || true

# Refresh LaunchServices so Finder picks up the new bundle.
touch "$APP"
echo "built $APP"
echo "run:  open \"$APP\"                     # start screen (File → Open)"
echo "      open \"$APP\" --args $REPO/test/hello   # launch a target"
