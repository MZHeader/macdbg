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

# The bundle executable is a NATIVE arm64 launcher, not a shell script: macOS
# launches script-based .app bundles under Rosetta/x86_64 by default on Apple
# Silicon, so a script here makes a double-click demand Rosetta (LaunchServices
# error -10669) even though macdbg is arm64-only. A native Mach-O is launched
# arm64 directly. It resolves the repo from its own path and execs GUI/run.sh
# (see GUI/launcher.c). Keep macdbg.app at the repo root for that to resolve.
# Compile + ad-hoc sign the Mach-O OUTSIDE the bundle, then move it in. An arm64
# binary needs an ad-hoc signature to run at all (AMFI); signing it as a bare
# file (not via its in-bundle path) signs only the executable and leaves the
# *bundle* unsigned. That matters: a real ad-hoc *bundle* signature makes
# Gatekeeper reject a quarantined double-click, whereas an unsigned, un-
# quarantined local app is allowed to run.
# -mmacosx-version-min pins the binary's minimum-OS load command; without it
# clang stamps the *build host's* macOS, and the app then refuses to launch on
# any older macOS ("you can't use this version of the application with this
# version of macOS"). 11.0 = the arm64 floor, matching LSMinimumSystemVersion.
LAUNCHER_BIN="$(mktemp -t macdbg-launcher)"
clang -arch arm64 -mmacosx-version-min=11.0 -O2 -Wall -o "$LAUNCHER_BIN" "$DIR/launcher.c"
codesign --force --sign - --identifier tech.mzheader.macdbg.gui "$LAUNCHER_BIN" >/dev/null 2>&1 || true
mv "$LAUNCHER_BIN" "$CONTENTS/MacOS/macdbg"
chmod +x "$CONTENTS/MacOS/macdbg"

# App icon (generated, ships in the repo as GUI/macdbg.icns).
if [ -f "$DIR/macdbg.icns" ]; then
    cp "$DIR/macdbg.icns" "$CONTENTS/Resources/macdbg.icns"
fi

# The launcher is ad-hoc signed above and the bundle is intentionally left
# unsigned. Strip the quarantine flag so a freshly built bundle launches cleanly
# from Finder.
xattr -dr com.apple.quarantine "$APP" >/dev/null 2>&1 || true

# Refresh LaunchServices so Finder picks up the new bundle.
touch "$APP"
echo "built $APP"
echo "run:  open \"$APP\"                     # start screen (File → Open)"
echo "      open \"$APP\" --args $REPO/test/hello   # launch a target"
