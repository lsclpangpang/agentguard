#!/usr/bin/env bash
# Builds an ad-hoc signed AgentGuard.app and build/AgentGuard.zip (macOS only).
# Environment: VERSION (default: contents of VERSION), BUILD_NUMBER (default: 0).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(cat VERSION)}"
BUILD_NUMBER="${BUILD_NUMBER:-0}"
APP=build/AgentGuard.app
MACOS="$APP/Contents/MacOS"

swift build -c release --arch arm64
BIN="$(swift build -c release --arch arm64 --show-bin-path)"

rm -rf build
mkdir -p "$MACOS" "$APP/Contents/Library/LaunchDaemons" "$APP/Contents/Resources"
for binary in AgentGuard guard agentguard-launcher agentguard-helper; do
    cp "$BIN/$binary" "$MACOS/"
done
sed -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD_NUMBER/" packaging/Info.plist > "$APP/Contents/Info.plist"
cp packaging/com.lsclpangpang.agentguard.helper.plist "$APP/Contents/Library/LaunchDaemons/"

# Ad-hoc signatures with fixed identifiers; the Helper pins the resulting cdhashes at runtime.
sign() { codesign --force --options runtime --timestamp=none --sign - --identifier "$1" "$2"; }
sign com.lsclpangpang.agentguard.cli "$MACOS/guard"
sign com.lsclpangpang.agentguard.launcher "$MACOS/agentguard-launcher"
sign com.lsclpangpang.agentguard.helper "$MACOS/agentguard-helper"
sign com.lsclpangpang.agentguard "$APP"
codesign --verify --strict --verbose=2 "$APP"

(cd build && ditto -c -k --keepParent AgentGuard.app AgentGuard.zip)
echo "built build/AgentGuard.zip ($VERSION build $BUILD_NUMBER)"
