#!/usr/bin/env bash
# Runs the GuardCore test suite and prints only failures and the summary.
# Usage: scripts/test.sh [--filter <pattern>]
set -uo pipefail
cd "$(dirname "$0")/.."
SWIFT_BIN=/opt/swift/swift-6.4.2-RELEASE-ubuntu24.04/usr/bin
[[ -d "$SWIFT_BIN" ]] && export PATH="$SWIFT_BIN:$PATH"
output=$(swift test "$@" 2>&1)
status=$?
echo "$output" | grep -E "error:|✘|recorded an issue|Test run with" || echo "$output" | tail -20
exit $status
