#!/usr/bin/env bash
# Nyctimene dev runner — builds debug and launches directly (no .app bundle).
# Usage: ./Scripts/dev.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Kill any existing instance
pkill -x Nyctimene 2>/dev/null && echo "Stopped existing Nyctimene." || true
sleep 0.3

echo "Building (debug)..."
swift build 2>&1

BINARY="${PROJECT_DIR}/.build/debug/Nyctimene"
echo ""
echo "Launching ${BINARY} ..."
"${BINARY}" &
echo "PID $!"
