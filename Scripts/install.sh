#!/usr/bin/env bash
# Nyctimene installer — builds the .app and installs it to /Applications.
# Usage: ./Scripts/install.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APP_NAME="Nyctimene"
APP_BUNDLE="${PROJECT_DIR}/${APP_NAME}.app"
INSTALL_DIR="/Applications"

# Build first
bash "${SCRIPT_DIR}/build.sh" release

# Stop any running instance
echo ""
echo "Stopping existing instance (if any) ..."
pkill -x "${APP_NAME}" 2>/dev/null || true

# Install
echo "Installing to ${INSTALL_DIR}/${APP_NAME}.app ..."
rm -rf "${INSTALL_DIR}/${APP_NAME}.app"
cp -r "${APP_BUNDLE}" "${INSTALL_DIR}/"

echo ""
echo "Installed: ${INSTALL_DIR}/${APP_NAME}.app"
echo ""
echo "Launch:"
echo "  open \"${INSTALL_DIR}/${APP_NAME}.app\""
