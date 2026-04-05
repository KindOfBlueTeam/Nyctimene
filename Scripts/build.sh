#!/usr/bin/env bash
# Nyctimene build script — compiles the Swift package and assembles a signed .app bundle.
# Usage: ./Scripts/build.sh [release|debug]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

CONFIG="${1:-release}"
APP_NAME="Nyctimene"
APP_BUNDLE="${PROJECT_DIR}/${APP_NAME}.app"
ENTITLEMENTS="${PROJECT_DIR}/${APP_NAME}.entitlements"
INFO_PLIST="${PROJECT_DIR}/Info.plist"

if [[ "$CONFIG" == "release" ]]; then
    swift build -c release
    BUILD_DIR="${PROJECT_DIR}/.build/release"
else
    swift build
    BUILD_DIR="${PROJECT_DIR}/.build/debug"
fi

echo ""
echo "Assembling ${APP_NAME}.app ..."

# --- Build .app directory structure ------------------------------------------
rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

# Main executable
cp "${BUILD_DIR}/${APP_NAME}" "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"

# Info.plist
cp "${INFO_PLIST}" "${APP_BUNDLE}/Contents/Info.plist"

# SPM resource bundle (contains owl.png and other Resources/)
RESOURCE_BUNDLE="${BUILD_DIR}/${APP_NAME}_${APP_NAME}.bundle"
if [[ -d "${RESOURCE_BUNDLE}" ]]; then
    cp -r "${RESOURCE_BUNDLE}" "${APP_BUNDLE}/Contents/Resources/"
fi

# --- Ad-hoc code signing -----------------------------------------------------
# Uses "-" as the identity, which creates a self-signed (ad-hoc) signature.
# This gives the binary a stable Gatekeeper identity so that macOS Keychain
# remembers "Always Allow" decisions across future runs of the *same* binary.
# Re-building naturally changes the signature — users re-save API keys once
# after each update and are never prompted again until the next update.
if [[ -f "${ENTITLEMENTS}" ]]; then
    codesign --force --deep --sign - \
             --entitlements "${ENTITLEMENTS}" \
             "${APP_BUNDLE}"
else
    codesign --force --deep --sign - "${APP_BUNDLE}"
fi

echo ""
echo "Done: ${APP_BUNDLE}"
echo ""
echo "First launch:"
echo "  open \"${APP_BUNDLE}\""
echo ""
echo "Or drag Nyctimene.app to /Applications, then open it from there."
