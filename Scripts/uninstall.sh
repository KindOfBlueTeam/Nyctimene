#!/usr/bin/env bash
# Nyctimene uninstall script — removes every trace from the system.
# Run from anywhere; no arguments needed.
set -euo pipefail

KEYCHAIN_SERVICE="com.nyctimene"
APP_SUPPORT="$HOME/Library/Application Support/Nyctimene"
TEMP_DIR="$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null || echo /tmp/)"

echo "=== Nyctimene Uninstaller ==="
echo ""

# 1. Quit running instance
echo "Stopping Nyctimene (if running)..."
pkill -x "Nyctimene" 2>/dev/null && echo "  Stopped." || echo "  Not running."
sleep 1

# 2. Remove .app bundle from /Applications or ~/Applications
echo "Removing app bundle..."
for loc in "/Applications/Nyctimene.app" "$HOME/Applications/Nyctimene.app"; do
    if [[ -d "$loc" ]]; then
        rm -rf "$loc"
        echo "  Removed $loc"
    fi
done

# 3. Remove all API keys from the Keychain
echo "Removing Keychain entries..."
for account in virustotal_api_key otx_api_key shodan_api_key urlscan_api_key ipinfo_api_key; do
    security delete-generic-password \
        -s "$KEYCHAIN_SERVICE" -a "$account" \
        2>/dev/null && echo "  Removed $account" || true
done

# 4. Remove application support directory (settings, database, IOC feeds)
echo "Removing application data..."
if [[ -d "$APP_SUPPORT" ]]; then
    rm -rf "$APP_SUPPORT"
    echo "  Removed $APP_SUPPORT"
else
    echo "  No application data found."
fi

# 5. Remove /etc/hosts entries written by Nyctimene
HOSTS_ENTRIES=$(grep -c "# Nyctimene" /etc/hosts 2>/dev/null || true)
if [[ "$HOSTS_ENTRIES" -gt 0 ]]; then
    echo "Removing $HOSTS_ENTRIES /etc/hosts block(s) (requires your password)..."
    sudo sed -i '' '/# Nyctimene/d' /etc/hosts
    sudo dscacheutil -flushcache
    echo "  Done."
else
    echo "No /etc/hosts entries to remove."
fi

# 6. Remove temporary PCAP capture files
rm -f "${TEMP_DIR}nyctimene_capture.pcap" "${TEMP_DIR}nyctimene_cap.pid"

echo ""
echo "Nyctimene has been fully removed."
