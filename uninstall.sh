#!/bin/sh
# Removes the app and its link handler. Your enrolled keys (devices.json) are kept unless you pass --purge.
set -eu
data=${XDG_DATA_HOME:-$HOME/.local/share}
bin=${PREFIX_BIN:-$HOME/.local/bin}
rm -rf "$data/thessley-passkey/app" "$bin/thessley-passkey" "$data/applications/thessley-passkey.desktop" "$data/icons/hicolor/scalable/apps/thessley-passkey.svg"
command -v update-desktop-database >/dev/null && update-desktop-database "$data/applications" || true
[ "${1:-}" = "--purge" ] && rm -rf "$data/thessley-passkey" && echo "Enrolled devices deleted."
echo "Uninstalled."
