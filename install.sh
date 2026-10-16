#!/bin/sh
# Installs Thessley Passkey for the current user and makes it the handler for
# thessleypasskey:// links ("Open on this device"). Nothing outside $HOME is touched.
# Needs the distro packages python3-gi, gir1.2-adw-1, python3-cryptography,
# python3-requests and (for security keys) python3-fido2 >= 1.2.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
data=${XDG_DATA_HOME:-$HOME/.local/share}
bin=${PREFIX_BIN:-$HOME/.local/bin}
app="$data/thessley-passkey/app"

python3 - <<'PY' || { echo "Missing Python packages. Install: sudo apt install python3-gi gir1.2-adw-1 python3-cryptography python3-requests python3-fido2"; exit 1; }
import gi; gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk
import cryptography, requests
PY

rm -rf "$app" && mkdir -p "$app" "$bin" "$data/applications" "$data/icons/hicolor/scalable/apps"
cp -r "$here/src/thessley_passkey" "$app/"
cat > "$bin/thessley-passkey" <<LAUNCH
#!/bin/sh
exec env PYTHONPATH="$app" python3 -m thessley_passkey "\$@"
LAUNCH
chmod 755 "$bin/thessley-passkey"
cp "$here/data/thessley-passkey.svg" "$data/icons/hicolor/scalable/apps/thessley-passkey.svg"
sed "s|@EXEC@|$bin/thessley-passkey|" "$here/data/thessley-passkey.desktop.in" > "$data/applications/thessley-passkey.desktop"
command -v desktop-file-validate >/dev/null && desktop-file-validate "$data/applications/thessley-passkey.desktop" || true
command -v update-desktop-database >/dev/null && update-desktop-database "$data/applications" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t "$data/icons/hicolor" 2>/dev/null || true
xdg-mime default thessley-passkey.desktop x-scheme-handler/thessleypasskey
xdg-mime default thessley-passkey.desktop x-scheme-handler/thessleypam
echo "Installed. Links starting with thessleypasskey:// (websites) or thessleypam:// (Linux computers) now open Thessley Passkey."
echo "Security keys: if yours is not detected, your user needs access to /dev/hidraw* (see README)."
