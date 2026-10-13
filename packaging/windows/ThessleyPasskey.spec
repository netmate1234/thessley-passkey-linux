# PyInstaller recipe. Run from the project root:  pyinstaller --noconfirm --clean packaging/windows/ThessleyPasskey.spec
# Produces dist/ThessleyPasskey/ with two programs:
#   ThessleyPasskey.exe      the window (no console); this is what opens when you press "Open on this device"
#   thessley-passkey-cli.exe the same program with a console, for `list`, `enroll`, `respond`, `--diagnose`
import os, sys
root = os.path.abspath(os.path.join(os.path.dirname(SPEC), "..", ".."))
icon = os.path.join(root, "data", "thessley-passkey.ico") if sys.platform == "win32" else None

hidden = ["fido2", "fido2.client", "fido2.client.windows", "fido2.hid", "asn1crypto", "asn1crypto.x509",
          "thessley_passkey.ui_qt", "thessley_passkey.winsetup", "thessley_passkey.diagnose"]
excludes = ["gi", "tkinter", "tpm2_pytss", "PySide6.QtWebEngineCore", "PySide6.QtQml", "PySide6.QtQuick"]

a = Analysis([os.path.join(root, "packaging", "windows", "launcher.py")], pathex=[os.path.join(root, "src")],
             hiddenimports=hidden, excludes=excludes, noarchive=False)
pyz = PYZ(a.pure)
gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name="ThessleyPasskey", console=False, icon=icon)
cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name="thessley-passkey-cli", console=True, icon=icon)
coll = COLLECT(gui, cli, a.binaries, a.datas, name="ThessleyPasskey")
