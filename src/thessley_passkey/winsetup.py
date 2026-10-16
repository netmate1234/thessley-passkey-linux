"""Windows integration: make `thessleypasskey://` (websites) and `thessleypam://` (Linux computers) links open this app
(per user, no admin needed)."""

from __future__ import annotations

import os
import sys

PROTOCOL = "thessleypasskey"
PROTOCOLS = ("thessleypasskey", "thessleypam")
KEY = rf"Software\Classes\{PROTOCOL}"


def launch_command() -> str:
    """What Windows should run for a link: the packaged .exe, or this Python module."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" "%1"'
    exe = sys.executable
    pythonw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.exists(pythonw):
        exe = pythonw  # no console window
    return f'"{exe}" -m thessley_passkey "%1"'


def register(winreg=None) -> str:
    """Create HKCU\\Software\\Classes\\thessleypasskey. Returns the command registered."""
    if winreg is None:
        import winreg  # type: ignore[no-redef]
    command = launch_command()
    for proto in PROTOCOLS:
        key = rf"Software\Classes\{proto}"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "URL:Thessley Passkey")
            winreg.SetValueEx(k, "URL Protocol", 0, winreg.REG_SZ, "")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key + r"\shell\open\command") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, command)
    return command


def unregister(winreg=None) -> None:
    if winreg is None:
        import winreg  # type: ignore[no-redef]
    for proto in PROTOCOLS:
        for sub in (r"\shell\open\command", r"\shell\open", r"\shell", ""):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{proto}" + sub)
            except FileNotFoundError:
                pass


def registered_command(winreg=None) -> str | None:
    if winreg is None:
        import winreg  # type: ignore[no-redef]
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY + r"\shell\open\command") as k:
            return winreg.QueryValueEx(k, "")[0]
    except FileNotFoundError:
        return None
