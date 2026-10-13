"""Windows only lets administrators run TPM2_ActivateCredential, the step that proves a key is in a genuine TPM.
When that is needed, the app asks Windows for permission (the UAC prompt) and reopens itself with the same link."""

from __future__ import annotations

import os
import sys


def is_admin() -> bool:
    if os.name != "nt":
        return True
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def needed_for(protection: str) -> bool:
    """True when enrolling with this protection has to run as administrator, and this process is not."""
    return os.name == "nt" and protection.startswith("tpm") and not is_admin()


def _command(link: str) -> tuple[str, str]:
    """(program, arguments) that start this app again on `link`."""
    if getattr(sys, "frozen", False):
        return sys.executable, f'"{link}"'
    src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # an elevated process does not inherit PYTHONPATH
    code = f"import sys; sys.path.insert(0, {src!r}); from thessley_passkey.__main__ import main; sys.exit(main())"
    return sys.executable, f'-c "{code}" "{link}"'


def relaunch(link: str) -> bool:
    """Reopen the app as administrator on `link`. False if the user declined the prompt."""
    import ctypes
    program, args = _command(link)
    # ShellExecuteW returns a value above 32 when the new process started.
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", program, args, os.getcwd(), 1) > 32
