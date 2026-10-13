"""`thessley-passkey --diagnose`: a plain-text report of what works on this computer.

Written to a file (and printed when there is a console) so it can be sent back when something does not
work. It contains no keys, PINs or site data: only versions, device availability and registry state.
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import traceback

from . import __version__


def _section(lines: list[str], title: str, fn) -> None:
    lines.append(f"\n== {title}")
    try:
        for line in fn() or []:
            lines.append("   " + line)
    except Exception as exc:  # a diagnostic must never crash; the error is the finding
        lines.append(f"   FAILED: {exc.__class__.__name__}: {exc}")
        lines.extend("   " + l for l in traceback.format_exc().splitlines()[-4:])


def _system():
    yield f"app {__version__}"
    yield f"python {sys.version.split()[0]} ({platform.machine()}), frozen={getattr(sys, 'frozen', False)}"
    yield f"os {platform.platform()}"
    if os.name == "nt":
        yield f"windows build {platform.version()}"


def _libs():
    for name in ("cryptography", "requests", "fido2", "asn1crypto", "PySide6", "gi", "tpm2_pytss"):
        try:
            mod = __import__(name)
            yield f"{name}: {getattr(mod, '__version__', 'present')}"
        except Exception as exc:
            yield f"{name}: missing ({exc.__class__.__name__})"


def _storage():
    from . import vault
    d = vault.data_dir()
    yield f"data folder: {d}"
    yield f"devices enrolled: {len(vault.Vault().all())}"


def _handler():
    if os.name != "nt":
        yield "not Windows: uses the .desktop file"
        return
    from . import winsetup
    cmd = winsetup.registered_command()
    yield f"link handler registered: {'yes' if cmd else 'NO'}"
    if cmd:
        yield f"command: {cmd}"


def _fido2():
    from . import protectors
    for line in protectors.describe_security_keys():
        yield line


def _tpm():
    from . import tpm
    usable, why = tpm.status()
    yield f"usable: {usable}" + (f" ({why})" if why else "")
    if hasattr(tpm, "diagnose"):
        yield from tpm.diagnose()


def report() -> str:
    lines = ["Thessley Passkey diagnostics"]
    _section(lines, "system", _system)
    _section(lines, "libraries", _libs)
    _section(lines, "storage", _storage)
    _section(lines, "link handler", _handler)
    _section(lines, "security key (FIDO2)", _fido2)
    _section(lines, "TPM", _tpm)
    return "\n".join(lines) + "\n"


def run() -> int:
    text = report()
    path = os.path.join(tempfile.gettempdir(), "thessley-passkey-diagnose.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    if sys.stdout is not None:
        print(text)
        print("Saved to", path)
    else:  # packaged GUI build without a console: show where it went
        try:
            from PySide6 import QtWidgets
            app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
            QtWidgets.QMessageBox.information(None, "Thessley Passkey diagnostics", f"Report saved to:\n{path}")
        except Exception:
            pass
    return 0
