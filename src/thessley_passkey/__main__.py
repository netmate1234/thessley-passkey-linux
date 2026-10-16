"""Entry point: `thessley-passkey [LINK]` opens the window; the subcommands work in a terminal."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, link, protectors, protocol, vault
from .core import Service, UnknownSite, WrongSecret, default_label
from .interaction import CliInteraction
from .pamlink import PamError
from .protocol import NetworkError, ServerError
from .vault import Locked


def _need(raw: str):
    req = link.parse_any(raw)
    if req is None:
        sys.exit("That is not a valid thessleypasskey:// (website) or thessleypam:// (Linux computer) link.")
    return req


def cli(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="thessley-passkey", description="Thessley Passkey for Linux (terminal mode)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="show enrolled sites")
    dt = sub.add_parser("details", help="show everything about one enrolled device (TPM version, protection, key)")
    dt.add_argument("device_id")
    rm = sub.add_parser("remove", help="forget a device on this computer")
    rm.add_argument("device_id")
    en = sub.add_parser("enroll", help="enrol this computer from an enrol link")
    en.add_argument("link")
    en.add_argument("--protect", choices=protectors.PROTECTIONS, default="pin")
    en.add_argument("--label", default=default_label())
    rs = sub.add_parser("respond", help="answer a login link")
    rs.add_argument("link")
    g = rs.add_mutually_exclusive_group()
    g.add_argument("--approve", action="store_true")
    g.add_argument("--deny", action="store_true")
    rs.add_argument("--device", help="device id when several match")
    a = p.parse_args(argv)

    svc = Service()
    ui = CliInteraction()
    try:
        if a.cmd == "list":
            for d in vault.sort_devices(svc.vault.all()):
                print(f"{d.id}  {d.title}  {d.username or '-'}  {d.label}  [{d.protection}]")
                if d.protection.startswith("tpm") and d.attestation != "tpm":
                    print(f"    not verified by the site: {d.attestation_note or 'no reason recorded (enrolled before this was kept)'}")
        elif a.cmd == "details":
            from .uicommon import device_details_text
            found = [d for d in svc.vault.all() if d.id.startswith(a.device_id)]
            if len(found) != 1:
                sys.exit("No device with that id." if not found else "Several devices start with that id; give more of it.")
            print(device_details_text(found[0]))
        elif a.cmd == "remove":
            gone = next((d for d in svc.vault.all() if d.id == a.device_id), None)
            svc.vault.remove(a.device_id)
            if gone is not None and gone.kind == "computer":
                print(f"Removed here. Also remove it on {gone.title}:  sudo thessley-pam remove {gone.credential_id} --user {gone.username}")
            else:
                print("Removed locally. Also revoke it on the site's profile page.")
        elif a.cmd == "enroll":
            d = svc.enroll(_need(a.link), a.label, a.protect, ui)
            print(f"Enrolled for {d.username or 'your account'} on {d.title}.")
        elif a.cmd == "respond":
            req = _need(a.link)
            devices = svc.candidates(req)
            if a.device:
                devices = [d for d in devices if d.id == a.device]
            if not devices:
                sys.exit(f"This app is not enrolled with {req.display}.")
            if len(devices) > 1:
                sys.exit("Several devices match; choose one with --device:\n" + "\n".join(f"  {d.id}  {d.username}  {d.label}" for d in devices))
            if not (a.approve or a.deny):
                print(f"{req.kind_label}: {req.display}\nType: {req.type}\nFrom: {(req.ip + ' ' + req.country).strip() or getattr(req, 'tty', '') or '-'}\nAccount: {req.username or '-'}")
                a.approve = input("Approve? [y/N] ").strip().lower() == "y"
            print(svc.respond(req, devices[0], a.approve, ui))
    except (WrongSecret, Locked, ValueError, protectors.ProtectionError, UnknownSite, NetworkError, PamError) as exc:
        sys.exit(str(exc))
    except ServerError as exc:
        sys.exit(protocol.friendly(exc))
    return 0


def _pick_ui() -> str:
    """Windows uses the Qt window; Linux the GTK one (THESSLEY_UI=qt|gtk overrides)."""
    choice = os.environ.get("THESSLEY_UI", "").lower()
    if choice in ("qt", "gtk"):
        return choice
    return "qt" if os.name == "nt" else "gtk"


def main() -> int:
    argv = sys.argv[1:]
    if argv[:1] == ["--version"]:
        print(__version__)
        return 0
    if argv[:1] in (["--register-handler"], ["--unregister-handler"]):
        from . import winsetup
        if argv[0] == "--register-handler":
            print("Registered:", winsetup.register())
        else:
            winsetup.unregister()
            print("Link handler removed.")
        return 0
    if argv[:1] == ["--diagnose"]:
        from . import diagnose
        return diagnose.run()
    if argv and argv[0] in ("list", "details", "remove", "enroll", "respond", "-h", "--help"):
        return cli(argv)
    if _pick_ui() == "qt":
        from .ui_qt import run as run_qt
        return run_qt()
    from .ui import run  # GTK is only needed for the window
    return run()


if __name__ == "__main__":
    sys.exit(main())
