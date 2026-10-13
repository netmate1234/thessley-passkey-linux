"""Entry point: `thessley-passkey [LINK]` opens the window; the subcommands work in a terminal."""

from __future__ import annotations

import argparse
import sys

from . import __version__, link, protectors, protocol, vault
from .core import Service, UnknownSite, WrongSecret, default_label
from .interaction import CliInteraction
from .protocol import NetworkError, ServerError
from .vault import Locked


def _need(raw: str) -> link.AuthRequest:
    req = link.parse(raw)
    if req is None:
        sys.exit("That is not a valid thessleypasskey:// link.")
    return req


def cli(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="thessley-passkey", description="Thessley Passkey for Linux (terminal mode)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="show enrolled sites")
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
                print(f"{d.id}  {d.origin}  {d.username or '-'}  {d.label}  [{d.protection}]")
        elif a.cmd == "remove":
            svc.vault.remove(a.device_id)
            print("Removed locally. Also revoke it on the site's profile page.")
        elif a.cmd == "enroll":
            d = svc.enroll(_need(a.link), a.label, a.protect, ui)
            print(f"Enrolled for {d.username or 'your account'} on {d.origin}.")
        elif a.cmd == "respond":
            req = _need(a.link)
            devices = svc.candidates(req)
            if a.device:
                devices = [d for d in devices if d.id == a.device]
            if not devices:
                sys.exit(f"This computer is not enrolled with {req.origin}.")
            if len(devices) > 1:
                sys.exit("Several devices match; choose one with --device:\n" + "\n".join(f"  {d.id}  {d.username}  {d.label}" for d in devices))
            if not (a.approve or a.deny):
                print(f"Site: {req.origin}\nType: {req.type}\nFrom: {req.ip} {req.country}\nAccount: {req.username or '-'}")
                a.approve = input("Approve? [y/N] ").strip().lower() == "y"
            print(svc.respond(req, devices[0], a.approve, ui))
    except (WrongSecret, Locked, ValueError, protectors.ProtectionError, UnknownSite, NetworkError) as exc:
        sys.exit(str(exc))
    except ServerError as exc:
        sys.exit(protocol.friendly(exc))
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if argv[:1] == ["--version"]:
        print(__version__)
        return 0
    if argv and argv[0] in ("list", "remove", "enroll", "respond", "-h", "--help"):
        return cli(argv)
    from .ui import run  # GTK is only needed for the window
    return run()


if __name__ == "__main__":
    sys.exit(main())
