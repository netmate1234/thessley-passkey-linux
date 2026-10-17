"""Text and rules shared by every front end (GTK on Linux, Qt on Windows)."""

from __future__ import annotations

from pathlib import Path

from . import protectors, protocol, tpm
from .core import UnknownSite, WrongSecret
from .pamlink import PamError
from .protocol import NetworkError, ServerError
from .vault import Locked

# The logo shown in the top right corner of the main window. It lives inside the package, so install.sh and the
# Windows build carry it along; a missing file just means no logo.
LOGO_PATH = Path(__file__).with_name("logo.png")
LOGO_SIZE = 48

def result_text(req, outcome: str) -> str:
    """What the result screen says after an approval or a refusal, for a site and for each kind of computer request.
    (It used to say "go back to the browser" for everything, ssh logins included.)"""
    approved = outcome == "approved"
    kind = getattr(req, "kind", None)
    host = getattr(req, "hostname", "") or "the computer"
    if kind is None:  # a site
        return ("Approved. You can go back to the browser." if approved
                else "Not approved. The login request on the site will expire on its own.")
    if not approved:
        return "Denied. Nothing was approved."
    return {
        "ssh": f"Approved. The ssh login to {host} continues.",
        "vpn": f"Approved. The VPN connection to {host} continues.",
        "sudo": f"Approved. The sudo command on {host} continues.",
        "screen": f"Approved. {host} lets the login through.",
        "device": f"Approved. The new phone or app can now be added on {host}.",
        "web": f"Approved. The admin page on {host} opens.",
        "webchange": f"Approved. The change on {host} goes through.",
    }.get(kind, "Approved.")


PROTECTION_LABELS = {
    "pin": "PIN",
    "fido2": "Security key",
    "pin+fido2": "PIN and security key",
    "tpm+pin": "TPM chip + PIN",
    "tpm+pin+fido2": "TPM chip + PIN + security key",
}

TYPE_TEXT = {
    "login": "Log in without a password",
    "2fa": "Confirm your login (second step after your password)",
}

ENROLL_EXPLANATION = (
    "A PIN is typed each time you approve. A security key (FIDO2) must be plugged in and touched. "
    "With the TPM option the signing key lives inside this computer's TPM chip and never leaves it; "
    "the chip itself checks the PIN and limits wrong tries."
)

NOT_ENROLLED = (
    "This computer is not enrolled with {origin}, so it cannot approve this. "
    "If a web page or someone else asked you to scan or open this, do not continue: "
    "it may be an attempt to log in as you elsewhere."
)


def not_enrolled_text(req) -> str:
    """Why this app cannot answer; a VPN request says how to enrol for it."""
    text = NOT_ENROLLED.format(origin=req.display)
    if getattr(req, "type", "") == "vpn":
        text += (f"\n\nTo approve VPN logins to {req.hostname} from this app, run “sudo thessley-pam vpn enroll” on that "
                 "computer, on its own network, and scan its code here.")
    return text


def available_protections() -> tuple[list[str], str]:
    """Protection choices to offer, and a hint about why the TPM ones are missing (if they are)."""
    keys = ["pin", "fido2", "pin+fido2"]
    usable, why = tpm.status()
    if usable:
        keys = ["tpm+pin", "tpm+pin+fido2"] + keys
    return keys, ("" if usable else why)


def explain(exc: Exception) -> str:
    """User-facing text for anything the core can raise."""
    if isinstance(exc, (WrongSecret, Locked, ValueError, protectors.ProtectionError, UnknownSite, NetworkError, PamError)):
        return str(exc)
    if isinstance(exc, ServerError):
        return protocol.friendly(exc)
    return f"Unexpected error: {exc.__class__.__name__}: {exc}"


def enrolled_text(device, origin: str, protection: str, note: str) -> str:
    if device.kind == "computer":  # this app is now an approver for another computer's logins
        text = f"This app can now approve logins for {device.username or 'your account'} on {origin}."
        if device.attestation == "tpm":
            text += " The computer verified that the key lives in a genuine TPM 2.0 chip here."
        elif protection.startswith("tpm") and note:
            text += " " + note
        return text
    text = f"This computer is now enrolled for {device.username or 'your account'} on {origin}."
    if device.attestation == "tpm":
        text += " The site verified that the key lives in this computer's TPM chip."
    elif protection.startswith("tpm") and note:
        text += " " + note
    return text


def home_sections(devices) -> list[tuple[str, list, tuple[str, str]]]:
    """The lists of the home window: (title, devices, (empty title, empty hint)). VPN entries, the ones enrolled with
    `thessley-pam vpn enroll` (they carry the public host their approvals come from), are a list of their own."""
    sites = [d for d in devices if d.kind != "computer"]
    computers = [d for d in devices if d.kind == "computer" and not getattr(d, "vpn_host", "")]
    vpn = [d for d in devices if d.kind == "computer" and getattr(d, "vpn_host", "")]
    return [
        ("Enrolled sites", sites, ("Nothing enrolled yet", "On a site's profile page choose Add a device, then press “Open on this device”.")),
        ("Enrolled computers", computers, ("No computers yet", "On a Linux computer with thessley-pam run “thessley-pam enroll --user NAME --link”.")),
        ("VPN", vpn, ("No VPN yet", "On the VPN server run “sudo thessley-pam vpn enroll”, then scan or paste its link here.")),
    ]


def device_summary(device) -> str:
    if device.kind == "computer":  # a computer this app approves for: its own verdict on the TPM, not a site's
        proof = ""
        if device.attestation == "tpm":
            proof = " · TPM verified by the computer"
        elif device.uses_tpm:
            proof = " · TPM not verified: " + (device.attestation_note or "the computer could not verify it")
        vpn = f" · VPN host {device.vpn_host}" if getattr(device, "vpn_host", "") else ""
        return f"{device.username or 'account'} · {device.label} · {PROTECTION_LABELS.get(device.protection, device.protection)}{proof}{vpn}"
    if device.attestation == "tpm":
        proof = " · verified by the site"
    elif device.uses_tpm:
        proof = " · not verified: " + (device.attestation_note or "the site could not verify the TPM")
    else:
        proof = ""
    return f"{device.username or 'account'} · {device.label} · {PROTECTION_LABELS.get(device.protection, device.protection)}{proof}"


def device_details(device):
    """The Details view of a device as sections of (label, value) rows (reads the TPM chip's facts for TPM devices)."""
    from . import details
    return details.describe(device, details.read_chip() if device.uses_tpm else None)


def device_details_text(device) -> str:
    """The same as plain text, for the terminal."""
    from . import details
    return details.format_text(device_details(device))
