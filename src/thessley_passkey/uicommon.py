"""Text and rules shared by every front end (GTK on Linux, Qt on Windows)."""

from __future__ import annotations

from . import protectors, protocol, tpm
from .core import UnknownSite, WrongSecret
from .pamlink import PamError
from .protocol import NetworkError, ServerError
from .vault import Locked

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
    text = f"This computer is now enrolled for {device.username or 'your account'} on {origin}."
    if device.attestation == "tpm":
        text += " The site verified that the key lives in this computer's TPM chip."
    elif protection.startswith("tpm") and note:
        text += " " + note
    return text


def device_summary(device) -> str:
    if device.kind == "computer":  # a Linux computer this app approves for: no site, no attestation to report
        return f"{device.username or 'account'} · {device.label} · {PROTECTION_LABELS.get(device.protection, device.protection)}"
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
