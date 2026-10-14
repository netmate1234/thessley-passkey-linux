"""The "Details" view of an enrolled device: everything the app knows about its key, in plain words.

Pure functions: the caller supplies the chip facts (tpm.chip_info()) so this can be tested without a TPM.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import time

Sections = list[tuple[str, list[tuple[str, str]]]]

MAKERS = {
    "INTC": "Intel", "AMD": "AMD", "IFX": "Infineon", "STM": "STMicroelectronics", "NTC": "Nuvoton",
    "NTZ": "Nationz", "MSFT": "Microsoft (software TPM)", "IBM": "IBM (software TPM)", "SMSN": "Samsung",
    "QCOM": "Qualcomm", "ATML": "Atmel", "BRCM": "Broadcom", "CSCO": "Cisco", "GOOG": "Google",
}

# TPMA_OBJECT bits worth telling a person about.
_ATTRIBUTES = (
    (0x00000002, "cannot be moved to another TPM"),
    (0x00000010, "cannot be re-parented"),
    (0x00000020, "generated inside the chip"),
    (0x00040000, "signing key"),
)


def when(timestamp: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp)) if timestamp else "never"


def key_fingerprint(public_key_b64: str) -> str:
    """SHA-256 of the public key (SPKI DER), shown as short hex groups."""
    try:
        digest = hashlib.sha256(base64.b64decode(public_key_b64)).hexdigest()
    except (binascii.Error, ValueError):
        return "unknown"
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))


def _tpm_key(blobs: dict) -> list[tuple[str, str]]:
    """What the stored TPM key blob says about the key (parsed from its public part)."""
    try:
        public = base64.b64decode(blobs["public"])
        body = public[2:]                                   # TPM2B_PUBLIC -> TPMT_PUBLIC
        attributes = int.from_bytes(body[4:8], "big")
        name = "000b" + hashlib.sha256(body).hexdigest()   # nameAlg is SHA-256 for every key this app creates
    except (KeyError, binascii.Error, ValueError):
        return []
    traits = ", ".join(text for bit, text in _ATTRIBUTES if attributes & bit)
    rows = [("Key in the chip", "ECC NIST P-256, ECDSA with SHA-256")]
    if traits:
        rows.append(("Key properties", traits))
    rows.append(("Key under", {"endorsement": "the endorsement hierarchy", "owner": "the owner hierarchy"}.get(blobs.get("hierarchy", "owner"), blobs.get("hierarchy", "owner"))))
    rows.append(("TPM object name", name[:20] + "…"))
    return rows


def _chip_rows(chip: dict | str) -> list[tuple[str, str]]:
    if isinstance(chip, str):
        return [("This computer's chip", chip)]
    rows: list[tuple[str, str]] = []
    maker = chip.get("manufacturer", "")
    if maker:
        rows.append(("Manufacturer", f"{MAKERS[maker]} ({maker})" if maker in MAKERS else maker))
    if chip.get("vendor_string"):
        rows.append(("Chip model", chip["vendor_string"]))
    if chip.get("family"):
        rows.append(("TPM version", chip["family"] + (f", specification revision {chip['spec_revision']}" if chip.get("spec_revision") else "")))
    if chip.get("spec_date"):
        rows.append(("Specification date", chip["spec_date"]))
    if chip.get("firmware"):
        rows.append(("Firmware version", chip["firmware"]))
    if "max_tries" in chip:
        rows.append(("Wrong tries allowed", f"{chip['max_tries']} in a row ({chip.get('tries_so_far', 0)} used so far; the chip's own count, shared by every key on it)"))
    if chip.get("recovery_seconds"):
        hours = chip["recovery_seconds"] / 3600
        rows.append(("Lockout recovery", f"{hours:g} hours after a lockout" if hours >= 1 else f"{chip['recovery_seconds']} seconds after a lockout"))
    return rows


def describe(device, chip: dict | str | None = None) -> Sections:
    """Sections of (label, value) rows. `chip` is tpm.chip_info()'s dict, or text saying why it was not available."""
    from .uicommon import PROTECTION_LABELS

    sections: Sections = [("Account", [
        ("Site", device.origin),
        ("Account", device.username or "—"),
        ("Name on this computer", device.label),
        ("Added", when(device.enrolled_at)),
        ("Last used", when(device.last_used)),
        ("Device id", device.id),
    ])]

    protection = [("Protected by", PROTECTION_LABELS.get(device.protection, device.protection))]
    if device.uses_pin:
        kdf = device.kdf or {}
        if device.uses_tpm:
            protection.append(("PIN", "checked by the TPM chip itself"))
        else:
            protection.append(("PIN", f"stretched with scrypt (cost {kdf.get('n')}, block {kdf.get('r')}, parallel {kdf.get('p')})" if kdf.get("n") else "set"))
    if device.uses_fido2:
        protection.append(("Security key", f"FIDO2 hmac-secret for {(device.fido2 or {}).get('rp_id', 'this app')}"))
    protection.append(("Wrong tries (app)", f"{device.failures} in a row" + (f", locked until {when(device.locked_until)}" if device.locked_until > time.time() else "")))
    sections.append(("Protection", protection))

    key = [("Signing key", "ECDSA P-256, SHA-256 signatures"), ("Public key fingerprint", key_fingerprint(device.public_key))]
    if device.uses_tpm:
        key = [("Public key fingerprint", key_fingerprint(device.public_key))] + _tpm_key(device.tpm)
    else:
        key.append(("Stored", "encrypted (AES-256-GCM) in this computer's app folder"))
    sections.append(("Key", key))

    if device.uses_tpm:
        if device.attestation == "tpm":
            proof = "Verified by the site: the key lives in a genuine TPM 2.0 chip"
        else:
            proof = "Not verified: " + (device.attestation_note or "the site could not verify the TPM")
        sections.append(("Hardware proof", [("Site's verdict", proof)]))
        sections.append(("TPM chip in this computer", _chip_rows(chip if chip is not None else "not read")))
    return sections


def format_text(sections: Sections) -> str:
    width = max((len(label) for _, rows in sections for label, _ in rows), default=0)
    lines: list[str] = []
    for title, rows in sections:
        lines.append(title)
        lines.extend(f"  {label.ljust(width)}  {value}" for label, value in rows)
        lines.append("")
    return "\n".join(lines).rstrip()


def read_chip() -> dict | str:
    """The TPM facts, or one line of text saying why they could not be read."""
    from . import tpm
    try:
        return tpm.chip_info()
    except tpm.TpmError as exc:
        return f"not readable now: {exc}"
    except Exception as exc:  # a missing or broken TPM must never stop the details from opening
        return f"not readable now: {exc.__class__.__name__}: {exc}"
