"""Enrol this computer and answer login requests."""

from __future__ import annotations

import socket
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import protectors, protocol, vault
from .interaction import Interaction
from .link import AuthRequest, clean_text
from .vault import Device, Locked, Vault


class WrongSecret(Exception):
    pass


class UnknownSite(Exception):
    """A login request for a site this computer was never enrolled with."""


def default_label() -> str:
    return clean_text(socket.gethostname(), 60) or "Linux computer"


def _public_key_b64(key: ec.EllipticCurvePrivateKey) -> str:
    return protocol.b64(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def _sign(key: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    return protocol.b64(key.sign(message, ec.ECDSA(hashes.SHA256())))  # DER (r, s), as the server expects


class Service:
    def __init__(self, store: Vault | None = None, fido2=protectors, client_factory=protocol.Client):
        self.vault = store or Vault()
        self.fido2 = fido2
        self.client_factory = client_factory

    # ---- lookup ---------------------------------------------------------------

    def candidates(self, req: AuthRequest) -> list[Device]:
        """Devices enrolled for this request's site, narrowed to the named account if there is one."""
        devices = self.vault.for_origin(req.origin)
        if req.username:
            named = [d for d in devices if d.username and d.username.casefold() == req.username.casefold()]
            if named:
                return named
        return devices

    # ---- unlocking -----------------------------------------------------------------

    def _unlock(self, device: Device, interaction: Interaction) -> ec.EllipticCurvePrivateKey:
        remaining = self.vault.lock_remaining(device)
        if remaining:
            raise Locked(remaining)
        pin_part = fido_part = None
        if device.uses_pin:
            pin_part = vault.pin_key(interaction.get_pin("Enter your PIN"), device.kdf)
        if device.uses_fido2:
            fido_part = self.fido2.fido2_secret(device.fido2, interaction)
        try:
            der = vault.unwrap(device.wrapped, vault.derive_kek(pin_part, fido_part), device.aad())
        except InvalidTag:
            if device.uses_pin:
                self.vault.record_attempt(device.id, success=False)
            raise WrongSecret("Wrong PIN." if not device.uses_fido2 else "Wrong PIN, or not the security key this device was set up with.")
        if device.uses_pin:
            self.vault.record_attempt(device.id, success=True)
        return serialization.load_der_private_key(der, password=None)

    # ---- enrol ---------------------------------------------------------------------

    def enroll(self, req: AuthRequest, label: str, protection: str, interaction: Interaction) -> Device:
        if req.type != "enroll":
            raise ValueError("This is not an enrolment request.")
        if protection not in protectors.PROTECTIONS:
            raise ValueError("Choose PIN, security key, or both.")
        label = clean_text(label, 100) or default_label()

        pin_part = fido_part = None
        kdf, fido = {}, {}
        if "pin" in protection:
            pin = interaction.get_pin("Choose a PIN", confirm=True)
            protectors.check_pin_strength(pin)
            kdf = vault.pin_params()
            pin_part = vault.pin_key(pin, kdf)
        if "fido2" in protection:
            fido, fido_part = self.fido2.fido2_create(interaction)

        key = ec.generate_private_key(ec.SECP256R1())
        der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        device_id = vault.new_device_id()
        probe = Device(id=device_id, origin=req.origin, credential_id="", username="", label=label, enrolled_at=0,
                       public_key="", protection=protection, wrapped={}, kdf=kdf, fido2=fido)
        wrapped = vault.wrap(der, vault.derive_kek(pin_part, fido_part), probe.aad())

        ts = protocol.now()
        proof = _sign(key, protocol.canonical_string("enroll", req.request_id, req.origin, req.nonce, ts, "register"))
        public_key = _public_key_b64(key)
        answer = self.client_factory(req.origin).enroll_respond(req.request_id, public_key, label, ts, proof)

        device = Device(
            id=device_id, origin=req.origin, credential_id=str(answer["credential_id"]),
            username=clean_text(answer.get("username"), 100), label=label, enrolled_at=int(time.time()),
            public_key=public_key, protection=protection, wrapped=wrapped, kdf=kdf, fido2=fido,
        )
        self.vault.add(device)
        return device

    # ---- approve / deny ----------------------------------------------------------------

    def respond(self, req: AuthRequest, device: Device, approve: bool, interaction: Interaction) -> str:
        if req.type not in ("login", "2fa"):
            raise ValueError("This is not a login request.")
        if device.origin != req.origin:
            raise UnknownSite(f"This computer is not enrolled with {req.origin}.")
        key = self._unlock(device, interaction)
        action = "approve" if approve else "deny"
        ts = protocol.now()
        signature = _sign(key, protocol.canonical_string(req.type, req.request_id, req.origin, req.nonce, ts, action))
        self.client_factory(req.origin).login_respond(req.request_id, device.credential_id, action, ts, signature)
        return "approved" if approve else "denied"
