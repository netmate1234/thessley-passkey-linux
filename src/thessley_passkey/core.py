"""Enrol this computer and answer login requests."""

from __future__ import annotations

import base64
import socket
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import protectors, protocol, tpm as tpm_mod, vault
from .interaction import Interaction
from .link import AuthRequest, clean_text
from .protocol import NetworkError, ServerError
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
    def __init__(self, store: Vault | None = None, fido2=protectors, client_factory=protocol.Client, tpm=tpm_mod):
        self.last_note = ""
        self.vault = store or Vault()
        self.fido2 = fido2
        self.client_factory = client_factory
        self.tpm = tpm

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

    def _signer(self, device: Device, interaction: Interaction):
        """Unlock the device and return a function that signs bytes -> DER signature."""
        remaining = self.vault.lock_remaining(device)
        if remaining:
            raise Locked(remaining)
        pin_part = fido_part = None
        if device.uses_pin:
            pin_part = vault.pin_key(interaction.get_pin("Enter your PIN"), device.kdf)
        if device.uses_fido2:
            fido_part = self.fido2.fido2_secret(device.fido2, interaction)
        kek = vault.derive_kek(pin_part, fido_part)

        if device.uses_tpm:
            # The TPM checks the password itself and counts wrong tries; our own counter sits in front
            # of it (5 tries) so a guesser cannot use up the chip's lockout, which is shared with
            # everything else on this computer that uses the TPM.
            def sign_with_tpm(message: bytes) -> bytes:
                try:
                    out = self.tpm.sign(device.tpm, kek, message)
                except tpm_mod.TpmWrongAuth:
                    self.vault.record_attempt(device.id, success=False)
                    raise WrongSecret("Wrong PIN, or not the security key this device was set up with.")
                except tpm_mod.TpmLockedOut as exc:
                    raise Locked(3600) from exc
                self.vault.record_attempt(device.id, success=True)
                return out
            return sign_with_tpm

        try:
            der = vault.unwrap(device.wrapped, kek, device.aad())
        except InvalidTag:
            if device.uses_pin:
                self.vault.record_attempt(device.id, success=False)
            raise WrongSecret("Wrong PIN." if not device.uses_fido2 else "Wrong PIN, or not the security key this device was set up with.")
        if device.uses_pin:
            self.vault.record_attempt(device.id, success=True)
        key = serialization.load_der_private_key(der, password=None)
        return lambda message: key.sign(message, ec.ECDSA(hashes.SHA256()))

    # ---- removal -------------------------------------------------------------------

    def remove(self, device: Device, interaction: Interaction) -> None:
        """Forget a device on this computer. Two steps: the caller has already asked "are you sure?"; this is the
        second, the same unlock an approval needs (PIN, security key, TPM). Whoever is only sitting at an
        unlocked computer cannot delete the keys. Wrong tries count towards the device's lockout like any other."""
        sign = self._signer(device, interaction)
        sign(b"thessley_passkey_v1|remove|" + device.id.encode("ascii", "replace"))  # a throwaway signature; it is never sent anywhere
        self.vault.remove(device.id)

    # ---- enrol ---------------------------------------------------------------------

    def _attest_tpm(self, client, req: AuthRequest, tpm_blobs: dict, kek: bytes) -> dict | None:
        """Prove to the site that the key lives in a genuine TPM. Never blocks enrolment: on any
        failure the device is enrolled without the proof and the reason is kept in last_note."""
        try:
            with self.tpm.Attestor() as at:
                certs = at.ek_certs()
                challenge = client.tpm_challenge(req.request_id, certs, at.ak_public())
                secret = at.activate(base64.b64decode(challenge["credential_blob"]), base64.b64decode(challenge["secret"]))
                parts = at.certify(tpm_blobs, kek, req.nonce.encode("ascii"))
            return {
                "ak_public": protocol.b64(at.ak_public()),
                "activated_secret": protocol.b64(secret),
                "certify_info": protocol.b64(parts["attest"]),
                "certify_signature": protocol.b64(parts["signature"]),
                "key_public": protocol.b64(parts["key_public"]),
            }
        except (tpm_mod.TpmError, ServerError, NetworkError, ValueError, OSError, KeyError) as exc:
            self.last_note = f"Enrolled without hardware proof: {protocol.friendly(exc) if isinstance(exc, ServerError) else exc}"
            return None


    def enroll(self, req: AuthRequest, label: str, protection: str, interaction: Interaction) -> Device:
        if req.type != "enroll":
            raise ValueError("This is not an enrolment request.")
        if protection not in protectors.PROTECTIONS:
            raise ValueError("Choose how to protect the key.")
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

        device_id = vault.new_device_id()
        client = self.client_factory(req.origin)
        self.last_note = ""
        attestation = None
        if protection.startswith("tpm"):
            kek = vault.derive_kek(pin_part, fido_part)
            tpm_blobs = self.tpm.create_key(kek)
            public_key = protocol.b64(self.tpm.spki_from_public(base64.b64decode(tpm_blobs["public"])))
            attestation = self._attest_tpm(client, req, tpm_blobs, kek)
            ts = protocol.now()  # after the (slow) TPM work: the site only accepts a fresh timestamp
            proof_msg = protocol.canonical_string("enroll", req.request_id, req.origin, req.nonce, ts, "register")
            proof = protocol.b64(self.tpm.sign(tpm_blobs, kek, proof_msg))
            wrapped = {}
        else:
            ts = protocol.now()
            proof_msg = protocol.canonical_string("enroll", req.request_id, req.origin, req.nonce, ts, "register")
            tpm_blobs = {}
            key = ec.generate_private_key(ec.SECP256R1())
            der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            probe = Device(id=device_id, origin=req.origin, credential_id="", username="", label=label, enrolled_at=0,
                           public_key="", protection=protection, wrapped={}, kdf=kdf, fido2=fido)
            wrapped = vault.wrap(der, vault.derive_kek(pin_part, fido_part), probe.aad())
            proof = _sign(key, proof_msg)
            public_key = _public_key_b64(key)
        answer = client.enroll_respond(req.request_id, public_key, label, ts, proof, attestation)
        if protection.startswith("tpm") and not answer.get("attestation") and not self.last_note:
            self.last_note = "The site accepted this computer but could not verify the TPM."

        device = Device(
            id=device_id, origin=req.origin, credential_id=str(answer["credential_id"]),
            username=clean_text(answer.get("username"), 100), label=label, enrolled_at=int(time.time()),
            public_key=public_key, protection=protection, wrapped=wrapped, kdf=kdf, fido2=fido, tpm=tpm_blobs,
            attestation=str(answer.get("attestation") or ""),
        )
        if tpm_blobs and device.attestation != "tpm":
            device.attestation_note = self.last_note.removeprefix("Enrolled without hardware proof: ")
        self.vault.add(device)
        return device

    # ---- approve / deny ----------------------------------------------------------------

    def respond(self, req: AuthRequest, device: Device, approve: bool, interaction: Interaction) -> str:
        if req.type not in ("login", "2fa"):
            raise ValueError("This is not a login request.")
        if device.origin != req.origin:
            raise UnknownSite(f"This computer is not enrolled with {req.origin}.")
        sign = self._signer(device, interaction)
        action = "approve" if approve else "deny"
        ts = protocol.now()
        signature = protocol.b64(sign(protocol.canonical_string(req.type, req.request_id, req.origin, req.nonce, ts, action)))
        self.client_factory(req.origin).login_respond(req.request_id, device.credential_id, action, ts, signature)
        return "approved" if approve else "denied"
