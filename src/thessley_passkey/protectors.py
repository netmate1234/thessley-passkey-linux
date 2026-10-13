"""What unlocks a device key: a PIN, a FIDO2 security key, or both.

PIN       -> scrypt(PIN, salt)
FIDO2 key -> the key's hmac-secret / PRF output for a per-device random salt
             (needs the physical key and a touch each time; its own PIN only
             when the key insists on it)
Both      -> the two secrets combined, so each one alone is useless.
"""

from __future__ import annotations

import base64
import os

from .interaction import Cancelled, Interaction

RP_ID = "thessley-passkey.local"   # only a label for the key; never contacted
MIN_PIN_LENGTH = 6
PROTECTIONS = ("pin", "fido2", "pin+fido2", "tpm+pin", "tpm+pin+fido2")  # tpm+...: the key lives in the TPM chip


class ProtectionError(Exception):
    """Something went wrong talking to the security key."""


class NoSecurityKey(ProtectionError):
    pass


def check_pin_strength(pin: str) -> None:
    if len(pin) < MIN_PIN_LENGTH:
        raise ValueError(f"Use at least {MIN_PIN_LENGTH} characters for the PIN.")
    if len(set(pin)) == 1:
        raise ValueError("A PIN of one repeated character is too easy to guess.")


def _dig(obj, *keys):
    """Read nested values from either plain dicts or the library's result objects.

    The library's result objects also behave like mappings, but then hand back the JSON form
    (binary values as base64 text), so attributes are preferred and only plain dicts use .get().
    """
    for key in keys:
        if obj is None:
            return None
        if isinstance(obj, dict):
            obj = obj.get(key)
        elif hasattr(obj, key):
            obj = getattr(obj, key)
        elif hasattr(obj, "get"):
            obj = obj.get(key)
        else:
            return None
    return obj


def _as_bytes(value) -> bytes | None:
    """The key's secret as raw bytes, whichever form the library gave it in."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):  # websafe base64 (JSON form)
        try:
            return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except ValueError:
            return None
    return None


def prf_secret(extension_results) -> bytes | None:
    """Pull the PRF output out of a get_assertion response's client extension results."""
    return _as_bytes(_dig(extension_results, "prf", "results", "first"))


def _client(interaction: Interaction):
    try:
        from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client, UserInteraction
        from fido2.hid import CtapHidDevice
    except ImportError as exc:  # pragma: no cover
        raise ProtectionError("The python3-fido2 package is needed for security-key protection.") from exc

    class UI(UserInteraction):
        def prompt_up(self):
            interaction.notify("Touch your security key now.")

        def request_pin(self, permissions, rp_id):
            return interaction.fido_pin()

        def request_uv(self, permissions, rp_id):
            interaction.notify("Verify on your security key.")
            return True

    try:
        devices = list(CtapHidDevice.list_devices())
    except Exception as exc:
        raise ProtectionError(f"Could not access security keys: {exc}") from exc
    if not devices:
        raise NoSecurityKey("No security key found. Plug it in and try again.")
    return Fido2Client(devices[0], DefaultClientDataCollector("https://" + RP_ID), user_interaction=UI()), ClientError


def _run(interaction: Interaction, action):
    client, ClientError = _client(interaction)
    try:
        return action(client)
    except Cancelled:
        raise
    except ClientError as exc:
        text = str(exc)
        if "TIMEOUT" in text:
            raise ProtectionError("Timed out waiting for the security key.") from exc
        if "DEVICE_INELIGIBLE" in text:
            raise ProtectionError("This security key does not hold the credential for this device (a different key?).") from exc
        raise ProtectionError(f"Security key error: {text}") from exc
    except OSError as exc:
        raise ProtectionError(f"Could not talk to the security key: {exc}") from exc
    finally:
        interaction.clear_notice()


def fido2_create(interaction: Interaction) -> tuple[dict, bytes]:
    """Make a credential on the key for this device; returns (params to store, secret)."""
    from fido2.webauthn import PublicKeyCredentialCreationOptions

    def make(client):
        options = PublicKeyCredentialCreationOptions.from_dict({
            "rp": {"id": RP_ID, "name": "Thessley Passkey"},
            "user": {"id": os.urandom(16), "name": "thessley-passkey", "displayName": "Thessley Passkey"},
            "challenge": os.urandom(32),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"userVerification": "discouraged", "residentKey": "discouraged"},
            "extensions": {"prf": {}},
        })
        reg = client.make_credential(options)
        if _dig(reg.client_extension_results, "prf", "enabled") is False:
            raise ProtectionError("This security key does not support hmac-secret, which is needed to protect the key.")
        return reg.response.attestation_object.auth_data.credential_data.credential_id

    interaction.notify("Touch your security key to set it up.")
    credential_id = _run(interaction, make)
    params = {"rp_id": RP_ID, "credential_id": base64.b64encode(credential_id).decode(), "salt": base64.b64encode(os.urandom(32)).decode()}
    return params, fido2_secret(params, interaction)


def fido2_secret(params: dict, interaction: Interaction) -> bytes:
    from fido2.webauthn import PublicKeyCredentialRequestOptions

    def get(client):
        options = PublicKeyCredentialRequestOptions.from_dict({
            "challenge": os.urandom(32),
            "rpId": params["rp_id"],
            "allowCredentials": [{"type": "public-key", "id": base64.b64decode(params["credential_id"])}],
            "userVerification": "discouraged",
            "extensions": {"prf": {"eval": {"first": base64.b64decode(params["salt"])}}},
        })
        response = client.get_assertion(options).get_response(0)
        return prf_secret(response.client_extension_results)

    interaction.notify("Touch your security key now.")
    secret = _run(interaction, get)
    if not secret or len(secret) != 32:
        raise ProtectionError("The security key did not return a secret (hmac-secret unsupported?).")
    return bytes(secret)
