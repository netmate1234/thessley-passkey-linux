"""The Thessley Passkey wire protocol, client side (same as the Android app)."""

from __future__ import annotations

import base64
import time

import requests

from . import __version__

SIG_VERSION = "thessley_passkey_v1"
TIMEOUT = 15


class ServerError(Exception):
    """The server answered, but not with success. `code` is its machine-readable error code."""

    def __init__(self, message: str, code: str = "", status: int = 0):
        super().__init__(message)
        self.code = code
        self.status = status


class NetworkError(Exception):
    pass


def canonical_string(rtype: str, request_id: str, origin: str, nonce: str, timestamp: int, action: str) -> bytes:
    """Byte-for-byte what the server verifies (Thessley_Passkey_Crypto::canonical_string)."""
    return "|".join((SIG_VERSION, rtype, request_id, origin, nonce, str(timestamp), action)).encode("utf-8")


def now() -> int:
    return int(time.time())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class Client:
    """One site. Uses the `?rest_route=` form, which every Thessley server accepts."""

    def __init__(self, origin: str, session: requests.Session | None = None):
        self.origin = origin
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = f"ThessleyPasskey-Linux/{__version__}"

    def _post(self, path: str, body: dict) -> dict:
        try:
            # Never follow redirects: a POST bounced to another host would carry the signature there.
            resp = self.session.post(
                self.origin + "/",
                params={"rest_route": "/thessley/v1/passkey" + path},
                json=body,
                timeout=TIMEOUT,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise NetworkError(f"Could not reach {self.origin}: {exc.__class__.__name__}") from exc
        if 300 <= resp.status_code < 400:
            raise ServerError(f"{self.origin} redirected the request; refusing to follow it.", "redirect", resp.status_code)
        try:
            data = resp.json()
        except ValueError:
            raise ServerError(f"Unexpected answer from {self.origin} (HTTP {resp.status_code}).", "bad_response", resp.status_code)
        if not isinstance(data, dict):
            raise ServerError("Unexpected answer from the server.", "bad_response", resp.status_code)
        return data

    def login_respond(self, request_id: str, credential_id: str, action: str, timestamp: int, signature_b64: str) -> None:
        data = self._post(f"/login/{request_id}/respond", {
            "credential_id": credential_id, "action": action, "timestamp": timestamp, "signature": signature_b64,
        })
        if data.get("result") != "ok":
            raise ServerError(str(data.get("message") or "The server rejected this response."), str(data.get("code") or ""), int((data.get("data") or {}).get("status", 0) or 0))

    def enroll_respond(self, request_id: str, public_key_b64: str, label: str, timestamp: int, proof_b64: str) -> dict:
        data = self._post(f"/enroll/{request_id}/respond", {
            "public_key": public_key_b64, "algorithm": "ES256", "label": label,
            "timestamp": timestamp, "proof_signature": proof_b64, "attestation_chain": [],
        })
        if data.get("result") != "ok" or not data.get("credential_id"):
            raise ServerError(str(data.get("message") or "Enrollment was rejected by the server."), str(data.get("code") or ""), int((data.get("data") or {}).get("status", 0) or 0))
        return data


FRIENDLY = {
    "thessley_stale": "This computer's clock is off by more than a minute. Fix the time and try again.",
    "thessley_expired": "This request has expired or was already answered. Start the login again.",
    "thessley_already_resolved": "This request was already answered.",
    "thessley_unknown_device": "The site no longer knows this computer (it may have been revoked). Remove it here and enrol again.",
    "thessley_wrong_account": "This device belongs to a different account than the one logging in.",
    "thessley_2fa_required": "This account has to enter its password first, then confirm here.",
    "thessley_rate_limited": "Too many attempts. Wait a few minutes.",
}


def friendly(exc: ServerError) -> str:
    return FRIENDLY.get(exc.code, str(exc))
