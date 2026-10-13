"""Encrypted key storage. The private key is only ever on disk AES-256-GCM wrapped."""

from __future__ import annotations

import base64
import contextlib
import fcntl
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N = 2 ** 16  # 64 MiB, ~0.2 s; tests lower it
SCRYPT_R = 8
SCRYPT_P = 1
MAX_FAILURES = 5          # wrong PINs in a row before the device is locked for a while
LOCK_BASE_SECONDS = 30    # doubles with every further failure, capped at an hour


class Locked(Exception):
    def __init__(self, seconds: int):
        super().__init__(f"Too many wrong PINs. Try again in {max(1, seconds // 60) if seconds >= 60 else seconds} {'minutes' if seconds >= 120 else 'minute' if seconds >= 60 else 'seconds'}.")
        self.seconds = seconds


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "thessley-passkey"


@dataclass
class Device:
    id: str
    origin: str
    credential_id: str
    username: str
    label: str
    enrolled_at: int
    public_key: str
    protection: str                     # "pin" | "fido2" | "pin+fido2"
    wrapped: dict                       # {"nonce": b64, "ct": b64}
    kdf: dict = field(default_factory=dict)    # PIN: {"salt": b64, "n", "r", "p"}
    fido2: dict = field(default_factory=dict)  # {"rp_id", "credential_id": b64, "salt": b64}
    tpm: dict = field(default_factory=dict)    # {"public": b64, "private": b64} when the key lives in the TPM
    attestation: str = ""                      # what the site was able to verify: "" (nothing) or "tpm"
    failures: int = 0
    locked_until: int = 0

    @property
    def uses_pin(self) -> bool:
        return "pin" in self.protection

    @property
    def uses_fido2(self) -> bool:
        return "fido2" in self.protection

    @property
    def uses_tpm(self) -> bool:
        return self.protection.startswith("tpm")

    def aad(self) -> bytes:
        return f"{self.id}|{self.origin}".encode("utf-8")


# ---- key wrapping --------------------------------------------------------------

def pin_params() -> dict:
    return {"salt": _b64e(os.urandom(16)), "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}


def pin_key(pin: str, params: dict) -> bytes:
    return Scrypt(salt=_b64d(params["salt"]), length=32, n=params["n"], r=params["r"], p=params["p"]).derive(pin.encode("utf-8"))


def derive_kek(pin_part: bytes | None, fido_part: bytes | None) -> bytes:
    """Combine whichever secrets protect this key into one 256-bit wrapping key."""
    ikm = b""
    for part in (pin_part, fido_part):
        ikm += (len(part).to_bytes(2, "big") + part) if part else b"\x00\x00"
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"thessley-passkey-linux/v1/kek").derive(ikm)


def wrap(private_key_der: bytes, kek: bytes, aad: bytes) -> dict:
    nonce = os.urandom(12)
    return {"nonce": _b64e(nonce), "ct": _b64e(AESGCM(kek).encrypt(nonce, private_key_der, aad))}


def unwrap(wrapped: dict, kek: bytes, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag if the key is wrong (wrong PIN / wrong security key)."""
    return AESGCM(kek).decrypt(_b64d(wrapped["nonce"]), _b64d(wrapped["ct"]), aad)


# ---- on-disk store ------------------------------------------------------------------

class Vault:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else data_dir() / "devices.json"

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        with open(self.path.parent / ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _read(self) -> list[Device]:
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except FileNotFoundError:
            return []
        return [Device(**d) for d in raw.get("devices", [])]

    def _write(self, devices: list[Device]) -> None:
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "devices": [asdict(d) for d in devices]}, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def all(self) -> list[Device]:
        with self._locked():
            return self._read()

    def add(self, device: Device) -> None:
        with self._locked():
            devices = [d for d in self._read() if d.id != device.id]
            devices.append(device)
            self._write(devices)

    def remove(self, device_id: str) -> None:
        with self._locked():
            self._write([d for d in self._read() if d.id != device_id])

    def for_origin(self, origin: str) -> list[Device]:
        return [d for d in self.all() if d.origin == origin]

    def record_attempt(self, device_id: str, success: bool, now: int | None = None) -> None:
        """Count wrong PINs; after MAX_FAILURES in a row lock the device for a growing delay."""
        now = int(time.time()) if now is None else now
        with self._locked():
            devices = self._read()
            for d in devices:
                if d.id != device_id:
                    continue
                if success:
                    d.failures, d.locked_until = 0, 0
                else:
                    d.failures += 1
                    if d.failures >= MAX_FAILURES:
                        d.locked_until = now + min(3600, LOCK_BASE_SECONDS * 2 ** (d.failures - MAX_FAILURES))
            self._write(devices)

    def lock_remaining(self, device: Device, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        current = next((d for d in self.all() if d.id == device.id), device)
        return max(0, current.locked_until - now)


def new_device_id() -> str:
    return uuid.uuid4().hex
