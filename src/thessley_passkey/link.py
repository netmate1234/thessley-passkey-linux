"""Parsing and validation of the thessleypasskey:// link.

The link arrives from a web page (same-device button) or a pasted QR payload,
so every field is untrusted input: it is length-limited, stripped of control
characters and checked against strict patterns before it is ever shown or used.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit

TYPES = ("login", "2fa", "enroll")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]")  # control + bidi override characters


def allow_insecure_loopback() -> bool:
    """Development only: accept http:// origins on localhost (never set in production)."""
    return os.environ.get("THESSLEY_PASSKEY_DEV") == "1"


def clean_text(value: str | None, limit: int = 100) -> str:
    """Display-only text: no control or bidi characters, length-capped."""
    if not value:
        return ""
    return _CTRL.sub("", value).strip()[:limit]


def normalize_origin(origin: str) -> str | None:
    """Return the canonical origin (scheme://host[:port], no trailing slash) or None."""
    try:
        parts = urlsplit(origin)
    except ValueError:
        return None
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        return None
    host = parts.hostname
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+|[0-9A-Fa-f:]+", host):
        return None
    if parts.scheme == "https":
        pass
    elif parts.scheme == "http" and allow_insecure_loopback() and host in ("localhost", "127.0.0.1", "::1"):
        pass
    else:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    netloc = host if ":" not in host else f"[{host}]"
    if port and not ((parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80)):
        netloc += f":{port}"
    return f"{parts.scheme}://{netloc}"


@dataclass(frozen=True)
class AuthRequest:
    type: str          # login | 2fa | enroll
    request_id: str
    nonce: str
    origin: str        # canonical; this exact string is what gets signed
    ip: str = ""       # display only
    country: str = ""  # display only
    username: str = "" # display only / device hint
    raw: str = field(default="", compare=False)  # the link as received, to reopen the app on it


def parse(raw: str) -> AuthRequest | None:
    """Parse a thessleypasskey://auth?... link; None if it is not a well-formed one."""
    if not isinstance(raw, str) or len(raw) > 2048:
        return None
    try:
        parts = urlsplit(raw.strip())
    except ValueError:
        return None
    if parts.scheme != "thessleypasskey" or parts.netloc != "auth":
        return None
    q = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
    rtype, rid, nonce, origin = q.get("type", ""), q.get("id", ""), q.get("nonce", ""), q.get("origin", "")
    if rtype not in TYPES or not _TOKEN.match(rid) or not _TOKEN.match(nonce):
        return None
    canonical = normalize_origin(origin)
    # The server verifies the signature over this string exactly as it put it in the link, so it is
    # signed untouched. Accept it only if it is already a plain origin (no trailing slash, no default
    # port): anything else is not something a Thessley server produces.
    if canonical is None or canonical.lower() != origin.lower():
        return None
    ip, country, username = clean_text(q.get("ip"), 45), clean_text(q.get("country"), 60), clean_text(q.get("username"), 100)
    # The link as it is handed to a re-launched (possibly elevated) copy of the app: rebuilt from the validated
    # fields only, so nothing unchecked in the original text (quotes, extra parameters) can travel with it.
    fields = {"type": rtype, "id": rid, "nonce": nonce, "origin": origin, "ip": ip, "country": country, "username": username}
    raw = "thessleypasskey://auth?" + urlencode({k: v for k, v in fields.items() if v})
    return AuthRequest(type=rtype, request_id=rid, nonce=nonce, origin=origin, ip=ip, country=country, username=username, raw=raw)
