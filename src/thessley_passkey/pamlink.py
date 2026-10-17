"""Linux computers (thessley-pam): approve their logins, sudo and ssh from this app.

A computer shows a QR code or prints a link:

    thessleypam://enroll?h=<LAN IPv4>&p=<port>&fp=<SHA-256 of its certificate>&id=..&n=..&m=<machine id>&hn=<host>&u=<user>
    thessleypam://sudo?...&tty=..        thessleypam://login?...

This is the same protocol as the Android app (see thessley-pam-linux, thessley_pam/protocol.py), so this app can be a
second approver next to the phone: if the phone is lost, a PC can still approve. The link arrives from a terminal
or a pasted line, so every field is untrusted: strict patterns, a private IPv4 address only, a pinned certificate.

The computer is reached over HTTPS on the local network and trusted only through the certificate fingerprint that
came in the link (no CA, no trust on first use), exactly like the phone.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit

SIG_VERSION = "thessley_pam_v1"
TYPES = ("enroll", "sudo", "login", "vpn")
ACTIONS = ("register", "approve", "deny")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,64}$")
_USER = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
_TTY = re.compile(r"^[A-Za-z0-9/_.:-]{1,32}$")
_FIELD = re.compile(r"^[^|\s]+$")
_SERVICE = re.compile(r"^[a-z0-9_-]{1,32}$")
_CLIENT = re.compile(r"^[0-9A-Fa-f.:]{1,45}$")
# A VPN login comes from the internet, so its link names a public host. Not a private address: a name with at least one dot, or
# a public IPv4 address. Whether this app trusts THAT host is decided from what it recorded at enrolment (core.Service).
_NAME = re.compile(r"^(?=.{4,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

# The link says type "sudo" for every request that is not a screen login (ssh included), so what is really being
# approved is told apart by the optional display-only fields: s (PAM service) and, for old computers, tty "ssh".
HEADINGS = {"enroll": "Add this app as an approver", "sudo": "Approve sudo", "ssh": "Approve ssh login", "vpn": "Approve VPN login",
            "screen": "Approve screen login", "device": "Approve adding a device",
            "web": "Approve the admin page sign-in", "webchange": "Approve a change to your keys"}
WHAT = {
    "sudo": "Allow a sudo command on that computer",
    "ssh": "Let someone log in to that computer over ssh",
    "vpn": "Let someone connect to that computer's VPN",
    "screen": "Log in at that computer's login or lock screen",
    "device": "Let a new phone or app be added for this account on that computer",
    "web": "Sign in to the Thessley admin page on that computer",
    "webchange": "Make the change you just asked for on the Thessley admin page",
}


@dataclass(frozen=True)
class PamRequest:
    type: str
    request_id: str
    nonce: str
    host: str          # the computer's LAN address
    port: int
    fingerprint: str   # SHA-256 of its certificate, hex: the only thing trusted
    machine_id: str
    hostname: str      # display only
    username: str      # the account on that computer; covered by the signature
    tty: str = ""      # display only
    service: str = ""  # display only: the PAM service (sudo, sshd, gdm-thessley); older computers do not send it
    client: str = ""   # display only: where an ssh login comes from
    raw: str = field(default="", compare=False)
    vpn_host: str = ""  # enrolment links only: the public host this computer's VPN approvals will come from (recorded, then required)

    # What the screens call things. Shared names with link.AuthRequest, so one screen serves both.
    country = ""

    @property
    def ip(self) -> str:
        """"Requested from": the ssh client's address (nothing for sudo or the screen, which are at the computer)."""
        return self.client if self.kind in ("ssh", "web", "vpn") else ""

    @property
    def kind(self) -> str:
        if self.type == "enroll":
            return "enroll"
        if self.type == "login":
            return "screen"
        if self.type == "vpn":
            return "vpn"
        if self.service == "thessley-enroll" or self.tty == "add-device":  # Linux names the service, Windows the terminal
            return "device"
        if self.service == "thessley-web":
            return "web"
        if self.service == "thessley-web-change":
            return "webchange"
        if self.service == "sshd" or (not self.service and self.tty == "ssh"):
            return "ssh"
        return "sudo"

    @property
    def terminal(self) -> str:
        return self.tty if self.kind == "sudo" and self.tty != "-" else ""

    @property
    def origin(self) -> str:
        """The stable key a device is stored under (the LAN address can change, the machine id does not)."""
        return "computer:" + self.machine_id

    @property
    def display(self) -> str:
        return f"{self.hostname} ({self.host})"

    @property
    def kind_label(self) -> str:
        return "Computer"

    @property
    def heading(self) -> str:
        return HEADINGS[self.kind]

    @property
    def what(self) -> str:
        return WHAT.get(self.kind, "")

    @property
    def enroll_title(self) -> str:
        return "Add this app as an approver"

    @property
    def enroll_button(self) -> str:
        return "Add as approver"

    @property
    def enroll_hint(self) -> str:
        return ("This app will be asked to approve sudo, ssh and screen logins for this account. "
                "Only continue if you just ran “thessley-pam enroll” on that computer yourself. "
                "You will compare a 6-digit code with its screen.")


def is_private_ipv4(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.version == 4 and (ip.is_private or ip.is_loopback) and not ip.is_multicast and not ip.is_unspecified


def is_public_host(host: str) -> bool:
    """A host name with a dot, or a globally routable IPv4 address: what a VPN approval may be reached at."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return bool(_NAME.match(host))
    return ip.version == 4 and ip.is_global


def parse(raw: str) -> PamRequest | None:
    """Parse a thessleypam://<type>?... link; None for anything that is not exactly what thessley-pam produces."""
    if not isinstance(raw, str) or len(raw) > 2048:
        return None
    try:
        parts = urlsplit(raw.strip())
    except ValueError:
        return None
    if parts.scheme != "thessleypam" or parts.netloc not in TYPES:
        return None
    q = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
    host = q.get("h", "")
    fp = q.get("fp", "").lower()
    try:
        port = int(q.get("p", ""))
    except ValueError:
        return None
    rid, nonce, mid = q.get("id", ""), q.get("n", ""), q.get("m", "")
    hostname, user, tty = q.get("hn", ""), q.get("u", ""), q.get("tty", "")
    # Only a VPN request may name a public host (and then only one this app was enrolled for: checked where it is used);
    # every other request still has to be on the local network.
    host_ok = is_public_host(host) or is_private_ipv4(host) if parts.netloc == "vpn" else is_private_ipv4(host)
    if not host_ok or not 1 <= port <= 65535 or not _HEX64.match(fp):
        return None
    vpn_host = q.get("vh", "") if parts.netloc == "enroll" else ""
    if vpn_host and not is_public_host(vpn_host):
        return None
    if not (_TOKEN.match(rid) and _TOKEN.match(nonce) and _HEX32.match(mid) and _HOST.match(hostname) and _USER.match(user)):
        return None
    if tty and not _TTY.match(tty):
        return None
    service, client = q.get("s", ""), q.get("r", "")
    service = service if _SERVICE.match(service) else ""
    client = client if _CLIENT.match(client) else ""
    if parts.netloc == "enroll":
        tty, service, client = "", "", ""
    fields = {"h": host, "p": port, "fp": fp, "id": rid, "n": nonce, "m": mid, "hn": hostname, "u": user}
    if vpn_host:
        fields["vh"] = vpn_host
    if tty:
        fields["tty"] = tty
    if service:
        fields["s"] = service
    if client:
        fields["r"] = client
    rebuilt = f"thessleypam://{parts.netloc}?" + urlencode(fields)  # only validated fields travel on
    return PamRequest(parts.netloc, rid, nonce, host, port, fp, mid, hostname, user, tty, service, client, rebuilt, vpn_host=vpn_host)


def canonical(type_: str, request_id: str, machine_id: str, username: str, nonce: str, timestamp: int, action: str) -> bytes:
    """Byte-for-byte what the computer verifies (thessley_pam.protocol.canonical)."""
    if type_ not in TYPES or action not in ACTIONS:
        raise ValueError("unknown type or action")
    fields = [SIG_VERSION, type_, request_id, machine_id, username, nonce, str(int(timestamp)), action]
    if not all(_FIELD.match(f) for f in fields):
        raise ValueError("empty field or field containing '|' or whitespace")
    return "|".join(fields).encode()


def pairing_code(spki_b64: str) -> str:
    """The six digits both screens show while enrolling (thessley_pam.protocol.pairing_code)."""
    digest = hashlib.sha256(base64.b64decode(spki_b64)).digest()
    n = int.from_bytes(digest[:4], "big") % 1_000_000
    s = f"{n:06d}"
    return s[:3] + " " + s[3:]


class PamError(Exception):
    """The computer could not be reached, is not the one in the link, or refused."""


class PinnedClient:
    """HTTPS to one computer, trusting exactly the certificate whose SHA-256 is in the link."""

    def __init__(self, req: PamRequest):
        self.req = req

    def post(self, path: str, body: dict, timeout: float = 20) -> tuple[int, dict]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # the pin below is the check; a LAN IP has no name a CA could have signed
        conn = http.client.HTTPSConnection(self.req.host, self.req.port, context=ctx, timeout=timeout)
        try:
            try:
                conn.connect()
            except (OSError, socket.timeout, ssl.SSLError) as exc:
                raise PamError(f"Cannot reach {self.req.hostname} at {self.req.host}:{self.req.port}: {exc}") from exc
            served = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
            if served != self.req.fingerprint:  # checked before anything is sent
                raise PamError("The computer's certificate does not match the link: not sending anything.")
            conn.request("POST", path, json.dumps(body), {"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read(65536)
        except (OSError, socket.timeout, ssl.SSLError, http.client.HTTPException) as exc:
            raise PamError(f"Lost the connection to {self.req.hostname}: {exc}") from exc
        finally:
            conn.close()
        try:
            return resp.status, json.loads(data)
        except ValueError:
            return resp.status, {"result": "error", "message": f"HTTP {resp.status}"}
