"""TPM 2.0 support: a signing key that lives inside the TPM and a hardware proof of that.

Phase 1 - key in the chip. An ECC P-256 signing key is created under the TPM's storage root.
  It cannot leave the chip (fixedTPM / fixedParent) and its password (derived from the PIN, and
  the security key if used) is checked by the TPM itself, which counts wrong tries and locks out.
  Only an encrypted blob that this one TPM can load is stored on disk.

Phase 2 - proof for the site. A fresh restricted "attestation key" (AK) is created, tied to the
  chip's endorsement key (EK) with TPM2_ActivateCredential, and certifies the signing key. The
  chip's EK certificate chain (Intel, Infineon, ...) is sent along so the site can check the whole
  chain back to the manufacturer.

All TPM traffic goes through tpm2.py (pure Python), so Windows (TPM Base Services) and Linux
(/dev/tpmrm0) run exactly the same code. Every function opens its own connection and releases
every object it loaded.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
from typing import Iterator

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

from . import tpm2

DEFAULT_CONNECTION = "tbs" if os.name == "nt" else "device:/dev/tpmrm0"


class TpmError(Exception):
    pass


class TpmUnavailable(TpmError):
    """No usable TPM (missing device, no permission)."""


class TpmWrongAuth(TpmError):
    """The password (PIN) was wrong; the TPM counted it."""


class TpmLockedOut(TpmError):
    """The TPM's own dictionary-attack protection is locking out password guesses."""


def tcti() -> str:
    """How to reach the TPM (THESSLEY_TPM_TCTI overrides: 'swtpm:host=H,port=P', 'device:/dev/tpm0', 'tbs')."""
    return os.environ.get("THESSLEY_TPM_TCTI") or DEFAULT_CONNECTION


def status() -> tuple[bool, str]:
    """(usable, explanation) for the settings screen: is there a TPM this user can use?"""
    spec = tcti()
    if spec.startswith("device:"):
        device = spec.split(":", 1)[1]
        if not os.path.exists(device):
            return False, "This computer has no TPM 2.0 chip (or it is turned off in the firmware)."
        if not os.access(device, os.R_OK | os.W_OK):
            return False, "A TPM was found, but your user may not use it. Add your user to the 'tss' group (sudo usermod -aG tss $USER) and log in again."
        return True, ""
    if spec == "tbs":
        try:
            tpm2.open_transport("tbs").close()
        except tpm2.TransportError as exc:
            return False, f"No usable TPM: {exc}"
        return True, ""
    return True, ""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _map_error(exc: Exception) -> TpmError:
    if isinstance(exc, tpm2.TpmRcError):
        if exc.is_lockout:
            return TpmLockedOut("The TPM has locked out password attempts for a while (too many wrong PINs).")
        if exc.is_wrong_auth:
            return TpmWrongAuth("Wrong PIN.")
        if exc.is_out_of_memory:
            return TpmError("The TPM is busy with other programs' objects. Close other TPM-using applications and try again.")
        return TpmError(f"TPM error 0x{exc.rc:X} (command 0x{exc.command:X})")
    if isinstance(exc, tpm2.TransportError):
        text = str(exc)
        if "ermission" in text:
            return TpmUnavailable("No permission to use the TPM. Add your user to the 'tss' group (sudo usermod -aG tss $USER) and log in again.")
        return TpmUnavailable(f"Could not talk to the TPM ({tcti()}): {text}")
    return TpmError(str(exc))


@contextlib.contextmanager
def _session(connection: str | None = None) -> Iterator[tpm2.Tpm]:
    try:
        client = tpm2.Tpm(tpm2.open_transport(connection or tcti()))
    except tpm2.TransportError as exc:
        raise _map_error(exc) from exc
    try:
        yield client
    except (tpm2.TpmRcError, tpm2.TransportError) as exc:
        raise _map_error(exc) from exc
    finally:
        with contextlib.suppress(Exception):
            client.close()


def _mapped(method):
    """Turn TPM errors into ours at the call, not only when the session closes."""
    import functools

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except (tpm2.TpmRcError, tpm2.TransportError) as exc:
            raise _map_error(exc) from exc
    return wrapper


HIERARCHIES = {"owner": tpm2.RH_OWNER, "endorsement": tpm2.RH_ENDORSEMENT}


def _storage_primary(t: tpm2.Tpm, hierarchy: str | None = None) -> tuple[int, str]:
    """The standard storage root: same template -> same key every time on this TPM.

    Normally under the owner hierarchy. If the system keeps the owner password to itself (Windows may), the
    same template under the endorsement hierarchy is used instead, and keys remember which one they need.
    """
    order = [hierarchy] if hierarchy else ["owner", "endorsement"]
    last: Exception | None = None
    for name in order:
        try:
            handle, _, _ = t.create_primary(HIERARCHIES[name], tpm2.SRK_TEMPLATE)
            return handle, name
        except tpm2.TpmRcError as exc:
            if not exc.is_wrong_auth:
                raise
            last = exc
    raise last  # type: ignore[misc]


def _release(t: tpm2.Tpm, handle: int) -> None:
    with contextlib.suppress(Exception):
        t.flush(handle)
    if handle in t.loaded:
        t.loaded.remove(handle)


def _parse_public(tpmt_public: bytes) -> tuple[int, int, int, bytes, bytes]:
    """(type, nameAlg, attributes, x, y) of an ECC TPMT_PUBLIC."""
    r = tpm2.Reader(tpmt_public)
    kind, name_alg, attributes = r.u16(), r.u16(), r.u32()
    r.tpm2b()  # authPolicy
    if r.u16() != tpm2.ALG_NULL:
        r.u16()
        r.u16()
    if r.u16() != tpm2.ALG_NULL:
        r.u16()
    r.u16()  # curve
    if r.u16() != tpm2.ALG_NULL:
        r.u16()
    return kind, name_alg, attributes, r.tpm2b(), r.tpm2b()


def spki_from_public(public_blob: bytes) -> bytes:
    """SubjectPublicKeyInfo DER (what the sites store) from a marshalled TPM2B_PUBLIC."""
    *_, x, y = _parse_public(tpm2.Reader(public_blob).tpm2b())
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


# ---- Phase 1: the signing key -------------------------------------------------------------

def create_key(auth: bytes, connection: str | None = None) -> dict:
    """Create the signing key. Returns {"public": b64, "private": b64} (marshalled blobs; the private one is
    encrypted by this TPM and useless anywhere else)."""
    with _session(connection) as t:
        parent, hierarchy = _storage_primary(t)
        private, public = t.create(parent, auth, tpm2.KEY_TEMPLATE)  # dictionary-attack protection stays ON
        blobs = {"public": _b64(public), "private": _b64(private)}
        if hierarchy != "owner":
            blobs["hierarchy"] = hierarchy  # keys made before this field existed are owner-hierarchy keys
        return blobs


def _load_key(t: tpm2.Tpm, blobs: dict, auth: bytes) -> int:
    parent, _ = _storage_primary(t, blobs.get("hierarchy", "owner"))
    handle, _ = t.load(parent, _unb64(blobs["private"]), _unb64(blobs["public"]))
    _release(t, parent)
    return handle


def sign(blobs: dict, auth: bytes, message: bytes, connection: str | None = None) -> bytes:
    """ECDSA-SHA256 over `message`, DER-encoded like every other Thessley signature."""
    with _session(connection) as t:
        key = _load_key(t, blobs, auth)
        r, s = t.sign(key, auth, hashlib.sha256(message).digest())
        return asym_utils.encode_dss_signature(int.from_bytes(r, "big"), int.from_bytes(s, "big"))


def check_auth(blobs: dict, auth: bytes, connection: str | None = None) -> None:
    """Raises TpmWrongAuth if `auth` is not the key's password (counts as one attempt)."""
    sign(blobs, auth, b"thessley-passkey-auth-check", connection)


# ---- Phase 2: proof for the site -------------------------------------------------------------------------

EK_CERT_NV = {"ecc": 0x01C0000A}
EK_CHAIN_NV = 0x01C00100          # Intel keeps the manufacturer's intermediate certificates here
MAX_CHAIN = 8
AMD_MANUFACTURER = 0x414D4400      # TPM_PT_MANUFACTURER "AMD" padded with a zero byte
AMD_AIA = "https://ftpm.amd.com/pki/aia/"   # AMD firmware TPMs keep no certificate in NV; AMD hosts them
AIA_TIMEOUT = 10


def _split_der_certs(blob: bytes) -> list[bytes]:
    """Back-to-back DER certificates (as found in the TPM's NV storage)."""
    certs, i = [], 0
    while i + 4 <= len(blob) and blob[i] == 0x30:
        if blob[i + 1] & 0x80:
            n = blob[i + 1] & 0x7F
            length, header = int.from_bytes(blob[i + 2:i + 2 + n], "big"), 2 + n
        else:
            length, header = blob[i + 1], 2
        if i + header + length > len(blob):
            break
        certs.append(blob[i:i + header + length])
        i += header + length
    return certs


def _cert(der: bytes):
    """Lenient certificate reader: some TPM makers' certificates are not strictly canonical DER."""
    from asn1crypto import x509 as a1
    return a1.Certificate.load(der)


def _https_get(url: str) -> bytes | None:
    """A small certificate over https only. A plain-http link is tried as https (AMD publishes http links to an https host)."""
    import requests
    if url.startswith("http://"):
        url = "https://" + url[len("http://"):]
    if not url.startswith("https://"):
        return None
    if url.startswith(AMD_AIA):
        url = url.lower()  # AMD's certificates list their links in capitals, but only lower case is served
    for attempt in range(3):  # AMD's server now and then drops a connection
        try:
            resp = requests.get(url, timeout=AIA_TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue
        return resp.content if resp.status_code == 200 and len(resp.content) < 16384 else None
    return None


def amd_ek_cert_url(x: int, y: int) -> str:
    """Where AMD publishes the certificate of a firmware TPM's ECC endorsement key (same scheme as tpm2_getekcertificate)."""
    digest = hashlib.sha256(bytes.fromhex("00004444") + x.to_bytes(32, "big") + y.to_bytes(32, "big")).digest()
    return AMD_AIA + digest[:16].hex()


def _issued_by(child, parent) -> bool:
    """Did `parent` issue `child`? By key identifiers when both have them (AMD's names do not match exactly), else by name."""
    aki, ski = child.authority_key_identifier, parent.key_identifier
    if aki and ski:
        return bytes(aki) == bytes(ski)
    return child.issuer.dump() == parent.subject.dump()


def _fetch_issuers(chain: list[bytes], fetch=None) -> list[bytes]:
    """Complete the chain: for the certificate whose issuer is missing, follow its 'CA Issuers' link (https only)."""
    fetch = fetch or _https_get
    chain = list(chain)
    while len(chain) < MAX_CHAIN:
        certs = [_cert(c) for c in chain]
        missing = next((c for c in certs if c.issuer.dump() != c.subject.dump() and not any(_issued_by(c, p) for p in certs if p is not c)), None)
        if missing is None:
            break
        urls = []
        for access in (missing.authority_information_access_value or []):
            if access["access_method"].native == "ca_issuers" and access["access_location"].name == "uniform_resource_identifier":
                urls.append(access["access_location"].native)
        found = None
        for url in urls:
            data = fetch(url)
            if not data:
                continue
            try:
                issuer = _cert(data)
            except ValueError:
                continue
            if _issued_by(missing, issuer):
                found = data
                break
        if found is None:
            break
        chain.append(found)
    return chain


class Attestor:
    """One enrolment's worth of attestation. Keep it open between asking the site for its challenge and answering."""

    def __init__(self, connection: str | None = None, ek_certs: list[bytes] | None = None, fetch=None):
        self.connection = connection
        self._ek_certs_override = ek_certs
        self._fetch = fetch
        self._cm = None
        self.t: tpm2.Tpm | None = None

    def __enter__(self):
        self._cm = _session(self.connection)
        self.t = self._cm.__enter__()
        try:
            self._setup()
        except BaseException:
            import sys
            self._cm.__exit__(*sys.exc_info())  # release whatever was loaded before failing
            raise
        return self

    def __exit__(self, *exc):
        return self._cm.__exit__(*exc)

    def _setup(self):
        # Attestation key: restricted signing key, fixed to this chip, no password (it lives for one enrolment).
        try:
            parent, _ = _storage_primary(self.t)
            private, public = self.t.create(parent, b"", tpm2.AK_TEMPLATE)
            self.ak, _ = self.t.load(parent, private, public)
            _release(self.t, parent)
        except (tpm2.TpmRcError, tpm2.TransportError) as exc:
            raise _map_error(exc) from exc
        self._ak_public = tpm2.Reader(public).tpm2b()

    # -- endorsement key and its certificates --------------------------------------------------

    @_mapped
    def ek_certs(self) -> list[bytes]:
        """The EK certificate first, then every intermediate we can find, as DER."""
        if self._ek_certs_override is not None:
            return list(self._ek_certs_override)
        leaf = self.t.nv_read(EK_CERT_NV["ecc"])
        if leaf:
            chain = _split_der_certs(leaf)[:1]
        else:
            chain = self._published_ek_cert()
        extra = self.t.nv_read(EK_CHAIN_NV)
        if extra:
            chain += _split_der_certs(extra)
        return _fetch_issuers(chain, self._fetch)

    def _published_ek_cert(self) -> list[bytes]:
        """AMD firmware TPMs: fetch the EK certificate AMD publishes, and only trust it if it is this chip's."""
        missing = TpmError("This TPM has no EK certificate, so it cannot be verified by a site.")
        if self.t.property(0x105) != AMD_MANUFACTURER:
            raise missing
        der = (self._fetch or _https_get)(amd_ek_cert_url(*self.ek_point()))
        if not der:
            raise TpmError("This TPM has no EK certificate on the chip, and AMD's copy could not be downloaded.")
        if not self.ek_matches_certificate(der):
            raise TpmError("The certificate AMD published does not belong to this TPM.")
        return [der]

    @_mapped
    def ek_point(self) -> tuple[int, int]:
        """The chip's endorsement key (P-256 point)."""
        ek, public, _ = self.t.create_primary(tpm2.RH_ENDORSEMENT, tpm2.EK_TEMPLATE)
        try:
            *_, x, y = _parse_public(public)
            return int.from_bytes(x, "big"), int.from_bytes(y, "big")
        finally:
            _release(self.t, ek)

    @_mapped
    def ek_matches_certificate(self, cert_der: bytes) -> bool:
        """The EK the chip derives must be the key its certificate vouches for."""
        point = bytes(_cert(cert_der).public_key["public_key"].native)
        if len(point) != 65 or point[0] != 4:
            return False
        return (int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:], "big")) == self.ek_point()

    # -- the three steps ------------------------------------------------------------------------

    def ak_public(self) -> bytes:
        """TPMT_PUBLIC of the attestation key (what the site names the credential after)."""
        return self._ak_public

    @_mapped
    def activate(self, credential_blob: bytes, secret: bytes) -> bytes:
        """TPM2_ActivateCredential: recovers the site's secret only if this chip holds both the EK and the AK."""
        session, _ = self.t.start_policy_session()
        self.t.policy_secret(session)
        ek, _, _ = self.t.create_primary(tpm2.RH_ENDORSEMENT, tpm2.EK_TEMPLATE)
        try:
            return self.t.activate_credential(self.ak, ek, session, credential_blob, secret)
        finally:
            _release(self.t, ek)
            _release(self.t, session)  # the TPM already ended it on success; a failed flush is fine

    @_mapped
    def certify(self, key_blobs: dict, key_auth: bytes, nonce: bytes) -> dict:
        """Have the AK sign a statement about the signing key, bound to `nonce`."""
        key = _load_key(self.t, key_blobs, key_auth)
        attest, signature = self.t.certify(key, key_auth, self.ak, nonce)
        public, _ = self.t.read_public(key)
        return {"attest": attest, "signature": signature, "key_public": public}


# ---- diagnostics ------------------------------------------------------------------------------------------------

def diagnose() -> Iterator[str]:
    """Step-by-step probe for the diagnostics report: what this computer's TPM lets an ordinary program do."""
    yield f"connection: {tcti()}"
    try:
        t = tpm2.Tpm(tpm2.open_transport(tcti()))
    except tpm2.TransportError as exc:
        yield f"cannot open: {exc}"
        return
    try:
        def step(name, fn):
            try:
                out = fn()
                return f"{name}: ok" + (f" ({out})" if out else "")
            except tpm2.TpmRcError as exc:
                return f"{name}: FAILED rc=0x{exc.rc:X}"
            except Exception as exc:
                return f"{name}: FAILED {exc.__class__.__name__}: {exc}"

        def maker():
            v = t.property(0x105)
            return bytes.fromhex(f"{v:08x}").decode("ascii", "replace").strip("\0 ") if v is not None else "unknown"

        yield step("manufacturer", maker)
        yield step("max wrong tries before lockout", lambda: t.property(0x20F))
        yield step("lockout recovery seconds", lambda: t.property(0x211))
        yield step("EK certificate (ECC) in NV", lambda: f"{len(t.nv_read(EK_CERT_NV['ecc']) or b'')} bytes")
        yield step("EK intermediate certificates in NV", lambda: f"{len(t.nv_read(EK_CHAIN_NV) or b'')} bytes")

        def srk():
            h, used = _storage_primary(t)
            _release(t, h)
            return f"under the {used} hierarchy"

        def ek():
            h, pub, _ = t.create_primary(tpm2.RH_ENDORSEMENT, tpm2.EK_TEMPLATE)
            _release(t, h)

        def keycycle():
            h, _ = _storage_primary(t)
            auth = hashlib.sha256(b"diagnose").digest()
            priv, pub = t.create(h, auth, tpm2.KEY_TEMPLATE)
            k, _ = t.load(h, priv, pub)
            _release(t, h)
            t.sign(k, auth, hashlib.sha256(b"x").digest())
            _release(t, k)

        def session():
            s, _ = t.start_policy_session()
            t.policy_secret(s)
            _release(t, s)

        yield step("create storage key", srk)
        yield step("create endorsement key", ek)
        yield step("create, load and sign with a key", keycycle)
        yield step("policy session on the endorsement hierarchy", session)
    finally:
        with contextlib.suppress(Exception):
            t.close()
