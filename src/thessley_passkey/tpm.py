"""TPM 2.0 support: a signing key that lives inside the TPM and a hardware proof of that.

Phase 1 - key in the chip. An ECC P-256 signing key is created under the TPM's storage root.
  It cannot leave the chip (fixedTPM / fixedParent) and its password (derived from the PIN, and
  the security key if used) is checked by the TPM itself, which counts wrong tries and locks out.
  Only an encrypted blob that this one TPM can load is stored on disk.

Phase 2 - proof for the site. A fresh restricted "attestation key" (AK) is created, tied to the
  chip's endorsement key (EK) with TPM2_ActivateCredential, and certifies the signing key. The
  chip's EK certificate chain (Intel, Infineon, ...) is sent along so the site can check the whole
  chain back to the manufacturer.

Every function opens its own connection and releases every object it loaded.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
from typing import Iterator

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

DEFAULT_TCTI = "device:/dev/tpmrm0"


class TpmError(Exception):
    pass


class TpmUnavailable(TpmError):
    """No usable TPM (missing device, no permission, library not installed)."""


class TpmWrongAuth(TpmError):
    """The password (PIN) was wrong; the TPM counted it."""


class TpmLockedOut(TpmError):
    """The TPM's own dictionary-attack protection is locking out password guesses."""


def tcti() -> str:
    return os.environ.get("THESSLEY_TPM_TCTI") or DEFAULT_TCTI


def _lib():
    try:
        from tpm2_pytss import ESAPI, constants, types
        from tpm2_pytss import utils as tpm_utils
        from tpm2_pytss.TSS2_Exception import TSS2_Exception
    except ImportError as exc:
        raise TpmUnavailable("The python3-tpm2-pytss package is needed for TPM protection.") from exc
    return ESAPI, constants, types, tpm_utils, TSS2_Exception


def status() -> tuple[bool, str]:
    """(usable, explanation) for the settings screen: is there a TPM this user can use?"""
    try:
        _lib()
    except TpmUnavailable as exc:
        return False, str(exc)
    if os.environ.get("THESSLEY_TPM_TCTI"):
        return True, ""
    device = DEFAULT_TCTI.split(":", 1)[1]
    if not os.path.exists(device):
        return False, "This computer has no TPM 2.0 chip (or it is turned off in the firmware)."
    if not os.access(device, os.R_OK | os.W_OK):
        return False, "A TPM was found, but your user may not use it. Add your user to the 'tss' group (sudo usermod -aG tss $USER) and log in again."
    return True, ""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@contextlib.contextmanager
def _session(connection: str | None = None) -> Iterator:
    ESAPI, constants, types, tpm_utils, TSS2 = _lib()
    try:
        esys = ESAPI(tcti=connection or tcti())
    except Exception as exc:
        text = str(exc)
        if "ermission" in text or "denied" in text.lower():
            raise TpmUnavailable("No permission to use the TPM. Add your user to the 'tss' group and log in again.") from exc
        raise TpmUnavailable(f"Could not open the TPM ({tcti()}): {exc}") from exc
    handles: list = []
    esys._thessley_handles = handles  # objects to release when the session ends
    try:
        yield esys
    except TSS2 as exc:
        raise _map_error(exc, constants) from exc
    finally:
        for h in reversed(handles):
            with contextlib.suppress(Exception):
                esys.flush_context(h)
        with contextlib.suppress(Exception):
            esys.close()


def _map_error(exc, constants) -> TpmError:
    rc = exc.rc & 0xFFF if hasattr(exc, "rc") else 0
    rc_fmt = exc.error if hasattr(exc, "error") else None
    text = str(exc)
    if "lockout" in text.lower() or rc == 0x921:
        return TpmLockedOut("The TPM has locked out password attempts for a while (too many wrong PINs).")
    if "authorization" in text.lower() or "auth" in text.lower() and "fail" in text.lower() or rc in (0x98E, 0x9A2, 0x1A2, 0x18E, 0x8E, 0xA2) or rc_fmt in (0x8E, 0xA2):
        return TpmWrongAuth("Wrong PIN.")
    return TpmError(f"TPM error: {text}")


def _mapped(method):
    """Turn the library's exceptions into our own at the call, not only when the session closes."""
    import functools

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        _, constants, _, _, TSS2 = _lib()
        try:
            return method(self, *args, **kwargs)
        except TSS2 as exc:
            raise _map_error(exc, constants) from exc
    return wrapper


def _track(esys, handle):
    esys._thessley_handles.append(handle)
    return handle


def _release(esys, handle) -> None:
    """Free a loaded object now. A TPM only holds a few at once; the kernel's resource manager hides that
    on a real machine, but code that works with three or fewer works everywhere."""
    with contextlib.suppress(Exception):
        esys.flush_context(handle)
    if handle in esys._thessley_handles:
        esys._thessley_handles.remove(handle)


def _storage_primary(esys):
    """The standard storage root: same template -> same key every time on this TPM."""
    _, constants, types, _, _ = _lib()
    A = constants.TPMA_OBJECT
    attrs = A.FIXEDTPM | A.FIXEDPARENT | A.SENSITIVEDATAORIGIN | A.USERWITHAUTH | A.RESTRICTED | A.DECRYPT | A.NODA
    template = types.TPM2B_PUBLIC.parse("ecc256:null:aes128cfb", objectAttributes=attrs)
    handle, *_ = esys.create_primary(types.TPM2B_SENSITIVE_CREATE(), template)
    return _track(esys, handle)


def _sig_scheme():
    _, constants, types, _, _ = _lib()
    return types.TPMT_SIG_SCHEME(scheme=constants.TPM2_ALG.ECDSA, details=types.TPMU_SIG_SCHEME(any=types.TPMS_SCHEME_HASH(hashAlg=constants.TPM2_ALG.SHA256)))


def _no_ticket():
    _, constants, types, _, _ = _lib()
    return types.TPMT_TK_HASHCHECK(tag=constants.TPM2_ST.HASHCHECK, hierarchy=constants.TPM2_RH.NULL)


def spki_from_public(public_blob: bytes) -> bytes:
    """SubjectPublicKeyInfo DER (what the sites store) from a marshalled TPM2B_PUBLIC."""
    _, _, types, _, _ = _lib()
    pub, _ = types.TPM2B_PUBLIC.unmarshal(public_blob)
    point = pub.publicArea.unique.ecc
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(bytes(point.x), "big"), int.from_bytes(bytes(point.y), "big"), ec.SECP256R1()).public_key()
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


# ---- Phase 1: the signing key -------------------------------------------------------------

def create_key(auth: bytes, connection: str | None = None) -> dict:
    """Create the signing key. Returns {"public": b64, "private": b64} (marshalled blobs; the private one is
    encrypted by this TPM and useless anywhere else)."""
    _, constants, types, _, _ = _lib()
    A = constants.TPMA_OBJECT
    with _session(connection) as esys:
        parent = _storage_primary(esys)
        attrs = A.FIXEDTPM | A.FIXEDPARENT | A.SENSITIVEDATAORIGIN | A.USERWITHAUTH | A.SIGN_ENCRYPT  # DA protection stays ON
        template = types.TPM2B_PUBLIC.parse("ecc256:ecdsa-sha256", objectAttributes=attrs)
        private, public, *_ = esys.create(parent, types.TPM2B_SENSITIVE_CREATE(types.TPMS_SENSITIVE_CREATE(userAuth=auth)), template)
        return {"public": _b64(public.marshal()), "private": _b64(private.marshal())}


def _load_key(esys, blobs: dict, auth: bytes):
    _, constants, types, _, _ = _lib()
    parent = _storage_primary(esys)
    private, _ = types.TPM2B_PRIVATE.unmarshal(_unb64(blobs["private"]))
    public, _ = types.TPM2B_PUBLIC.unmarshal(_unb64(blobs["public"]))
    handle = _track(esys, esys.load(parent, private, public))
    _release(esys, parent)
    esys.tr_set_auth(handle, auth)
    return handle


def sign(blobs: dict, auth: bytes, message: bytes, connection: str | None = None) -> bytes:
    """ECDSA-SHA256 over `message`, DER-encoded like every other Thessley signature."""
    _, constants, types, _, _ = _lib()
    with _session(connection) as esys:
        key = _load_key(esys, blobs, auth)
        sig = esys.sign(key, types.TPM2B_DIGEST(hashlib.sha256(message).digest()), _sig_scheme(), _no_ticket())
        return asym_utils.encode_dss_signature(int.from_bytes(bytes(sig.signature.ecdsa.signatureR), "big"), int.from_bytes(bytes(sig.signature.ecdsa.signatureS), "big"))


def check_auth(blobs: dict, auth: bytes, connection: str | None = None) -> None:
    """Raises TpmWrongAuth if `auth` is not the key's password (counts as one attempt)."""
    sign(blobs, auth, b"thessley-passkey-auth-check", connection)


# ---- Phase 2: proof for the site -------------------------------------------------------------------------

EK_CERT_NV = {"ecc": 0x01C0000A}
EK_CHAIN_NV = 0x01C00100          # Intel keeps the manufacturer's intermediate certificates here
EK_PERSISTENT = 0x81010001        # the default EK handle, when the maker provisioned one
MAX_CHAIN = 8
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


def _fetch_issuers(chain: list[bytes], fetch=None) -> list[bytes]:
    """Complete the chain: for the certificate whose issuer is missing, follow its 'CA Issuers' link (https only)."""
    def default_fetch(url: str) -> bytes | None:
        import requests
        if not url.startswith("https://"):
            return None
        try:
            resp = requests.get(url, timeout=AIA_TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            return None
        return resp.content if resp.status_code == 200 and len(resp.content) < 16384 else None

    fetch = fetch or default_fetch
    chain = list(chain)
    while len(chain) < MAX_CHAIN:
        certs = [_cert(c) for c in chain]
        subjects = {c.subject.dump() for c in certs}
        missing = next((c for c in certs if c.issuer.dump() != c.subject.dump() and c.issuer.dump() not in subjects), None)
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
            if issuer.subject.dump() == missing.issuer.dump():
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
        self.esys = None

    def __enter__(self):
        self._cm = _session(self.connection)
        self.esys = self._cm.__enter__()
        try:
            self._setup()
        except BaseException:
            self._cm.__exit__(*__import__("sys").exc_info())  # release whatever was loaded before failing
            raise
        return self

    def _setup(self):
        _, constants, types, _, _ = _lib()
        A = constants.TPMA_OBJECT
        self.parent = _storage_primary(self.esys)
        # Attestation key: restricted signing key, fixed to this chip, no password (it lives for one enrolment).
        attrs = A.FIXEDTPM | A.FIXEDPARENT | A.SENSITIVEDATAORIGIN | A.USERWITHAUTH | A.RESTRICTED | A.SIGN_ENCRYPT | A.NODA
        template = types.TPM2B_PUBLIC.parse("ecc256:ecdsa-sha256:null", objectAttributes=attrs)
        private, public, *_ = self.esys.create(self.parent, types.TPM2B_SENSITIVE_CREATE(), template)
        self.ak = _track(self.esys, self.esys.load(self.parent, private, public))
        _release(self.esys, self.parent)
        self.ak_public_area = public.publicArea

    def __exit__(self, *exc):
        return self._cm.__exit__(*exc)

    # -- endorsement key and its certificates --------------------------------------------------

    def _create_ek(self):
        _, constants, types, tpm_utils, _ = _lib()
        template = tpm_utils.ek_template.lookup("EK-ECC256").template
        handle, *_ = self.esys.create_primary(types.TPM2B_SENSITIVE_CREATE(), template, primary_handle=constants.ESYS_TR.RH_ENDORSEMENT)
        return _track(self.esys, handle)

    def _nv_read(self, index: int) -> bytes | None:
        _, constants, types, _, TSS2 = _lib()
        try:
            nv = self.esys.tr_from_tpmpublic(index)
            public = self.esys.nv_read_public(nv)[0]
            size = public.nvPublic.dataSize
            out, offset = b"", 0
            while offset < size:
                chunk = min(512, size - offset)
                out += bytes(self.esys.nv_read(nv, chunk, offset, auth_handle=constants.ESYS_TR.RH_OWNER))
                offset += chunk
            return out
        except TSS2:
            return None

    @_mapped
    def ek_certs(self) -> list[bytes]:
        """The EK certificate first, then every intermediate we can find, as DER."""
        if self._ek_certs_override is not None:
            return list(self._ek_certs_override)
        leaf = self._nv_read(EK_CERT_NV["ecc"])
        if not leaf:
            raise TpmError("This TPM has no EK certificate, so it cannot be verified by a site.")
        chain = _split_der_certs(leaf)[:1]
        extra = self._nv_read(EK_CHAIN_NV)
        if extra:
            chain += _split_der_certs(extra)
        return _fetch_issuers(chain, self._fetch)

    @_mapped
    def ek_point(self) -> tuple[int, int]:
        """The chip's endorsement key (P-256 point)."""
        ek = self._create_ek()
        try:
            pub = self.esys.read_public(ek)[0].publicArea.unique.ecc
            return int.from_bytes(bytes(pub.x), "big"), int.from_bytes(bytes(pub.y), "big")
        finally:
            _release(self.esys, ek)

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
        return self.ak_public_area.marshal()

    @_mapped
    def activate(self, credential_blob: bytes, secret: bytes) -> bytes:
        """TPM2_ActivateCredential: recovers the site's secret only if this chip holds both the EK and the AK."""
        _, constants, types, _, _ = _lib()
        cred, _ = types.TPM2B_ID_OBJECT.unmarshal(credential_blob)
        enc, _ = types.TPM2B_ENCRYPTED_SECRET.unmarshal(secret)
        session = _track(self.esys, self.esys.start_auth_session(
            constants.ESYS_TR.NONE, constants.ESYS_TR.NONE, constants.TPM2_SE.POLICY,
            types.TPMT_SYM_DEF(algorithm=constants.TPM2_ALG.NULL), constants.TPM2_ALG.SHA256))
        self.esys.policy_secret(constants.ESYS_TR.RH_ENDORSEMENT, session)
        ek = self._create_ek()
        try:
            out = self.esys.activate_credential(self.ak, ek, cred, enc, session1=constants.ESYS_TR.PASSWORD, session2=session)
        finally:
            _release(self.esys, ek)
            _release(self.esys, session)
        return bytes(out)

    @_mapped
    def certify(self, key_blobs: dict, key_auth: bytes, nonce: bytes) -> dict:
        """Have the AK sign a statement about the signing key, bound to `nonce`."""
        _, constants, types, _, _ = _lib()
        key = _load_key(self.esys, key_blobs, key_auth)
        scheme = types.TPMT_SIG_SCHEME(scheme=constants.TPM2_ALG.NULL)
        attest, signature = self.esys.certify(key, self.ak, nonce, scheme, session1=constants.ESYS_TR.PASSWORD, session2=constants.ESYS_TR.PASSWORD)
        key_public = self.esys.read_public(key)[0].publicArea
        return {"attest": bytes(attest.attestationData), "signature": signature.marshal(), "key_public": key_public.marshal()}
