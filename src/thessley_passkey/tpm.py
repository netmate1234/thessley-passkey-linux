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


def _track(esys, handle):
    esys._thessley_handles.append(handle)
    return handle


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
