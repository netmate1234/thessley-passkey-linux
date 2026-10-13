"""A small TPM 2.0 client in pure Python (no TSS library), for Windows and Linux alike.

Only the commands this app needs, with password sessions and one policy session (for the endorsement key).
The same code runs everywhere; only the transport differs:

  device:/dev/tpmrm0            Linux kernel resource manager
  swtpm:host=H,port=P           a software TPM (tests)
  tbs                           Windows TPM Base Services (tbs.dll)

Reference: TCG TPM 2.0 Library specification, parts 1-3.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import socket
import struct

# ---- constants (part 2) ----------------------------------------------------------------------------------------
ST_NO_SESSIONS = 0x8001
ST_SESSIONS = 0x8002
ST_HASHCHECK = 0x8024

RH_OWNER = 0x40000001
RH_NULL = 0x40000007
RS_PW = 0x40000009
RH_ENDORSEMENT = 0x4000000B

ALG_ECC = 0x0023
ALG_SHA256 = 0x000B
ALG_NULL = 0x0010
ALG_ECDSA = 0x0018
ALG_AES = 0x0006
ALG_CFB = 0x0043
CURVE_P256 = 0x0003
SE_POLICY = 0x01

CC_ACTIVATE_CREDENTIAL = 0x147
CC_CERTIFY = 0x148
CC_CREATE = 0x153
CC_CREATE_PRIMARY = 0x131
CC_FLUSH_CONTEXT = 0x165
CC_GET_CAPABILITY = 0x17A
CC_LOAD = 0x157
CC_NV_READ = 0x14E
CC_NV_READ_PUBLIC = 0x169
CC_POLICY_SECRET = 0x151
CC_READ_PUBLIC = 0x173
CC_SIGN = 0x15D
CC_START_AUTH_SESSION = 0x176

A_FIXEDTPM = 0x00000002
A_FIXEDPARENT = 0x00000010
A_SENSITIVEDATAORIGIN = 0x00000020
A_USERWITHAUTH = 0x00000040
A_ADMINWITHPOLICY = 0x00000080
A_NODA = 0x00000400
A_RESTRICTED = 0x00010000
A_DECRYPT = 0x00020000
A_SIGN = 0x00040000

MAX_RESPONSE = 4096

# Response codes (part 2, section 6.6): format-one codes have bit 7 set.
RC_AUTH_FAIL = 0x8E
RC_BAD_AUTH = 0xA2
RC_LOCKOUT = 0x921
RC_OBJECT_MEMORY = 0x902
RC_SESSION_MEMORY = 0x903
RC_MEMORY = 0x904


class TpmRcError(Exception):
    """The TPM answered with an error code."""

    def __init__(self, rc: int, command: int):
        self.rc, self.command = rc, command
        self.code = (rc & 0x3F) | 0x80 if rc & 0x80 else rc & 0xFFF
        super().__init__(f"TPM command 0x{command:X} failed with code 0x{rc:X}")

    @property
    def is_wrong_auth(self) -> bool:
        return self.code in (RC_AUTH_FAIL, RC_BAD_AUTH)

    @property
    def is_lockout(self) -> bool:
        return self.rc & 0xFFF == RC_LOCKOUT

    @property
    def is_out_of_memory(self) -> bool:
        return self.rc & 0xFFF in (RC_OBJECT_MEMORY, RC_SESSION_MEMORY, RC_MEMORY)


class TransportError(Exception):
    pass


# ---- marshalling ----------------------------------------------------------------------------------------------------

def u8(v: int) -> bytes:
    return struct.pack(">B", v)


def u16(v: int) -> bytes:
    return struct.pack(">H", v)


def u32(v: int) -> bytes:
    return struct.pack(">I", v)


def tpm2b(b: bytes) -> bytes:
    return u16(len(b)) + b


class Reader:
    def __init__(self, data: bytes, off: int = 0):
        self.data, self.off = data, off

    def take(self, n: int) -> bytes:
        if n < 0 or self.off + n > len(self.data):
            raise ValueError("truncated TPM response")
        out = self.data[self.off:self.off + n]
        self.off += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def tpm2b(self) -> bytes:
        return self.take(self.u16())


def ecc_public(attributes: int, *, aes_storage: bool = False, ecdsa_sha256: bool = False,
               auth_policy: bytes = b"", unique_len: int = 0) -> bytes:
    """TPMT_PUBLIC for an ECC P-256 key named with SHA-256.

    aes_storage: a storage (parent) key, symmetric AES-128-CFB.  ecdsa_sha256: signing scheme fixed to ECDSA/SHA-256.
    unique_len: bytes of zero for each of x and y (the endorsement key template uses 32, the others none).
    """
    sym = u16(ALG_AES) + u16(128) + u16(ALG_CFB) if aes_storage else u16(ALG_NULL)
    scheme = u16(ALG_ECDSA) + u16(ALG_SHA256) if ecdsa_sha256 else u16(ALG_NULL)
    return (u16(ALG_ECC) + u16(ALG_SHA256) + u32(attributes) + tpm2b(auth_policy)
            + sym + scheme + u16(CURVE_P256) + u16(ALG_NULL)
            + tpm2b(b"\0" * unique_len) + tpm2b(b"\0" * unique_len))


# The templates this app uses. They must stay byte-for-byte what earlier versions used, or keys already created
# under them could no longer be loaded (the storage key is re-derived from its template every time).
SRK_TEMPLATE = ecc_public(A_FIXEDTPM | A_FIXEDPARENT | A_SENSITIVEDATAORIGIN | A_USERWITHAUTH | A_NODA | A_RESTRICTED | A_DECRYPT, aes_storage=True)
KEY_TEMPLATE = ecc_public(A_FIXEDTPM | A_FIXEDPARENT | A_SENSITIVEDATAORIGIN | A_USERWITHAUTH | A_SIGN, ecdsa_sha256=True)
AK_TEMPLATE = ecc_public(A_FIXEDTPM | A_FIXEDPARENT | A_SENSITIVEDATAORIGIN | A_USERWITHAUTH | A_NODA | A_RESTRICTED | A_SIGN, ecdsa_sha256=True)
# TCG EK Credential Profile, ECC P-256 "low range" template (policy: PolicySecret(endorsement)).
EK_POLICY = bytes.fromhex("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa")
EK_TEMPLATE = ecc_public(A_FIXEDTPM | A_FIXEDPARENT | A_SENSITIVEDATAORIGIN | A_ADMINWITHPOLICY | A_RESTRICTED | A_DECRYPT,
                         aes_storage=True, auth_policy=EK_POLICY, unique_len=32)


def name_of(tpmt_public: bytes) -> bytes:
    return u16(ALG_SHA256) + hashlib.sha256(tpmt_public).digest()


def pw_auth(password: bytes = b"") -> bytes:
    """A password session: the object's auth value travels as the 'hmac'."""
    return u32(RS_PW) + tpm2b(b"") + u8(0) + tpm2b(password)


def policy_auth(handle: int, nonce_caller: bytes) -> bytes:
    """A policy session whose policy needs no auth value (PolicySecret on another object), so no HMAC."""
    return u32(handle) + tpm2b(nonce_caller) + u8(0) + tpm2b(b"")


def build_command(cc: int, handles: tuple = (), auths: tuple = (), params: bytes = b"") -> bytes:
    body = b"".join(u32(h) for h in handles)
    if auths:
        area = b"".join(auths)
        body += u32(len(area)) + area
    body += params
    return u16(ST_SESSIONS if auths else ST_NO_SESSIONS) + u32(10 + len(body)) + u32(cc) + body


def parse_response(data: bytes, cc: int, response_handles: int = 0) -> tuple[list[int], bytes]:
    """Check the header and return (response handles, parameter bytes)."""
    if len(data) < 10:
        raise TransportError("TPM answer too short")
    tag, size, rc = struct.unpack(">HII", data[:10])
    if size != len(data):
        raise TransportError(f"TPM answer has the wrong length ({size} announced, {len(data)} received)")
    if rc != 0:
        raise TpmRcError(rc, cc)
    r = Reader(data, 10)
    handles = [r.u32() for _ in range(response_handles)]
    if tag == ST_SESSIONS:
        params = r.take(r.u32())
    else:
        params = data[r.off:]
    return handles, params


# ---- transports -----------------------------------------------------------------------------------------------------

class DeviceTransport:
    """/dev/tpmrm0 (kernel resource manager) or /dev/tpm0."""

    def __init__(self, path: str):
        try:
            self.fd = os.open(path, os.O_RDWR)
        except PermissionError as exc:
            raise TransportError("permission denied") from exc
        except OSError as exc:
            raise TransportError(str(exc)) from exc

    def send(self, command: bytes) -> bytes:
        os.write(self.fd, command)
        return os.read(self.fd, MAX_RESPONSE)

    def close(self) -> None:
        os.close(self.fd)


class SocketTransport:
    """A software TPM (swtpm) data socket: raw commands and responses."""

    def __init__(self, host: str, port: int):
        try:
            self.sock = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            raise TransportError(str(exc)) from exc

    def _recv(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise TransportError("connection closed")
            out += chunk
        return out

    def send(self, command: bytes) -> bytes:
        self.sock.sendall(command)
        header = self._recv(10)
        size = struct.unpack(">I", header[2:6])[0]
        return header + self._recv(size - 10)

    def close(self) -> None:
        self.sock.close()


class TbsTransport:
    """Windows TPM Base Services (tbs.dll): the normal, non-elevated way to talk to the TPM."""

    TBS_CONTEXT_VERSION_TWO = 2
    TBS_COMMAND_LOCALITY_ZERO = 0
    TBS_COMMAND_PRIORITY_NORMAL = 200
    INCLUDE_TPM20 = 0x4  # TBS_CONTEXT_PARAMS2 flags: bit 2 = includeTpm20

    def __init__(self):
        try:
            self.tbs = ctypes.WinDLL("tbs.dll")  # type: ignore[attr-defined]
        except (AttributeError, OSError) as exc:
            raise TransportError("TPM Base Services are not available on this system") from exc

        class ContextParams2(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("flags", ctypes.c_uint32)]

        params = ContextParams2(self.TBS_CONTEXT_VERSION_TWO, self.INCLUDE_TPM20)
        self.context = ctypes.c_void_p()
        rc = self.tbs.Tbsi_Context_Create(ctypes.byref(params), ctypes.byref(self.context))
        if rc != 0:
            raise TransportError(f"Tbsi_Context_Create failed (0x{rc & 0xFFFFFFFF:08X}): is the TPM turned on?")

    def send(self, command: bytes) -> bytes:
        out = ctypes.create_string_buffer(MAX_RESPONSE)
        out_len = ctypes.c_uint32(MAX_RESPONSE)
        rc = self.tbs.Tbsip_Submit_Command(
            self.context, self.TBS_COMMAND_LOCALITY_ZERO, self.TBS_COMMAND_PRIORITY_NORMAL,
            command, ctypes.c_uint32(len(command)), out, ctypes.byref(out_len))
        if rc != 0:
            raise TransportError(f"Tbsip_Submit_Command failed (0x{rc & 0xFFFFFFFF:08X})")
        return out.raw[:out_len.value]

    def close(self) -> None:
        self.tbs.Tbsip_Context_Close(self.context)


def open_transport(spec: str):
    """spec: 'device:/dev/tpmrm0' | 'swtpm:host=127.0.0.1,port=2321' | 'tbs'"""
    kind, _, arg = spec.partition(":")
    if kind == "device":
        return DeviceTransport(arg)
    if kind == "swtpm":
        opts = dict(p.split("=", 1) for p in arg.split(",") if "=" in p)
        return SocketTransport(opts.get("host", "127.0.0.1"), int(opts.get("port", "2321")))
    if kind == "tbs":
        return TbsTransport()
    raise TransportError(f"unknown TPM connection '{spec}'")


# ---- the client ---------------------------------------------------------------------------------------------------

class Tpm:
    def __init__(self, transport):
        self.transport = transport
        self.loaded: list[int] = []  # transient objects and sessions to release

    def close(self) -> None:
        for h in reversed(self.loaded[:]):
            try:
                self.flush(h)
            except Exception:
                pass
        self.transport.close()

    def run(self, cc: int, handles: tuple = (), auths: tuple = (), params: bytes = b"", response_handles: int = 0):
        return parse_response(self.transport.send(build_command(cc, handles, auths, params)), cc, response_handles)

    def flush(self, handle: int) -> None:
        self.run(CC_FLUSH_CONTEXT, params=u32(handle))
        if handle in self.loaded:
            self.loaded.remove(handle)

    # -- keys ---------------------------------------------------------------------------------------------------------

    @staticmethod
    def _create_params(user_auth: bytes, template: bytes) -> bytes:
        sensitive = tpm2b(user_auth) + tpm2b(b"")
        return tpm2b(sensitive) + tpm2b(template) + tpm2b(b"") + u32(0)

    def create_primary(self, hierarchy: int, template: bytes, hierarchy_auth: bytes = b"") -> tuple[int, bytes, bytes]:
        """Returns (handle, TPMT_PUBLIC of the new key, its name)."""
        (handle,), params = self.run(CC_CREATE_PRIMARY, (hierarchy,), (pw_auth(hierarchy_auth),),
                                     self._create_params(b"", template), response_handles=1)
        self.loaded.append(handle)
        r = Reader(params)
        public = r.tpm2b()
        r.tpm2b()  # creationData
        r.tpm2b()  # creationHash
        r.take(2 + 4)
        r.tpm2b()  # ticket digest
        return handle, public, r.tpm2b()

    def create(self, parent: int, user_auth: bytes, template: bytes, parent_auth: bytes = b"") -> tuple[bytes, bytes]:
        """Returns (TPM2B_PRIVATE, TPM2B_PUBLIC), both marshalled with their size prefix."""
        _, params = self.run(CC_CREATE, (parent,), (pw_auth(parent_auth),), self._create_params(user_auth, template))
        r = Reader(params)
        private = tpm2b(r.tpm2b())
        public = tpm2b(r.tpm2b())
        return private, public

    def load(self, parent: int, private_tpm2b: bytes, public_tpm2b: bytes, parent_auth: bytes = b"") -> tuple[int, bytes]:
        (handle,), params = self.run(CC_LOAD, (parent,), (pw_auth(parent_auth),), private_tpm2b + public_tpm2b, response_handles=1)
        self.loaded.append(handle)
        return handle, Reader(params).tpm2b()

    def read_public(self, handle: int) -> tuple[bytes, bytes]:
        _, params = self.run(CC_READ_PUBLIC, (handle,))
        r = Reader(params)
        return r.tpm2b(), r.tpm2b()  # TPMT_PUBLIC, name

    def sign(self, key: int, auth: bytes, digest: bytes) -> tuple[bytes, bytes]:
        """ECDSA over a SHA-256 digest. Returns raw (r, s)."""
        params = tpm2b(digest) + u16(ALG_ECDSA) + u16(ALG_SHA256) + u16(ST_HASHCHECK) + u32(RH_NULL) + tpm2b(b"")
        _, out = self.run(CC_SIGN, (key,), (pw_auth(auth),), params)
        r = Reader(out)
        if r.u16() != ALG_ECDSA:
            raise ValueError("unexpected signature algorithm")
        r.u16()
        return r.tpm2b(), r.tpm2b()

    # -- attestation ------------------------------------------------------------------------------------------------------

    def start_policy_session(self) -> tuple[int, bytes]:
        params = tpm2b(os.urandom(16)) + tpm2b(b"") + u8(SE_POLICY) + u16(ALG_NULL) + u16(ALG_SHA256)
        (handle,), out = self.run(CC_START_AUTH_SESSION, (RH_NULL, RH_NULL), (), params, response_handles=1)
        self.loaded.append(handle)
        return handle, Reader(out).tpm2b()

    def policy_secret(self, session: int, auth_handle: int = RH_ENDORSEMENT, auth: bytes = b"") -> None:
        self.run(CC_POLICY_SECRET, (auth_handle, session), (pw_auth(auth),), tpm2b(b"") + tpm2b(b"") + tpm2b(b"") + struct.pack(">i", 0))

    def activate_credential(self, ak: int, ek: int, session: int, credential_blob: bytes, secret: bytes) -> bytes:
        """credential_blob / secret: marshalled TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET (with size prefix)."""
        _, out = self.run(CC_ACTIVATE_CREDENTIAL, (ak, ek), (pw_auth(b""), policy_auth(session, os.urandom(16))), credential_blob + secret)
        return Reader(out).tpm2b()

    def certify(self, obj: int, obj_auth: bytes, signer: int, qualifying_data: bytes) -> tuple[bytes, bytes]:
        """The signer certifies `obj`. Returns (TPMS_ATTEST bytes, marshalled TPMT_SIGNATURE)."""
        _, out = self.run(CC_CERTIFY, (obj, signer), (pw_auth(obj_auth), pw_auth(b"")), tpm2b(qualifying_data) + u16(ALG_NULL))
        r = Reader(out)
        attest = r.tpm2b()
        return attest, out[r.off:]

    # -- non-volatile storage (manufacturer certificates) ----------------------------------------------------------

    def nv_size(self, index: int) -> int | None:
        try:
            _, out = self.run(CC_NV_READ_PUBLIC, (index,))
        except TpmRcError:
            return None
        pub = Reader(Reader(out).tpm2b())
        pub.u32()
        pub.u16()
        pub.u32()
        pub.tpm2b()
        return pub.u16()

    def nv_read(self, index: int) -> bytes | None:
        size = self.nv_size(index)
        if size is None:
            return None
        out, offset = b"", 0
        while offset < size:
            chunk = min(512, size - offset)
            # The index authorizes its own read with its (empty) auth value: no owner password needed.
            _, params = self.run(CC_NV_READ, (index, index), (pw_auth(b""),), u16(chunk) + u16(offset))
            out += Reader(params).tpm2b()
            offset += chunk
        return out

    def property(self, number: int) -> int | None:
        """A fixed TPM property (TPM_PT_*), e.g. 0x105 manufacturer."""
        try:
            _, out = self.run(CC_GET_CAPABILITY, (), (), u32(6) + u32(number) + u32(1))
        except TpmRcError:
            return None
        r = Reader(out)
        r.u8()
        r.u32()
        if r.u32() < 1:
            return None
        if r.u32() != number:
            return None
        return r.u32()
