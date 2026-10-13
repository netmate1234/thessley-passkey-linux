"""The client's TPM code against the PHP verifier, with a software TPM (swtpm) standing in for the chip.

    swtpm socket --tpm2 --tpmstate dir=/tmp/x --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
        --flags not-need-init,startup-clear --daemon
    THESSLEY_TPM_TCTI=swtpm:host=127.0.0.1,port=2321 python3 tests/tpm_interop.py

Builds a test manufacturer root and an EK certificate for the emulated TPM, then runs the whole proof:
EK chain -> credential activation -> certification of the signing key, plus forged variants that must fail.
"""
import base64
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
# IMPL=drupal (default) or IMPL=wp selects which server implementation is under test.
IMPL = os.environ.get("IMPL", "drupal")
_WP = ROOT.parent / "wp_opsec"
if IMPL == "wp":
    TPM_PHP = _WP / "thessley-security-hardening" / "includes" / "modules" / "passkey-login" / "class-tpm.php"
    SHIM = ROOT / "tests" / "php" / "tpm_cli_wp.php"
else:
    TPM_PHP = _WP / "infra" / "thessley_passkey" / "src" / "Tpm.php"
    SHIM = ROOT / "tests" / "php" / "tpm_cli.php"
if not TPM_PHP.exists():
    TPM_PHP = Path(os.environ["TPM_PHP"])

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

from thessley_passkey import tpm

CONN = os.environ.get("THESSLEY_TPM_TCTI")
b64 = lambda b: base64.b64encode(b).decode()


def php(**req):
    out = subprocess.run(["php", str(SHIM), str(TPM_PHP)], input=json.dumps(req), capture_output=True, text=True)
    return json.loads(out.stdout)


def make_ca(name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1)).not_valid_after(datetime.datetime(2049, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def ek_cert(ca_key, ca_cert, ek_x, ek_y, maker=b"TEST"):
    pub = ec.EllipticCurvePublicNumbers(ek_x, ek_y, ec.SECP256R1()).public_key()
    san_name = x509.Name([
        x509.NameAttribute(ObjectIdentifier("2.23.133.2.1"), "id:" + maker.hex().upper()),
        x509.NameAttribute(ObjectIdentifier("2.23.133.2.2"), "SWTPM"),
        x509.NameAttribute(ObjectIdentifier("2.23.133.2.3"), "id:00010001"),
    ])
    return (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(ca_cert.subject).public_key(pub).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2021, 1, 1)).not_valid_after(datetime.datetime(2048, 1, 1))
            .add_extension(x509.SubjectAlternativeName([x509.DirectoryName(san_name)]), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier("2.23.133.8.1")]), critical=False)
            .add_extension(x509.KeyUsage(False, False, False, False, True, False, False, False, False), critical=True)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))


@unittest.skipUnless(CONN, "needs THESSLEY_TPM_TCTI pointing at a software TPM")
class Interop(unittest.TestCase):
    NONCE = ("N" * 43).encode()

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.ca_key, cls.ca = make_ca("Test TPM Root")
        cls.roots = str(Path(cls.tmp.name) / "roots.pem")
        Path(cls.roots).write_bytes(cls.ca.public_bytes(serialization.Encoding.PEM))
        cls.auth = hashlib.sha256(b"pin").digest()
        cls.key = tpm.create_key(cls.auth)
        cls.spki = tpm.spki_from_public(base64.b64decode(cls.key["public"]))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_proof(self, mutate=None, nonce=None):
        """The honest flow end to end; `mutate(parts)` lets a test forge something on the way."""
        with tpm.Attestor(CONN) as at:
            ex, ey = at.ek_point()
            cert = ek_cert(self.ca_key, self.ca, ex, ey)
            der = cert.public_bytes(serialization.Encoding.DER)
            chain = php(cmd="verify_chain", certs=[b64(der)], roots=self.roots)
            ak = at.ak_public()
            name = base64.b64decode(php(cmd="name", public=b64(ak))["name"])
            secret = os.urandom(32)
            cred = php(cmd="make_credential", x=chain["x"], y=chain["y"], ak_name=b64(name), secret=b64(secret))
            recovered = at.activate(base64.b64decode(cred["credential_blob"]), base64.b64decode(cred["secret"]))
            cert_parts = at.certify(self.key, self.auth, nonce or self.NONCE)
            parts = {"chain": chain, "secret": secret, "recovered": recovered, "ak_public": ak, **cert_parts, "spki": self.spki}
            if mutate:
                mutate(parts)
            verdict = php(cmd="verify_certification", ak_public=b64(parts["ak_public"]), attest=b64(parts["attest"]), signature=b64(parts["signature"]),
                          key_public=b64(parts["key_public"]), nonce=(nonce or self.NONCE).decode() if parts.get("nonce") is None else parts["nonce"], spki=b64(parts["spki"]))
            return parts, verdict

    def test_honest_flow(self):
        parts, verdict = self.run_proof()
        self.assertIsNotNone(parts["chain"])
        self.assertEqual(parts["chain"]["manufacturer"], "TEST")
        self.assertEqual(parts["recovered"], parts["secret"], "the TPM recovered the site's secret (PHP MakeCredential == real TPM ActivateCredential)")
        self.assertIsNone(verdict["reason"], verdict)

    def test_chain_from_an_unknown_root_is_rejected(self):
        other_key, other_ca = make_ca("Someone else")
        with tpm.Attestor(CONN) as at:
            ex, ey = at.ek_point()
            der = ek_cert(other_key, other_ca, ex, ey).public_bytes(serialization.Encoding.DER)
        self.assertIsNone(php(cmd="verify_chain", certs=[b64(der)], roots=self.roots))

    def test_garbage_chain_is_rejected(self):
        self.assertIsNone(php(cmd="verify_chain", certs=[b64(b"not a certificate")], roots=self.roots))

    def test_wrong_nonce_is_rejected(self):
        _, verdict = self.run_proof(mutate=lambda p: p.update(nonce="X" * 43))
        self.assertIn("not bound to this enrolment", verdict["reason"])

    def test_certified_key_must_be_the_submitted_key(self):
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        _, verdict = self.run_proof(mutate=lambda p: p.update(spki=other))
        self.assertIn("not the submitted key", verdict["reason"])

    def test_tampered_attestation_is_rejected(self):
        def flip(p):
            a = bytearray(p["attest"]); a[-1] ^= 1; p["attest"] = bytes(a)
        _, verdict = self.run_proof(mutate=flip)
        self.assertIn("bad certification signature", verdict["reason"])

    def test_software_key_cannot_pass_as_tpm_key(self):
        """A key whose public area lacks fixedTPM (e.g. made outside the chip) is refused even if an AK signed it."""
        def forge(p):
            a = bytearray(p["key_public"]); a[7] &= ~0x02; p["key_public"] = bytes(a)  # clear fixedTPM
        _, verdict = self.run_proof(mutate=forge)
        self.assertIn("not fixed to the TPM", verdict["reason"])

    def test_unrestricted_attestation_key_is_refused(self):
        """An AK that is not restricted could sign any statement, so its attributes are checked."""
        def forge(p):
            a = bytearray(p["ak_public"]); a[5] &= ~0x01; p["ak_public"] = bytes(a)  # clear restricted (0x00010000 -> byte 5 bit0)
        _, verdict = self.run_proof(mutate=forge)
        self.assertIn("not a restricted", verdict["reason"])

    def test_wrong_pin_cannot_get_a_certification(self):
        with tpm.Attestor(CONN) as at:
            with self.assertRaises(tpm.TpmWrongAuth):
                at.certify(self.key, hashlib.sha256(b"wrong").digest(), self.NONCE)

    @unittest.skipUnless(__import__("shutil").which("tpm2_changeauth"), "needs tpm2-tools to set the owner password")
    def test_owner_password_held_by_the_system_falls_back_to_the_endorsement_hierarchy(self):
        """Windows may keep the owner password to itself; the storage key then lives under the endorsement hierarchy."""
        env = dict(os.environ, TPM2TOOLS_TCTI=CONN)
        subprocess.run(["tpm2_changeauth", "-c", "o", "ownerpw"], env=env, check=True, capture_output=True)
        try:
            auth = hashlib.sha256(b"fallback").digest()
            blobs = tpm.create_key(auth)
            self.assertEqual(blobs.get("hierarchy"), "endorsement")
            spki = tpm.spki_from_public(base64.b64decode(blobs["public"]))
            sig = tpm.sign(blobs, auth, b"x")
            serialization.load_der_public_key(spki).verify(sig, b"x", ec.ECDSA(hashes.SHA256()))
            # and the attestation steps still work on such a system
            with tpm.Attestor(CONN) as at:
                at.certify(blobs, auth, self.NONCE)
        finally:
            subprocess.run(["tpm2_changeauth", "-c", "o", "-p", "ownerpw"], env=env, capture_output=True)


if __name__ == "__main__":
    unittest.main()
