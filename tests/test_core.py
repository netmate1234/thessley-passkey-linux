import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
os.environ.pop("THESSLEY_PASSKEY_DEV", None)

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from thessley_passkey import core, link, protectors, protocol, tpm as tpm_mod, vault
from thessley_passkey.interaction import Interaction
from thessley_passkey.protocol import ServerError

vault.SCRYPT_N = 2 ** 10  # fast for tests

RID = "A" * 43
NONCE = "B" * 43


def mklink(**kw):
    q = dict(type="login", id=RID, nonce=NONCE, origin="https://site.example")
    q.update(kw)
    from urllib.parse import urlencode
    return "thessleypasskey://auth?" + urlencode(q)


class FakeServer:
    """Verifies exactly like the PHP/Drupal servers do and keeps single-use state."""

    def __init__(self):
        self.keys = {}      # credential_id -> public key
        self.used = set()
        self.calls = []
        self.tpm_payloads, self.challenges = [], []
        self.accept_tpm, self.refuse_tpm = True, False

    def factory(self, origin):
        server = self

        class C:
            def enroll_respond(self, request_id, public_key_b64, label, ts, proof_b64, tpm=None):
                server.tpm_payloads.append(tpm)
                key = serialization.load_der_public_key(base64.b64decode(public_key_b64))
                msg = protocol.canonical_string("enroll", request_id, origin, NONCE, ts, "register")
                try:
                    key.verify(base64.b64decode(proof_b64), msg, ec.ECDSA(hashes.SHA256()))
                except InvalidSignature:
                    raise ServerError("Proof of possession failed.", "thessley_bad_signature", 401)
                cred = "cred%d" % (len(server.keys) + 1)
                server.keys[cred] = key
                return {"result": "ok", "credential_id": cred, "username": "alice", "attestation": "tpm" if tpm and server.accept_tpm else ""}

            def tpm_challenge(self, request_id, ek_certs, ak_public):
                if server.refuse_tpm:
                    raise ServerError("The TPM could not be verified: the TPM certificate chain is not one we trust.", "thessley_tpm_unverified", 400)
                server.challenges.append((request_id, len(ek_certs)))
                return {"credential_blob": base64.b64encode(b"blob").decode(), "secret": base64.b64encode(b"secret").decode()}

            def login_respond(self, request_id, credential_id, action, ts, sig_b64):
                if request_id in server.used:
                    raise ServerError("This request is no longer valid.", "thessley_expired", 409)
                key = server.keys.get(credential_id)
                if key is None:
                    raise ServerError("Unknown or revoked device.", "thessley_unknown_device", 401)
                msg = protocol.canonical_string(server.rtype, request_id, origin, NONCE, ts, action)
                try:
                    key.verify(base64.b64decode(sig_b64), msg, ec.ECDSA(hashes.SHA256()))
                except InvalidSignature:
                    raise ServerError("Signature verification failed.", "thessley_bad_signature", 401)
                server.used.add(request_id)
                server.calls.append((request_id, action))

        return C()

    rtype = "login"


class FakeFido2:
    """Stands in for the security key: a fixed secret per credential."""

    def __init__(self):
        self.created = 0
        self.fail_with = None

    def fido2_create(self, interaction):
        self.created += 1
        interaction.notify("touch")
        params = {"rp_id": "x", "credential_id": base64.b64encode(os.urandom(16)).decode(), "salt": base64.b64encode(os.urandom(32)).decode()}
        return params, self.fido2_secret(params, interaction)

    def fido2_secret(self, params, interaction):
        if self.fail_with:
            raise self.fail_with
        import hashlib
        return hashlib.sha256(b"key-secret" + params["credential_id"].encode() + params["salt"].encode()).digest()


class FakeTpm:
    """Behaves like the TPM layer: key never leaves, password checked inside, wrong tries counted."""

    def __init__(self):
        self.keys, self.wrong_tries = {}, 0

    class Attestor:
        """Stands in for the chip's attestation steps."""
        broken = False

        def __enter__(self):
            if FakeTpm.Attestor.broken:
                raise tpm_mod.TpmUnavailable("No TPM here.")
            return self

        def __exit__(self, *a):
            return False

        def ek_certs(self):
            return [b"leaf", b"intermediate"]

        def ak_public(self):
            return b"ak-public"

        def activate(self, blob, secret):
            assert (blob, secret) == (b"blob", b"secret")
            return b"activated"

        def certify(self, blobs, auth, nonce):
            assert nonce == NONCE.encode()
            return {"attest": b"attest", "signature": b"sig", "key_public": b"pub"}

    def create_key(self, auth):
        key = ec.generate_private_key(ec.SECP256R1())
        ident = base64.b64encode(os.urandom(8)).decode()
        self.keys[ident] = (key, auth)
        pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"public": base64.b64encode(pub).decode(), "private": ident}

    def spki_from_public(self, public_blob):
        return public_blob

    def sign(self, blobs, auth, message):
        key, expected = self.keys[blobs["private"]]
        if auth != expected:
            self.wrong_tries += 1
            raise tpm_mod.TpmWrongAuth("Wrong PIN.")
        return key.sign(message, ec.ECDSA(hashes.SHA256()))


class ScriptedUI(Interaction):
    def __init__(self, pins):
        self.pins = list(pins)
        self.notices = []

    def get_pin(self, prompt, confirm=False):
        return self.pins.pop(0)

    def fido_pin(self):
        return "0000"

    def notify(self, message):
        self.notices.append(message)


class LinkTests(unittest.TestCase):
    def test_valid(self):
        r = link.parse(mklink(ip="1.2.3.4", country="Belgium", username="alice"))
        self.assertEqual((r.type, r.origin, r.ip, r.country, r.username), ("login", "https://site.example", "1.2.3.4", "Belgium", "alice"))

    def test_rejects(self):
        for bad in (
            mklink(type="x"), mklink(id="short"), mklink(nonce="has space " * 5), mklink(origin="http://site.example"),
            mklink(origin="https://site.example/path"), mklink(origin="https://u:p@site.example"), mklink(origin="javascript:alert(1)"),
            "https://site.example/", "thessleypasskey://other?type=login", "", "thessleypasskey://auth",
        ):
            self.assertIsNone(link.parse(bad), bad)

    def test_origin_kept_exactly_as_the_server_wrote_it(self):
        self.assertEqual(link.parse(mklink(origin="https://Site.Example")).origin, "https://Site.Example")
        self.assertEqual(link.parse(mklink(origin="https://site.example:8443")).origin, "https://site.example:8443")

    def test_origin_not_in_canonical_form_is_refused(self):
        for odd in ("https://site.example/", "https://site.example:443", "https://site.example/?x=1"):
            self.assertIsNone(link.parse(mklink(origin=odd)), odd)

    def test_display_fields_sanitised(self):
        r = link.parse(mklink(username="ali‮ce\x00\n" + "x" * 300))
        self.assertNotIn("‮", r.username)
        self.assertNotIn("\x00", r.username)
        self.assertLessEqual(len(r.username), 100)

    def test_http_loopback_only_in_dev(self):
        self.assertIsNone(link.parse(mklink(origin="http://127.0.0.1:8080")))
        os.environ["THESSLEY_PASSKEY_DEV"] = "1"
        try:
            self.assertEqual(link.parse(mklink(origin="http://127.0.0.1:8080")).origin, "http://127.0.0.1:8080")
            self.assertIsNone(link.parse(mklink(origin="http://evil.example")))
        finally:
            del os.environ["THESSLEY_PASSKEY_DEV"]


class ProtocolTests(unittest.TestCase):
    def test_canonical_string(self):
        self.assertEqual(
            protocol.canonical_string("login", "id", "https://s", "n", 1700000000, "approve"),
            b"thessley_passkey_v1|login|id|https://s|n|1700000000|approve",
        )


class PrfResultTests(unittest.TestCase):
    """The security-key library hands the secret back as an object (bytes) or, via its mapping view, as base64 text."""

    SECRET = bytes(range(32))

    def test_object_form(self):
        from types import SimpleNamespace as NS
        r = {"prf": NS(enabled=None, results=NS(first=self.SECRET, second=None))}
        self.assertEqual(protectors.prf_secret(r), self.SECRET)

    def test_real_library_objects(self):
        from fido2.ctap2.extensions import AuthenticatorExtensionsPRFOutputs, AuthenticatorExtensionsPRFValues
        out = AuthenticatorExtensionsPRFOutputs(enabled=None, results=AuthenticatorExtensionsPRFValues(self.SECRET, None))
        self.assertEqual(protectors.prf_secret({"prf": out}), self.SECRET)

    def test_json_text_form(self):
        text = base64.urlsafe_b64encode(self.SECRET).decode().rstrip("=")
        self.assertEqual(protectors.prf_secret({"prf": {"results": {"first": text}}}), self.SECRET)

    def test_missing(self):
        self.assertIsNone(protectors.prf_secret({}))
        self.assertIsNone(protectors.prf_secret({"prf": {"results": None}}))


class VaultTests(unittest.TestCase):
    def test_wrap_roundtrip_and_wrong_key(self):
        kek = vault.derive_kek(b"p" * 32, None)
        w = vault.wrap(b"secret", kek, b"aad")
        self.assertEqual(vault.unwrap(w, kek, b"aad"), b"secret")
        from cryptography.exceptions import InvalidTag
        with self.assertRaises(InvalidTag):
            vault.unwrap(w, vault.derive_kek(b"q" * 32, None), b"aad")
        with self.assertRaises(InvalidTag):
            vault.unwrap(w, kek, b"other-aad")

    def test_secrets_are_not_interchangeable(self):
        a = vault.derive_kek(b"x" * 32, None)
        b = vault.derive_kek(None, b"x" * 32)
        self.assertNotEqual(a, b)
        self.assertNotEqual(vault.derive_kek(b"x" * 32, b"y" * 32), vault.derive_kek(b"y" * 32, b"x" * 32))

    def test_file_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            v = vault.Vault(Path(d) / "sub" / "devices.json")
            v.add(vault.Device(id="1", origin="https://s", credential_id="c", username="u", label="l", enrolled_at=1, public_key="p", protection="pin", wrapped={}))
            self.assertEqual(oct(v.path.stat().st_mode & 0o777), "0o600")
            self.assertEqual(oct(v.path.parent.stat().st_mode & 0o777), "0o700")


class FakeWinreg:
    """Just enough of the Windows registry to see what winsetup writes."""
    HKEY_CURRENT_USER = "HKCU"
    REG_SZ = 1

    def __init__(self):
        self.keys = {}

    def CreateKey(self, root, path):
        outer = self
        self.keys.setdefault((root, path), {})

        class K:
            def __enter__(self_):
                return (root, path)

            def __exit__(self_, *a):
                return False
        return K()

    def SetValueEx(self, key, name, _r, _t, value):
        self.keys[key][name] = value

    def OpenKey(self, root, path):
        if (root, path) not in self.keys:
            raise FileNotFoundError(path)

        class K:
            def __enter__(self_):
                return (root, path)

            def __exit__(self_, *a):
                return False
        return K()

    def QueryValueEx(self, key, name):
        return (self.keys[key][name], 1)

    def DeleteKey(self, root, path):
        if (root, path) not in self.keys:
            raise FileNotFoundError(path)
        del self.keys[(root, path)]


class WindowsGlueTests(unittest.TestCase):
    def test_link_handler_is_registered_for_the_current_user_only(self):
        from thessley_passkey import winsetup
        reg = FakeWinreg()
        command = winsetup.register(reg)
        self.assertIn(("HKCU", r"Software\Classes\thessleypasskey"), reg.keys)
        self.assertEqual(reg.keys[("HKCU", r"Software\Classes\thessleypasskey")]["URL Protocol"], "")
        self.assertEqual(reg.keys[("HKCU", r"Software\Classes\thessleypasskey\shell\open\command")][""], command)
        self.assertTrue(command.endswith('"%1"'))
        self.assertEqual(winsetup.registered_command(reg), command)

    def test_unregister_removes_everything_and_is_repeatable(self):
        from thessley_passkey import winsetup
        reg = FakeWinreg()
        winsetup.register(reg)
        winsetup.unregister(reg)
        self.assertIsNone(winsetup.registered_command(reg))
        winsetup.unregister(reg)  # nothing left: must not raise

    def test_windows_data_folder_is_under_localappdata(self):
        os.environ["LOCALAPPDATA"] = r"C:\Users\me\AppData\Local"
        self.assertTrue(str(vault.data_dir(nt=True)).endswith("ThessleyPasskey"))
        self.assertIn("AppData", str(vault.data_dir(nt=True)))

    def test_diagnostics_never_crash_and_hold_no_secrets(self):
        from thessley_passkey import diagnose
        text = diagnose.report()
        self.assertIn("Thessley Passkey diagnostics", text)
        self.assertNotIn("BEGIN", text)


class SortTests(unittest.TestCase):
    def test_sites_are_listed_alphabetically_ignoring_case(self):
        def dev(i, origin, user="u", label="l"):
            return vault.Device(id=i, origin=origin, credential_id=i, username=user, label=label, enrolled_at=1, public_key="p", protection="pin", wrapped={})
        shuffled = [dev("1", "https://zeta.example"), dev("2", "https://Alpha.example", "bob"), dev("3", "https://alpha.example", "Alice"), dev("4", "https://mid.example")]
        self.assertEqual([d.id for d in vault.sort_devices(shuffled)], ["3", "2", "4", "1"])


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.vault = vault.Vault(Path(self.tmp.name) / "devices.json")
        self.server = FakeServer()
        self.fido = FakeFido2()
        self.svc = core.Service(self.vault, fido2=self.fido, client_factory=self.server.factory)

    def tearDown(self):
        self.tmp.cleanup()

    def enroll(self, protection="pin", pins=("123456", "123456")):
        # the fake server signs with NONCE, so the enrolment request must carry it
        return self.svc.enroll(link.parse(mklink(type="enroll")), "My PC", protection, ScriptedUI(pins))

    def login_req(self, rid=RID, rtype="login", **kw):
        self.server.rtype = rtype
        return link.parse(mklink(type=rtype, id=rid, **kw))

    def test_pin_enrol_then_approve(self):
        dev = self.enroll("pin", ["123456"])
        self.assertEqual((dev.username, dev.protection), ("alice", "pin"))
        self.assertEqual(self.svc.respond(self.login_req(), dev, True, ScriptedUI(["123456"])), "approved")
        self.assertEqual(self.server.calls[-1][1], "approve")

    def test_private_key_never_stored_in_clear(self):
        dev = self.enroll("pin", ["123456"])
        text = self.vault.path.read_text()
        self.assertNotIn("BEGIN", text)
        self.assertNotIn("123456", text)
        self.assertIn(dev.wrapped["ct"], text)

    def test_deny_is_signed_too(self):
        dev = self.enroll("pin", ["123456"])
        self.assertEqual(self.svc.respond(self.login_req("D" * 43), dev, False, ScriptedUI(["123456"])), "denied")
        self.assertEqual(self.server.calls[-1][1], "deny")

    def test_2fa_type_is_signed(self):
        dev = self.enroll("pin", ["123456"])
        self.assertEqual(self.svc.respond(self.login_req("E" * 43, "2fa", username="alice"), dev, True, ScriptedUI(["123456"])), "approved")

    def test_wrong_pin_then_lockout(self):
        dev = self.enroll("pin", ["123456"])
        for _ in range(vault.MAX_FAILURES):
            with self.assertRaises(core.WrongSecret):
                self.svc.respond(self.login_req(), dev, True, ScriptedUI(["000000"]))
        with self.assertRaises(vault.Locked):
            self.svc.respond(self.login_req(), dev, True, ScriptedUI(["123456"]))  # even the right PIN is refused while locked
        self.assertFalse(self.server.calls)

    def test_right_pin_resets_failures(self):
        dev = self.enroll("pin", ["123456"])
        with self.assertRaises(core.WrongSecret):
            self.svc.respond(self.login_req(), dev, True, ScriptedUI(["000000"]))
        self.svc.respond(self.login_req(), dev, True, ScriptedUI(["123456"]))
        self.assertEqual(self.vault.all()[0].failures, 0)

    def test_weak_pin_refused_and_nothing_stored(self):
        with self.assertRaises(ValueError):
            self.enroll("pin", ["123"])
        with self.assertRaises(ValueError):
            self.enroll("pin", ["111111"])
        self.assertEqual(self.vault.all(), [])

    def test_fido2_only(self):
        dev = self.enroll("fido2", [])
        self.assertEqual(self.fido.created, 1)
        ui = ScriptedUI([])
        self.assertEqual(self.svc.respond(self.login_req(), dev, True, ui), "approved")

    def test_fido2_missing_key(self):
        dev = self.enroll("fido2", [])
        self.fido.fail_with = protectors.NoSecurityKey("No security key found.")
        with self.assertRaises(protectors.NoSecurityKey):
            self.svc.respond(self.login_req("F" * 43), dev, True, ScriptedUI([]))
        self.assertFalse(self.server.calls)

    def test_wrong_security_key_cannot_unlock(self):
        dev = self.enroll("fido2", [])
        class Other(FakeFido2):
            def fido2_secret(self, params, interaction):
                return b"\x01" * 32
        svc = core.Service(self.vault, fido2=Other(), client_factory=self.server.factory)
        with self.assertRaises(core.WrongSecret):
            svc.respond(self.login_req(), dev, True, ScriptedUI([]))

    def test_pin_plus_fido2_needs_both(self):
        dev = self.enroll("pin+fido2", ["123456"])
        self.assertEqual(self.svc.respond(self.login_req(), dev, True, ScriptedUI(["123456"])), "approved")
        with self.assertRaises(core.WrongSecret):
            self.svc.respond(self.login_req("G" * 43), dev, True, ScriptedUI(["654321"]))
        class Other(FakeFido2):
            def fido2_secret(self, params, interaction):
                return b"\x02" * 32
        with self.assertRaises(core.WrongSecret):
            core.Service(self.vault, fido2=Other(), client_factory=self.server.factory).respond(self.login_req("H" * 43), dev, True, ScriptedUI(["123456"]))

    def test_unknown_site_refused_before_any_unlock(self):
        dev = self.enroll("pin", ["123456"])
        req = link.parse(mklink(origin="https://evil.example"))
        self.assertEqual(self.svc.candidates(req), [])
        with self.assertRaises(core.UnknownSite):
            self.svc.respond(req, dev, True, ScriptedUI([]))   # would raise IndexError if it tried to ask for a PIN

    def test_candidates_pick_named_account(self):
        a = self.enroll("pin", ["123456"])
        self.assertEqual([d.id for d in self.svc.candidates(self.login_req(username="ALICE"))], [a.id])
        self.assertEqual([d.id for d in self.svc.candidates(self.login_req(username="someone-else"))], [a.id])  # falls back to all for the site

    def test_enrol_failure_stores_nothing(self):
        class Refusing:
            def enroll_respond(self, *a):
                raise ServerError("This request is no longer valid.", "thessley_expired", 409)
        svc = core.Service(self.vault, fido2=self.fido, client_factory=lambda origin: Refusing())
        with self.assertRaises(ServerError):
            svc.enroll(link.parse(mklink(type="enroll")), "x", "pin", ScriptedUI(["123456", "123456"]))
        self.assertEqual(self.vault.all(), [])

    def test_replayed_request_rejected_by_server(self):
        dev = self.enroll("pin", ["123456"])
        self.svc.respond(self.login_req(), dev, True, ScriptedUI(["123456"]))
        with self.assertRaises(ServerError) as ctx:
            self.svc.respond(self.login_req(), dev, True, ScriptedUI(["123456"]))
        self.assertEqual(ctx.exception.code, "thessley_expired")

class TpmProtectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.vault = vault.Vault(Path(self.tmp.name) / "devices.json")
        self.server = FakeServer()
        self.fake_tpm = FakeTpm()
        self.svc = core.Service(self.vault, fido2=FakeFido2(), client_factory=self.server.factory, tpm=self.fake_tpm)

    def tearDown(self):
        self.tmp.cleanup()

    def enroll(self, protection="tpm+pin", pins=("123456", "123456")):
        return self.svc.enroll(link.parse(mklink(type="enroll")), "PC", protection, ScriptedUI(pins))

    def req(self, rid=RID):
        self.server.rtype = "login"
        return link.parse(mklink(id=rid))

    def test_enrol_and_approve_with_the_key_in_the_tpm(self):
        dev = self.enroll()
        self.assertTrue(dev.uses_tpm)
        self.assertEqual(dev.wrapped, {})           # nothing to unwrap on disk: the key is in the chip
        self.assertEqual(self.svc.respond(self.req(), dev, True, ScriptedUI(["123456"])), "approved")

    def test_the_stored_public_key_is_the_one_the_site_verifies(self):
        dev = self.enroll()
        site_key = self.server.keys[dev.credential_id].public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(base64.b64decode(dev.public_key), site_key)

    def test_wrong_pin_never_reaches_the_tpm_once_locked(self):
        dev = self.enroll()
        for _ in range(vault.MAX_FAILURES):
            with self.assertRaises(core.WrongSecret):
                self.svc.respond(self.req(), dev, True, ScriptedUI(["000000"]))
        self.assertEqual(self.fake_tpm.wrong_tries, vault.MAX_FAILURES)
        with self.assertRaises(vault.Locked):
            self.svc.respond(self.req(), dev, True, ScriptedUI(["000000"]))
        self.assertEqual(self.fake_tpm.wrong_tries, vault.MAX_FAILURES)   # the chip's own counter was not burned further

    def test_tpm_plus_security_key_needs_both(self):
        dev = self.enroll("tpm+pin+fido2")
        self.assertEqual(self.svc.respond(self.req(), dev, True, ScriptedUI(["123456"])), "approved")
        class Other(FakeFido2):
            def fido2_secret(self, params, interaction):
                return b"\x09" * 32
        with self.assertRaises(core.WrongSecret):
            core.Service(self.vault, fido2=Other(), client_factory=self.server.factory, tpm=self.fake_tpm).respond(self.req("K" * 43), dev, True, ScriptedUI(["123456"]))

    def test_chip_lockout_is_reported_not_mistaken_for_a_wrong_pin(self):
        dev = self.enroll()
        class Locked(FakeTpm):
            def sign(self, *a):
                raise tpm_mod.TpmLockedOut("locked")
        svc = core.Service(self.vault, fido2=FakeFido2(), client_factory=self.server.factory, tpm=Locked())
        with self.assertRaises(vault.Locked):
            svc.respond(self.req(), dev, True, ScriptedUI(["123456"]))


    def test_attested_enrolment_sends_the_proof_and_records_it(self):
        dev = self.enroll()
        payload = self.server.tpm_payloads[-1]
        self.assertEqual(dev.attestation, "tpm")
        self.assertEqual(set(payload), {"ak_public", "activated_secret", "certify_info", "certify_signature", "key_public"})
        self.assertEqual(base64.b64decode(payload["activated_secret"]), b"activated")
        self.assertEqual(self.server.challenges[-1], (RID, 2))

    def test_no_usable_tpm_still_enrols_without_proof(self):
        FakeTpm.Attestor.broken = True
        try:
            dev = self.enroll()
        finally:
            FakeTpm.Attestor.broken = False
        self.assertEqual(dev.attestation, "")
        self.assertIsNone(self.server.tpm_payloads[-1])
        self.assertIn("without hardware proof", self.svc.last_note)

    def test_site_that_refuses_the_chain_still_enrols_without_proof(self):
        self.server.refuse_tpm = True
        dev = self.enroll()
        self.assertEqual(dev.attestation, "")
        self.assertIn("not one we trust", self.svc.last_note)
        self.assertEqual(self.svc.respond(self.req(), dev, True, ScriptedUI(["123456"])), "approved")

    def test_site_that_does_not_verify_leaves_the_device_unverified(self):
        self.server.accept_tpm = False
        dev = self.enroll()
        self.assertEqual(dev.attestation, "")
        self.assertIn("could not verify the TPM", self.svc.last_note)

    def test_software_devices_send_no_tpm_payload(self):
        svc = core.Service(self.vault, fido2=FakeFido2(), client_factory=self.server.factory, tpm=self.fake_tpm)
        svc.enroll(link.parse(mklink(type="enroll")), "PC", "pin", ScriptedUI(["123456"]))
        self.assertIsNone(self.server.tpm_payloads[-1])

    def test_tpm_without_a_pin_is_not_offered(self):
        self.assertNotIn("tpm", protectors.PROTECTIONS)
        with self.assertRaises(ValueError):
            self.enroll("tpm")


if __name__ == "__main__":
    unittest.main()
