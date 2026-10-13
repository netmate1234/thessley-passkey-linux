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

from thessley_passkey import core, link, protectors, protocol, vault
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

    def factory(self, origin):
        server = self

        class C:
            def enroll_respond(self, request_id, public_key_b64, label, ts, proof_b64):
                key = serialization.load_der_public_key(base64.b64decode(public_key_b64))
                msg = protocol.canonical_string("enroll", request_id, origin, NONCE, ts, "register")
                try:
                    key.verify(base64.b64decode(proof_b64), msg, ec.ECDSA(hashes.SHA256()))
                except InvalidSignature:
                    raise ServerError("Proof of possession failed.", "thessley_bad_signature", 401)
                cred = "cred%d" % (len(server.keys) + 1)
                server.keys[cred] = key
                return {"result": "ok", "credential_id": cred, "username": "alice"}

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


if __name__ == "__main__":
    unittest.main()
