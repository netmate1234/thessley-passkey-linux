"""Linux computers (thessley-pam) in the desktop app: the link, the signed string, the pinned HTTPS client and the two
core flows with a stand-in for the computer. Run from the repo root:  python3 -I tests/test_pamlink.py

If the thessley-pam-linux repo is next to this one (or THESSLEY_PAM_REPO points at it), the signed string and the
pairing code are also compared with its own implementation, byte for byte.
"""

import base64
import datetime
import json
import os
import ssl
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from thessley_passkey import core, link, pamlink, vault
from thessley_passkey.interaction import Interaction

vault.SCRYPT_N = 2 ** 10
_DEV_BEFORE = None


def setUpModule():
    """The pinned-client tests talk to 127.0.0.1, which the app accepts only in dev mode. Switch it on for this module's
    tests only: set at import time it leaked into test_core's check that plain-http links are refused."""
    global _DEV_BEFORE
    _DEV_BEFORE = os.environ.get("THESSLEY_PASSKEY_DEV")
    os.environ["THESSLEY_PASSKEY_DEV"] = "1"


def tearDownModule():
    if _DEV_BEFORE is None:
        os.environ.pop("THESSLEY_PASSKEY_DEV", None)
    else:
        os.environ["THESSLEY_PASSKEY_DEV"] = _DEV_BEFORE


MID = "ab" * 16
FP = "cd" * 32


def mklink(kind="sudo", **kw):
    q = {"h": "192.168.1.200", "p": "47810", "fp": FP, "id": "RequestId12345678", "n": "NonceNonce12345678", "m": MID,
         "hn": "orangepi5", "u": "ubuntu"}
    if kind != "enroll":
        q["tty"] = "ssh"
    q.update(kw)
    q = {k: v for k, v in q.items() if v is not None}
    from urllib.parse import urlencode
    return f"thessleypam://{kind}?" + urlencode(q)


class KindTest(unittest.TestCase):
    """The link says "sudo" for ssh too; the screens must say what is really being approved."""

    def test_ssh_with_service_and_client(self):
        r = pamlink.parse(mklink("sudo", s="sshd", r="192.168.1.111"))
        self.assertEqual((r.kind, r.heading, r.ip, r.terminal), ("ssh", "Approve ssh login", "192.168.1.111", ""))
        self.assertIn("ssh", r.what)
        self.assertIn("s=sshd", r.raw)
        self.assertIn("r=192.168.1.111", r.raw)

    def test_old_computer_without_service_is_told_by_the_terminal(self):
        self.assertEqual(pamlink.parse(mklink("sudo")).kind, "ssh")  # tty=ssh
        r = pamlink.parse(mklink("sudo", tty="/dev/pts/3"))
        self.assertEqual((r.kind, r.heading, r.terminal), ("sudo", "Approve sudo", "/dev/pts/3"))

    def test_adding_a_device(self):
        r = pamlink.parse(mklink("sudo", tty="-", s="thessley-enroll"))
        self.assertEqual((r.kind, r.heading, r.terminal), ("device", "Approve adding a device", ""))

    def test_screen_login(self):
        r = pamlink.parse(mklink("login", tty="-", s="gdm-thessley"))
        self.assertEqual((r.kind, r.heading, r.ip, r.terminal), ("screen", "Approve screen login", "", ""))

    def test_enroll_and_bad_display_fields(self):
        self.assertEqual(pamlink.parse(mklink("enroll")).kind, "enroll")
        r = pamlink.parse(mklink("sudo", s="ssh d;rm", r="not an address"))
        self.assertEqual((r.service, r.client), ("", ""))  # dropped, the rest of the link still counts

    def test_display_fields_do_not_change_the_signed_string(self):
        a = pamlink.canonical("sudo", "RequestId12345678", MID, "ubuntu", "NonceNonce12345678", 1700000000, "approve")
        self.assertEqual(a, b"thessley_pam_v1|sudo|RequestId12345678|" + MID.encode() + b"|ubuntu|NonceNonce12345678|1700000000|approve")


class ParseTest(unittest.TestCase):
    def test_valid_links(self):
        for kind in ("enroll", "sudo", "login"):
            r = pamlink.parse(mklink(kind))
            self.assertEqual((r.type, r.host, r.port, r.machine_id, r.hostname, r.username), (kind, "192.168.1.200", 47810, MID, "orangepi5", "ubuntu"))
        self.assertEqual(pamlink.parse(mklink("sudo")).tty, "ssh")
        self.assertEqual(pamlink.parse(mklink("enroll")).tty, "")

    def test_only_private_addresses(self):
        for host in ("8.8.8.8", "example.com", "::1", "0.0.0.0", "224.0.0.1", "192.168.1.200/x", ""):
            self.assertIsNone(pamlink.parse(mklink(h=host)), host)
        for host in ("192.168.1.5", "10.1.2.3", "172.16.0.9", "127.0.0.1"):
            self.assertIsNotNone(pamlink.parse(mklink(h=host)), host)

    def test_rejects_bad_fields(self):
        bad = [mklink(fp="zz" * 32), mklink(fp="ab" * 31), mklink(m="short"), mklink(id="x"), mklink(n="has space here"),
               mklink(u="Root"), mklink(u="a b"), mklink(hn="bad host!"), mklink(p="0"), mklink(p="70000"), mklink(p="x"),
               mklink(tty="a b"), "thessleypam://other?h=192.168.1.1", "thessleypasskey://auth?x=1", "", "thessleypam://sudo",
               mklink() + "x" * 3000]
        for raw in bad:
            self.assertIsNone(pamlink.parse(raw), raw[:80])

    def test_rebuilt_link_carries_only_validated_fields(self):
        hostile = mklink() + '&extra=" -c "import os" "&x=%0d%0a'
        r = pamlink.parse(hostile)
        self.assertIsNotNone(r)
        self.assertNotIn('"', r.raw)
        self.assertNotIn("extra", r.raw)
        self.assertEqual(pamlink.parse(r.raw), r)

    def test_parse_any_picks_the_right_kind(self):
        self.assertIsInstance(link.parse_any(mklink()), pamlink.PamRequest)
        site = link.parse_any("thessleypasskey://auth?type=login&id=" + "A" * 20 + "&nonce=" + "B" * 20 + "&origin=https%3A%2F%2Fsite.example")
        self.assertIsInstance(site, link.AuthRequest)
        self.assertIsNone(link.parse_any("https://example.com"))

    def test_screens_see_the_same_names_for_both(self):
        r = pamlink.parse(mklink("sudo", tty="/dev/pts/3", s="sudo"))
        self.assertEqual((r.kind_label, r.display, r.heading), ("Computer", "orangepi5 (192.168.1.200)", "Approve sudo"))
        self.assertEqual(r.origin, "computer:" + MID)
        s = link.parse_any("thessleypasskey://auth?type=2fa&id=" + "A" * 20 + "&nonce=" + "B" * 20 + "&origin=https%3A%2F%2Fsite.example")
        self.assertEqual((s.kind_label, s.display, s.heading), ("Site", "https://site.example", "Confirm your login"))


class ProtocolTest(unittest.TestCase):
    def test_signed_string(self):
        msg = pamlink.canonical("sudo", "rid", MID, "ubuntu", "nonce", 1700000000, "approve")
        self.assertEqual(msg, f"thessley_pam_v1|sudo|rid|{MID}|ubuntu|nonce|1700000000|approve".encode())
        for bad in (("x", "approve"), ("sudo", "nope")):
            with self.assertRaises(ValueError):
                pamlink.canonical(bad[0], "rid", MID, "ubuntu", "nonce", 1, bad[1])
        with self.assertRaises(ValueError):
            pamlink.canonical("sudo", "r|id", MID, "ubuntu", "nonce", 1, "approve")

    def test_pairing_code(self):
        self.assertRegex(pamlink.pairing_code(base64.b64encode(b"k" * 91).decode()), r"^\d{3} \d{3}$")

    def test_identical_to_the_computer_side(self):
        repo = Path(os.environ.get("THESSLEY_PAM_REPO") or Path(__file__).resolve().parent.parent.parent / "thessley-pam-linux")
        if not (repo / "thessley_pam" / "protocol.py").exists():
            self.skipTest("thessley-pam-linux repo not found")
        sys.path.insert(0, str(repo))
        from thessley_pam import protocol as pp
        for t in ("enroll", "sudo", "login"):
            for a in ("register", "approve", "deny"):
                self.assertEqual(pamlink.canonical(t, "rid", MID, "ubuntu", "nonce", 1700000000, a),
                                 pp.canonical(t, "rid", MID, "ubuntu", "nonce", 1700000000, a))
        for blob in (b"a", b"k" * 91, os.urandom(91), os.urandom(33)):
            spki = base64.b64encode(blob).decode()
            self.assertEqual(pamlink.pairing_code(spki), pp.pairing_code(spki))


def make_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "thessley-pam-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    return key, cert


class PinnedClientTest(unittest.TestCase):
    """A tiny HTTPS server with its own self-signed certificate, like the computer's listener."""

    def setUp(self):
        key, cert = make_cert()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        crt, pk = os.path.join(self.tmp.name, "c.pem"), os.path.join(self.tmp.name, "k.pem")
        open(crt, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
        open(pk, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.fp = __import__("hashlib").sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        self.seen = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.seen.append((self.path, json.loads(body)))
                out = json.dumps({"result": "ok"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, pk)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def req(self, fp):
        return pamlink.parse(mklink(h="127.0.0.1", p=str(self.port), fp=fp))

    def test_sends_when_the_certificate_is_the_one_in_the_link(self):
        status, answer = pamlink.PinnedClient(self.req(self.fp)).post("/x", {"a": 1})
        self.assertEqual((status, answer["result"]), (200, "ok"))
        self.assertEqual(self.seen, [("/x", {"a": 1})])

    def test_sends_nothing_to_a_different_certificate(self):
        with self.assertRaises(pamlink.PamError):
            pamlink.PinnedClient(self.req("00" * 32)).post("/x", {"secret": "never sent"})
        self.assertEqual(self.seen, [])

    def test_unreachable_computer_is_an_error_not_a_crash(self):
        r = pamlink.parse(mklink(h="127.0.0.1", p="1", fp=self.fp))
        with self.assertRaises(pamlink.PamError):
            pamlink.PinnedClient(r).post("/x", {}, timeout=2)


class FakeComputer:
    """Stands in for pamlink.PinnedClient: records the request, answers like thessley-pam."""

    def __init__(self):
        self.calls = []
        self.answer = (200, {"result": "ok", "credential_id": "c_0123456789abcdef", "username": "ubuntu", "hostname": "orangepi5"})

    def __call__(self, req):
        outer = self

        class C:
            def post(self, path, body, timeout=20):
                outer.calls.append((path, body))
                return outer.answer
        return C()


class Pin(Interaction):
    def __init__(self, *pins):
        self.pins, self.notes = list(pins), []

    def get_pin(self, prompt, confirm=False):
        return self.pins.pop(0)

    def fido_pin(self):
        return "0000"

    def notify(self, message):
        self.notes.append(message)


class CoreFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.vault = vault.Vault(Path(self.tmp.name) / "devices.json")
        self.svc = core.Service(self.vault)
        self.computer = FakeComputer()
        self._orig = core.PinnedClient
        core.PinnedClient = self.computer
        self.addCleanup(setattr, core, "PinnedClient", self._orig)

    def enrol(self, pins=("246810", "246810")):
        ui = Pin(*pins)
        d = self.svc.enroll(pamlink.parse(mklink("enroll")), "My PC", "pin", ui)
        return d, ui

    def test_enrol_stores_a_computer_and_shows_the_pairing_code_first(self):
        d, ui = self.enrol()
        self.assertEqual((d.kind, d.machine_id, d.hostname, d.username, d.credential_id), ("computer", MID, "orangepi5", "ubuntu", "c_0123456789abcdef"))
        self.assertEqual(d.origin, "computer:" + MID)
        path, body = self.computer.calls[0]
        self.assertEqual(path, "/thessley-pam/v1/enroll/RequestId12345678/respond")
        code = pamlink.pairing_code(body["public_key"])
        self.assertTrue(any(code in n for n in ui.notes), ui.notes)  # the person can compare it while the computer waits
        # the proof really is a signature over the right string by the key that was sent
        msg = pamlink.canonical("enroll", "RequestId12345678", MID, "ubuntu", "NonceNonce12345678", body["timestamp"], "register")
        pub = serialization.load_der_public_key(base64.b64decode(body["public_key"]))
        pub.verify(base64.b64decode(body["proof_signature"]), msg, ec.ECDSA(hashes.SHA256()))
        self.assertEqual(self.vault.all()[0].id, d.id)
        self.assertEqual(body["attestation_chain"], [])

    def test_refused_enrolment_stores_nothing(self):
        self.computer.answer = (200, {"result": "denied", "message": "Not confirmed on the computer."})
        with self.assertRaises(pamlink.PamError):
            self.enrol()
        self.assertEqual(self.vault.all(), [])

    def test_approve_and_deny_sign_the_right_thing(self):
        d, _ = self.enrol()
        self.computer.calls.clear()
        for kind in ("sudo", "login"):
            for approve in (True, False):
                req = pamlink.parse(mklink(kind))
                self.assertEqual(self.svc.candidates(req)[0].id, d.id)
                out = self.svc.respond(req, d, approve, Pin("246810"))
                self.assertEqual(out, "approved" if approve else "denied")
                path, body = self.computer.calls[-1]
                self.assertEqual(path, f"/thessley-pam/v1/{kind}/RequestId12345678/respond")
                action = "approve" if approve else "deny"
                self.assertEqual(body["action"], action)
                self.assertEqual(body["credential_id"], "c_0123456789abcdef")
                msg = pamlink.canonical(kind, "RequestId12345678", MID, "ubuntu", "NonceNonce12345678", body["timestamp"], action)
                serialization.load_der_public_key(base64.b64decode(d.public_key)).verify(
                    base64.b64decode(body["signature"]), msg, ec.ECDSA(hashes.SHA256()))

    def test_wrong_pin_sends_nothing(self):
        d, _ = self.enrol()
        self.computer.calls.clear()
        with self.assertRaises(core.WrongSecret):
            self.svc.respond(pamlink.parse(mklink("sudo")), d, True, Pin("000000"))
        self.assertEqual(self.computer.calls, [])

    def test_only_the_right_computer_and_account(self):
        d, _ = self.enrol()
        for kw in ({"m": "ef" * 16}, {"u": "other"}):
            req = pamlink.parse(mklink("sudo", **kw))
            self.assertEqual(self.svc.candidates(req), [])
            with self.assertRaises(core.UnknownSite):
                self.svc.respond(req, d, True, Pin("246810"))

    def test_a_site_request_still_goes_the_old_way(self):
        site = link.parse("thessleypasskey://auth?type=login&id=" + "A" * 20 + "&nonce=" + "B" * 20 + "&origin=https%3A%2F%2Fsite.example")
        self.assertEqual(self.svc.candidates(site), [])  # no site enrolled, and a computer never answers for a site

    def test_list_and_summary_name_the_computer(self):
        d, _ = self.enrol()
        from thessley_passkey.uicommon import device_summary
        self.assertEqual(d.title, "orangepi5")
        self.assertIn("ubuntu · My PC", device_summary(d))

    def test_old_vault_files_still_load(self):
        d, _ = self.enrol()
        raw = json.loads(self.vault.path.read_text())
        for entry in raw["devices"]:
            for k in ("kind", "machine_id", "hostname"):
                entry.pop(k, None)
        self.vault.path.write_text(json.dumps(raw))
        self.assertEqual(self.vault.all()[0].kind, "site")


if __name__ == "__main__":
    unittest.main()
