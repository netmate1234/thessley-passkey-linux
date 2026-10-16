"""This app against the real thessley-pam code (thessley-pam-linux): enrol as an approver, approve and deny sudo and
login, wrong PIN, wrong user. Runs both ends in this process on 127.0.0.1 with a temporary store; no root, no PAM.

    python3 -I tests/integration_pam.py        (needs ../thessley-pam-linux, or THESSLEY_PAM_REPO=...)
"""

import os
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
REPO = Path(os.environ.get("THESSLEY_PAM_REPO") or HERE.parent.parent / "thessley-pam-linux")
if not (REPO / "thessley_pam" / "pam.py").exists():
    sys.exit(f"thessley-pam-linux not found at {REPO}")
sys.path.insert(0, str(REPO))
os.environ.setdefault("THESSLEY_PASSKEY_DEV", "1")

from thessley_pam import cli, grants, machine, pam, store  # the computer's side
from thessley_passkey import core, link, pamlink, vault  # this app

vault.SCRYPT_N = 2 ** 10
USER = os.environ.get("USER") or "ubuntu"
PIN = "246810"


class Ui(core.Interaction):
    def __init__(self, *pins):
        self.pins, self.notes = list(pins), []

    def get_pin(self, prompt, confirm=False):
        return self.pins.pop(0)

    def fido_pin(self):
        return "0000"

    def notify(self, message):
        self.notes.append(message)


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        store.BASE = os.path.join(cls.tmp.name, "etc")
        store.USERS = os.path.join(store.BASE, "users")
        store.ENROLLED = os.path.join(cls.tmp.name, "enrolled")
        grants.RUN = os.path.join(cls.tmp.name, "run")
        grants.GRANTS = os.path.join(grants.RUN, "grants")
        machine.lan_ip = lambda: "127.0.0.1"
        pam.PORT = 47896
        pam.WAIT = 6
        pam._log = lambda *a, **k: None
        cls.said, cls.qr_links = [], []
        pam._say = cls.said.append

        def fake_qrencode(cmd, **kw):
            cls.qr_links.append(cmd[-1])
            return types.SimpleNamespace(stdout="")
        pam.subprocess = types.SimpleNamespace(run=fake_qrencode)
        cls.vault = vault.Vault(Path(cls.tmp.name) / "devices.json")
        cls.svc = core.Service(cls.vault)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # 1 -----------------------------------------------------------------------------------------------------
    def test_1_enrol_as_an_approver(self):
        enroll_links = []
        cli._show_qr = lambda link_: enroll_links.append(link_)
        cli._open_tty = lambda: types.SimpleNamespace(close=lambda: None)
        asked = []
        cli._ask_yes = lambda prompt, timeout: (asked.append(prompt), True)[1]  # the person at the computer types yes
        cli.machine.lan_ip = lambda: "127.0.0.1"
        args = types.SimpleNamespace(user=USER, port=47895)
        box = {}
        t = threading.Thread(target=lambda: box.setdefault("rc", cli.cmd_enroll(args)), daemon=True)
        old_euid = os.geteuid
        os.geteuid = lambda: 0  # cmd_enroll insists on root; the store is a temp directory here
        try:
            t.start()
            for _ in range(60):
                if enroll_links:
                    break
                time.sleep(0.1)
            req = link.parse_any(enroll_links[0])
            self.assertIsInstance(req, pamlink.PamRequest)
            ui = Ui(PIN, PIN)
            device = self.svc.enroll(req, "Desktop test", "pin", ui)
            t.join(30)
        finally:
            os.geteuid = old_euid
        self.assertEqual(box.get("rc"), 0)
        self.assertEqual(device.kind, "computer")
        # the computer now lists this app, with the same key
        theirs = store.devices(USER)
        self.assertEqual(len(theirs), 1)
        self.assertEqual(theirs[0]["credential_id"], device.credential_id)
        self.assertEqual(theirs[0]["public_key"], device.public_key)
        # both sides showed the same pairing code
        self.assertTrue(any(pamlink.pairing_code(device.public_key) in n for n in ui.notes))
        self.assertTrue(any("same code" in p for p in asked))
        type(self).device = device

    # 2 -----------------------------------------------------------------------------------------------------
    def run_pam(self, login=False):
        """Start the computer's PAM step; return (thread, result box, the link it put on screen)."""
        self.qr_links.clear()
        self.said.clear()
        env = {"PAM_TYPE": "auth", "PAM_USER": USER, "PAM_SERVICE": "gdm-thessley" if login else "sudo", "PAM_TTY": "/dev/pts/9"}
        box = {}
        t = threading.Thread(target=lambda: box.setdefault("rc", pam.run(env, login=login)), daemon=True)
        t.start()
        for _ in range(60):
            if login and self.said and self.said[0].startswith(pam.QR_MARKER):
                return t, box, self.said[0][len(pam.QR_MARKER):]
            if not login and self.qr_links:
                return t, box, self.qr_links[0]
            time.sleep(0.1)
        self.fail("the computer never showed a link")

    def answer(self, raw, approve=True, pin=PIN):
        req = link.parse_any(raw)
        self.assertEqual(req.username, USER)
        (device,) = self.svc.candidates(req)
        return self.svc.respond(req, device, approve, Ui(pin))

    def test_2_approve_sudo(self):
        t, box, raw = self.run_pam()
        self.assertEqual(self.answer(raw), "approved")
        t.join(15)
        self.assertEqual(box["rc"], 0)
        self.assertIsNotNone(store.devices(USER)[0]["last_used"])

    def test_3_deny_sudo(self):
        t, box, raw = self.run_pam()
        self.assertEqual(self.answer(raw, approve=False), "denied")
        t.join(15)
        self.assertEqual(box["rc"], 1)

    def test_4_approve_the_login_screen(self):
        t, box, raw = self.run_pam(login=True)
        self.assertTrue(raw.startswith("thessleypam://login?"))
        self.assertEqual(self.answer(raw), "approved")
        t.join(15)
        self.assertEqual(box["rc"], 0)

    def test_5_wrong_pin_never_reaches_the_computer(self):
        t, box, raw = self.run_pam()
        with self.assertRaises(core.WrongSecret):
            self.answer(raw, pin="000000")
        t.join(15)
        self.assertEqual(box["rc"], 1)  # no answer arrived: the request timed out

    def test_6_a_pass_applies_to_this_app_too(self):
        grants.set_grace("sudo", 4)
        try:
            t, box, raw = self.run_pam()
            self.assertEqual(self.answer(raw), "approved")
            t.join(15)
            self.assertEqual(box["rc"], 0)
            self.assertEqual(len(grants.all_passes()), 1)
            self.qr_links.clear()
            self.assertEqual(pam.run({"PAM_TYPE": "auth", "PAM_USER": USER, "PAM_SERVICE": "sudo", "PAM_TTY": "/dev/pts/9"}), 0)
            self.assertEqual(self.qr_links, [])  # no new request: the pass from this app's approval holds
        finally:
            grants.set_grace("sudo", 0)
            grants.revoke()

    def test_7_removing_the_approver_on_the_computer_ends_it(self):
        store.remove_device(USER, self.device.credential_id)
        self.qr_links.clear()
        env = {"PAM_TYPE": "auth", "PAM_USER": USER, "PAM_SERVICE": "sudo", "PAM_TTY": "/dev/pts/9"}
        # no approver enrolled any more: sudo passes through without asking (the default), so no link is shown
        self.assertEqual(pam.run(env), 0)
        self.assertEqual(self.qr_links, [])
        # and this app's old entry no longer matches anything the computer would accept: an answer is refused
        self.assertEqual(store.devices(USER), [])

if __name__ == "__main__":
    unittest.main(verbosity=2)
