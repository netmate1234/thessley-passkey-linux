"""A TPM-protected key enrolled for a COMPUTER, with the real TPM proof, both ends in this process.

    python3 tests/integration_tpm.py                 # this computer's real TPM (user in the 'tss' group)
    THESSLEY_TPM_TCTI=swtpm:host=127.0.0.1,port=2321 python3 tests/integration_tpm.py
        # a software TPM stands in; it has no manufacturer certificate chain, so the chain test is skipped there

The app (thessley_passkey) creates a key inside the TPM and runs the proof with the computer's side (thessley_pam, from
../thessley-pam-linux): the chip's certificate chain, credential activation, certification of the key. Only temporary TPM
objects are made and released; no persistent TPM state changes and no wrong password is ever tried.
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
if not (REPO / "thessley_pam" / "tpmproof.py").exists():
    sys.exit(f"thessley-pam-linux with the TPM proof not found at {REPO}")
sys.path.insert(0, str(REPO))
os.environ.setdefault("THESSLEY_PASSKEY_DEV", "1")

from thessley_pam import cli, machine, store, tpmproof  # the computer's side
from thessley_passkey import core, link, pamlink, tpm, vault  # this app

vault.SCRYPT_N = 2 ** 10
USER = os.environ.get("USER") or "ubuntu"
PIN = "246810"
SOFTWARE_TPM = bool(os.environ.get("THESSLEY_TPM_TCTI"))


class Ui(core.Interaction):
    def __init__(self, *pins):
        self.pins, self.notes = list(pins), []

    def get_pin(self, prompt, confirm=False):
        return self.pins.pop(0)

    def fido_pin(self):
        return "0000"

    def notify(self, message):
        self.notes.append(message)


class TpmEnrolment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        store.BASE = os.path.join(self.tmp.name, "etc")
        store.USERS = os.path.join(store.BASE, "users")
        store.ENROLLED = os.path.join(self.tmp.name, "enrolled")
        machine.lan_ip = lambda: "127.0.0.1"
        cli.machine.lan_ip = lambda: "127.0.0.1"
        self.said = []
        self.links = []
        cli._open_tty = lambda: types.SimpleNamespace(close=lambda: None)
        cli._show_qr = self.links.append
        cli._ask_yes = lambda prompt, timeout: True
        self.vault = vault.Vault(Path(self.tmp.name) / "devices.json")
        self.svc = core.Service(self.vault)
        self.saved_roots = tpmproof.root_files

    def tearDown(self):
        tpmproof.root_files = self.saved_roots

    def enrol(self, protection="tpm+pin"):
        args = types.SimpleNamespace(user=USER, port=47870)
        box = {}
        old = os.geteuid
        os.geteuid = lambda: 0  # cmd_enroll insists on root; the store is a temp directory here
        printed = []
        cli.print = lambda *a, **k: printed.append(" ".join(str(x) for x in a))
        try:
            t = threading.Thread(target=lambda: box.setdefault("rc", cli.cmd_enroll(args)), daemon=True)
            t.start()
            for _ in range(60):
                if self.links:
                    break
                time.sleep(0.1)
            req = link.parse_any(self.links[0])
            self.assertIsInstance(req, pamlink.PamRequest)
            ui = Ui(PIN, PIN)
            device = self.svc.enroll(req, "TPM test", protection, ui)
            t.join(60)
        finally:
            os.geteuid = old
            del cli.print
        return device, box.get("rc"), printed

    @unittest.skipIf(SOFTWARE_TPM, "a software TPM has no manufacturer certificate chain")
    def test_a_real_tpm_key_is_verified_by_the_computer(self):
        device, rc, printed = self.enrol()
        self.assertEqual(rc, 0)
        self.assertEqual(device.protection, "tpm+pin")
        theirs = store.devices(USER)
        self.assertEqual(len(theirs), 1)
        att = theirs[0].get("attestation")
        self.assertIsNotNone(att, "the computer recorded no attestation")
        self.assertEqual(att["level"], "tpm", att)
        self.assertTrue(att["maker"], att)
        self.assertEqual(device.attestation, "tpm")   # the app was told it was verified
        self.assertTrue(any("TPM:" in line and "verified, a genuine TPM 2.0 chip" in line for line in printed), printed)
        print(f"\n   verified by the computer: {att['maker']} {att['model']}")

    @unittest.skipIf(SOFTWARE_TPM, "a software TPM has no manufacturer certificate chain")
    def test_a_chain_the_computer_does_not_trust_leaves_the_key_unverified_but_enrolled(self):
        tpmproof.root_files = lambda: []     # this computer trusts no manufacturer
        device, rc, printed = self.enrol()
        self.assertEqual(rc, 0)              # enrolment is not blocked
        theirs = store.devices(USER)
        self.assertEqual(len(theirs), 1)
        self.assertNotIn("attestation", theirs[0])   # no proof was accepted, so none is recorded
        self.assertNotEqual(device.attestation, "tpm")
        self.assertIn("not one we trust", device.attestation_note)  # the app keeps the computer's own reason

    def test_a_pin_only_key_sends_no_tpm_proof(self):
        device, rc, printed = self.enrol(protection="pin")
        self.assertEqual(rc, 0)
        self.assertNotIn("attestation", store.devices(USER)[0])
        self.assertEqual(device.attestation, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
