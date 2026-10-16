"""When does enrolling need administrator rights on Windows?"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from thessley_passkey import elevate


class NeededFor(unittest.TestCase):
    def windows(self, admin: bool):
        return mock.patch.multiple(elevate, is_admin=lambda: admin), mock.patch.object(os, "name", "nt")

    def check(self, protection, proof, admin=False):
        a, b = self.windows(admin)
        with a, b:
            return elevate.needed_for(protection, proof)

    def test_a_websites_tpm_proof_needs_administrator_rights(self):
        for p in ("tpm+pin", "tpm+pin+fido2"):
            self.assertTrue(self.check(p, True), p)

    def test_enrolling_as_an_approver_for_a_computer_does_not(self):
        """A key made in the TPM and signed with needs no ActivateCredential, so no administrator prompt (and the relaunch
        only accepts website links, so asking would just fail)."""
        for p in ("tpm+pin", "tpm+pin+fido2"):
            self.assertFalse(self.check(p, False), p)

    def test_protections_without_the_tpm_never_do(self):
        for p in ("pin", "fido2", "pin+fido2"):
            self.assertFalse(self.check(p, True), p)

    def test_an_administrator_window_never_needs_to_ask(self):
        self.assertFalse(self.check("tpm+pin", True, admin=True))

    def test_the_default_is_the_websites_proof(self):
        a, b = self.windows(False)
        with a, b:
            self.assertTrue(elevate.needed_for("tpm+pin"))

    def test_only_windows_ever_asks(self):
        with mock.patch.object(os, "name", "posix"):
            self.assertFalse(elevate.needed_for("tpm+pin", True))

    def test_the_relaunch_only_takes_a_website_link(self):
        """Why the computer link must not go through it."""
        self.assertFalse(elevate.relaunch("thessleypam://enroll?h=192.168.1.5&p=47810"))


if __name__ == "__main__":
    unittest.main()
