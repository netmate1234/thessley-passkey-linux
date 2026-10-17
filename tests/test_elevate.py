"""When does enrolling need administrator rights on Windows, and what may an administrator copy be opened on?"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from thessley_passkey import elevate

WEBSITE = "thessleypasskey://auth?type=enroll&id=" + "A" * 20 + "&nonce=" + "B" * 20 + "&origin=https%3A%2F%2Fsite.example"
COMPUTER = ("thessleypam://enroll?h=192.168.1.5&p=47810&fp=" + "cd" * 32 + "&id=" + "A" * 16 + "&n=" + "B" * 22 +
            "&m=" + "ab" * 16 + "&hn=LAPTOP&u=sshuser")


class NeededFor(unittest.TestCase):
    def check(self, protection, admin=False, name="nt"):
        with mock.patch.object(elevate, "is_admin", lambda: admin), mock.patch.object(os, "name", name):
            return elevate.needed_for(protection)

    def test_a_tpm_enrolment_includes_the_proof_and_needs_administrator_rights(self):
        for p in ("tpm+pin", "tpm+pin+fido2"):
            self.assertTrue(self.check(p), p)

    def test_protections_without_the_tpm_never_do(self):
        for p in ("pin", "fido2", "pin+fido2"):
            self.assertFalse(self.check(p), p)

    def test_an_administrator_window_never_needs_to_ask(self):
        self.assertFalse(self.check("tpm+pin", admin=True))

    def test_only_windows_ever_asks(self):
        self.assertFalse(self.check("tpm+pin", name="posix"))


class Relaunch(unittest.TestCase):
    """An administrator copy only ever receives a link the app rebuilt from validated fields."""

    def run_relaunch(self, link):
        with mock.patch("ctypes.windll", create=True) as windll:
            windll.shell32.ShellExecuteW.return_value = 33
            return elevate.relaunch(link), windll.shell32.ShellExecuteW.call_count

    def test_a_website_link_and_a_computer_enrolment_link_are_accepted(self):
        self.assertEqual(self.run_relaunch(WEBSITE), (True, 1))
        self.assertEqual(self.run_relaunch(COMPUTER), (True, 1))

    def test_nothing_else_is_ever_handed_to_the_administrator_copy(self):
        hostile = [
            COMPUTER + '" & calc & "',                   # a quote
            COMPUTER + "\r\ncalc",                       # a line break
            COMPUTER.replace("enroll", "sudo"),          # an approval is answered in the normal window
            COMPUTER.replace("thessleypam://enroll?", "thessleypam://login?"),
            "thessleypam://enroll",                      # no query
            "file:///C:/Windows/System32/calc.exe",
            "https://example.com/",
            "calc.exe",
            "",
        ]
        for link in hostile:
            self.assertEqual(self.run_relaunch(link), (False, 0), link[:60])

    def test_a_declined_prompt_is_a_refusal_not_an_error(self):
        with mock.patch("ctypes.windll", create=True) as windll:
            windll.shell32.ShellExecuteW.return_value = 5  # ERROR_ACCESS_DENIED: the user said No to the prompt
            self.assertFalse(elevate.relaunch(COMPUTER))


if __name__ == "__main__":
    unittest.main()
