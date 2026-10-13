"""Enrols this computer's REAL TPM against a WordPress site and approves a login, as a one-off check.

    python3 tests/real_enrol_wp.py 'thessleypasskey://auth?type=enroll&...'

(needs the TPM device to be readable by your user). DEV SITES ONLY: it adds a device to whichever account
the link was made for.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import requests

from thessley_passkey import core, link, vault
from thessley_passkey.interaction import Interaction


class UI(Interaction):
    def get_pin(self, prompt, confirm=False):
        return "wp-real-pin-1"


req = link.parse(sys.argv[1])
assert req and req.type == "enroll", "need an enrol link"
import tempfile
tmp = tempfile.mkdtemp()
svc = core.Service(vault.Vault(Path(tmp) / "devices.json"))
dev = svc.enroll(req, "Real TPM test", "tpm+pin", UI())
print("ENROLLED", dev.credential_id, "username:", dev.username, "attestation:", repr(dev.attestation), "note:", svc.last_note or "-")
# a login through the same site, answered by the TPM-held key
base = req.origin
b = requests.Session()
start = b.post(base + "/", params={"rest_route": "/thessley/v1/passkey/login/start"}, json={}, timeout=20).json()
lreq = link.parse(start["app_link"])
print("LOGIN", svc.respond(lreq, dev, True, UI()), start["request_id"])
