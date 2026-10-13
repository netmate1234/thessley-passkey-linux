"""Run this yourself, in a terminal, with a FIDO2 security key plugged in.

    python3 tests/hardware_fido2_check.py

It checks that your key can protect a Thessley Passkey device: it creates a credential
on the key, derives a secret with hmac-secret / PRF, and checks that the same secret
comes back on a second touch. Nothing is sent to any website and nothing is stored.

You will be asked for: the key's PIN (only if the key requires it to create a credential,
which YubiKeys do once a PIN is set), then touch the key two times.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from thessley_passkey import protectors
from thessley_passkey.interaction import CliInteraction

try:
    ui = CliInteraction()
    print("1/2  Creating a credential on the key (PIN, then touch)...")
    params, secret1 = protectors.fido2_create(ui)
    print("     ok, secret length", len(secret1))
    print("2/2  Asking the key for the secret again (touch)...")
    secret2 = protectors.fido2_secret(params, ui)
    if secret1 == secret2:
        print("PASS: the key returns the same secret every time. It can protect a device.")
        sys.exit(0)
    print("FAIL: the secret changed between calls.")
    sys.exit(1)
except protectors.ProtectionError as exc:
    print("FAIL:", exc)
    sys.exit(1)
