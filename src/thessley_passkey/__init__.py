"""Thessley Passkey for Linux desktops.

Approves Thessley Passkey logins and enrolments (the same protocol the Android
app speaks) from a PC. The signing key is a software EC P-256 key that never
sits on disk unencrypted: it is wrapped with a key derived from a PIN, from a
FIDO2 security key (hmac-secret / PRF), or from both.
"""

__version__ = "0.1.0"
