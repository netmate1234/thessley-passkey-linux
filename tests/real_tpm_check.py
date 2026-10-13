"""Checks the whole TPM proof against this computer's REAL TPM and the PHP verifier.

    sudo env PYTHONPATH=src python3 tests/real_tpm_check.py     # or as a user in the 'tss' group, without sudo

It only reads the chip's stored certificates and creates short-lived objects that are released at the end.
No persistent TPM state is changed and no wrong password is ever tried (that would count against the
chip's lockout). Nothing is sent to any website.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
TPM_PHP = Path(os.environ.get("TPM_PHP") or ROOT.parent / "wp_opsec" / "infra" / "thessley_passkey" / "src" / "Tpm.php")
ROOTS = Path(os.environ.get("TPM_ROOTS") or ROOT.parent / "wp_opsec" / "infra" / "thessley_passkey" / "tpm-roots" / "intel-ondie-ca-root.pem")

from thessley_passkey import tpm

b64 = lambda b: base64.b64encode(b).decode()


def php(**req):
    out = subprocess.run(["php", str(ROOT / "tests" / "php" / "tpm_cli.php"), str(TPM_PHP)], input=json.dumps(req), capture_output=True, text=True)
    return json.loads(out.stdout)


ok = True
def check(name, cond, extra=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  [{extra}]"))
    ok = ok and bool(cond)


auth = hashlib.sha256(b"real-tpm-check").digest()
key = tpm.create_key(auth)
spki = tpm.spki_from_public(base64.b64decode(key["public"]))
nonce = ("R" * 43).encode()
with tpm.Attestor() as at:
    certs = at.ek_certs()
    check(f"read the EK certificate and its chain ({len(certs)} certificates)", len(certs) >= 2)
    check("the chip's own endorsement key matches its EK certificate", at.ek_matches_certificate(certs[0]))
    chain = php(cmd="verify_chain", certs=[b64(c) for c in certs], roots=str(ROOTS))
    check("PHP verifies the chain up to the Intel On-Die root", chain is not None and "error" not in (chain or {}), chain)
    if chain:
        print("     maker:", chain["manufacturer"], "model:", chain["model"])
        ak = at.ak_public()
        name = base64.b64decode(php(cmd="name", public=b64(ak))["name"])
        secret = os.urandom(32)
        cred = php(cmd="make_credential", x=chain["x"], y=chain["y"], ak_name=b64(name), secret=b64(secret))
        recovered = at.activate(base64.b64decode(cred["credential_blob"]), base64.b64decode(cred["secret"]))
        check("the real chip recovers the secret PHP encrypted for it (credential activation)", recovered == secret)
        parts = at.certify(key, auth, nonce)
        verdict = php(cmd="verify_certification", ak_public=b64(ak), attest=b64(parts["attest"]), signature=b64(parts["signature"]),
                      key_public=b64(parts["key_public"]), nonce=nonce.decode(), spki=b64(spki))
        check("PHP accepts the chip's certification of the signing key", verdict.get("reason") is None, verdict)
        verdict = php(cmd="verify_certification", ak_public=b64(ak), attest=b64(parts["attest"]), signature=b64(parts["signature"]),
                      key_public=b64(parts["key_public"]), nonce=("X" * 43), spki=b64(spki))
        check("...and refuses the same proof for a different enrolment (nonce)", verdict.get("reason") is not None)
sig = tpm.sign(key, auth, b"sign something")
check("the TPM-held key signs", len(sig) > 60)
print("ALL PASS" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)
