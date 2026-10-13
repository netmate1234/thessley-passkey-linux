"""End-to-end check of the desktop app's core against a Drupal sandbox running the
thessley_passkey module (real HTTP, real server-side signature verification).

    THESSLEY_PASSKEY_DEV=1 BASE=http://127.0.0.1:10190 SSH_HOST=<host> DRUPAL_DIR=~/drupal-sandbox \
        python3 tests/integration_drupal.py

SANDBOX ONLY: creates and deletes users pkd_a/pkd_b and a role, and flips the module's mode.
(THESSLEY_PASSKEY_DEV=1 lets the app accept http://127.0.0.1; a production install never does.)
"""
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
os.environ["THESSLEY_PASSKEY_DEV"] = "1"

import requests

from thessley_passkey import core, link, vault
from thessley_passkey.interaction import Interaction
from thessley_passkey.protocol import ServerError

vault.SCRYPT_N = 2 ** 10

BASE = os.environ.get("BASE", "http://127.0.0.1:10190").rstrip("/")
SSH = os.environ.get("SSH_HOST")
DIR = os.environ.get("DRUPAL_DIR", "~/drupal-sandbox")
if not SSH:
    sys.exit("Set SSH_HOST (the sandbox machine with drush), BASE and DRUPAL_DIR.")

bad = 0


def ok(name, cond, extra=""):
    global bad
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  [{extra}]"))
    bad += 0 if cond else 1


SSH_OPTS = shlex.split(os.environ.get("SSH_OPTS", ""))  # e.g. "-i /home/me/.ssh/id_ed25519" when run under sudo


def drush(args):
    cmd = f"cd {DIR} && vendor/bin/drush {args}"
    return subprocess.run(["ssh", *SSH_OPTS, SSH, cmd], capture_output=True, text=True).stdout.strip()


def setcfg(mode):
    drush(f"config:set thessley_passkey.settings mode {mode} -y")
    drush("config:set thessley_passkey.settings identify false --input-format=yaml -y")
    drush("php:eval " + shlex.quote('\\Drupal::database()->query("DELETE FROM {flood} WHERE event LIKE \'thessley_passkey%\'");'))


class UI(Interaction):
    def __init__(self, *pins):
        self.pins = list(pins)

    def get_pin(self, prompt, confirm=False):
        return self.pins.pop(0)


def form_login(session, name, pw):
    page = session.get(BASE + "/user/login").text
    bid = re.search(r'name="form_build_id" value="([^"]+)"', page).group(1)
    return session.post(BASE + "/user/login", data={"name": name, "pass": pw, "form_build_id": bid, "form_id": "user_login_form", "op": "Log in"}, allow_redirects=False)


def whoami(session):
    r = session.get(BASE + "/user", allow_redirects=False)
    m = re.search(r"/user/(\d+)", r.headers.get("Location", ""))
    return int(m.group(1)) if m else 0


def poll(session, rid):
    return session.get(f"{BASE}/thessley/v1/passkey/login/{rid}/status").json()


print("== setup")
drush('role:create passkey_user "Passkey user"')
drush('role:perm:add passkey_user "use thessley passkey"')
pw = "Pw-" + os.urandom(6).hex()
for u in ("pkd_a", "pkd_b"):
    drush(f"user:create {u} --mail={u}@example.invalid --password={shlex.quote(pw)}")
    drush(f"user:role:add passkey_user {u}")
uid = {u: int(drush("php:eval " + shlex.quote(f'echo array_values(\\Drupal::entityQuery("user")->accessCheck(FALSE)->condition("name","{u}")->execute())[0];'))) for u in ("pkd_a", "pkd_b")}
setcfg("optional")

tmp = tempfile.TemporaryDirectory()
store = vault.Vault(Path(tmp.name) / "devices.json")
svc = core.Service(store)

try:
    print("== enrol through the real server")
    sess = requests.Session()
    form_login(sess, "pkd_a", pw)
    tok = sess.get(BASE + "/session/token").text.strip()
    start = sess.post(BASE + "/thessley/v1/passkey/enroll/start", headers={"X-CSRF-Token": tok}, json={}).json()
    req = link.parse(start["app_link"])
    ok("enrol link parses and carries the site origin", req is not None and req.type == "enroll" and req.origin == BASE, start.get("app_link"))
    dev = svc.enroll(req, "Test PC", "pin", UI("correct-pin"))
    ok("server accepted the proof of possession and returned credential + account", bool(dev.credential_id) and dev.username == "pkd_a", dev)
    st = sess.get(f"{BASE}/thessley/v1/passkey/enroll/{start['request_id']}/status").json()
    ok("site shows the new device", st.get("status") == "approved" and st.get("label") == "Test PC", st)
    ok("device is stored wrapped, not in the clear", "BEGIN" not in store.path.read_text() and "correct-pin" not in store.path.read_text())

    print("== anonymous QR login (optional mode)")
    browser = requests.Session()
    s = browser.post(BASE + "/thessley/v1/passkey/login/start", json={}).json()
    lr = link.parse(s["app_link"])
    cands = svc.candidates(lr)
    ok("the link's site matches an enrolled device", [c.id for c in cands] == [dev.id])
    try:
        svc.respond(lr, cands[0], True, UI("wrong-pin"))
        ok("wrong PIN is refused", False)
    except core.WrongSecret:
        ok("wrong PIN is refused (nothing sent to the site)", poll(browser, s["request_id"]).get("status") == "pending")
    ok("approve with the right PIN", svc.respond(lr, cands[0], True, UI("correct-pin")) == "approved")
    ok("the starting browser is logged in as the approving account", poll(browser, s["request_id"]).get("status") == "approved" and whoami(browser) == uid["pkd_a"])

    if os.environ.get("THESSLEY_TPM_TCTI") or os.environ.get("REAL_TPM"):
        import types as _types
        from thessley_passkey import tpm as tpm_mod
        emulated = bool(os.environ.get("THESSLEY_TPM_TCTI"))
        print("== key held inside a TPM (" + ("software TPM, test manufacturer root" if emulated else "THIS COMPUTER'S REAL TPM, Intel root") + ")")
        tpm_backend = tpm_mod
        if emulated:
            # The sandbox site only trusts Intel's root; give it a throwaway test root for the emulated chip.
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import tpm_interop as T
            from cryptography.hazmat.primitives import serialization
            ca_key, ca = T.make_ca("Test TPM Root")
            root_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
            subprocess.run(["ssh", *SSH_OPTS, SSH, f"cat > {DIR}/web/modules/custom/thessley_passkey/tpm-roots/zz-test-root.pem"], input=root_pem, text=True)

            class TestAttestor(tpm_mod.Attestor):
                def ek_certs(self):
                    x, y = self.ek_point()
                    return [T.ek_cert(ca_key, ca, x, y).public_bytes(serialization.Encoding.DER)]

            tpm_backend = _types.SimpleNamespace(create_key=tpm_mod.create_key, spki_from_public=tpm_mod.spki_from_public, sign=tpm_mod.sign, Attestor=TestAttestor)
        tsvc = core.Service(store, tpm=tpm_backend)
        tpm_sess = requests.Session()
        form_login(tpm_sess, "pkd_b", pw)
        ttok = tpm_sess.get(BASE + "/session/token").text.strip()
        tstart = tpm_sess.post(BASE + "/thessley/v1/passkey/enroll/start", headers={"X-CSRF-Token": ttok}, json={}).json()
        tdev = tsvc.enroll(link.parse(tstart["app_link"]), "TPM PC", "tpm+pin", UI("tpm-pin-1"))
        ok("the site accepted a TPM-signed proof of possession", bool(tdev.credential_id) and tdev.username == "pkd_b" and tdev.uses_tpm and tdev.wrapped == {}, tdev)
        ok("the site VERIFIED the TPM (device marked as TPM hardware)", tdev.attestation == "tpm", tsvc.last_note or tdev.attestation)
        level = drush("php:eval " + shlex.quote('echo \\Drupal::database()->query("SELECT attestation_level FROM {thessley_passkeys} WHERE credential_id=:c", [":c"=>"%s"])->fetchField();' % tdev.credential_id))
        ok("the site stored attestation level 'tpm'", level == "tpm", level)
        listing = tpm_sess.get(BASE + "/thessley/v1/passkey/devices").json()["devices"]
        ok("the device list reports the security level to the browser", any(d["security"] == "tpm" for d in listing), listing)
        tb = requests.Session()
        ts_ = tb.post(BASE + "/thessley/v1/passkey/login/start", json={}).json()
        tr = link.parse(ts_["app_link"])
        if emulated:  # never burn a real chip's lockout counter with a deliberate wrong PIN
            try:
                tsvc.respond(tr, tdev, True, UI("wrong-pin"))
                ok("TPM rejects a wrong PIN", False)
            except core.WrongSecret:
                ok("TPM rejects a wrong PIN (nothing sent to the site)", poll(tb, ts_["request_id"]).get("status") == "pending")
        ok("approve with the TPM-held key", tsvc.respond(tr, tdev, True, UI("tpm-pin-1")) == "approved")
        ok("the site logged the browser in as pkd_b", poll(tb, ts_["request_id"]).get("status") == "approved" and whoami(tb) == uid["pkd_b"])
        if emulated:
            subprocess.run(["ssh", *SSH_OPTS, SSH, f"rm -f {DIR}/web/modules/custom/thessley_passkey/tpm-roots/zz-test-root.pem"])

    print("== deny and replay")
    b2 = requests.Session()
    s2 = b2.post(BASE + "/thessley/v1/passkey/login/start", json={}).json()
    lr2 = link.parse(s2["app_link"])
    ok("deny", svc.respond(lr2, cands[0], False, UI("correct-pin")) == "denied")
    ok("site reports denied, nobody logged in", poll(b2, s2["request_id"]).get("status") == "denied" and whoami(b2) == 0)
    try:
        svc.respond(lr2, cands[0], True, UI("correct-pin"))
        ok("a request cannot be answered twice", False)
    except ServerError as exc:
        ok("a request cannot be answered twice", exc.code in ("thessley_expired", "thessley_already_resolved"), exc.code)

    print("== a QR relayed from another site")
    evil = link.parse(s["app_link"].replace(BASE.replace(":", "%3A").replace("/", "%2F"), "http%3A%2F%2F127.0.0.1%3A9"))
    ok("is for an origin this computer was never enrolled with", evil is not None and svc.candidates(evil) == [])

    print("== password, then app (2fa)")
    setcfg("2fa")
    b3 = requests.Session()
    r = form_login(b3, "pkd_a", pw)
    loc = r.headers.get("Location", "")
    ok("password step lands on the confirm page, not logged in", "/thessley-auth/2fa/" in loc and whoami(b3) == 0, loc)
    page = b3.get(BASE + loc if loc.startswith("/") else loc).text
    settings = json.loads(re.search(r'data-drupal-selector="drupal-settings-json">(.*?)</script>', page, re.S).group(1))
    raw = settings["thessleyPasskey"]["appLink"]
    l3 = link.parse(raw)
    ok("2fa link names the account", l3 is not None and l3.type == "2fa" and l3.username == "pkd_a", raw[:120])
    ok("approve the 2fa request", svc.respond(l3, svc.candidates(l3)[0], True, UI("correct-pin")) == "approved")
    ok("password browser is now logged in", poll(b3, re.search(r"2fa/([A-Za-z0-9_-]+)", loc).group(1)).get("status") == "approved" and whoami(b3) == uid["pkd_a"])
    setcfg("optional")

    print("== revoked device")
    tok = sess.get(BASE + "/session/token").text.strip()
    did = int(drush("php:eval " + shlex.quote('echo \\Drupal::database()->query("SELECT id FROM {thessley_passkeys} WHERE credential_id=:c", [":c"=>"%s"])->fetchField();' % dev.credential_id)))
    sess.post(f"{BASE}/thessley/v1/passkey/devices/{did}/revoke", headers={"X-CSRF-Token": tok})
    b4 = requests.Session()
    s4 = b4.post(BASE + "/thessley/v1/passkey/login/start", json={}).json()
    try:
        svc.respond(link.parse(s4["app_link"]), dev, True, UI("correct-pin"))
        ok("a revoked device is rejected by the site", False)
    except ServerError as exc:
        ok("a revoked device is rejected by the site", exc.code == "thessley_unknown_device", exc.code)

finally:
    print("== cleanup")
    for u in ("pkd_a", "pkd_b"):
        drush(f"user:cancel -y --delete-content {u}")
    drush("role:delete passkey_user")
    setcfg("optional")
    drush("php:eval " + shlex.quote('\\Drupal::database()->query("DELETE FROM {thessley_passkey_requests}");'))
    tmp.cleanup()

print("ALL PASS" if not bad else f"{bad} FAILED")
sys.exit(1 if bad else 0)
