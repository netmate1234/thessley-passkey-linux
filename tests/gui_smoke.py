"""Drives the real GTK window (headless, under Xvfb) against a Drupal sandbox.

    THESSLEY_PASSKEY_DEV=1 SSH_HOST=<host> DRUPAL_DIR=~/drupal-sandbox BASE=http://127.0.0.1:10190 \
        xvfb-run -a python3 tests/gui_smoke.py

SANDBOX ONLY (creates and deletes user pkd_gui and a role). Exercises: PIN dialog, a wrong PIN then the
right one, Approve, Deny, enrolment, and a login request for a site this computer is not enrolled with.
"""
import json, os, re, shlex, subprocess, sys, tempfile, threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
os.environ["THESSLEY_PASSKEY_DEV"] = "1"
os.environ.setdefault("GSK_RENDERER", "cairo")
os.environ.setdefault("GDK_BACKEND", "x11")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import requests
from thessley_passkey import core, link, vault
from thessley_passkey.interaction import Interaction

vault.SCRYPT_N = 2 ** 10
BASE = os.environ.get("BASE", "http://127.0.0.1:10190").rstrip("/")
SSH, DIR = os.environ.get("SSH_HOST"), os.environ.get("DRUPAL_DIR", "~/drupal-sandbox")
PIN = "246810"


def run_gui(link_text, script_json, store_dir):
    """Child process: open the window on `link_text`, perform the scripted steps, print JSON results."""
    import gi
    gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk
    from thessley_passkey import ui

    os.environ["XDG_DATA_HOME"] = store_dir
    app = ui.Application(core.Service(vault.Vault(Path(store_dir) / "thessley-passkey" / "devices.json")))
    steps, log, state = json.loads(script_json), [], {"i": 0, "ticks": 0}

    def walk(w):
        c = w.get_first_child()
        while c:
            yield c
            yield from walk(c)
            c = c.get_next_sibling()

    def find(root, cls, text=None):
        for w in walk(root):
            if isinstance(w, cls) and (text is None or (hasattr(w, "get_label") and w.get_label() == text)):
                return w

    def visible_texts(win):
        return [w.get_text() for w in walk(win) if isinstance(w, Gtk.Label) and w.get_visible() and w.get_text()]

    def tick():
        state["ticks"] += 1
        win = app.get_active_window()
        if win is None or state["ticks"] > 400:
            log.append({"error": "timeout", "step": state["i"], "texts": (visible_texts(win)[:6] if win else [])})
            app.quit()
            return False
        step = steps[state["i"]] if state["i"] < len(steps) else None
        if step is None:
            app.quit()
            return False
        kind = step[0]
        if kind == "click":
            btn = find(win, Gtk.Button, step[1])
            if btn is not None and btn.get_sensitive():
                btn.emit("clicked"); state["i"] += 1
        elif kind == "entry":      # set the text of an Adw.EntryRow
            row = find(win, Adw.EntryRow)
            if row is not None:
                row.set_text(step[1]); state["i"] += 1
        elif kind == "pin":        # answer the PIN dialog
            dlg = win.get_visible_dialog()
            if dlg is not None:
                entries = [w for w in walk(dlg.get_extra_child()) if isinstance(w, Gtk.PasswordEntry)] or [dlg.get_extra_child()]
                for e in entries:
                    e.set_text(step[1])
                dlg.emit("response", "ok"); dlg.force_close(); state["i"] += 1
        elif kind == "expect_text":  # wait for a visible label containing text
            if any(step[1] in t for t in visible_texts(win)):
                log.append({"seen": step[1]}); state["i"] += 1
        elif kind == "expect_page":
            if win.stack.get_visible_child_name() == step[1]:
                log.append({"page": step[1], "texts": visible_texts(win)}); state["i"] += 1
        return True

    GLib.timeout_add(150, tick)
    app.run(["thessley-passkey", link_text] if link_text else ["thessley-passkey"])
    print("GUIRESULT " + json.dumps({"log": log, "done": state["i"] >= len(steps)}))


def run_gui_qt(link_text, script_json, store_dir):
    """Same scripted run as run_gui(), against the Qt window (THESSLEY_UI=qt)."""
    from PySide6 import QtCore, QtWidgets
    from thessley_passkey import ui_qt

    os.environ["XDG_DATA_HOME"] = store_dir
    app = QtWidgets.QApplication(["thessley-passkey"])
    request = link.parse(link_text) if link_text else None
    service = core.Service(vault.Vault(Path(store_dir) / "thessley-passkey" / "devices.json"))
    window = ui_qt.Window(service, request, bool(link_text), "That link is not a valid Thessley Passkey link." if link_text and request is None else "")
    window.show()
    steps, log, state = json.loads(script_json), [], {"i": 0, "ticks": 0}

    def visible_texts():
        return [w.text() for w in window.findChildren(QtWidgets.QLabel) if w.isVisibleTo(window) and w.text()]

    def tick():
        state["ticks"] += 1
        if state["ticks"] > 400:
            log.append({"error": "timeout", "step": state["i"], "texts": visible_texts()[:6]})
            app.quit()
            return
        if state["i"] >= len(steps):
            app.quit()
            return
        step = steps[state["i"]]
        kind = step[0]
        if kind == "click":
            for b in window.findChildren(QtWidgets.QPushButton):
                if b.text() == step[1] and b.isEnabled() and b.isVisibleTo(window):
                    b.click(); state["i"] += 1
                    break
        elif kind == "entry":
            edit = window.findChild(QtWidgets.QLineEdit, "name")
            if edit is not None:
                edit.setText(step[1]); state["i"] += 1
        elif kind == "pin":
            dlg = app.activeModalWidget()
            if isinstance(dlg, ui_qt.PinDialog):
                dlg.first.setText(step[1])
                if dlg.second is not None:
                    dlg.second.setText(step[1])
                dlg.accept(); state["i"] += 1
        elif kind == "expect_text":
            if any(step[1] in t for t in visible_texts()):
                log.append({"seen": step[1]}); state["i"] += 1
        elif kind == "expect_page":
            if window.page_name() == step[1]:
                log.append({"page": step[1], "texts": visible_texts()}); state["i"] += 1

    timer = QtCore.QTimer()
    timer.timeout.connect(tick)
    timer.start(150)
    app.exec()
    print("GUIRESULT " + json.dumps({"log": log, "done": state["i"] >= len(steps)}))


if len(sys.argv) > 1 and sys.argv[1] == "child":
    (run_gui_qt if os.environ.get("THESSLEY_UI") == "qt" else run_gui)(sys.argv[2], sys.argv[3], sys.argv[4])
    sys.exit(0)

if not SSH:
    sys.exit("Set SSH_HOST (sandbox machine with drush), BASE, DRUPAL_DIR; run under xvfb-run.")

bad = 0
def ok(name, cond, extra=""):
    global bad
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  [{extra}]"))
    bad += 0 if cond else 1

def drush(a):
    return subprocess.run(["ssh", SSH, f"cd {DIR} && vendor/bin/drush {a}"], capture_output=True, text=True).stdout.strip()

def gui(link_text, steps, store):
    out = subprocess.run([sys.executable, __file__, "child", link_text, json.dumps(steps), store], capture_output=True, text=True, timeout=120)
    m = re.search(r"GUIRESULT (.*)", out.stdout)
    if not m:
        print(out.stdout[-800:], out.stderr[-1500:])
        return {"log": [], "done": False}
    return json.loads(m.group(1))

class PinUI(Interaction):
    def get_pin(self, prompt, confirm=False): return PIN

drush('role:create passkey_user "Passkey user"'); drush('role:perm:add passkey_user "use thessley passkey"')
pw = "Pw-" + os.urandom(5).hex()
drush(f"user:create pkd_gui --mail=pkd_gui@example.invalid --password={shlex.quote(pw)}"); drush("user:role:add passkey_user pkd_gui")
tmp = tempfile.mkdtemp()
store = Path(tmp) / "thessley-passkey" / "devices.json"
svc = core.Service(vault.Vault(store))
s = requests.Session()
page = s.get(BASE + "/user/login").text
s.post(BASE + "/user/login", data={"name": "pkd_gui", "pass": pw, "form_build_id": re.search(r'name="form_build_id" value="([^"]+)"', page).group(1), "form_id": "user_login_form", "op": "Log in"}, allow_redirects=False)
tok = s.get(BASE + "/session/token").text.strip()
def start_enroll():
    return s.post(BASE + "/thessley/v1/passkey/enroll/start", headers={"X-CSRF-Token": tok}, json={}).json()
def start_login():
    b = requests.Session()
    return b, b.post(BASE + "/thessley/v1/passkey/login/start", json={}).json()

try:
    print("== enrol through the window")
    e = start_enroll()
    r = gui(e["app_link"], [["entry", "GUI test PC"], ["click", "Add this computer"], ["pin", PIN], ["expect_page", "result"]], str(tmp))
    ok("enrol window reaches the success page", r["done"] and any("enrolled" in " ".join(x.get("texts", [])) for x in r["log"]), r)
    st = s.get(f"{BASE}/thessley/v1/passkey/enroll/{e['request_id']}/status").json()
    ok("site shows the device with the label typed in the window", st.get("status") == "approved" and st.get("label") == "GUI test PC", st)
    from thessley_passkey import tpm as _tpm
    want = "tpm+pin" if _tpm.status()[0] else "pin"   # the window offers the TPM first whenever this user can use one
    ok(f"one device is stored, protected as {want}", len(svc.vault.all()) == 1 and svc.vault.all()[0].protection == want, [d.protection for d in svc.vault.all()])

    print("== approve: wrong PIN, then the right one")
    b, st = start_login()
    r = gui(st["app_link"], [["click", "Approve"], ["pin", "000000"], ["expect_text", "Wrong PIN"], ["click", "Approve"], ["pin", PIN], ["expect_page", "result"]], str(tmp))
    ok("window showed the wrong-PIN message and let me retry", r["done"] and any(x.get("seen") == "Wrong PIN" for x in r["log"]), r)
    ok("result page says approved", any("Approved" in " ".join(x.get("texts", [])) for x in r["log"]), r)
    ok("the site logged the browser in", b.get(f"{BASE}/thessley/v1/passkey/login/{st['request_id']}/status").json().get("status") == "approved")

    print("== deny")
    b, st = start_login()
    r = gui(st["app_link"], [["click", "Deny"], ["pin", PIN], ["expect_page", "result"]], str(tmp))
    ok("deny reaches the result page", r["done"] and any("Denied" in " ".join(x.get("texts", [])) for x in r["log"]), r)
    ok("site reports denied", b.get(f"{BASE}/thessley/v1/passkey/login/{st['request_id']}/status").json().get("status") == "denied")

    print("== a request for a site this computer is not enrolled with")
    b, st = start_login()
    foreign = st["app_link"].replace("127.0.0.1%3A10190", "127.0.0.1%3A9")
    r = gui(foreign, [["expect_text", "not enrolled"]], str(tmp))
    ok("window refuses with a warning and offers no Approve", r["done"], r)

    print("== the app refuses a malformed link")
    r = gui("thessleypasskey://auth?type=login&id=x", [["expect_page", "home"]], str(tmp))
    ok("falls back to the home page", r["done"], r)
finally:
    drush("user:cancel -y --delete-content pkd_gui"); drush("role:delete passkey_user")
    drush('php:eval ' + shlex.quote('\\Drupal::database()->query("DELETE FROM {thessley_passkey_requests}");'))
print("ALL PASS" if not bad else f"{bad} FAILED")
sys.exit(1 if bad else 0)
