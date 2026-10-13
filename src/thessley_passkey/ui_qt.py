"""Qt (PySide6) front end: the window used on Windows, and available on Linux with THESSLEY_UI=qt.

Mirrors ui.py page for page. Every field shown came from a web page or the network, so nothing is ever
interpreted as rich text: labels are plain text.
"""

from __future__ import annotations

import sys
import threading

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt

from . import __version__, elevate, link, vault
from .core import Service, default_label
from .interaction import Cancelled, Interaction
from .uicommon import (
    ENROLL_EXPLANATION, NOT_ENROLLED, PROTECTION_LABELS, TYPE_TEXT, available_protections, device_summary, enrolled_text, explain,
)

STYLE = """
QLabel[role="title"] { font-size: 24px; font-weight: 600; }
QLabel[role="dim"] { }
QLabel[role="error"] { color: #c01c28; }
QLabel[role="notice"] { font-size: 15px; font-weight: 600; }
QLabel[role="caption"] { font-size: 12px; }
QFrame[card="true"] { border: 1px solid palette(midlight); border-radius: 10px; background: palette(base); }
QPushButton { padding: 10px 18px; border-radius: 8px; font-size: 14px; border: 1px solid palette(mid); background: palette(button); }
QPushButton[kind="primary"] { background: #3584e4; color: white; border: none; font-weight: 600; }
QPushButton[kind="primary"]:disabled { background: #9db8dd; }
QPushButton[kind="danger"] { color: #c01c28; border: 1px solid #c01c28; }
"""


def _dim(label: QtWidgets.QLabel) -> None:
    """Secondary text: the normal text colour pulled 40% towards the background, so it reads in light and dark themes."""
    pal = label.palette()
    fg, bg = pal.color(QtGui.QPalette.WindowText), pal.color(QtGui.QPalette.Window)
    mix = lambda a, b: int(a * 0.6 + b * 0.4)
    pal.setColor(QtGui.QPalette.WindowText, QtGui.QColor(mix(fg.red(), bg.red()), mix(fg.green(), bg.green()), mix(fg.blue(), bg.blue())))
    label.setPalette(pal)


def _label(text: str, role: str = "", wrap: bool = True) -> QtWidgets.QLabel:
    lab = QtWidgets.QLabel(text)
    lab.setTextFormat(Qt.PlainText)
    lab.setWordWrap(wrap)
    lab.setTextInteractionFlags(Qt.TextSelectableByMouse)
    if role:
        lab.setProperty("role", role)
    if role in ("dim", "caption"):
        _dim(lab)
    return lab


def _button(text: str, kind: str = "") -> QtWidgets.QPushButton:
    btn = QtWidgets.QPushButton(text)
    if kind:
        btn.setProperty("kind", kind)
    return btn


def _rows(pairs: list[tuple[str, str]]) -> QtWidgets.QFrame:
    """A card of 'caption / value' rows."""
    card = QtWidgets.QFrame()
    card.setProperty("card", "true")
    lay = QtWidgets.QVBoxLayout(card)
    lay.setContentsMargins(14, 10, 14, 10)
    for name, value in pairs:
        lay.addWidget(_label(name, "caption"))
        lay.addWidget(_label(value))
    return card


class PinRequest:
    def __init__(self, prompt: str, confirm: bool, key_pin: bool):
        self.prompt, self.confirm, self.key_pin = prompt, confirm, key_pin
        self.done = threading.Event()
        self.value = None


class Bridge(QtCore.QObject):
    """Lets worker threads ask the window for things; slots run on the GUI thread."""

    pin_requested = QtCore.Signal(object)
    notice = QtCore.Signal(str)
    finished = QtCore.Signal(bool, str)
    failed = QtCore.Signal(str)


class QtInteraction(Interaction):
    def __init__(self, bridge: Bridge):
        self.bridge = bridge

    def _ask(self, prompt: str, confirm: bool, key_pin: bool) -> str:
        req = PinRequest(prompt, confirm, key_pin)
        self.bridge.pin_requested.emit(req)
        req.done.wait()
        if isinstance(req.value, BaseException):
            raise req.value
        return req.value

    def get_pin(self, prompt: str, confirm: bool = False) -> str:
        return self._ask(prompt, confirm, False)

    def fido_pin(self) -> str:
        return self._ask("PIN of your security key", False, True)

    def notify(self, message: str) -> None:
        self.bridge.notice.emit(message)

    def clear_notice(self) -> None:
        self.bridge.notice.emit("")


class PinDialog(QtWidgets.QDialog):
    def __init__(self, parent, req: PinRequest):
        super().__init__(parent)
        self.setWindowTitle(req.prompt)
        self.setModal(True)
        self.req = req
        lay = QtWidgets.QVBoxLayout(self)
        lay.addWidget(_label(req.prompt, "notice"))
        lay.addWidget(_label(
            "This is the PIN you set on your security key." if req.key_pin else
            ("Choose a PIN of at least 6 characters. You will enter it every time you approve a login." if req.confirm
             else "Needed to unlock the key that signs this login."), "dim"))
        self.first = QtWidgets.QLineEdit()
        self.first.setEchoMode(QtWidgets.QLineEdit.Password)
        self.first.setObjectName("pin")
        lay.addWidget(self.first)
        self.second = None
        if req.confirm:
            lay.addWidget(_label("Repeat the PIN", "caption"))
            self.second = QtWidgets.QLineEdit()
            self.second.setEchoMode(QtWidgets.QLineEdit.Password)
            self.second.setObjectName("pin2")
            lay.addWidget(self.second)
        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        self.first.returnPressed.connect(self.accept if self.second is None else self.second.setFocus)
        if self.second is not None:
            self.second.returnPressed.connect(self.accept)

    def done(self, result: int) -> None:
        if self.req.done.is_set():
            return super().done(result)
        if result != QtWidgets.QDialog.Accepted:
            self.req.value = Cancelled()
        elif self.second is not None and self.second.text() != self.first.text():
            self.req.value = ValueError("The two entries do not match.")
        else:
            self.req.value = self.first.text()
        self.req.done.set()
        super().done(result)


class Window(QtWidgets.QMainWindow):
    def __init__(self, service: Service, request: link.AuthRequest | None, launched_with_link: bool, toast: str = ""):
        super().__init__()
        self.service = service
        self.request = request
        self.launched_with_link = launched_with_link
        self.setWindowTitle("Thessley Passkey")
        self.resize(680, 820)
        self.stack = QtWidgets.QStackedWidget()
        self.setCentralWidget(self.stack)
        self.bridge = Bridge()
        self.bridge.pin_requested.connect(self._show_pin)
        self.bridge.notice.connect(self._set_notice)
        self.bridge.finished.connect(self.show_result)
        self.bridge.failed.connect(self._show_error)
        self.notice = _label("", "notice")
        self.error = _label("", "error")
        self.error.hide()
        self._busy_widgets: list[QtWidgets.QWidget] = []
        if request is None:
            self.show_home(toast)
        elif request.type == "enroll":
            self.show_enroll(request)
        else:
            self.show_approve(request)

    # ---- plumbing -----------------------------------------------------------------------

    def _page(self, name: str, build) -> None:
        old = self.stack.findChild(QtWidgets.QWidget, name, Qt.FindDirectChildrenOnly)
        if old is not None:
            self.stack.removeWidget(old)
            old.deleteLater()
        outer = QtWidgets.QWidget()
        outer.setObjectName(name)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        body = QtWidgets.QWidget()
        col = QtWidgets.QVBoxLayout(body)
        col.setContentsMargins(24, 24, 24, 24)
        col.setSpacing(14)
        build(col)
        col.addStretch(1)
        scroll.setWidget(body)
        lay = QtWidgets.QVBoxLayout(outer)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(scroll)
        self.stack.addWidget(outer)
        self.stack.setCurrentWidget(outer)

    def page_name(self) -> str:
        return self.stack.currentWidget().objectName() if self.stack.currentWidget() else ""

    def _set_notice(self, text: str) -> None:
        self.notice.setText(text)
        self.notice.setVisible(bool(text))

    def _show_error(self, message: str) -> None:
        for w in self._busy_widgets:
            w.setEnabled(True)
        self._set_notice("")
        self.error.setText(message)
        self.error.setVisible(bool(message))

    def _busy(self, widgets: list[QtWidgets.QWidget]) -> None:
        self._busy_widgets = widgets
        self.error.hide()
        for w in widgets:
            w.setEnabled(False)

    def _show_pin(self, req: PinRequest) -> None:
        dlg = PinDialog(self, req)
        dlg.show()
        dlg.first.setFocus()

    def _worker(self, fn) -> None:
        threading.Thread(target=fn, daemon=True).start()

    # ---- pages ------------------------------------------------------------------------------

    def show_home(self, toast: str = "") -> None:
        def build(col):
            col.addWidget(_label("Thessley Passkey", "title"))
            col.addWidget(_label("Approve logins to your Thessley-protected sites from this computer. "
                                 "Open a site's “Open on this device” link to enrol or approve.", "dim"))
            if toast:
                col.addWidget(_label(toast, "error"))
            col.addWidget(_label("Enrolled sites", "notice"))
            devices = vault.sort_devices(self.service.vault.all())
            if not devices:
                col.addWidget(_rows([("Nothing enrolled yet", "On a site's profile page choose Add a device, then press “Open on this device”.")]))
            for d in devices:
                card = QtWidgets.QFrame()
                card.setProperty("card", "true")
                row = QtWidgets.QHBoxLayout(card)
                row.setContentsMargins(14, 10, 10, 10)
                text = QtWidgets.QVBoxLayout()
                text.addWidget(_label(d.origin))
                text.addWidget(_label(device_summary(d), "caption"))
                row.addLayout(text, 1)
                rm = _button("Remove")
                rm.setProperty("kind", "danger")
                rm.clicked.connect(lambda _=False, dev=d: self._confirm_remove(dev))
                row.addWidget(rm)
                col.addWidget(card)
            col.addWidget(_label("Paste a link", "notice"))
            paste = QtWidgets.QLineEdit()
            paste.setPlaceholderText("thessleypasskey://…")
            paste.setObjectName("paste")
            paste.returnPressed.connect(lambda: self._open_pasted(paste.text()))
            col.addWidget(paste)
            open_btn = _button("Open")
            open_btn.clicked.connect(lambda: self._open_pasted(paste.text()))
            col.addWidget(open_btn)
            col.addWidget(_label(f"Version {__version__}. Removing a device here does not revoke it on the site; "
                                 "do that on your profile page too.", "caption"))
        self._page("home", build)

    def _open_pasted(self, text: str) -> None:
        req = link.parse(text.strip())
        if req is None:
            self.show_home("That is not a valid Thessley Passkey link.")
            return
        self.request = req
        (self.show_enroll if req.type == "enroll" else self.show_approve)(req)

    def _confirm_remove(self, device) -> None:
        box = QtWidgets.QMessageBox(self)
        box.setIcon(QtWidgets.QMessageBox.Warning)
        box.setWindowTitle("Remove this computer?")
        box.setText(f"{device.origin}\nYou will not be able to log in to this site from here until you enrol again. "
                    "Also revoke it on the site's profile page.")
        box.setStandardButtons(QtWidgets.QMessageBox.Cancel | QtWidgets.QMessageBox.Yes)
        box.button(QtWidgets.QMessageBox.Yes).setText("Remove")
        if box.exec() == QtWidgets.QMessageBox.Yes:
            self.service.vault.remove(device.id)
            self.show_home()

    def show_enroll(self, req: link.AuthRequest) -> None:
        protections, tpm_hint = available_protections()

        def build(col):
            col.addWidget(_label("Add this computer", "title"))
            col.addWidget(_label("Only continue if you just pressed “Add a device” on this site yourself.", "dim"))
            rows = [("Site", req.origin)]
            if req.ip:
                rows.append(("Requested from", f"{req.ip} {req.country}".strip()))
            col.addWidget(_rows(rows))
            col.addWidget(_label("Name", "caption"))
            name = QtWidgets.QLineEdit(default_label())
            name.setObjectName("name")
            col.addWidget(name)
            col.addWidget(_label("Protect the key with", "caption"))
            combo = QtWidgets.QComboBox()
            combo.setObjectName("protection")
            for key in protections:
                combo.addItem(PROTECTION_LABELS[key], key)
            col.addWidget(combo)
            col.addWidget(_label(ENROLL_EXPLANATION, "caption"))
            if tpm_hint:
                col.addWidget(_label("TPM option not available: " + tpm_hint, "caption"))
            col.addWidget(self.notice)
            self.notice.hide()
            col.addWidget(self.error)
            self.error.hide()
            add = _button("Add this computer", "primary")
            cancel = _button("Cancel")
            cancel.clicked.connect(self.close)
            col.addWidget(add)
            col.addWidget(cancel)

            def go():
                protection = combo.currentData()
                label = name.text()
                if elevate.needed_for(protection):
                    # Windows only lets administrators prove a key is in the TPM: ask permission, reopen on this link.
                    if req.raw and elevate.relaunch(req.raw):
                        self.close()
                    else:
                        self.error.setText("To prove the key is in the TPM, Windows needs your permission "
                                           "(administrator). Press the button again and choose Yes, or pick a protection without the TPM.")
                        self.error.show()
                    return
                self._busy([add, cancel, name, combo])
                ui = QtInteraction(self.bridge)

                def work():
                    try:
                        device = self.service.enroll(req, label, protection, ui)
                        self.bridge.finished.emit(True, enrolled_text(device, req.origin, protection, self.service.last_note))
                    except Cancelled:
                        self.bridge.failed.emit("")
                    except Exception as exc:
                        self.bridge.failed.emit(explain(exc))
                self._worker(work)

            add.clicked.connect(go)
        self._page("enroll", build)

    def show_approve(self, req: link.AuthRequest) -> None:
        devices = self.service.candidates(req)

        def build(col):
            col.addWidget(_label("Log in" if req.type == "login" else "Confirm your login", "title"))
            rows = [("Site", req.origin), ("What this does", TYPE_TEXT[req.type])]
            if req.username:
                rows.append(("Account", req.username))
            if req.ip:
                rows.append(("Requested from", f"{req.ip} {req.country}".strip()))
            col.addWidget(_rows(rows))
            if not devices:
                col.addWidget(_label(NOT_ENROLLED.format(origin=req.origin), "error"))
                close = _button("Close")
                close.clicked.connect(self.close)
                col.addWidget(close)
                return
            combo = None
            if len(devices) > 1:
                col.addWidget(_label("Log in as", "caption"))
                combo = QtWidgets.QComboBox()
                combo.setObjectName("device")
                for d in devices:
                    combo.addItem(f"{d.username or 'account'} ({d.label})", d)
                col.addWidget(combo)
            else:
                d = devices[0]
                col.addWidget(_label(f"Signing with: {d.username or 'your account'} · {d.label} · "
                                     f"{PROTECTION_LABELS.get(d.protection, '')}", "caption"))
            col.addWidget(_label("Only approve if you just started this login yourself.", "dim"))
            col.addWidget(self.notice)
            self.notice.hide()
            col.addWidget(self.error)
            self.error.hide()
            approve = _button("Approve", "primary")
            deny = _button("Deny", "danger")
            col.addWidget(approve)
            col.addWidget(deny)

            def go(approved: bool):
                device = combo.currentData() if combo else devices[0]
                self._busy([approve, deny] + ([combo] if combo else []))
                ui = QtInteraction(self.bridge)

                def work():
                    try:
                        outcome = self.service.respond(req, device, approved, ui)
                        self.bridge.finished.emit(True, "Approved. You can go back to the browser." if outcome == "approved"
                                                  else "Denied. The login was refused.")
                    except Cancelled:
                        self.bridge.failed.emit("")
                    except Exception as exc:
                        self.bridge.failed.emit(explain(exc))
                self._worker(work)

            approve.clicked.connect(lambda: go(True))
            deny.clicked.connect(lambda: go(False))
        self._page("approve", build)

    def show_result(self, success: bool, message: str) -> None:
        def build(col):
            col.addStretch(1)
            icon = _label("✓" if success else "✕", "title", wrap=False)
            icon.setAlignment(Qt.AlignCenter)
            col.addWidget(icon)
            text = _label(message, "notice")
            text.setAlignment(Qt.AlignCenter)
            col.addWidget(text)
            done = _button("Close")
            done.clicked.connect(self.close)
            col.addWidget(done)
        self._page("result", build)
        if success and self.launched_with_link:
            QtCore.QTimer.singleShot(3000, self.close)


def run(service: Service | None = None, argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    app = QtWidgets.QApplication(argv)
    app.setApplicationName("Thessley Passkey")
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    raw = next((a for a in argv[1:] if a.startswith("thessleypasskey:")), None)
    request = link.parse(raw) if raw else None
    toast = "That link is not a valid Thessley Passkey link." if raw and request is None else ""
    window = Window(service or Service(), request, bool(raw), toast)
    window.show()
    return app.exec()
