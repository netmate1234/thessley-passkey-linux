"""Qt (PySide6) front end: the window used on Windows, and available on Linux with THESSLEY_UI=qt.

Mirrors ui.py page for page. Every field shown came from a web page or the network, so nothing is ever
interpreted as rich text: labels are plain text.
"""

from __future__ import annotations

import os
import sys
import threading

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt

from . import __version__, elevate, link, pamlink, protectors, vault
from .core import Service, default_label
from .interaction import Cancelled, Interaction
from .uicommon import (
    ENROLL_EXPLANATION, LOGO_PATH, LOGO_SIZE, NOT_ENROLLED, PROTECTION_LABELS, TYPE_TEXT, available_protections, device_details, device_summary, enrolled_text, explain,
)

STYLE = """
QLabel[role="title"] { font-size: 24px; font-weight: 600; }
QLabel[role="dim"] { }
QLabel[role="error"] { color: @ERROR@; }
QLabel[role="notice"] { font-size: 15px; font-weight: 600; }
QLabel[role="caption"] { font-size: 12px; }
QFrame[card="true"] { border: 1px solid palette(midlight); border-radius: 10px; background: palette(base); }
QPushButton { padding: 10px 18px; border-radius: 8px; font-size: 14px; border: 1px solid palette(mid); background: palette(button); }
QPushButton[kind="primary"] { background: #3584e4; color: white; border: none; font-weight: 600; }
QPushButton[kind="primary"]:disabled { background: @PRIMARY_OFF@; }
QPushButton[kind="danger"] { color: @ERROR@; border: 1px solid @ERROR@; }
"""


DIM_COLOR = "#9a9a9a"  # readable on both the dark and the light palette


def dark_palette() -> QtGui.QPalette:
    """A neutral dark palette (Fusion draws everything else from it)."""
    c = QtGui.QColor
    pal = QtGui.QPalette()
    for role, colour in (
        (QtGui.QPalette.Window, "#242424"), (QtGui.QPalette.WindowText, "#eeeeee"),
        (QtGui.QPalette.Base, "#1c1c1c"), (QtGui.QPalette.AlternateBase, "#2a2a2a"),
        (QtGui.QPalette.Text, "#eeeeee"), (QtGui.QPalette.Button, "#383838"),
        (QtGui.QPalette.ButtonText, "#eeeeee"), (QtGui.QPalette.ToolTipBase, "#383838"),
        (QtGui.QPalette.ToolTipText, "#eeeeee"), (QtGui.QPalette.PlaceholderText, "#8a8a8a"),
        (QtGui.QPalette.Highlight, "#3584e4"), (QtGui.QPalette.HighlightedText, "#ffffff"),
        (QtGui.QPalette.Link, "#78aeed"), (QtGui.QPalette.Mid, "#555555"), (QtGui.QPalette.Midlight, "#454545"),
        (QtGui.QPalette.Light, "#4a4a4a"), (QtGui.QPalette.Dark, "#1a1a1a"), (QtGui.QPalette.Shadow, "#000000"),
    ):
        pal.setColor(role, c(colour))
    for role in (QtGui.QPalette.WindowText, QtGui.QPalette.Text, QtGui.QPalette.ButtonText):
        pal.setColor(QtGui.QPalette.Disabled, role, c("#777777"))
    return pal


def apply_theme(app: QtWidgets.QApplication) -> None:
    """Dark by default. THESSLEY_THEME=light keeps Fusion's light look, =system follows Windows' own setting."""
    mode = os.environ.get("THESSLEY_THEME", "dark").lower()
    dark = mode == "dark" or (mode == "system" and app.styleHints().colorScheme() == Qt.ColorScheme.Dark)
    app.setStyle("Fusion")
    if dark:
        app.setPalette(dark_palette())
    app.setProperty("thessley_error_color", "#ff7b72" if dark else "#c01c28")
    app.setStyleSheet(STYLE.replace("@ERROR@", "#ff7b72" if dark else "#c01c28")
                      .replace("@PRIMARY_OFF@", "#2c4a73" if dark else "#9db8dd"))


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


def _icon(kind: str, color: QtGui.QColor, size: int = 22) -> QtGui.QIcon:
    """A small line icon drawn with the painter (no icon font or image files): 'info' = a circled i, 'bin' = a waste bin."""
    ratio = 2  # drawn at twice the size so it stays sharp on high-DPI screens
    pix = QtGui.QPixmap(size * ratio, size * ratio)
    pix.setDevicePixelRatio(ratio)
    pix.fill(Qt.transparent)
    p = QtGui.QPainter(pix)
    p.setRenderHint(QtGui.QPainter.Antialiasing)
    pen = QtGui.QPen(color, 1.8)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    s = float(size)
    if kind == "info":
        p.drawEllipse(QtCore.QRectF(2, 2, s - 4, s - 4))
        p.drawPoint(QtCore.QPointF(s / 2, s * 0.32))
        p.drawLine(QtCore.QPointF(s / 2, s * 0.46), QtCore.QPointF(s / 2, s * 0.72))
    else:  # bin
        p.drawLine(QtCore.QPointF(s * 0.2, s * 0.27), QtCore.QPointF(s * 0.8, s * 0.27))         # lid
        p.drawLine(QtCore.QPointF(s * 0.4, s * 0.27), QtCore.QPointF(s * 0.4, s * 0.17))         # handle
        p.drawLine(QtCore.QPointF(s * 0.4, s * 0.17), QtCore.QPointF(s * 0.6, s * 0.17))
        p.drawLine(QtCore.QPointF(s * 0.6, s * 0.17), QtCore.QPointF(s * 0.6, s * 0.27))
        body = QtGui.QPainterPath()                                                                # tapered body
        body.moveTo(s * 0.26, s * 0.27)
        body.lineTo(s * 0.31, s * 0.84)
        body.lineTo(s * 0.69, s * 0.84)
        body.lineTo(s * 0.74, s * 0.27)
        p.drawPath(body)
        p.drawLine(QtCore.QPointF(s * 0.44, s * 0.42), QtCore.QPointF(s * 0.44, s * 0.7))        # slats
        p.drawLine(QtCore.QPointF(s * 0.56, s * 0.42), QtCore.QPointF(s * 0.56, s * 0.7))
    p.end()
    return QtGui.QIcon(pix)


def _icon_button(kind: str, tooltip: str, color: QtGui.QColor) -> QtWidgets.QPushButton:
    """A square icon-only button. The tooltip and accessible name carry the words for mouse hover and screen readers."""
    btn = QtWidgets.QPushButton()
    btn.setIcon(_icon(kind, color))
    btn.setIconSize(QtCore.QSize(22, 22))
    btn.setFixedSize(40, 40)
    btn.setToolTip(tooltip)
    btn.setAccessibleName(tooltip)
    btn.setObjectName(kind + "-button")
    btn.setCursor(Qt.PointingHandCursor)
    btn.setStyleSheet("QPushButton { padding: 0; }")
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
            header = QtWidgets.QHBoxLayout()
            words = QtWidgets.QVBoxLayout()
            words.addWidget(_label("Thessley Passkey", "title"))
            words.addWidget(_label("Approve logins to your Thessley-protected sites and Linux computers from this computer. "
                                   "Open a site's “Open on this device” link, or paste a computer's link, to enrol or approve.", "dim"))
            header.addLayout(words, 1)
            pix = QtGui.QPixmap(str(LOGO_PATH)) if LOGO_PATH.is_file() else QtGui.QPixmap()
            if not pix.isNull():
                ratio = self.devicePixelRatioF()
                pix = pix.scaled(int(LOGO_SIZE * ratio), int(LOGO_SIZE * ratio), Qt.KeepAspectRatio, Qt.SmoothTransformation)
                pix.setDevicePixelRatio(ratio)
                logo = QtWidgets.QLabel()
                logo.setPixmap(pix)
                logo.setAccessibleName("Thessley Passkey logo")
                header.addWidget(logo, 0, Qt.AlignTop | Qt.AlignRight)
            col.addLayout(header)
            if toast:
                col.addWidget(_label(toast, "error"))
            devices = vault.sort_devices(self.service.vault.all())
            sections = (
                ("Enrolled sites", [d for d in devices if d.kind != "computer"],
                 ("Nothing enrolled yet", "On a site's profile page choose Add a device, then press “Open on this device”.")),
                ("Enrolled computers", [d for d in devices if d.kind == "computer"],
                 ("No computers yet", "On a Linux computer with thessley-pam run “thessley-pam enroll --user NAME --link”.")),
            )
            for title, items, empty in sections:
                col.addWidget(_label(title, "notice"))
                if not items:
                    col.addWidget(_rows([empty]))
                for d in items:
                    card = QtWidgets.QFrame()
                    card.setProperty("card", "true")
                    row = QtWidgets.QHBoxLayout(card)
                    row.setContentsMargins(14, 10, 10, 10)
                    text = QtWidgets.QVBoxLayout()
                    text.addWidget(_label(d.title))
                    text.addWidget(_label(device_summary(d), "caption"))
                    row.addLayout(text, 1)
                    more = _icon_button("info", "Details: TPM version, protection, key", self.palette().color(QtGui.QPalette.ButtonText))
                    more.clicked.connect(lambda _=False, dev=d: self._show_details(dev))
                    row.addWidget(more)
                    rm = _icon_button("bin", "Remove from this computer", QtGui.QColor(QtWidgets.QApplication.instance().property("thessley_error_color") or "#c01c28"))
                    rm.clicked.connect(lambda _=False, dev=d: self._confirm_remove(dev))
                    row.addWidget(rm)
                    col.addWidget(card)
            col.addWidget(_label("Paste a link", "notice"))
            paste = QtWidgets.QLineEdit()
            paste.setPlaceholderText("thessleypasskey://… or thessleypam://…")
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
        req = link.parse_any(text.strip())
        if req is None:
            self.show_home("That is not a valid Thessley Passkey link.")
            return
        self.request = req
        (self.show_enroll if req.type == "enroll" else self.show_approve)(req)

    def _show_details(self, device) -> None:
        import html
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle(f"{device.label} on {device.title}")
        dialog.resize(640, 600)
        layout = QtWidgets.QVBoxLayout(dialog)
        view = QtWidgets.QTextBrowser()
        view.setOpenLinks(False)
        parts = []
        for title, rows in device_details(device):
            parts.append(f"<h3 style='margin:14px 0 4px 0'>{html.escape(title)}</h3><table width='100%' cellspacing='0' cellpadding='4'>")
            for name, value in rows:
                parts.append(f"<tr><td width='34%' valign='top'><span style='color:{DIM_COLOR}'>{html.escape(name)}</span></td>"
                             f"<td valign='top'>{html.escape(value)}</td></tr>")
            parts.append("</table>")
        view.setHtml("".join(parts))  # a QTextBrowser wraps long values and follows the app's palette
        layout.addWidget(view)
        close = _button("Close")
        close.clicked.connect(dialog.accept)
        layout.addWidget(close)
        dialog.exec()

    def _confirm_remove(self, device) -> None:
        box = QtWidgets.QMessageBox(self)
        box.setIcon(QtWidgets.QMessageBox.Warning)
        box.setWindowTitle("Remove this computer?")
        box.setText(f"{device.title}\nYou will not be able to log in to this " + ("computer" if device.kind == "computer" else "site") + " from here until you enrol again. "
                    "Also revoke it on the site's profile page.")
        box.setStandardButtons(QtWidgets.QMessageBox.Cancel | QtWidgets.QMessageBox.Yes)
        box.button(QtWidgets.QMessageBox.Yes).setText("Remove")
        if box.exec() == QtWidgets.QMessageBox.Yes:
            self.service.vault.remove(device.id)
            self.show_home()

    def show_enroll(self, req: link.AuthRequest) -> None:
        protections, tpm_hint = available_protections()

        def build(col):
            col.addWidget(_label(req.enroll_title, "title"))
            col.addWidget(_label(req.enroll_hint, "dim"))
            rows = [(req.kind_label, req.display)]
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
            add = _button(req.enroll_button, "primary")
            cancel = _button("Cancel")
            cancel.clicked.connect(self.close)
            col.addWidget(add)
            col.addWidget(cancel)

            def go():
                protection = combo.currentData()
                label = name.text()
                # Only a website's TPM proof needs administrator rights; enrolling as an approver for a computer does not.
                if elevate.needed_for(protection, proof=not isinstance(req, pamlink.PamRequest)):
                    # Windows only lets administrators prove a key is in the TPM: explain, ask permission, reopen on this link.
                    box = QtWidgets.QMessageBox(self)
                    box.setIcon(QtWidgets.QMessageBox.Information)
                    box.setWindowTitle("Administrator permission needed")
                    box.setText("Windows needs your permission to prove that this key is stored in your computer's TPM chip.")
                    box.setInformativeText("Windows will ask you next: choose Yes. This app then reopens on this same page, "
                                           "and you press “Add this computer” again. Only this proof uses the permission; "
                                           "nothing else on your computer is changed.\n\n"
                                           "If you would rather not, choose a protection without the TPM.")
                    box.setStandardButtons(QtWidgets.QMessageBox.Cancel | QtWidgets.QMessageBox.Ok)
                    box.button(QtWidgets.QMessageBox.Ok).setText("Continue")
                    box.setDefaultButton(QtWidgets.QMessageBox.Ok)
                    if box.exec() != QtWidgets.QMessageBox.Ok:
                        return
                    if req.raw and elevate.relaunch(req.raw):
                        self.close()
                    else:
                        self.error.setText("Permission was not given, so the TPM proof can't be made. "
                                           "Press “Add this computer” to try again and choose Yes, or pick a protection without the TPM.")
                        self.error.show()
                    return
                self._busy([add, cancel, name, combo])
                ui = QtInteraction(self.bridge)

                def work():
                    try:
                        device = self.service.enroll(req, label, protection, ui)
                        self.bridge.finished.emit(True, enrolled_text(device, req.display, protection, self.service.last_note))
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
            col.addWidget(_label(req.heading, "title"))
            rows = [(req.kind_label, req.display), ("What this does", req.what)]
            if req.username:
                rows.append(("Account", req.username))
            if req.ip:
                rows.append(("Requested from", f"{req.ip} {req.country}".strip()))
            if getattr(req, "terminal", ""):
                rows.append(("Terminal", req.terminal))
            col.addWidget(_rows(rows))
            if not devices:
                col.addWidget(_label(NOT_ENROLLED.format(origin=req.display), "error"))
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
    apply_theme(app)
    raw = next((a for a in argv[1:] if a.startswith(("thessleypasskey:", "thessleypam:"))), None)
    request = link.parse_any(raw) if raw else None
    toast = "That is not a valid Thessley link." if raw and request is None else ""
    window = Window(service or Service(), request, bool(raw), toast)
    window.show()
    if sys.platform == "win32":
        protectors.set_parent_window(int(window.winId()))  # the security-key dialog is owned by this window
        window.raise_()
        window.activateWindow()
    return app.exec()
