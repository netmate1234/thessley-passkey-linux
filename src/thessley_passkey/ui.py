"""GTK4 / libadwaita front end.

Every field shown here came from a web page or the network, so nothing is ever
interpreted as markup (rows set use_markup off, labels are plain text).
"""

from __future__ import annotations

import os
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Adw, Gdk, GdkPixbuf, Gio, GLib, Gtk  # noqa: E402

from . import __version__, link, protectors, protocol, tpm, vault  # noqa: E402
from .core import Service, UnknownSite, WrongSecret, default_label  # noqa: E402
from .interaction import Cancelled, Interaction  # noqa: E402
from .protocol import NetworkError, ServerError  # noqa: E402
from .vault import Device, Locked  # noqa: E402

APP_ID = "se.thessley.Passkey"
from .uicommon import (  # noqa: E402
    ENROLL_EXPLANATION, LOGO_PATH, LOGO_SIZE, NOT_ENROLLED, PROTECTION_LABELS, TYPE_TEXT, available_protections, device_details, device_summary, enrolled_text, explain,
)


def _plain_row(title: str, subtitle: str = "") -> Adw.ActionRow:
    row = Adw.ActionRow()
    row.set_use_markup(False)
    row.set_title(title)
    row.set_subtitle(subtitle)
    row.set_subtitle_selectable(True)
    return row


def _label(text: str, css: list[str] | None = None, wrap: bool = True) -> Gtk.Label:
    lab = Gtk.Label(label=text)
    lab.set_use_markup(False)
    lab.set_wrap(wrap)
    lab.set_xalign(0)
    for c in css or []:
        lab.add_css_class(c)
    return lab


class GtkInteraction(Interaction):
    """Runs on the worker thread; shows dialogs on the main thread and waits for the answer."""

    def __init__(self, window: "Window"):
        self.window = window

    def _ask(self, builder):
        done, box = threading.Event(), {}

        def reply(value):
            box["v"] = value
            done.set()

        def start():
            try:
                builder(reply)
            except Exception as exc:  # never leave the worker waiting on a dialog that failed to open
                reply(exc)
            return False

        GLib.idle_add(start)
        done.wait()
        if isinstance(box["v"], BaseException):
            raise box["v"]
        return box["v"]

    def get_pin(self, prompt: str, confirm: bool = False) -> str:
        return self._ask(lambda reply: self.window.pin_dialog(prompt, confirm, reply, key_pin=False))

    def fido_pin(self) -> str:
        return self._ask(lambda reply: self.window.pin_dialog("PIN of your security key", False, reply, key_pin=True))

    def notify(self, message: str) -> None:
        GLib.idle_add(self.window.show_notice, message)

    def clear_notice(self) -> None:
        GLib.idle_add(self.window.show_notice, "")


class Window(Adw.ApplicationWindow):
    def __init__(self, app: "Application", service: Service, request: link.AuthRequest | None, launched_with_link: bool):
        super().__init__(application=app)
        self.service = service
        self.request = request
        self.launched_with_link = launched_with_link
        self.set_title("Thessley Passkey")
        self.set_default_size(680, 820)
        self.busy = False

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        view = Adw.ToolbarView()
        view.add_top_bar(Adw.HeaderBar())
        self.toasts = Adw.ToastOverlay()
        self.toasts.set_child(self.stack)
        view.set_content(self.toasts)
        self.set_content(view)

        self.notice = Gtk.Label()
        self.notice.set_use_markup(False)
        self.notice.set_wrap(True)
        self.notice.add_css_class("title-4")

        if request is None:
            self.show_home()
        elif request.type == "enroll":
            self.show_enroll(request)
        else:
            self.show_approve(request)

    # ---- plumbing ----------------------------------------------------------------

    def _page(self, name: str, widget: Gtk.Widget) -> None:
        old = self.stack.get_child_by_name(name)
        if old is not None:
            self.stack.remove(old)
        clamp = Adw.Clamp(maximum_size=600, margin_top=18, margin_bottom=18, margin_start=18, margin_end=18)
        clamp.set_child(widget)
        scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroll.set_child(clamp)
        self.stack.add_named(scroll, name)
        self.stack.set_visible_child_name(name)

    def _column(self) -> Gtk.Box:
        return Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)

    def show_notice(self, text: str) -> bool:
        self.notice.set_text(text)
        self.notice.set_visible(bool(text))
        return False

    def set_busy(self, busy: bool, widgets: list[Gtk.Widget]) -> None:
        self.busy = busy
        for w in widgets:
            w.set_sensitive(not busy)

    def pin_dialog(self, prompt: str, confirm: bool, reply, key_pin: bool) -> None:
        dialog = Adw.AlertDialog()
        dialog.set_heading(prompt)
        dialog.set_body("This is the PIN you set on your security key." if key_pin else
                        ("Choose a PIN of at least 6 characters. You will enter it every time you approve a login." if confirm else "Needed to unlock the key that signs this login."))
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        first = Gtk.PasswordEntry(show_peek_icon=True)
        box.append(_label("PIN of your security key" if key_pin else ("New PIN" if confirm else "PIN"), ["caption"]))
        box.append(first)
        second = None
        if confirm:
            second = Gtk.PasswordEntry(show_peek_icon=True)
            box.append(_label("Repeat the PIN", ["caption"]))
            box.append(second)
        dialog.set_extra_child(box)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("ok", "Continue")
        dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("ok")
        dialog.set_close_response("cancel")
        answered = []

        def finish(response):
            if answered:
                return
            answered.append(True)
            if response != "ok":
                reply(Cancelled())
            elif second is not None and second.get_text() != first.get_text():
                reply(ValueError("The two entries do not match."))
            else:
                reply(first.get_text())

        def accept(*_):
            finish("ok")
            dialog.force_close()

        first.connect("activate", lambda *_: accept() if second is None else second.grab_focus())
        if second is not None:
            second.connect("activate", accept)
        dialog.connect("response", lambda _d, response: finish(response))
        dialog.present(self)
        first.grab_focus()

    # ---- pages -------------------------------------------------------------------------

    def show_home(self) -> None:
        col = self._column()
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, hexpand=True)
        words.append(_label("Thessley Passkey", ["title-1"]))
        words.append(_label("Approve logins to your Thessley-protected sites and Linux computers from this computer. "
                            "Open a site's “Open on this device” link, or paste a computer's link, to enrol or approve.", ["dim-label"]))
        header.append(words)
        if LOGO_PATH.is_file():
            try:  # scaled to a fixed size here: a Gtk.Picture would show the file's own 256 pixels
                pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(LOGO_PATH), LOGO_SIZE, LOGO_SIZE, True)
                logo = Gtk.Image.new_from_paintable(Gdk.Texture.new_for_pixbuf(pixbuf))
                logo.set_pixel_size(LOGO_SIZE)
                logo.set_halign(Gtk.Align.END)
                logo.set_valign(Gtk.Align.START)
                header.append(logo)
            except GLib.Error:
                pass  # no logo is better than no window
        col.append(header)
        devices = vault.sort_devices(self.service.vault.all())
        sites = [d for d in devices if d.kind != "computer"]
        computers = [d for d in devices if d.kind == "computer"]
        for title, items, empty in (
            ("Enrolled sites", sites, ("Nothing enrolled yet", "On a site's profile page choose Add a device, then press “Open on this device”.")),
            ("Enrolled computers", computers, ("No computers yet", "On a Linux computer with thessley-pam run “thessley-pam enroll --user NAME --link”.")),
        ):
            group = Adw.PreferencesGroup(title=title)
            if not items:
                group.add(_plain_row(*empty))
            for d in items:
                row = _plain_row(d.title, device_summary(d))
                info = Gtk.Button(icon_name="dialog-information-symbolic", valign=Gtk.Align.CENTER)
                info.add_css_class("flat")
                info.set_tooltip_text("Details: TPM version, protection, key")
                info.connect("clicked", self._show_details, d)
                row.add_suffix(info)
                btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER)
                btn.add_css_class("flat")
                btn.set_tooltip_text("Remove from this computer")
                btn.connect("clicked", self._confirm_remove, d)
                row.add_suffix(btn)
                group.add(row)
            col.append(group)

        paste = Adw.PreferencesGroup(title="Paste a link")
        entry = Adw.EntryRow(title="thessleypasskey://… or thessleypam://…")
        entry.set_show_apply_button(True)
        entry.connect("apply", self._open_pasted)
        paste.add(entry)
        col.append(paste)
        col.append(_label(f"Version {__version__}. Removing a device here does not revoke it on the site; do that on your profile page too.", ["caption", "dim-label"]))
        self._page("home", col)

    def _open_pasted(self, entry) -> None:
        req = link.parse_any(entry.get_text())
        if req is None:
            self.toasts.add_toast(Adw.Toast(title="That is not a valid Thessley link."))
            return
        self.request = req
        (self.show_enroll if req.type == "enroll" else self.show_approve)(req)

    def _show_details(self, _btn, device: Device) -> None:
        dialog = Adw.Dialog(title=f"{device.label} on {device.title}", content_width=560, content_height=640)
        page = Adw.PreferencesPage()
        for title, rows in device_details(device):
            group = Adw.PreferencesGroup(title=title)
            for name, value in rows:
                row = Adw.ActionRow(title=GLib.markup_escape_text(name), subtitle=GLib.markup_escape_text(value))
                row.set_subtitle_selectable(True)
                row.set_subtitle_lines(0)   # show the whole value, wrapped
                row.set_title_lines(0)
                row.add_css_class("property")  # value first, name small: how libadwaita shows key/value pairs
                group.add(row)
            page.add(group)
        box = Adw.ToolbarView()
        box.add_top_bar(Adw.HeaderBar())
        box.set_content(page)
        dialog.set_child(box)
        dialog.present(self)

    def _confirm_remove(self, _btn, device: Device) -> None:
        dialog = Adw.AlertDialog(heading="Remove this computer?")
        dialog.set_body(f"{device.title}\nYou will not be able to log in to this " + ("computer" if device.kind == "computer" else "site") + " from here until you enrol again. "
                        "Also revoke it on the site's profile page.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("remove", "Remove")
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)

        def done(_d, response):
            if response == "remove":
                self.service.vault.remove(device.id)
                self.show_home()

        dialog.connect("response", done)
        dialog.present(self)

    def show_enroll(self, req: link.AuthRequest) -> None:
        col = self._column()
        col.append(_label(req.enroll_title, ["title-1"]))
        col.append(_label(req.enroll_hint, ["dim-label"]))
        group = Adw.PreferencesGroup()
        group.add(_plain_row(req.kind_label, req.display))
        if req.ip:
            group.add(_plain_row("Requested from", f"{req.ip} {req.country}".strip()))
        col.append(group)

        form = Adw.PreferencesGroup(title="This computer")
        label_row = Adw.EntryRow(title="Name")
        label_row.set_text(default_label())
        form.add(label_row)
        protections, tpm_hint = available_protections()
        combo = Adw.ComboRow(title="Protect the key with")
        combo.set_model(Gtk.StringList.new([PROTECTION_LABELS[k] for k in protections]))
        combo.set_selected(0)
        form.add(combo)
        col.append(form)
        col.append(_label(ENROLL_EXPLANATION, ["caption", "dim-label"]))
        if tpm_hint:
            col.append(_label("TPM option not available: " + tpm_hint, ["caption", "dim-label"]))
        col.append(self.notice)
        error = _label("", ["error"])
        error.set_visible(False)
        col.append(error)
        add = Gtk.Button(label=req.enroll_button)
        add.add_css_class("suggested-action")
        add.add_css_class("pill")
        cancel = Gtk.Button(label="Cancel")
        cancel.add_css_class("pill")
        cancel.connect("clicked", lambda *_: self.close())
        col.append(add)
        col.append(cancel)

        def go(*_):
            protection = protections[combo.get_selected()]
            error.set_visible(False)
            self.set_busy(True, [add, cancel, label_row, combo])
            ui = GtkInteraction(self)
            label = label_row.get_text()

            def work():
                try:
                    device = self.service.enroll(req, label, protection, ui)
                    GLib.idle_add(self.show_result, True, enrolled_text(device, req.display, protection, self.service.last_note))
                except Cancelled:
                    GLib.idle_add(self._back, [add, cancel, label_row, combo], error, "")
                except Exception as exc:  # shown to the user, not swallowed
                    GLib.idle_add(self._back, [add, cancel, label_row, combo], error, self.explain(exc))

            threading.Thread(target=work, daemon=True).start()

        add.connect("clicked", go)
        self._page("enroll", col)

    def show_approve(self, req: link.AuthRequest) -> None:
        devices = self.service.candidates(req)
        col = self._column()
        col.append(_label(req.heading, ["title-1"]))
        group = Adw.PreferencesGroup()
        group.add(_plain_row(req.kind_label, req.display))
        group.add(_plain_row("What this does", req.what))
        if req.username:
            group.add(_plain_row("Account", req.username))
        if req.ip:
            group.add(_plain_row("Requested from", f"{req.ip} {req.country}".strip()))
        if getattr(req, "terminal", ""):
            group.add(_plain_row("Terminal", req.terminal))
        col.append(group)

        if not devices:
            col.append(_label(NOT_ENROLLED.format(origin=req.display), ["error"]))
            close = Gtk.Button(label="Close")
            close.add_css_class("pill")
            close.connect("clicked", lambda *_: self.close())
            col.append(close)
            self._page("approve", col)
            return

        combo = None
        if len(devices) > 1:
            combo = Adw.ComboRow(title="Log in as")
            combo.set_model(Gtk.StringList.new([f"{d.username or 'account'} ({d.label})" for d in devices]))
            holder = Adw.PreferencesGroup()
            holder.add(combo)
            col.append(holder)
        else:
            col.append(_label(f"Signing with: {devices[0].username or 'your account'} · {devices[0].label} · {PROTECTION_LABELS.get(devices[0].protection, '')}", ["caption", "dim-label"]))

        warn = _label("Only approve if you just started this login yourself.", ["dim-label"])
        col.append(warn)
        col.append(self.notice)
        error = _label("", ["error"])
        error.set_visible(False)
        col.append(error)
        approve = Gtk.Button(label="Approve")
        approve.add_css_class("suggested-action")
        approve.add_css_class("pill")
        deny = Gtk.Button(label="Deny")
        deny.add_css_class("destructive-action")
        deny.add_css_class("pill")
        col.append(approve)
        col.append(deny)

        def go(approved: bool):
            device = devices[combo.get_selected() if combo else 0]
            error.set_visible(False)
            widgets = [approve, deny] + ([combo] if combo else [])
            self.set_busy(True, widgets)
            ui = GtkInteraction(self)

            def work():
                try:
                    outcome = self.service.respond(req, device, approved, ui)
                    text = "Approved. You can go back to the browser." if outcome == "approved" else "Denied. The login was refused."
                    GLib.idle_add(self.show_result, True, text)
                except Cancelled:
                    GLib.idle_add(self._back, widgets, error, "")
                except Exception as exc:
                    GLib.idle_add(self._back, widgets, error, self.explain(exc))

            threading.Thread(target=work, daemon=True).start()

        approve.connect("clicked", lambda *_: go(True))
        deny.connect("clicked", lambda *_: go(False))
        self._page("approve", col)

    def _back(self, widgets, error_label: Gtk.Label, message: str) -> bool:
        self.set_busy(False, widgets)
        self.show_notice("")
        error_label.set_text(message)
        error_label.set_visible(bool(message))
        return False

    def explain(self, exc: Exception) -> str:
        return explain(exc)

    def show_result(self, success: bool, message: str) -> bool:
        col = self._column()
        col.set_valign(Gtk.Align.CENTER)
        icon = Gtk.Image(icon_name="emblem-ok-symbolic" if success else "dialog-error-symbolic", pixel_size=64)
        col.append(icon)
        text = _label(message, ["title-3"])
        text.set_justify(Gtk.Justification.CENTER)
        text.set_xalign(0.5)
        col.append(text)
        done = Gtk.Button(label="Close")
        done.add_css_class("pill")
        done.set_halign(Gtk.Align.CENTER)
        done.connect("clicked", lambda *_: self.close())
        col.append(done)
        self._page("result", col)
        if success and self.launched_with_link:
            GLib.timeout_add_seconds(3, lambda: (self.close(), False)[1])
        return False


class Application(Adw.Application):
    def __init__(self, service: Service):
        # Tests set THESSLEY_APP_ID so they never hand their links to the copy running on someone's desktop.
        super().__init__(application_id=os.environ.get("THESSLEY_APP_ID", APP_ID), flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        self.service = service

    def do_command_line(self, cmdline):
        args = cmdline.get_arguments()[1:]
        raw = next((a for a in args if a.startswith(("thessleypasskey:", "thessleypam:"))), None)
        request = link.parse_any(raw) if raw else None
        if raw and request is None:
            window = Window(self, self.service, None, False)
            window.toasts.add_toast(Adw.Toast(title="That is not a valid Thessley link."))
        else:
            window = Window(self, self.service, request, bool(raw))
        window.present()
        return 0


def run(service: Service | None = None) -> int:
    return Application(service or Service()).run(sys.argv)
