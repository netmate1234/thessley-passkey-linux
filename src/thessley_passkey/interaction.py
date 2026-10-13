"""What the core needs from whoever is driving it (GTK window, terminal, tests)."""

from __future__ import annotations

import getpass


class Cancelled(Exception):
    """The user backed out (closed a dialog, pressed Cancel)."""


class Interaction:
    """Override in the GUI / CLI / tests. All methods may block; call from a worker thread."""

    def get_pin(self, prompt: str, confirm: bool = False) -> str:
        raise NotImplementedError

    def fido_pin(self) -> str:
        """The security key's own PIN, when the key insists on it (e.g. to create a credential)."""
        raise NotImplementedError

    def notify(self, message: str) -> None:
        """Status line, e.g. 'Touch your security key now'."""

    def clear_notice(self) -> None:
        pass


class CliInteraction(Interaction):
    def get_pin(self, prompt: str, confirm: bool = False) -> str:
        pin = getpass.getpass(prompt + ": ")
        if confirm and getpass.getpass("Repeat it: ") != pin:
            raise ValueError("The two entries do not match.")
        return pin

    def fido_pin(self) -> str:
        return getpass.getpass("PIN of your security key: ")

    def notify(self, message: str) -> None:
        print(message, flush=True)
