"""Entry point for the packaged app (PyInstaller)."""
import sys

from thessley_passkey.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
