"""Entry point for the standalone executable."""

import os
import sys


def _configure_console() -> None:
    """Make Chinese output readable in a default Windows console."""
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:  # noqa: BLE001 - non-console sessions
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - already reconfigured / detached
            pass


_configure_console()

from ipasign.app import main  # noqa: E402  (after console setup)

if __name__ == "__main__":
    sys.exit(main())
