"""Entry point shared by ``python -m ipasign`` and the ``ipasign`` script.

No arguments  -> interactive TUI
Any argument  -> the argparse CLI (``ipasign --help``)
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    # ``--lang`` is handled here so it works for both the TUI and the CLI, and
    # before any translation is loaded.
    if "--lang" in args:
        index = args.index("--lang")
        if index + 1 < len(args):
            language = args[index + 1]
            if language in ("en", "zh"):
                os.environ["IPASIGN_LANG"] = language
            del args[index:index + 2]

    if not args:
        from .tui import main as tui_main

        return tui_main()
    from .cli import main as cli_main

    return cli_main(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
