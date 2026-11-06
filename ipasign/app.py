"""Entry point shared by ``python -m ipasign`` and the ``ipasign`` script.

No arguments  -> interactive TUI
Any argument  -> the argparse CLI (``ipasign --help``)
"""

from __future__ import annotations

import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        from .tui import main as tui_main

        return tui_main()
    from .cli import main as cli_main

    return cli_main(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
