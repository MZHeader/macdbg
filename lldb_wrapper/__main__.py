from __future__ import annotations

import argparse
import sys

from .ui.app import WrapperApp


def main() -> int:
    p = argparse.ArgumentParser(prog="macdbg")
    p.add_argument("program", nargs="?")
    p.add_argument("args", nargs=argparse.REMAINDER)
    ns = p.parse_args()
    app = WrapperApp(program=ns.program, program_args=ns.args or [])
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
