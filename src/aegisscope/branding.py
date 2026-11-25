from __future__ import annotations

import os
import sys

from . import __version__


LOGO = r"""
             .-----------------------.
          .-'      AEGIS SCOPE        '-.
        .'       .---------------.       '.
       /        /   /\       /\   \        \
      |        |   /  \ [::] /  \   |        |
      |        |   \__/  ||  \__/   |        |
      |        |        /__\         |        |
       \        \   SCOPE LOCKED    /        /
        '.       '---------------'       .'
          '-._______________________.-'
                  WEB SECURITY
""".strip("\n")


def print_banner() -> None:
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    cyan = "\033[1;36m" if color else ""
    violet = "\033[1;35m" if color else ""
    reset = "\033[0m" if color else ""
    print(f"{cyan}{LOGO}{reset}")
    print(f"{violet}AegisScope v{__version__} | Authorized use only{reset}\n")
