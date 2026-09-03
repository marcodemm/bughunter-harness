"""Startup banner — ASCII art of BUGHUNTER / HARNESS / MANU + a beetle
rendered in red, à la Hexstrike. Printed once at the top of `main()`
before any orchestrator output.

Colors are ANSI escapes; auto-disabled when stderr is not a TTY (piped
runs, `--help`, `NO_COLOR` env, etc.) so log files stay clean.
"""
from __future__ import annotations

import os
import sys


_RED = "\033[38;5;196m"       # bright red (xterm-256)
_RED_BOLD = "\033[1;91m"      # bold bright red — used for the beetle
_DIM = "\033[2m"
_RESET = "\033[0m"


# ─── ASCII text: BUGHUNTER (block, 6 rows) ─────────────────────────────
_BUGHUNTER = r"""
 ██████╗  ██╗   ██╗  ██████╗  ██╗  ██╗ ██╗   ██╗ ███╗   ██╗ ████████╗ ███████╗ ██████╗
 ██╔══██╗ ██║   ██║ ██╔════╝  ██║  ██║ ██║   ██║ ████╗  ██║ ╚══██╔══╝ ██╔════╝ ██╔══██╗
 ██████╔╝ ██║   ██║ ██║  ███╗ ███████║ ██║   ██║ ██╔██╗ ██║    ██║    █████╗   ██████╔╝
 ██╔══██╗ ██║   ██║ ██║   ██║ ██╔══██║ ██║   ██║ ██║╚██╗██║    ██║    ██╔══╝   ██╔══██╗
 ██████╔╝ ╚██████╔╝ ╚██████╔╝ ██║  ██║ ╚██████╔╝ ██║ ╚████║    ██║    ███████╗ ██║  ██║
 ╚═════╝   ╚═════╝   ╚═════╝  ╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═══╝    ╚═╝    ╚══════╝ ╚═╝  ╚═╝
"""

# ─── ASCII text: HARNESS (block, 6 rows) ───────────────────────────────
_HARNESS = r"""
 ██╗  ██╗  █████╗  ██████╗  ███╗   ██╗ ███████╗ ███████╗ ███████╗
 ██║  ██║ ██╔══██╗ ██╔══██╗ ████╗  ██║ ██╔════╝ ██╔════╝ ██╔════╝
 ███████║ ███████║ ██████╔╝ ██╔██╗ ██║ █████╗   ███████╗ ███████╗
 ██╔══██║ ██╔══██║ ██╔══██╗ ██║╚██╗██║ ██╔══╝   ╚════██║ ╚════██║
 ██║  ██║ ██║  ██║ ██║  ██║ ██║ ╚████║ ███████╗ ███████║ ███████║
 ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═══╝ ╚══════╝ ╚══════╝ ╚══════╝
"""

# ─── MANU + beetle side by side (6 rows) ───────────────────────────────
# The beetle is stitched to the right of MANU on the same 6 lines so the
# whole third block sits on the same vertical strip as the two above.
#     Beetle art (7 cols wide, 6 rows) — a stylised scarab:
#          .--.
#       .-(    ).-.
#      /   ,__,   \
#     ((=(  ⚫⚫  )=))
#      \   \__/   /
#       `-.____.-'
_MANU_BEETLE = r"""
 ███╗   ███╗  █████╗  ███╗   ██╗ ██╗   ██╗            .--.
 ████╗ ████║ ██╔══██╗ ████╗  ██║ ██║   ██║         .-(    ).-.
 ██╔████╔██║ ███████║ ██╔██╗ ██║ ██║   ██║        /   ,__,   \
 ██║╚██╔╝██║ ██╔══██║ ██║╚██╗██║ ██║   ██║      ((=(  o  o  )=))
 ██║ ╚═╝ ██║ ██║  ██║ ██║ ╚████║ ╚██████╔╝        \   \__/   /
 ╚═╝     ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═══╝  ╚═════╝          `-.____.-'
"""


_TAGLINE = "autonomous local-LLM pentest agent · rate-limited · scope-gated · redact-by-default"


def _colors_ok() -> bool:
    """Return True when ANSI colors should be emitted to stderr.
    Disabled when: NO_COLOR set, TERM=dumb, or stderr isn't a TTY."""
    if os.environ.get("NO_COLOR"):
        return False
    if (os.environ.get("TERM") or "").lower() == "dumb":
        return False
    try:
        return bool(sys.stderr.isatty())
    except Exception:
        return False


def render_banner(color: bool | None = None) -> str:
    """Return the full banner as a string. Color pass optional — defaults
    to auto-detection via _colors_ok()."""
    if color is None:
        color = _colors_ok()
    parts = [_BUGHUNTER, _HARNESS, _MANU_BEETLE]
    body = "\n".join(p.rstrip() for p in parts)
    tagline_line = f"    {_TAGLINE}"
    if color:
        return (f"{_RED}{body}{_RESET}\n"
                f"{_DIM}{tagline_line}{_RESET}\n")
    return f"{body}\n{tagline_line}\n"


def print_banner() -> None:
    """Print the banner to stderr (so it doesn't mix with tool JSON on
    stdout). No-op if colors are disabled AND stdin/stdout look non-
    interactive — keeps `python harness.py --help | less` clean."""
    try:
        sys.stderr.write(render_banner())
        sys.stderr.flush()
    except Exception:
        # Never let a decorative banner break a run
        pass
