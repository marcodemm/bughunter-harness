"""Best-effort cleanup of temp files the agents may have written to /tmp.

Called from:
  - orchestrator.py at the end of Orchestrator.run()  (report + cleanup)
  - harness.py SIGINT handler  (Ctrl+C / /quit)
  - harness.py REPL exit  (bye)

Patterns limited to those our agents actually generate, so we never wipe
someone else's tempfiles. The full list of matched patterns is logged for
auditability.
"""
from __future__ import annotations

import glob
import os
from pathlib import Path
from typing import Iterable

# Patterns of tempfiles our agents write via `> /tmp/...` in run_shell.
# Kept intentionally narrow — anything not starting with a recognizable
# prefix is left alone, so we don't touch unrelated files.
_TEMP_PATTERNS: tuple[str, ...] = (
    "/tmp/harness-*",
    "/tmp/harness_*",
    "/tmp/gau_*",
    "/tmp/subfinder_*",
    "/tmp/subfinder-*",
    "/tmp/subs_*",
    "/tmp/subs-*",
    "/tmp/wayback_*",
    "/tmp/wayback-*",
    "/tmp/nuclei_*",
    "/tmp/nuclei-*",
    "/tmp/ffuf_*",
    "/tmp/ffuf-*",
    "/tmp/katana_*",
    "/tmp/katana-*",
    "/tmp/dnsx_*",
    "/tmp/dnsx-*",
    "/tmp/naabu_*",
    "/tmp/naabu-*",
    "/tmp/httpx_*",
    "/tmp/httpx-*",
    "/tmp/subs.txt",
    "/tmp/live.txt",
    "/tmp/urls.txt",
    "/tmp/paths.txt",
    "/tmp/f.txt",
)


def _matches() -> list[str]:
    hits: list[str] = []
    for pat in _TEMP_PATTERNS:
        hits.extend(glob.glob(pat))
    # dedup + only real files (skip symlinks pointing outside /tmp)
    real: list[str] = []
    seen: set[str] = set()
    for p in hits:
        try:
            real_path = os.path.realpath(p)
            if not real_path.startswith("/private/tmp/") \
               and not real_path.startswith("/tmp/"):
                continue  # never delete outside /tmp
            if p in seen:
                continue
            seen.add(p)
            real.append(p)
        except Exception:
            continue
    return real


def cleanup(verbose: bool = True) -> list[str]:
    """Delete matching tempfiles. Returns the list of paths removed."""
    removed: list[str] = []
    for p in _matches():
        try:
            os.remove(p)
            removed.append(p)
        except FileNotFoundError:
            pass
        except OSError:
            continue
    if verbose:
        if removed:
            print(f"[+] Cleaned {len(removed)} tempfile(s) from /tmp")
        # Silent when nothing to clean — usually the case with a happy run
    return removed


def list_matches() -> list[str]:
    """Debug helper — list what would be cleaned without deleting."""
    return _matches()
