"""Simple background spinner shown while a tool call is running.

Writes to stderr on a single line, updated every 200ms. On stop() the line is
cleared and the terminal cursor returns to column 0, so the harness's
`[tool←]` line renders cleanly right after.
"""
from __future__ import annotations

import itertools
import sys
import threading
import time

_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class Spinner:
    def __init__(self, label: str, timeout_sec: int):
        self.label = label
        self.timeout = int(timeout_sec)
        self._stop = threading.Event()
        self._start = 0.0
        self._thread: threading.Thread | None = None
        # Only animate on a TTY; on non-interactive stderr (piped, log file)
        # we print one static line at start and nothing else.
        self._interactive = sys.stderr.isatty()

    def __enter__(self):
        self._start = time.monotonic()
        if self._interactive:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        else:
            sys.stderr.write(f"  … {self.label} (timeout {self.timeout}s)\n")
            sys.stderr.flush()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        if self._interactive:
            # Wipe the spinner line and return to column 0
            sys.stderr.write("\r" + " " * 90 + "\r")
            sys.stderr.flush()

    def _loop(self):
        frames = itertools.cycle(_FRAMES)
        while not self._stop.is_set():
            elapsed = int(time.monotonic() - self._start)
            # Cap the visible label so it fits terminals ~90 cols wide
            label = self.label if len(self.label) <= 60 else self.label[:57] + "..."
            frame = next(frames)
            bar = f"\r  {frame} {label} · {elapsed}s / {self.timeout}s "
            sys.stderr.write(bar)
            sys.stderr.flush()
            time.sleep(0.2)
