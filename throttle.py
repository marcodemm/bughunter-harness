"""Global rate limiter. Enforced at the tool layer, NOT in the prompt.

The model cannot bypass this — every http_get / http_post / run_shell call
blocks until the min interval has elapsed.
"""
from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, min_interval_sec: float = 1.0):
        self.min_interval = float(min_interval_sec)
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last = time.monotonic()
