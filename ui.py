"""Multi-agent progress panel (rich-based).

The Orchestrator instantiates one MultiAgentUI, then registers agents. Each
BaseAgent emits events via its progress_hook (start/progress/done/skipped/error)
and the UI updates a rich.Live panel with per-agent status.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

try:
    from rich.console import Console
    from rich.live import Live
    from rich.progress import (BarColumn, Progress, SpinnerColumn,
                               TaskProgressColumn, TextColumn,
                               TimeElapsedColumn)
    from rich.table import Table
    _HAVE_RICH = True
except Exception:  # pragma: no cover
    _HAVE_RICH = False


class MultiAgentUI:
    def __init__(self, agent_names: list[str]):
        self.agent_names = list(agent_names)
        self._lock = threading.Lock()
        self._states: dict[str, dict] = {
            n: {"status": "queued", "turn": 0, "max": 1,
                "elapsed": 0.0, "tool_calls": 0, "note": ""}
            for n in self.agent_names
        }
        self._start_ts: dict[str, float] = {}
        self._live: Optional[Live] = None
        self._console = Console() if _HAVE_RICH else None
        self._enabled = _HAVE_RICH and self._console.is_terminal

    def __enter__(self):
        if self._enabled:
            self._live = Live(self._render(), console=self._console,
                              refresh_per_second=5, transient=False)
            self._live.__enter__()
        else:
            self._plain_start()
        return self

    def __exit__(self, exc_type, exc, tb):
        # Final refresh so the panel shows final states
        if self._enabled and self._live:
            self._live.update(self._render())
            self._live.__exit__(exc_type, exc, tb)
        else:
            self._plain_end()

    def hook(self, name: str, event: str, **kw):
        with self._lock:
            st = self._states.setdefault(name, {"status": "queued",
                                                 "turn": 0, "max": 1,
                                                 "elapsed": 0.0,
                                                 "tool_calls": 0, "note": ""})
            if event == "start":
                st["status"] = "running"
                st["max"] = int(kw.get("max_iterations", 1)) or 1
                st["note"] = kw.get("description", "")
                self._start_ts[name] = time.monotonic()
            elif event == "progress":
                st["turn"] = int(kw.get("turn", st["turn"]))
                st["max"] = int(kw.get("max_turns", st["max"])) or 1
                st["elapsed"] = time.monotonic() - self._start_ts.get(
                    name, time.monotonic())
            elif event == "done":
                st["status"] = "done"
                st["elapsed"] = float(kw.get("elapsed", st["elapsed"]))
                st["tool_calls"] = int(kw.get("tool_calls", st["tool_calls"]))
                st["turn"] = int(kw.get("turns", st["turn"]))
                st["note"] = f"{st['tool_calls']} tool calls"
            elif event == "skipped":
                st["status"] = "skipped"
                st["note"] = kw.get("reason", "not applicable")
            elif event == "error":
                st["status"] = "error"
                st["note"] = str(kw.get("err", "error"))[:60]
        if self._enabled and self._live:
            self._live.update(self._render())
        else:
            self._plain_line(name)

    def notify(self, msg: str):
        """Non-agent narrator lines (orchestrator decisions)."""
        if self._enabled and self._console:
            self._console.print(f"[dim]→[/dim] {msg}")
        else:
            print(f"→ {msg}")

    # ── rich render ─────────────────────────────────────────────────
    def _render(self):
        if not _HAVE_RICH:
            return None
        table = Table(title="ORCHESTRATOR — agent pipeline",
                      title_style="bold cyan",
                      show_lines=False, header_style="bold")
        table.add_column("", width=2, no_wrap=True)
        table.add_column("Agent", style="cyan", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Progress", ratio=2)
        table.add_column("Elapsed", justify="right", no_wrap=True)
        table.add_column("Note", ratio=2)

        icons = {"queued": "[dim]○[/dim]",
                 "running": "[yellow]▶[/yellow]",
                 "done": "[green]✔[/green]",
                 "skipped": "[dim]–[/dim]",
                 "error": "[red]✗[/red]"}
        status_style = {"queued": "dim",
                        "running": "yellow bold",
                        "done": "green",
                        "skipped": "dim",
                        "error": "red bold"}

        with self._lock:
            for name in self.agent_names:
                st = self._states[name]
                status = st["status"]
                pct = int(100 * st["turn"] / max(1, st["max"])) \
                      if status == "running" else \
                      (100 if status in ("done", "skipped") else 0)
                bar_width = 24
                filled = int(bar_width * pct / 100)
                bar = "█" * filled + "░" * (bar_width - filled)
                bar_col = ("green" if status == "done" else
                           "yellow" if status == "running" else
                           "red" if status == "error" else "dim")
                elapsed = f"{st['elapsed']:.0f}s"
                table.add_row(
                    icons[status],
                    name,
                    f"[{status_style[status]}]{status.upper()}[/]",
                    f"[{bar_col}]{bar}[/] {pct:>3d}%",
                    elapsed,
                    st["note"],
                )
        return table

    # ── plain fallback ──────────────────────────────────────────────
    def _plain_start(self):
        print("[orchestrator] agents queued:", ", ".join(self.agent_names))

    def _plain_end(self):
        print("[orchestrator] pipeline complete.")

    def _plain_line(self, name: str):
        st = self._states.get(name, {})
        print(f"  [{st.get('status','?').upper():>7s}] {name}"
              f"  {st.get('turn',0)}/{st.get('max',0)} turns"
              f"  {st.get('elapsed',0):.0f}s"
              f"  {st.get('note','')}")
