"""Screenshot extension agent (iter 14, 2026-09-04).

Runs `gowitness` against every live host discovered by recon+httpx to
produce a PNG per host + a browsable HTML gallery under
`<run_dir>/screenshots/`. Deterministic (no LLM turns) — the tool is
mechanical, no reasoning helps.

Position in pipeline: right after `content_discovery` (which is when
`state.live_hosts` is fully populated with tech-detected metadata).

Skips itself cleanly when:
  - `gowitness` is not installed (state.missing_tools populated by
    orchestrator._precheck_optional_tools at startup).
  - state.live_hosts is empty.
  - state.target_unreachable is set (nothing to shoot).

Publishes to state on success:
  - screenshots_dir            (absolute path to the PNG directory)
  - screenshots_captured       (list of {url, file, ok:bool})
  - screenshots_gallery_html   (path to the browsable gallery)

Config knobs (config.yaml → screenshot.*):
  screenshot:
    enabled: true                     # opt-out
    max_hosts: 50                     # cap the shoot to N first hosts
    timeout_per_host_sec: 15
    resolution: "1440,900"

Copy this file, rename NAME + class, if you want a variant for another
capture tool (eyewitness, aquatone). Everything else is orchestration
that stays the same.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from agents.base import BaseAgent


class ScreenshotAgent(BaseAgent):
    NAME = "screenshot"
    DESCRIPTION = "Visual triage — gowitness screenshots per live host"
    ENTRY_AFTER = "content_discovery"
    MAX_ITERATIONS = 0
    TOOL_NAMES = ["finish"]  # unused — we short-circuit .run()

    def entry_condition(self, state) -> bool:
        # Config opt-out
        cfg = (self.cfg.get("screenshot") or {}) if hasattr(self, "cfg") else {}
        if not cfg.get("enabled", True):
            return False
        # Skip if binary missing (populated by _precheck_optional_tools)
        missing = state.get("missing_tools") or []
        if "gowitness" in missing:
            return False
        # Skip if target unreachable / no live hosts
        if state.get("target_unreachable"):
            return False
        if not (state.get("live_hosts") or []):
            return False
        return True

    def run(self, state) -> str:
        """Override — no LLM; deterministic gowitness call."""
        started = time.time()
        self._emit("start", description=self.DESCRIPTION, max_iterations=1)
        try:
            cfg = (self.cfg.get("screenshot") or {}) if hasattr(self, "cfg") else {}
            max_hosts = int(cfg.get("max_hosts", 50))
            timeout_per_host = int(cfg.get("timeout_per_host_sec", 15))
            resolution = str(cfg.get("resolution", "1440,900"))

            # Belt-and-braces re-check (also done in entry_condition)
            if shutil.which("gowitness") is None:
                state.log(self.NAME, "info",
                          "gowitness not on PATH — skipping (install with "
                          "`go install github.com/sensepost/gowitness@latest`).")
                self._emit("done", elapsed=time.time() - started,
                           tool_calls=0, turns=0)
                state.mark_agent_run(self.NAME, "skipped",
                                     time.time() - started, 0, 0,
                                     reason="gowitness not installed")
                return "skipped"

            live = state.get("live_hosts") or []
            urls: list[str] = []
            for h in live[:max_hosts]:
                host = str(h.get("host", "")).strip()
                if not host:
                    continue
                scheme = h.get("scheme", "https")
                port = h.get("port", "")
                port_s = f":{port}" if port else ""
                urls.append(f"{scheme}://{host}{port_s}")
            if not urls:
                state.log(self.NAME, "info",
                          "no live hosts to screenshot — skipping.")
                self._emit("done", elapsed=time.time() - started,
                           tool_calls=0, turns=0)
                state.mark_agent_run(self.NAME, "skipped",
                                     time.time() - started, 0, 0,
                                     reason="live_hosts empty")
                return "skipped"

            shots_dir = self.run_dir / "screenshots"
            shots_dir.mkdir(parents=True, exist_ok=True)
            urls_file = shots_dir / "hosts.txt"
            urls_file.write_text("\n".join(urls) + "\n", encoding="utf-8")

            # gowitness v3+ CLI: `scan file -f <urls.txt> -s <dir> --write-db=false`
            # Older builds used `file -f <urls.txt> -P <dir>`; we probe by
            # trying the v3 form first and fall back to the v2 form on
            # non-zero exit.
            cmd_v3 = [
                "gowitness", "scan", "file",
                "-f", str(urls_file),
                "-s", str(shots_dir),
                "--timeout", str(timeout_per_host),
                "--chrome-window-x", resolution.split(",")[0],
                "--chrome-window-y", resolution.split(",")[1],
                "--write-db=false",
            ]
            cmd_v2 = [
                "gowitness", "file",
                "-f", str(urls_file),
                "-P", str(shots_dir),
                "--timeout", str(timeout_per_host),
            ]
            total_timeout = max(60, timeout_per_host * len(urls) + 30)
            state.log(self.NAME, "info",
                      f"gowitness scanning {len(urls)} host(s) → "
                      f"{shots_dir} (timeout {total_timeout}s)")

            proc = None
            used_cmd = cmd_v3
            try:
                proc = subprocess.run(cmd_v3, capture_output=True,
                                       text=True, timeout=total_timeout)
                if proc.returncode != 0:
                    state.log(self.NAME, "info",
                              "gowitness v3 syntax failed, retrying v2")
                    used_cmd = cmd_v2
                    proc = subprocess.run(cmd_v2, capture_output=True,
                                           text=True, timeout=total_timeout)
            except subprocess.TimeoutExpired:
                state.log(self.NAME, "warn",
                          f"gowitness timed out after {total_timeout}s — "
                          f"partial screenshots may still be on disk.")

            captured: list[dict] = []
            from urllib.parse import urlparse as _up
            for u in urls:
                # Iter 14 fix (2026-09-05): gowitness v3 writes `.jpeg`
                # by default (was `.png` in v2), and the filename keeps
                # the hostname's dots intact (e.g. `https---www.
                # example.com-443.jpeg`). Look up by literal hostname
                # and accept jpeg/jpg/png so both codebases match.
                hostname = _up(u).hostname or u.split("://", 1)[-1].split(
                    "/", 1)[0].split(":", 1)[0]
                imgs: list = []
                for ext in ("jpeg", "jpg", "png"):
                    imgs.extend(shots_dir.glob(f"*{hostname}*.{ext}"))
                # Fallback: v2-style slug with underscores
                if not imgs:
                    host_slug = hostname.replace(".", "_")
                    for ext in ("jpeg", "jpg", "png"):
                        imgs.extend(shots_dir.glob(f"*{host_slug}*.{ext}"))
                captured.append({
                    "url": u,
                    "file": str(imgs[0].relative_to(self.run_dir))
                            if imgs else "",
                    "ok": bool(imgs),
                })

            # Write a tiny HTML gallery so the operator can page through
            # thumbnails in one browser tab.
            gallery = shots_dir / "gallery.html"
            _write_gallery(gallery, captured, self.run_dir)

            state.set("screenshots_dir", str(shots_dir))
            state.set("screenshots_captured", captured)
            state.set("screenshots_gallery_html", str(gallery))
            ok_count = sum(1 for c in captured if c["ok"])
            state.log(self.NAME, "info",
                      f"gowitness: {ok_count}/{len(captured)} host(s) "
                      f"captured. Gallery: {gallery}")

            elapsed = time.time() - started
            self._emit("progress", turn=1, max_turns=1)
            self._emit("done", elapsed=elapsed, tool_calls=1, turns=1)
            state.mark_agent_run(self.NAME, "done", elapsed, 1, 1)
            return "done"
        except Exception as e:
            state.error(self.NAME, str(e))
            self._emit("error", err=str(e))
            state.mark_agent_run(self.NAME, "error",
                                 time.time() - started, 0, 0)
            return "error"


def _write_gallery(gallery_path: Path, captured: list[dict],
                    run_dir: Path) -> None:
    """Write a minimal responsive HTML gallery of the captured PNGs.
    All paths inside are relative to `run_dir` so the file works when
    the whole session directory is moved or shared."""
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>Screenshot gallery</title>",
        "<style>",
        "body{font-family:system-ui,sans-serif;background:#111;color:#eee;"
        "margin:0;padding:20px}",
        "h1{margin:0 0 12px 0;font-size:18px}",
        ".grid{display:grid;grid-template-columns:repeat(auto-fill,"
        "minmax(280px,1fr));gap:16px}",
        ".card{background:#1a1a1a;border-radius:6px;overflow:hidden;"
        "border:1px solid #2a2a2a}",
        ".card img{width:100%;height:auto;display:block;"
        "background:#000}",
        ".card .caption{padding:8px 10px;font-size:12px;"
        "word-break:break-all}",
        ".card .caption a{color:#7bb3ff;text-decoration:none}",
        ".card.err{opacity:.5}",
        "</style></head><body>",
        f"<h1>Screenshots — {len(captured)} host(s)</h1>",
        "<div class='grid'>",
    ]
    for c in captured:
        ok = c.get("ok")
        url = c.get("url", "")
        file_rel = c.get("file", "")
        # `file_rel` is relative to run_dir; gallery.html sits inside
        # `screenshots/` so we need the relative path from there.
        img_src = ""
        if file_rel:
            img_src = str(Path("..") / file_rel)
        cls = "card" if ok else "card err"
        parts.append(f"<div class='{cls}'>")
        if ok and img_src:
            parts.append(
                f"<a href='{img_src}' target='_blank'>"
                f"<img src='{img_src}' loading='lazy'></a>")
        parts.append(
            f"<div class='caption'>"
            f"<a href='{url}' target='_blank'>{url}</a>"
            f"{'' if ok else ' — <em>capture failed</em>'}"
            "</div></div>")
    parts.append("</div></body></html>")
    gallery_path.write_text("".join(parts), encoding="utf-8")
