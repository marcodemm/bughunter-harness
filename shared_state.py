"""Findings/context shared across agents in an orchestrated run.

Every agent reads what previous agents put here and writes its own findings.
Serialised to sessions/<run_id>/state.json for auditability.

Standard keys (agents should stick to these, add new only if needed):
  target              str  — primary target URL or host (e.g. https://x.com)
  in_scope_hosts      list — hostnames explicitly authorized for this run
  subdomains          list — from Recon Agent (subfinder + friends)
  live_hosts          list of {host, port, scheme, status, tech?, title?}
  detected_techs      list — tags/names of stack (wordpress, dokploy, next.js…)
  endpoints_found     list — URL paths discovered (with method + status)
  secrets_found       list of {source, kind, redacted}
  cves_matched        list of {cve, target, evidence}
  findings            list of {agent, severity, title, evidence, recommendation}
  logs                list of {agent, ts, kind, msg}
  errors              list of {agent, ts, err}
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class SharedState:
    def __init__(self, run_dir: Path, target: str,
                 in_scope_hosts: list[str] | None = None):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.run_dir / "state.json"
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {
            "target": target,
            "in_scope_hosts": list(in_scope_hosts or []),
            "subdomains": [],
            "live_hosts": [],
            "detected_techs": [],
            "endpoints_found": [],
            "secrets_found": [],
            "cves_matched": [],
            "findings": [],
            "logs": [],
            "errors": [],
            "agents_run": [],
            # host → "PHPSESSID=abc; token=xyz" — harvested by login_probe
            "session_cookies": {},
        }
        self._save_unlocked()

    # ── read ────────────────────────────────────────────────────────
    def get(self, key: str, default=None):
        with self._lock:
            return self._data.get(key, default)

    def snapshot(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._data))

    def has_tech(self, name: str) -> bool:
        """Case-insensitive substring match against detected_techs."""
        name = name.lower()
        with self._lock:
            return any(name in str(t).lower() for t in self._data["detected_techs"])

    def has_live_http(self) -> bool:
        """True if the target OR any discovered live_host is HTTP/HTTPS."""
        with self._lock:
            t = str(self._data.get("target", "")).lower()
            if t.startswith("http://") or t.startswith("https://"):
                return True
            if any(h.get("scheme", "").startswith("http")
                   for h in self._data["live_hosts"]):
                return True
        return False

    def has_endpoint_matching(self, substrings: list[str]) -> bool:
        """True if any known URL (target + endpoints + live_hosts) contains
        any of the substrings (case-insensitive)."""
        subs_low = [s.lower() for s in substrings]
        with self._lock:
            haystack: list[str] = []
            haystack.append(str(self._data.get("target", "")).lower())
            for e in self._data["endpoints_found"]:
                haystack.append(str(e.get("url", "")).lower())
            for h in self._data["live_hosts"]:
                if h.get("host"):
                    haystack.append(str(h.get("host", "")).lower())
        for h in haystack:
            if any(s in h for s in subs_low):
                return True
        return False

    # ── write ───────────────────────────────────────────────────────
    def set(self, key: str, value):
        with self._lock:
            self._data[key] = value
            self._save_unlocked()

    def append(self, key: str, value):
        with self._lock:
            self._data.setdefault(key, []).append(value)
            self._save_unlocked()

    def extend(self, key: str, values):
        with self._lock:
            self._data.setdefault(key, []).extend(values)
            self._save_unlocked()

    def log(self, agent: str, kind: str, msg: str):
        self.append("logs", {"ts": _now_iso(), "agent": agent,
                             "kind": kind, "msg": msg[:400]})

    def error(self, agent: str, err: str):
        self.append("errors", {"ts": _now_iso(), "agent": agent,
                               "err": str(err)[:400]})

    def add_finding(self, agent: str, severity: str, title: str,
                    evidence: str = "", recommendation: str = ""):
        self.append("findings", {
            "ts": _now_iso(),
            "agent": agent,
            "severity": severity,
            "title": title,
            "evidence": evidence[:2000],
            "recommendation": recommendation[:2000],
        })

    def set_session_cookie(self, host: str, cookie: str) -> None:
        """Store a Cookie-header value for `host`, harvested by login_probe.
        Later agents' http_get/http_post + curl/nuclei/dalfox/sqlmap shell
        commands will send this cookie automatically."""
        if not host or not cookie:
            return
        with self._lock:
            self._data.setdefault("session_cookies", {})[host] = cookie
            self._save_unlocked()

    def get_session_cookie(self, host: str) -> str:
        """Return the Cookie header value for `host`, or '' if none."""
        if not host:
            return ""
        with self._lock:
            return self._data.get("session_cookies", {}).get(host, "")

    def has_session_cookie(self) -> bool:
        """True if login_probe stored at least one session cookie."""
        with self._lock:
            return bool(self._data.get("session_cookies"))

    def mark_agent_run(self, agent: str, status: str, elapsed_sec: float,
                       turns: int = 0, tool_calls: int = 0,
                       reason: str = ""):
        """Record an agent's outcome. `reason` is a short human-readable
        note explaining WHY a status was reached — especially useful for
        `skipped` so the report tells the operator why (quick mode /
        entry condition / target unreachable) instead of a silent skip."""
        self.append("agents_run", {
            "ts": _now_iso(),
            "agent": agent,
            "status": status,   # done | skipped | error
            "elapsed_sec": round(elapsed_sec, 1),
            "turns": turns,
            "tool_calls": tool_calls,
            "reason": (reason or "")[:200],
        })

    def _save_unlocked(self):
        try:
            self.path.write_text(json.dumps(self._data, indent=2,
                                            ensure_ascii=False),
                                 encoding="utf-8")
        except Exception:
            pass  # never let state save break a session


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
