"""Content Discovery Agent — dir/file brute-force + historical URLs.
Populates endpoints_found.
"""
from __future__ import annotations

import re

from agents.base import BaseAgent


class ContentDiscoveryAgent(BaseAgent):
    NAME = "content_discovery"
    DESCRIPTION = "Directory + file discovery (ffuf / feroxbuster / gau)"
    MAX_ITERATIONS = 8
    TOOL_NAMES = ["run_shell", "http_get", "finish"]

    SYSTEM_PROMPT = """/no_think

You are the CONTENT DISCOVERY AGENT. Find hidden paths, endpoints and
historical URLs on THE TARGET host given in the user message. Do NOT test
each finding for vulns — that is the vuln agent's job.

CRITICAL: use the EXACT target URL/host from the user message. NEVER use
example.com / example.org / target.com / placeholder domains. If unsure,
copy the "Primary host" verbatim from the user message.

Workflow (one tool_call per turn):
  1. gau <target-host>                  (Wayback + AlienVault; NOT example.*)
  2. waybackurls <target-host>          (backup source)
  3. katana -u <target-url> -silent -jc (JS crawl)
     — if the user message shows "Session cookie captured", add:
         katana -u <target-url> -silent -jc -H "Cookie: <cookie>"
       so authenticated pages are discovered too.
  4. ffuf -u <target-url>/FUZZ -w <wordlist> -mc all -rate 10 -o /tmp/f.txt
     — with cookie, add: -H "Cookie: <cookie>"
     — Wordlists to try in this order (use `ls` first if unsure):
        /opt/homebrew/share/seclists/Discovery/Web-Content/common.txt
        /opt/homebrew/share/seclists/Discovery/Web-Content/raft-small-words.txt
        /usr/share/seclists/Discovery/Web-Content/common.txt
  5. finish() with count of unique paths discovered on THE TARGET

Rules:
  - EVERY command must use the target host/URL from the user message.
    Replace <target-host> and <target-url> in the workflow above with it.
  - One tool_call per turn.
  - Keep rate ≤ 20 req/s at the tool level. The harness also rate-limits.
  - Deduplicate before reporting.
  - If a session cookie is available, ALWAYS pass it to katana + ffuf so
    the crawl discovers post-login endpoints (DVWA /vulnerabilities/*, WP
    /wp-admin/*, etc.). This is the difference between 0 and 20+ findings.
"""

    def entry_condition(self, state) -> bool:
        return state.has_live_http() or bool(state.get("target"))

    def build_objective(self, state) -> str:
        host = _first_live_host(state) or state.get("target")
        cookie_note = ""
        cookies = state.get("session_cookies", {}) or {}
        from urllib.parse import urlparse as _up
        primary_host = _up(host).hostname or host or ""
        for h, c in cookies.items():
            if h == primary_host or h in primary_host or primary_host in h:
                cookie_note = (f"\nSession cookie captured by login_probe: "
                                f"{c}\n"
                                "→ Add -H \"Cookie: <value>\" to your katana "
                                "and ffuf commands to discover post-login "
                                "endpoints. Use the EXACT value above.")
                break
        return (
            f"Primary host: {host}\n"
            f"Detected techs: {state.get('detected_techs', [])}"
            f"{cookie_note}\n\n"
            "Discover hidden paths + historical URLs. Finish with a "
            "deduped count."
        )

    def after_run(self, state, transcript):
        # Build a set of allowed hostnames from the target + in_scope_hosts.
        # Anything else discovered (Wayback / gau frequently returns URLs
        # from unrelated domains when a path matches) is dropped.
        from urllib.parse import urlparse as _up
        allowed_hosts: set[str] = set()
        target = state.get("target") or ""
        try:
            th = (_up(target).hostname or "").lower()
            if th:
                allowed_hosts.add(th)
        except Exception:
            pass
        for pat in state.get("in_scope_hosts") or []:
            # scope patterns can be exact hosts (localhost, api.example.com)
            # or wildcards (*.example.com); keep as substring seeds
            p = str(pat).lower().lstrip("*.").strip()
            if p:
                allowed_hosts.add(p)
        # Also seed from live_hosts (recon might have added canonical hostnames)
        for h in state.get("live_hosts") or []:
            host = str(h.get("host", "")).lower().split(":", 1)[0]
            if host:
                allowed_hosts.add(host)

        def _in_scope(url: str) -> bool:
            if not allowed_hosts:
                return True   # no scope → accept everything (warn/off modes)
            try:
                h = (_up(url).hostname or "").lower()
            except Exception:
                return False
            if not h:
                return False
            # Match exact or wildcard-suffix
            for allow in allowed_hosts:
                if h == allow or h.endswith("." + allow):
                    return True
            return False

        found: set[str] = set()
        dropped_off_scope = 0
        for entry in transcript:
            result = str(entry.get("result", ""))
            for m in re.finditer(r"https?://[^\s\"'<>]+", result):
                u = m.group(0)
                if _in_scope(u):
                    found.add(u)
                else:
                    dropped_off_scope += 1
        if dropped_off_scope:
            state.log(self.NAME, "info",
                      f"dropped {dropped_off_scope} URLs from other domains "
                      f"(gau/Wayback contamination) — kept only in-scope")
        if found:
            state.extend("endpoints_found",
                         [{"url": u, "via": "content_discovery"}
                          for u in sorted(found)])


def _first_live_host(state):
    hosts = state.get("live_hosts", [])
    if not hosts:
        return None
    h = hosts[0]
    scheme = h.get("scheme", "https")
    if scheme in ("http", "https"):
        return f"{scheme}://{h.get('host')}"
    return h.get("host")
