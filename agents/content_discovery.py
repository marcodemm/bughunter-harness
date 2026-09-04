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
        ../wordlists/quick-500.txt              ← DEFAULT (top-500, ~10× faster)
        /opt/homebrew/share/seclists/Discovery/Web-Content/common.txt
        /opt/homebrew/share/seclists/Discovery/Web-Content/raft-small-words.txt
        /usr/share/seclists/Discovery/Web-Content/common.txt
     — quick-500.txt lives INSIDE this harness (wordlists/quick-500.txt);
       resolve its absolute path from the harness root. It contains the
       500 most popular paths from raft-small-words-lowercase.txt and is
       ~10× faster than common.txt (4.7k) with ~90% of the discovery.
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
        # B4 URL validator: descarta URLs malformadas que gau/wayback/
        # katana ocasionalmente escupen — texto narrativo del LLM URL-
        # encoded (%5Cn), fragmentos de regex de plugins SEO en robots.txt
        # (`(?:...)?feed`), templates literales... Sin filtro llegan al
        # REPORT (visto en run 20260903T094840Z:
        # `.../%5Cn%5CnRecomendaciones:%5Cn%5Cn%E2%96%BA` y
        # `.../(?:.+/)?feed(?:/(?:.+/?)?)?$|/(?:.+/)?embed/...`).
        _BAD_URL_MARKERS = ("(?:", "?:", "\\n", "%5cn", "|/", "\\.",
                             "%e2%96%ba")
        # PN19 iter 10 (2026-09-04): the LLM commonly invokes
        # `ffuf -u https://x/FUZZ -w wordlist.txt` and the URL with the
        # placeholder ends up in stdout/log — parsed as an endpoint. The
        # /FUZZ endpoint then pollutes `endpoints_found` (HEAD-probes
        # 301, listed for the operator to open — dead lead). Same for
        # other common LLM/tool placeholders. Uses a boundary-anchored
        # regex to avoid false positives on real paths (e.g. `/fuzz`
        # must not eat `/fuzzy-search`, `/target.com/` must be a
        # placeholder, not a real target). Case-insensitive.
        _PLACEHOLDER_RE = re.compile(
            r"/(?:FUZZ|BASEURL|PLACEHOLDER|HOST|"
            r"\{\{[^/]*\}\}|<[^/>]+>|"
            r"example\.com|target\.com|domain\.com)"
            r"(?:[/?#]|$)",
            re.IGNORECASE,
        )

        def _is_valid_url(u: str) -> bool:
            if not u or not (u.startswith("http://")
                             or u.startswith("https://")):
                return False
            try:
                p = _up(u)
            except Exception:
                return False
            if not p.netloc:
                return False
            u_low = u.lower()
            if any(m in u_low for m in _BAD_URL_MARKERS):
                return False
            # PN19: reject URLs still carrying an ffuf/tool placeholder
            if _PLACEHOLDER_RE.search(u):
                return False
            if p.path and len(p.path) > 1:
                # Path que empieza por metachar regex tras el `/`
                if re.search(r"/[?(|\\]", p.path):
                    return False
            return True

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
        dropped_invalid = 0
        dropped_truncated = 0

        # N8 fix (2026-09-03): drop URLs that look TRUNCATED by an upstream
        # pipeline (e.g. `awk -F/ '{print $1,$2,$3,$4}'` on gau output
        # produces `.../analisis-impacto-` — a path ending in a dash with
        # no extension / no query params. Downstream fuzzer/scanner would
        # waste requests on nonsense.
        def _looks_truncated(u: str) -> bool:
            try:
                p = _up(u)
            except Exception:
                return True
            path = p.path or ""
            if not path or path == "/":
                return False  # bare root is fine
            # Trailing dash/underscore: probably truncated
            if path.rstrip().endswith(("-", "_")):
                return True
            return False

        def _harvest_urls_from_text(text: str) -> None:
            for m in re.finditer(r"https?://[^\s\"'<>]+", text):
                u = m.group(0).rstrip(".,;:'\"")  # trim trailing punctuation
                if not _is_valid_url(u):
                    nonlocal_stats["invalid"] += 1
                    continue
                if _looks_truncated(u):
                    nonlocal_stats["truncated"] += 1
                    continue
                if _in_scope(u):
                    found.add(u)
                else:
                    nonlocal_stats["off_scope"] += 1

        # Wrap mutable counters so the nested helper can update them.
        nonlocal_stats = {"invalid": 0, "truncated": 0, "off_scope": 0}
        for entry in transcript:
            _harvest_urls_from_text(str(entry.get("result", "")))

        # PN12 fix (2026-09-04): the LLM commonly redirects `gau`/`waybackurls`
        # output to a temp file with `> /tmp/gau.txt` and then only shows
        # `wc -l /tmp/gau.txt` in the shell result — stdout carries just
        # "3 /tmp/gau.txt", zero URLs, so the transcript scan above sees
        # nothing to harvest. Iter 7 run 20260904T063504Z lost all endpoints
        # to this class of bug (Endpoints=0). Fix: after the transcript scan,
        # also read the temp files the LLM created and harvest URLs from them.
        # Uses a conservative glob list to avoid pulling in wordlists or the
        # harness's own JSONL sinks.
        from pathlib import Path as _P
        tmp = _P("/tmp")
        if tmp.is_dir():
            _URL_TMP_GLOBS = (
                "gau*.txt", "target_gau*.txt", "wayback*.txt",
                "harness-gau*.txt", "harness-wayback*.txt",
                "harness-katana*.txt", "katana*.txt", "hakrawler*.txt",
                "harness-content*.txt", "urls*.txt", "endpoints*.txt",
            )
            _files_read = 0
            _bytes_read = 0
            _MAX_FILES = 12
            _MAX_BYTES = 4 * 1024 * 1024  # 4 MB safety cap
            for pattern in _URL_TMP_GLOBS:
                for path in sorted(tmp.glob(pattern)):
                    if _files_read >= _MAX_FILES:
                        break
                    try:
                        size = path.stat().st_size
                    except Exception:
                        continue
                    if size < 2 or _bytes_read + size > _MAX_BYTES:
                        continue
                    try:
                        with open(path, "r", encoding="utf-8",
                                   errors="ignore") as fh:
                            _harvest_urls_from_text(fh.read())
                    except Exception:
                        continue
                    _files_read += 1
                    _bytes_read += size
            if _files_read:
                state.log(self.NAME, "info",
                           f"PN12 fallback: harvested URLs from "
                           f"{_files_read} temp file(s) ({_bytes_read} bytes) "
                           f"— LLM redirected tool output to disk instead "
                           f"of stdout, so transcript scan missed them")

        dropped_invalid = nonlocal_stats["invalid"]
        dropped_truncated = nonlocal_stats["truncated"]
        dropped_off_scope = nonlocal_stats["off_scope"]
        if dropped_truncated:
            state.log(self.NAME, "info",
                      f"dropped {dropped_truncated} truncated URLs "
                      f"(trailing dash/underscore — likely awk|cut pipeline "
                      f"cut them mid-slug)")
        if dropped_off_scope:
            state.log(self.NAME, "info",
                      f"dropped {dropped_off_scope} URLs from other domains "
                      f"(gau/Wayback contamination) — kept only in-scope")
        if dropped_invalid:
            state.log(self.NAME, "info",
                      f"dropped {dropped_invalid} malformed URLs (regex "
                      f"fragments, LLM narrative text, escape sequences)")
        # PN10 fix (2026-09-04): HEAD-probe every candidate before
        # promoting to endpoints_found. `.well-known/*` are RFC 8615
        # canonical paths content_discovery probes on every target;
        # verification in-the-wild showed 8/8 of them return 404/500/000
        # on this class of target. Un-probed endpoints polluted the
        # REPORT and misled the operator into opening dead URLs. Now:
        #   endpoints_found          → status 2xx/3xx (real)
        #   endpoints_probed_negative → status 4xx/5xx/000 (attempted)
        # Report renders them in two separate sections.
        confirmed: list[dict] = []
        negative: list[dict] = []
        if found:
            try:
                import requests as _rq
            except Exception:
                _rq = None
            # Attribution headers from cfg
            _hdrs = {}
            for name, value in (self.cfg.get("custom_headers") or {}).items():
                if name and value:
                    _hdrs[str(name)] = str(value)
            _hdrs.setdefault("User-Agent",
                              "Mozilla/5.0 (compatible; bughunter-harness/1)")
            _seen_5xx: set[str] = set()
            for u in sorted(found):
                # Skip repeated 5xx paths on the same host to avoid MySQL
                # pool exhaust on unstable WP sites — many VDPs prohibit
                # anything that could hurt availability, so short-circuit
                # further requests to the same host after the first 5xx.
                host = _up(u).hostname or ""
                if host in _seen_5xx:
                    negative.append({"url": u, "via": "content_discovery",
                                      "status": None,
                                      "skipped_reason": "prior 5xx on host"})
                    continue
                if _rq is None:
                    confirmed.append({"url": u, "via": "content_discovery"})
                    continue
                try:
                    r = _rq.head(u, timeout=5, allow_redirects=False,
                                  verify=False, headers=_hdrs)
                    status = r.status_code
                except _rq.RequestException:
                    status = 0
                except Exception:
                    status = 0
                if 200 <= status < 400:
                    confirmed.append({"url": u, "via": "content_discovery",
                                       "status": status})
                else:
                    negative.append({"url": u, "via": "content_discovery",
                                      "status": status})
                    if 500 <= status < 600:
                        _seen_5xx.add(host)
                        state.log(self.NAME, "warn",
                                   f"{u} → HTTP {status}; short-circuiting "
                                   f"further probes on {host} to avoid "
                                   f"DoS-ish load on an unstable service")
                # Throttle: 0.5 req/s per probe (respects operational rules)
                import time as _t
                _t.sleep(0.5)
        if confirmed:
            state.extend("endpoints_found", confirmed)
        if negative:
            state.extend("endpoints_probed_negative", negative)
            state.log(self.NAME, "info",
                       f"HEAD-probe filter: {len(confirmed)} endpoint(s) "
                       f"confirmed status 2xx/3xx, {len(negative)} probed "
                       f"negative (4xx/5xx/000) — see REPORT sections")


def _first_live_host(state):
    hosts = state.get("live_hosts", [])
    if not hosts:
        return None
    h = hosts[0]
    scheme = h.get("scheme", "https")
    if scheme in ("http", "https"):
        return f"{scheme}://{h.get('host')}"
    return h.get("host")
