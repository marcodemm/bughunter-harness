"""Login Probe Agent — attempts lab-only default credentials against a
detected login form, harvests the session cookie into SharedState so all
subsequent agents (content_discovery re-crawl, web_vuln sqlmap/dalfox,
api_fuzzer) run authenticated.

CRITICAL — this agent runs ONLY against clearly-labeled LAB / LOCAL targets:
  - hostname in {localhost, 127.0.0.1, ::1, *.local}
  - IP in private ranges (10/8, 172.16/12, 192.168/16)
  - URL/tech mentions dvwa / juice-shop / mutillidae / bwa / vulnhub / hackthebox

For real bug-bounty targets, entry_condition() returns False so this agent
is silently skipped. Never brute-forces — only tries a tiny curated list of
STOCK LAB defaults (admin:password, admin:admin, admin:vulnerables).

Harvested cookies are consumed by tools.py::_http (auto-injects Cookie header
on every http_get / http_post) and by web_vuln.py / content_discovery.py
(inject `-b "<cookie>"` on curl / `-H "Cookie: ..."` on nuclei / ffuf).
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urljoin, urlparse

import requests

from agents.base import BaseAgent


# Curated defaults per common lab target. Order matters — first hit wins.
# Never expand this list beyond well-known deliberately-vulnerable apps.
LAB_DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "password"),       # DVWA, Mutillidae, many labs
    ("admin", "admin"),           # generic
    ("admin", "vulnerables"),     # bWAPP, WebGoat sometimes
    ("root", "root"),             # generic
    ("user", "user"),             # generic lab
    ("test", "test"),             # generic lab
]

# Signals that a target is a LAB — used by entry_condition and prompt.
LAB_TECH_HINTS = ["dvwa", "juice shop", "juiceshop", "juice-shop",
                  "mutillidae", "bwapp", "vulnerables/", "vulnhub",
                  "hackthebox", "webgoat", "bee-box"]


class LoginProbeAgent(BaseAgent):
    NAME = "login_probe"
    DESCRIPTION = "Lab-only default-cred probe → harvest session cookie"
    MAX_ITERATIONS = 6
    TOOL_NAMES = ["run_shell", "http_get", "http_post", "finish"]
    # Skipped in quick mode — lab-only default-cred probing is a full-scan
    # activity; quick mode is for triage.
    RUNS_IN_QUICK = False

    SYSTEM_PROMPT = """/no_think

You are the LOGIN PROBE AGENT. Your ONLY job is to try 3-4 stock LAB
default-credential pairs against a detected login form and — if one works —
capture the Set-Cookie header for the next agents to use.

CRITICAL RULES:
  - You run ONLY when the target is a KNOWN LAB (localhost / private IP /
    DVWA / Juice Shop / Mutillidae / bWAPP / WebGoat). If in doubt, call
    finish() with an empty findings list.
  - You NEVER try more than 6 credential pairs. This is NOT brute force.
  - You NEVER touch real bug-bounty targets. Reject anything else.
  - You do NOT report findings — capturing a lab cookie is expected, not a vuln.

Workflow (one tool_call per turn):
  1. curl -s -c /tmp/harness-cookies.txt <login-url>
       (get initial CSRF token / session cookie if any)
  2. For each (user, pass) in the small default list, POST to the login
     endpoint. Watch for Set-Cookie changes AND for a 302 to a
     post-login page AND for absence of the "wrong credentials" text.
       Example DVWA:
         curl -s -c /tmp/harness-cookies.txt -b /tmp/harness-cookies.txt \
           -X POST -d "username=admin&password=password&Login=Login&user_token=<tok>" \
           http://localhost:8080/login.php -o /tmp/login-out.html -w "%{http_code}\\n"
  3. finish() with a one-line summary of what worked (or nothing).

Do NOT waste turns on:
  - Password bruteforce beyond the 6 stock pairs.
  - CAPTCHA solving.
  - 2FA bypass.
  - Non-lab targets.
"""

    # ── gates ─────────────────────────────────────────────────────
    def entry_condition(self, state) -> bool:
        target = str(state.get("target") or "")
        techs = " ".join(str(t).lower()
                         for t in state.get("detected_techs", []))
        # Must be a lab: localhost / private IP / lab tech marker
        if not (_is_local_or_private(target) or _tech_is_lab(techs)):
            return False
        # Must have found a login-like endpoint
        return state.has_endpoint_matching(
            ["/login", "/signin", "/wp-login", "/admin/login",
             "login.php", "signin.aspx"]
        )

    def build_objective(self, state) -> str:
        target = state.get("target")
        login_hits = [e.get("url") for e in state.get("endpoints_found", [])
                      if _is_login_url(str(e.get("url", "")))]
        techs = state.get("detected_techs", [])
        return (
            f"Primary target: {target}\n"
            f"Detected techs: {techs}\n"
            f"Login endpoints detected: {login_hits[:5]}\n\n"
            "Try lab-default creds (admin/password, admin/admin) against the "
            "login form. On success, finish() with a one-line note. "
            "Do NOT run more than 6 attempts total."
        )

    # ── main override: skip LLM loop for the deterministic probe ──
    def run(self, state):
        """Skip the LLM loop — do the probe deterministically. It's a fixed
        6-attempt lab probe; giving a 27B model 6 shots at wiring a POST
        with CSRF tokens burns 10 minutes for something we can do in code."""
        import time as _t
        started = _t.time()

        primary = _primary_url(state) or state.get("target")
        if not primary:
            self._finalize(state, started, "no target url")
            return "no-target"

        # Pick login URLs whose hostname matches the target's — content_discovery
        # (via gau/Wayback) often adds URLs from other websites when the path
        # collides. Login-probing /alfresco/service/api/login on an unrelated
        # domain is pointless AND wastes credentials attempts.
        primary_host = (urlparse(primary).hostname or "").lower()
        primary_port = urlparse(primary).port
        primary_netloc = urlparse(primary).netloc.lower()

        def _same_host(url: str) -> bool:
            try:
                p = urlparse(url)
            except Exception:
                return False
            h = (p.hostname or "").lower()
            nl = p.netloc.lower()
            if not h:
                return False
            # Match on host OR netloc so localhost and localhost:8080 both
            # count when the target is localhost:8080.
            return (h == primary_host
                    or nl == primary_netloc
                    or (primary_port and h == primary_host))

        login_urls = [e.get("url") for e in state.get("endpoints_found", [])
                      if _is_login_url(str(e.get("url", "")))
                      and _same_host(str(e.get("url", "")))]
        # Always append the canonical login paths on the primary host as
        # fallbacks — the harvester may have missed them.
        fallback_paths = ["/login.php", "/login", "/wp-login.php",
                          "/admin/login", "/user/login"]
        fallbacks = [urljoin(primary, p) for p in fallback_paths]
        # Combine, de-dupe preserving order, top-3
        seen = set()
        candidates = []
        for u in login_urls + fallbacks:
            if u and u not in seen:
                seen.add(u)
                candidates.append(u)
        candidates = candidates[:5]

        session = requests.Session()
        # Inherit custom headers from ToolRegistry (attribution etc.)
        if getattr(self.tool_registry, "custom_headers", None):
            session.headers.update(self.tool_registry.custom_headers)

        for login_url in candidates:
            host_ok, _ = self.tool_registry._scope_gate(
                urlparse(login_url).hostname or "", "login_probe")
            if not host_ok:
                state.log(self.NAME, "info",
                          f"login candidate off-scope: {login_url}")
                continue

            # 1. GET to harvest initial cookies + potential CSRF token
            try:
                r0 = session.get(login_url, timeout=10,
                                 allow_redirects=True, verify=False)
            except Exception as e:
                state.log(self.NAME, "error",
                          f"GET {login_url} failed: {type(e).__name__}")
                continue
            if r0.status_code >= 400:
                state.log(self.NAME, "info",
                          f"login GET {login_url} → {r0.status_code} (skip)")
                continue

            html = r0.text[:20000]
            csrf_token = _extract_csrf_token(html)
            form_field_user, form_field_pass = _detect_field_names(html)

            state.log(self.NAME, "info",
                      f"login form at {login_url}: "
                      f"user_field={form_field_user!r}, "
                      f"pass_field={form_field_pass!r}, "
                      f"csrf={'yes' if csrf_token else 'no'}")

            # 2. Try each default cred pair
            for user, pw in LAB_DEFAULT_CREDS:
                self.tool_registry.limiter.wait()
                data = {form_field_user: user, form_field_pass: pw}
                # DVWA-specific extra fields
                if "dvwa" in login_url.lower() or "8080" in login_url:
                    data["Login"] = "Login"
                # WordPress
                if "wp-login" in login_url:
                    data.update({"log": user, "pwd": pw,
                                 "wp-submit": "Log In",
                                 "redirect_to": primary, "testcookie": "1"})
                if csrf_token:
                    # DVWA uses user_token; WP/Django/others vary — cover the
                    # most common field names.
                    for tok_field in ("user_token", "csrfmiddlewaretoken",
                                       "_csrf", "_token", "authenticity_token"):
                        data[tok_field] = csrf_token

                try:
                    r = session.post(login_url, data=data,
                                     timeout=10, allow_redirects=False,
                                     verify=False)
                except Exception as e:
                    state.log(self.NAME, "error",
                              f"POST {login_url} {user}: "
                              f"{type(e).__name__}")
                    continue

                # Success heuristics:
                #   (a) 302 redirect away from login page
                #   (b) new session cookie set + not on login page anymore
                #   (c) response body no longer contains "login incorrect"
                cookies_after = "; ".join(f"{k}={v}"
                                           for k, v in session.cookies.items())
                is_redirect = r.status_code in (301, 302, 303, 307)
                loc = r.headers.get("Location", "")
                looks_success = (
                    is_redirect and "login" not in loc.lower()
                ) or (
                    r.status_code == 200
                    and cookies_after
                    and not _has_login_failure_marker(r.text)
                )

                if looks_success:
                    host = urlparse(login_url).hostname or ""
                    if cookies_after:
                        state.set_session_cookie(host, cookies_after)
                    state.log(self.NAME, "info",
                              f"login OK: {user}:*** at {login_url} "
                              f"→ HTTP {r.status_code} loc={loc[:80]} "
                              f"cookies={len(session.cookies)} stored")
                    self._finalize(state, started,
                                   f"cookie captured from {login_url} "
                                   f"with {user}:*** (6 default pairs tried)")
                    return "login-ok"
                else:
                    state.log(self.NAME, "info",
                              f"login FAIL: {user} at {login_url} "
                              f"→ HTTP {r.status_code}")

        self._finalize(state, started, "no lab creds worked")
        return "no-login"

    def _finalize(self, state, started, summary):
        import time as _t
        elapsed = _t.time() - started
        state.mark_agent_run(self.NAME, "done", elapsed, turns=1, tool_calls=0)
        # Store the deterministic summary so it appears in the REPORT.md
        # under "Agent Narrative Summaries" like every other agent.
        state.append("agent_summaries", {
            "agent": self.NAME,
            "summary": summary[:2000],
        })
        self._emit("done", elapsed=elapsed, summary=summary)


# ── helpers ─────────────────────────────────────────────────────────

def _primary_url(state) -> str:
    hosts = state.get("live_hosts", [])
    if hosts:
        h = hosts[0]
        return f"{h.get('scheme', 'https')}://{h.get('host')}"
    return state.get("target") or ""


def _is_local_or_private(target: str) -> bool:
    try:
        host = urlparse(target).hostname or target
    except Exception:
        host = target
    host = (host or "").lower().strip()
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return True
    if host.endswith(".local"):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_loopback or addr.is_private or addr.is_reserved
    except ValueError:
        return False


def _tech_is_lab(techs_lower: str) -> bool:
    return any(hint in techs_lower for hint in LAB_TECH_HINTS)


def _is_login_url(url: str) -> bool:
    low = url.lower()
    return any(m in low for m in
               ("/login", "/signin", "/wp-login", "/admin/login",
                "login.php", "signin.aspx", "/session/new"))


def _extract_csrf_token(html: str) -> str:
    # DVWA: <input type="hidden" name="user_token" value="..." />
    # WP:   <input type="hidden" name="wpnonce" value="..." />
    # Django: name="csrfmiddlewaretoken"
    # Rails: name="authenticity_token"
    patterns = [
        r'name=["\']user_token["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']csrf["\'][^>]*value=["\']([^"\']+)["\']',
        # Reverse (value first, name second)
        r'value=["\']([^"\']+)["\'][^>]*name=["\']user_token["\']',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _detect_field_names(html: str) -> tuple[str, str]:
    """Return (user_field, pass_field) — best-effort from the HTML.
    Defaults to ('username', 'password') if not found."""
    user_field, pass_field = "username", "password"
    # <input ... name="..." ... type="password">
    m = re.search(r'name=["\']([^"\']+)["\'][^>]*type=["\']password["\']',
                  html, re.IGNORECASE)
    if not m:
        m = re.search(r'type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
                      html, re.IGNORECASE)
    if m:
        pass_field = m.group(1)
    # Try to find the username field — first text/email input before password
    m2 = re.search(
        r'name=["\']([^"\']+)["\'][^>]*type=["\'](?:text|email)["\']',
        html, re.IGNORECASE)
    if m2:
        user_field = m2.group(1)
    else:
        # Common names
        for cand in ("username", "user", "email", "login", "log", "userid"):
            if re.search(rf'name=["\']{cand}["\']', html, re.IGNORECASE):
                user_field = cand
                break
    return user_field, pass_field


def _has_login_failure_marker(html: str) -> bool:
    low = html.lower()
    markers = [
        "login failed", "invalid credentials", "incorrect password",
        "wrong password", "authentication failed", "bad username",
        "invalid username", "please try again", "invalid login",
        "credenciales", "usuario o contraseña", "wrong user", "no autorizado",
    ]
    return any(m in low for m in markers)
