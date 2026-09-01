"""Auth Agent — dispatched if a login/auth endpoint or panel was found.
Focuses on auth-bypass CVEs, not credential brute-force.
"""
from __future__ import annotations

import re

from agents.base import BaseAgent

AUTH_HINTS = ["/login", "/signin", "/sign-in", "/auth", "/oauth",
              "/sso", "/wp-login", "/admin", "/manage", "/console",
              "/dashboard"]


class AuthAgent(BaseAgent):
    NAME = "auth"
    DESCRIPTION = "Auth-bypass + SSO/OAuth misconfig check"
    MAX_ITERATIONS = 10
    TOOL_NAMES = ["run_shell", "http_get", "http_post", "finish"]

    SYSTEM_PROMPT = """/no_think

You are the AUTH AGENT. Only dispatched when a login/auth endpoint or
admin panel was discovered on the ACTUAL target.

Focus: authentication bypass, SSO/OAuth misconfig, session flaws. NEVER
attempt credential brute-force or dictionary attacks.

CRITICAL — DO NOT INVENT ENDPOINTS FROM MEMORY:
  Every URL you test MUST come from the "Auth endpoints found" list in the
  user message OR be a small, tech-appropriate variant of one of them.
  Do NOT probe /admin-console/secure/summary.seam (JBoss Seam),
  /alfresco/service/api/login (Alfresco),
  /manager/html (Tomcat manager),
  /wp-admin/admin-ajax.php (WordPress) — unless the corresponding tech
  (jboss / seam / alfresco / tomcat / wordpress) is in "Detected techs".
  Probing endpoints unrelated to the detected stack wastes turns.

Workflow (one tool_call per turn, ≤6 total turns):
  1. curl -sI <login-url-from-list>   (headers, framework hints)
  2. nuclei -u <primary-host> -tags auth-bypass,exposed-panels \
       -severity medium,high,critical -rl 5 -c 5 -silent
     (Note: nuclei will only fire tech-appropriate templates; do NOT
     also try random per-product tags outside detected_techs.)
  3. IF the detected tech has a well-known post-login area, curl to it
     with the harvested session cookie (already auto-injected by the
     harness). Examples:
       - dvwa → /vulnerabilities/, /security.php
       - juice-shop → /rest/user/whoami, /api/Users
       - wordpress → /wp-admin/, /wp-json/wp/v2/users
     If none apply, skip this step.
  4. Check for auth flaws on the endpoints already in scope:
     - JWT: none/HS-to-RS confusion (only if JWTs were seen)
     - OAuth: redirect_uri wildcard, missing state check
     - 401 vs 403: verb tampering on ONE known endpoint
  5. finish() with findings — do NOT include any real credentials

Rules:
  - One tool_call per turn.
  - PoC is enough. Do not chain further exploitation.
  - EVERY URL you probe must come from the endpoints list OR the target's
    detected techs. NO memory-based guesses of "typical admin panels".
"""

    def entry_condition(self, state) -> bool:
        return state.has_endpoint_matching(AUTH_HINTS)

    def build_objective(self, state) -> str:
        host = _primary_url(state)
        auth_hits = [e.get("url") for e in state.get("endpoints_found", [])
                     if any(h in str(e.get("url", "")).lower()
                            for h in AUTH_HINTS)]
        techs = state.get("detected_techs", [])[:8]
        cookie_note = ""
        cookies = state.get("session_cookies", {}) or {}
        from urllib.parse import urlparse as _up
        primary_host = _up(host).hostname or ""
        for h, c in cookies.items():
            if h == primary_host or h in primary_host or primary_host in h:
                cookie_note = (f"\nSession cookie captured by login_probe: "
                                f"{c}\n(auto-injected on http_get/http_post; "
                                f"add -H \"Cookie: {c}\" to curl/nuclei "
                                f"commands manually).")
                break
        return (
            f"Primary host: {host}\n"
            f"Detected techs: {techs}\n"
            f"Auth endpoints found: {auth_hits[:10]}{cookie_note}\n\n"
            "Check for auth-bypass and misconfig. No brute-force. "
            "Do NOT probe endpoints from other tech stacks."
        )

    def after_run(self, state, transcript):
        pattern = re.compile(
            r"\[([\w\-]+)\]\s*\[\w+\]\s*\[(medium|high|critical)\]\s*(\S+)"
        )
        # nuclei-style output → structured findings
        for entry in transcript:
            result = str(entry.get("result", ""))
            if entry.get("tool") == "run_shell":
                for m in pattern.finditer(result):
                    state.add_finding(
                        agent=self.NAME, severity=m.group(2),
                        title=f"auth/{m.group(1)} on {m.group(3)}",
                        evidence=m.group(0),
                        recommendation="Verify manually and report")

            # Auto-detect: admin-like path returning 200 without auth challenge.
            # Guarded against SPA false positives (Next.js/React/Vue apps that
            # render an empty <div id="__next"></div> shell and redirect via
            # client-side JS — `curl` sees the shell as 200 but the app is
            # actually protected).
            if entry.get("tool") == "http_get":
                url = str(entry.get("args", {}).get("url", "")).lower()
                is_admin_path = any(seg in url for seg in
                                    ("/admin", "/manage", "/console",
                                     "/dashboard", "/administrator"))
                if is_admin_path and "HTTP 200" in result:
                    body_lower = result.lower()

                    # SPA shell signals — if any of these are present, it's
                    # almost certainly a client-side-auth SPA, NOT a bypass.
                    spa_markers = [
                        '<div id="__next">',        # Next.js
                        'id="__next"',
                        '<div id="root">',          # CRA / Vite / Vue
                        'id="app"',                 # Vue / Nuxt
                        'data-reactroot',
                        'ng-version=',              # Angular
                        '/_next/static/',
                        '/_nuxt/',
                        '"application/javascript"',
                        'window.__nuxt__',
                        'window.__next_data__',
                    ]
                    is_spa_shell = any(m in body_lower for m in spa_markers)

                    # A login form in the body is the classic "protected".
                    has_login_form = (
                        "<form" in body_lower
                        and ("password" in body_lower
                             or "sign in" in body_lower
                             or "login" in body_lower)
                    )

                    # Real bypass signals — the response actually contains
                    # data or admin-panel-content, not just a shell.
                    admin_data_markers = [
                        "manage users", "user list", "list of users",
                        "teams overview", "site settings", "database",
                        '"users":[', '"teams":[', '"admin":true',
                        "delete user", "reset password",
                    ]
                    has_admin_data = any(m in body_lower
                                         for m in admin_data_markers)

                    if has_login_form:
                        # Server-side rendered login = protected (normal)
                        pass
                    elif is_spa_shell and not has_admin_data:
                        # SPA with client-side auth — likely a false positive.
                        # Log as info-level breadcrumb for manual review,
                        # NOT as a HIGH finding.
                        state.add_finding(
                            agent=self.NAME, severity="info",
                            title=(f"Admin path returns 200 but body is SPA "
                                   f"shell (probable client-side auth): {url}"),
                            evidence=("HTTP 200 with SPA framework markers; "
                                      "verify manually in a real browser — "
                                      "SPA usually redirects to /login via JS."),
                            recommendation=("Manual verify with browser + "
                                            "network tab; check that /api/* "
                                            "endpoints also require auth."))
                    elif has_admin_data:
                        # Actual admin content in the body = HIGH.
                        state.add_finding(
                            agent=self.NAME, severity="high",
                            title=f"Admin panel accessible without auth: {url}",
                            evidence=result[:500],
                            recommendation=("Add server-side auth middleware. "
                                            "Verify with fresh cookie-jar."))
                    else:
                        # Ambiguous — flag as low for manual review
                        state.add_finding(
                            agent=self.NAME, severity="low",
                            title=(f"Admin path returns 200, "
                                   f"needs manual verification: {url}"),
                            evidence=result[:400],
                            recommendation=("Verify manually whether real "
                                            "admin data is exposed."))


def _primary_url(state):
    hosts = state.get("live_hosts", [])
    if hosts:
        h = hosts[0]
        return f"{h.get('scheme','https')}://{h.get('host')}"
    return state.get("target")
