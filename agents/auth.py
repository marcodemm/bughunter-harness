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
    # Skipped in quick mode — auth-bypass hunting benefits from the full
    # endpoints_found list content_discovery builds in full mode.
    RUNS_IN_QUICK = False

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
                # PN21 iter 13 (2026-09-04): parse WordPress-specific
                # unauth-info endpoints that the LLM commonly probes but
                # doesn't always promote to a finding via its finish()
                # narrative. Regression trigger: run 20260904T181945Z ran
                # `curl -s .../wp-json/wp/v2/users` (exit=0, 200 body)
                # and 14 other tool calls over 44 min, but the auth agent
                # after_run parser had no branch for it → 0 findings, 0
                # narrative. A prior run against a different WordPress target got the finding only
                # because the LLM happened to remember to call add_finding
                # from its finish() summary; not a robust guarantee.
                _wp_user_enum(state, self.NAME, entry, result)
            # http_get with the SAME endpoint — the harness's native tool
            # also produces a body that we can parse deterministically.
            if entry.get("tool") == "http_get":
                _wp_user_enum(state, self.NAME, entry, result)

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


def _wp_user_enum(state, agent_name: str, entry: dict, result: str) -> None:
    """PN21 iter 13 (2026-09-04): parse WordPress unauth-user-enumeration
    signals from a shell/http_get result and emit a finding when the
    output shows the classic REST-API JSON array of users.

    Fired by both `run_shell` (curl) and `http_get` branches — either
    tool the LLM chose to hit `/wp-json/wp/v2/users` (or `/users/<id>`,
    or `/?author=1`) leaves a signature in the response body that we
    can detect independently of the LLM narrative summary.

    Idempotent — checks `state.findings` for a pre-existing finding
    with the same title before adding (LLM's finish() may already have
    emitted it)."""
    if not result:
        return
    cmd = str(entry.get("args", {}).get("command", ""))
    url_arg = str(entry.get("args", {}).get("url", ""))
    signature = (cmd + " " + url_arg).lower()
    if "/wp-json/wp/v2/users" not in signature and \
       "/?author=" not in signature:
        return
    # Signature 1: JSON array response `[{"id":<n>,"slug":"…"}]` — WP
    # REST returns this for /wp-json/wp/v2/users when unauth-readable.
    import re as _re
    users: list[dict] = []
    m = _re.search(r"\[\s*\{[^\[\]]{0,200}?\"id\"\s*:\s*\d+", result)
    if m:
        for u in _re.finditer(r'"id"\s*:\s*(\d+)[^{}]*?'
                               r'"slug"\s*:\s*"([^"]+)"[^{}]*?'
                               r'(?:"name"\s*:\s*"([^"]*)")?', result):
            users.append({
                "id": u.group(1),
                "slug": u.group(2),
                "name": u.group(3) or "",
            })
    # Signature 2: /?author=<N> → Location redirect leaking the slug in
    # the wp-json canonical URL.
    if not users and "/?author=" in signature:
        m2 = _re.search(r"location:\s*https?://[^/]+/author/([^/\s]+)/?",
                         result, _re.IGNORECASE)
        if m2:
            users.append({"id": "?", "slug": m2.group(1), "name": ""})
    if not users:
        return
    # Extract target host from url_arg or cmd
    _url = _re.search(r"https?://[^\s\"'<>]+", url_arg + " " + cmd)
    target = _url.group(0) if _url else _primary_url(state)

    # PN23 iter 15 (2026-09-05): distinguish two cases that used to be
    # collapsed under one INFO finding:
    #   (a) TRUE CVE-2023-5561 — the JSON response carries an explicit
    #       `"email":"user@host"` field. Fix WP 6.4.1 was NOT applied
    #       OR a plugin re-exposes the field. Real MEDIUM severity.
    #   (b) Gravatar-hash + slug-leak — the JSON has NO `email` field
    #       but `avatar_urls` carry the Gravatar SHA-256 of the email
    #       (WordPress default). Combined with the `slug` (which is
    #       created from the username, often the email itself), an
    #       attacker can reverse the hash offline against a wordlist of
    #       common corporate email prefixes and confirm the real email
    #       in <5 seconds. WordPress considers this by-design; strictly
    #       INFO, but worth surfacing with the gravatar hashes captured.
    emails_leaked = _re.findall(r'"email"\s*:\s*"([^"]+@[^"]+)"', result)
    gravatar_hashes = list(dict.fromkeys(
        _re.findall(r"gravatar\.com/avatar/([a-f0-9]{32,64})", result,
                     _re.IGNORECASE)))
    slugs = ", ".join(u["slug"] for u in users[:5])
    more = f" +{len(users)-5} more" if len(users) > 5 else ""

    # Idempotent — skip if already emitted (LLM's finish() may have,
    # OR this function on a prior transcript entry).
    existing = state.get("findings", []) or []
    for f in existing:
        t = str(f.get("title", "")).lower()
        if ("wp-json/wp/v2/users" in t
                or "wordpress rest api" in t):
            return

    if emails_leaked:
        # Case (a) — real CVE-2023-5561
        email_preview = ", ".join(list(dict.fromkeys(emails_leaked))[:5])
        state.add_finding(
            agent=agent_name, severity="medium",
            title=(f"WordPress REST API email disclosure (CVE-2023-5561): "
                    f"/wp-json/wp/v2/users returns {len(users)} user(s) "
                    f"WITH `email` field populated — {email_preview}")[:200],
            evidence=(f"{target} — {len(users)} user record(s) with real "
                       f"emails exposed. Emails: {email_preview}. Slugs: "
                       f"{slugs}{more}. Response snippet: "
                       f"{result[:400].strip()}"),
            recommendation=(
                "Real CVE-2023-5561: fixed in WordPress 6.4.1 by hiding "
                "the `email` field in the public REST response. Either "
                "the WP core is < 6.4.1, OR a plugin (or custom "
                "functions.php filter) re-exposes the field. Upgrade WP "
                "to latest AND audit `rest_prepare_user` filter usage in "
                "the codebase. Mitigation while fixing: block the "
                "endpoint entirely (Wordfence 'Disable WP REST API user "
                "enumeration' toggle) OR filter `rest_endpoints` for the "
                "`wp/v2/users` route."),
        )
    else:
        # Case (b) — gravatar-hash + slug leak (WP by-design, INFO)
        gv_note = ""
        if gravatar_hashes:
            first = gravatar_hashes[0]
            gv_note = (f" Gravatar SHA-256 hash captured ({first[:12]}…) — "
                        f"reversible offline against a wordlist of common "
                        f"corporate email prefixes (`info@`, `admin@`, "
                        f"`contacto@`, `hola@`, `hello@`, `support@`, "
                        f"`ventas@`, `contact@`) + the target domain in "
                        f"<5s.")
        state.add_finding(
            agent=agent_name, severity="info",
            title=(f"WordPress REST API user enum + gravatar hash leak: "
                    f"/wp-json/wp/v2/users returns {len(users)} user(s) "
                    f"({slugs}{more})")[:200],
            evidence=(f"{target} — {len(users)} user record(s), NO `email` "
                       f"field (WP 6.4.1+ fix applied). Slugs: {slugs}"
                       f"{more}. Gravatar SHA-256 hash(es): "
                       f"{', '.join(gravatar_hashes[:3]) or '(none)'}. "
                       f"Response snippet: {result[:400].strip()}"),
            recommendation=(
                "WordPress exposes the users array on `/wp-json/wp/v2/"
                "users` and via `/?author=<id>` redirects by default. "
                "Impact on its own is Info — but (1) each slug is a "
                "valid login username, and (2) the `avatar_urls` field "
                "carries the Gravatar SHA-256 of the user's email, "
                "reversible offline against a small wordlist of common "
                "corporate email prefixes.")
            + gv_note
            + " Mitigation: filter `rest_endpoints` for `wp/v2/users` "
              "OR install a security plugin (Wordfence 'Disable WP REST "
              "API user enumeration'). Also disable pretty-permalink "
              "author redirects if not used.",
        )
        # Publish the raw hashes to state so a downstream agent (or the
        # operator) can reverse them offline.
        if gravatar_hashes:
            state.set("wp_gravatar_hashes", gravatar_hashes)


def _primary_url(state):
    hosts = state.get("live_hosts", [])
    if hosts:
        h = hosts[0]
        return f"{h.get('scheme','https')}://{h.get('host')}"
    return state.get("target")
