"""Web Vuln Agent — general vulnerability scanning per detected tech.
Runs nuclei + nikto for passive/CVE scans, plus dalfox + sqlmap on the
parameterized endpoints discovered by content_discovery for ACTIVE param
injection scans.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from agents.base import BaseAgent


class WebVulnAgent(BaseAgent):
    NAME = "web_vuln"
    DESCRIPTION = "Nuclei + Nikto + dalfox (XSS) + sqlmap (SQLi) scans"
    MAX_ITERATIONS = 16
    TOOL_NAMES = ["run_shell", "http_get", "finish"]

    SYSTEM_PROMPT = """/no_think

You are the WEB VULNERABILITY AGENT. Scan live hosts for known CVEs,
misconfigurations, AND actively test parameterized endpoints for SQLi/XSS
using sqlmap and dalfox.

MANDATORY SCAN SUITE — run in this order (one tool_call per turn):

  1. Generic exposures (always, first):
       nuclei -u <host> -tags exposures,exposed-panels,misconfig \
         -severity info,low,medium,high,critical -rl 5 -c 5 -silent
     Reason: catches .git / .env / config files / debug pages / open dashboards.

  2. Security headers:
       nuclei -u <host> -t http/misconfiguration/http-missing-security-headers.yaml \
         -silent

  3. Default credentials scan (LAB ONLY — DVWA/Juice Shop/Mutillidae/BWA/
     self-hosted lab). Skip against real bug-bounty targets:
       nuclei -u <host> -tags default-login -severity medium,high,critical \
         -rl 5 -c 5 -silent

  4. Per-tech CVE scan — one call per tech in detected_techs (max 5 techs).
     If a tech has known nuclei templates:
       nuclei -u <host> -tags <tech-lowercase> -severity medium,high,critical \
         -rl 5 -c 5 -silent
     Common product tags nuclei supports:
       wordpress, joomla, drupal, magento, adminer, phpmyadmin, grafana,
       jenkins, gitlab, jira, confluence, nginx, apache, iis, tomcat,
       jboss, weblogic, spring, symfony, laravel, django, rails, express,
       nodejs, dokploy, coolify, portainer, traefik, minio, elasticsearch,
       kibana, airflow, metabase, keycloak, vault, consul, n8n.

  5. Nikto (quick pass):
       nikto -h <host> -Pause 1 -Tuning 1234567 -nointeractive

  6. ACTIVE PARAM SCAN — for EACH endpoint with GET parameters listed in
     "Parametrized endpoints" below (up to 8), run BOTH:

       (a) XSS with dalfox — one call per endpoint:
             dalfox url "<endpoint-with-params>" \
               --skip-bav --skip-mining-dom --skip-mining-dict \
               --worker 2 --delay 500 --timeout 10 --format plain --silence \
               [--cookie "<cookie-if-any>"]

       (b) SQLi with sqlmap — one call per endpoint (BATCH, small, fast):
             sqlmap -u "<endpoint-with-params>" --batch --smart \
               --level=1 --risk=1 --timeout=10 --retries=1 \
               --technique=BEUS --threads=2 --disable-coloring \
               [--cookie="<cookie-if-any>"]

     Cookie: if the user message says "Session cookie captured: <val>",
     add --cookie / --cookie= EXACTLY as shown. Otherwise omit.

  7. finish() with EVERY finding, formatted:
       ["<severity> — <template-or-tool> on <host> — <evidence-1-line>", ...]

Rules:
  - One tool per invocation. NEVER stack 10 nuclei tags — timeouts.
  - dalfox + sqlmap are AUTHORITATIVE for XSS/SQLi — trust their output.
  - PoC of the vuln itself only. Do NOT chain further exploitation.
  - Report EVERY finding regardless of "will it be dup?" — the operator
    decides when they read the REPORT.md.
  - Default-credential test (step 3) is LAB-ONLY. If the user message
    mentions localhost / juice shop / dvwa / mutillidae / bwa / vulnerable
    → run it. On real bug bounty targets: SKIP step 3.
  - Active param scan (step 6) works on any target where content_discovery
    found endpoints with query parameters. If the "Parametrized endpoints"
    list is empty, SKIP step 6.
"""

    def entry_condition(self, state) -> bool:
        return state.has_live_http()

    def build_objective(self, state) -> str:
        techs = state.get("detected_techs", [])[:8]
        host = _primary_url(state)

        # Extract endpoints with GET params from content_discovery
        param_urls = _extract_param_endpoints(state, limit=8)

        # If login_probe captured a cookie, tell the model
        cookie_note = ""
        cookies = state.get("session_cookies", {}) or {}
        # Match by hostname substring so the primary host maps to the cookie
        primary_host = urlparse(host).hostname or ""
        cookie_val = ""
        for h, c in cookies.items():
            if h == primary_host or h in primary_host or primary_host in h:
                cookie_val = c
                break
        if cookie_val:
            cookie_note = (f"\nSession cookie captured by login_probe: "
                           f"{cookie_val}\n"
                           "→ Add --cookie=\"<value>\" to sqlmap and "
                           "--cookie \"<value>\" to dalfox for ALL step-6 "
                           "scans. Also add -H \"Cookie: <value>\" to any "
                           "step 1-5 nuclei/curl/nikto command.")

        param_block = ""
        if param_urls:
            param_block = ("\n\nParametrized endpoints (run sqlmap + dalfox "
                           "on each in step 6):\n"
                           + "\n".join(f"  - {u}" for u in param_urls))
        else:
            param_block = ("\n\nParametrized endpoints: (none found — "
                           "SKIP step 6)")

        return (
            f"Primary host: {host}\n"
            f"Detected techs (scan one at a time): {techs}"
            f"{cookie_note}"
            f"{param_block}\n\n"
            "Scan for CVEs, misconfigs AND actively test the parametrized "
            "endpoints. Finish with all findings."
        )

    def after_run(self, state, transcript):
        # Parse nuclei output lines: [template-id] [protocol] [severity] URL
        pattern = re.compile(
            r"\[([\w\-]+)\]\s*\[\w+\]\s*\[(info|low|medium|high|critical)\]\s*(\S+)"
        )
        # Nikto output: "+ /path: message (or CVE tag)"
        nikto_pattern = re.compile(r"^\+\s+(/\S*):\s+(.+)$", re.MULTILINE)
        # sqlmap: "Parameter: <name> (<method>)" + "Type: <blind|error|union|...>"
        sqlmap_param_re = re.compile(
            r"Parameter:\s+([^\s]+)\s+\(([A-Z]+)\)", re.MULTILINE)
        sqlmap_type_re = re.compile(
            r"Type:\s+([^\n\r]+)", re.MULTILINE)
        sqlmap_url_re = re.compile(
            r"sqlmap\s+.*?-u\s+[\"']([^\"']+)[\"']")
        # dalfox: lines like "[POC][R][GET] http://... payload=..."
        # More reliable: "[VULN]" and "[POC]" markers
        dalfox_poc_re = re.compile(
            r"\[POC\][^\n]*?(https?://\S+)[^\n]*?(?:payload=?)?([^\n]{0,200})",
            re.IGNORECASE)
        dalfox_vuln_re = re.compile(
            r"\[VULN\][^\n]*?(https?://\S+)[^\n]*",
            re.IGNORECASE)

        for entry in transcript:
            if entry.get("tool") != "run_shell":
                continue
            cmd = str(entry.get("args", {}).get("command", ""))
            result = str(entry.get("result", ""))
            cmd_low = cmd.lower()

            # nuclei findings — keep ALL severities; skip generic tech-detects
            for m in pattern.finditer(result):
                template, severity, url = m.group(1), m.group(2), m.group(3)
                if severity == "info" and (template.endswith("-detect")
                                            or template.endswith("-panel")):
                    continue
                state.add_finding(
                    agent=self.NAME,
                    severity=severity,
                    title=f"nuclei/{template} on {url}",
                    evidence=m.group(0),
                    recommendation=f"Investigate template {template}",
                )
                if severity in ("high", "critical"):
                    state.append("cves_matched",
                                 {"cve": template, "target": url,
                                  "evidence": m.group(0)})

            # nikto findings
            if "nikto" in cmd_low:
                for m in nikto_pattern.finditer(result):
                    path, msg = m.group(1), m.group(2)[:180]
                    low = msg.lower()
                    if "cve-" in low:
                        sev = "high"
                    elif any(k in low for k in ("info", "banner", "cookie",
                                                 "header", "options")):
                        sev = "low"
                    else:
                        sev = "medium"
                    state.add_finding(
                        agent=self.NAME, severity=sev,
                        title=f"nikto: {path}",
                        evidence=msg,
                        recommendation="Review the nikto item and confirm.")

            # sqlmap findings — parse "Parameter: X (METHOD)\nType: ..."
            if "sqlmap" in cmd_low:
                # Extract target URL from the command itself
                target_url = ""
                m_u = sqlmap_url_re.search(cmd)
                if m_u:
                    target_url = m_u.group(1)
                # Group Parameter/Type pairs — sqlmap outputs them adjacent
                params = sqlmap_param_re.findall(result)
                types = sqlmap_type_re.findall(result)
                if params:
                    for i, (pname, pmethod) in enumerate(params):
                        vtype = types[i] if i < len(types) else "unknown"
                        state.add_finding(
                            agent=self.NAME, severity="critical",
                            title=f"sqlmap: SQL injection in "
                                  f"param '{pname}' ({pmethod}) at {target_url}",
                            evidence=f"Injection type: {vtype}. "
                                     f"Confirmed by sqlmap --batch --smart.",
                            recommendation=(
                                "Use parameterized queries / ORM binds. "
                                "Escape/whitelist the parameter. "
                                "Reproduce with: "
                                f"sqlmap -u \"{target_url}\" "
                                f"-p \"{pname}\" --dbs"),
                        )
                        state.append("cves_matched",
                                     {"cve": "SQLi",
                                      "target": target_url,
                                      "evidence": f"param={pname} "
                                                  f"method={pmethod} "
                                                  f"type={vtype[:60]}"})

            # dalfox findings — [POC] or [VULN] markers
            if "dalfox" in cmd_low:
                # POC markers = confirmed XSS with proof
                for m in dalfox_poc_re.finditer(result):
                    url_hit = m.group(1)[:400]
                    payload = m.group(2)[:200]
                    state.add_finding(
                        agent=self.NAME, severity="high",
                        title=f"dalfox: XSS confirmed at {url_hit[:120]}",
                        evidence=f"POC: {url_hit}\nPayload: {payload}",
                        recommendation=("Escape user input in HTML/JS/URL "
                                         "context. Add CSP with no unsafe-inline. "
                                         f"Reproduce: {url_hit}"),
                    )
                # VULN markers without POC = probable XSS
                if not dalfox_poc_re.search(result):
                    for m in dalfox_vuln_re.finditer(result):
                        url_hit = m.group(1)[:400]
                        state.add_finding(
                            agent=self.NAME, severity="medium",
                            title=f"dalfox: potential XSS at {url_hit[:120]}",
                            evidence=m.group(0)[:400],
                            recommendation=("Manually verify — dalfox flagged "
                                             "as potential XSS."),
                        )


def _primary_url(state):
    hosts = state.get("live_hosts", [])
    if hosts:
        h = hosts[0]
        return f"{h.get('scheme','https')}://{h.get('host')}"
    return state.get("target")


def _extract_param_endpoints(state, limit: int = 8) -> list[str]:
    """Return unique endpoint URLs that have GET query parameters.
    Prefers endpoints discovered by content_discovery (most likely to be
    real app endpoints, not static assets)."""
    seen: set[str] = set()
    out: list[str] = []
    for e in state.get("endpoints_found", []) or []:
        url = str(e.get("url", ""))
        if not url:
            continue
        try:
            p = urlparse(url)
        except Exception:
            continue
        if not p.query:
            continue
        # Skip obvious static assets
        low_path = p.path.lower()
        if any(low_path.endswith(ext) for ext in
               (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                ".woff", ".woff2", ".ttf", ".ico", ".map", ".mp4")):
            continue
        # Deduplicate by (path, sorted-param-names) so ?id=1 and ?id=999
        # don't both show up as separate scan targets.
        try:
            params = tuple(sorted(parse_qs(p.query).keys()))
        except Exception:
            params = ()
        key = (p.scheme, p.netloc, p.path, params)
        if key in seen:
            continue
        seen.add(key)
        out.append(url)
        if len(out) >= limit:
            break
    return out
