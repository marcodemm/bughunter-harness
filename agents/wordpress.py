"""WordPress Agent — dispatched only if Fingerprint / Recon detected WordPress.
Uses wpscan (if installed) + nuclei -tags wordpress.
"""
from __future__ import annotations

import os
import re

from agents.base import BaseAgent


class WordPressAgent(BaseAgent):
    NAME = "wordpress"
    DESCRIPTION = "WordPress-specific enum + CVE match (wpscan)"
    MAX_ITERATIONS = 8
    TOOL_NAMES = ["run_shell", "http_get", "finish"]
    # Skipped in quick mode — wpscan is slow (~5-10 min per target) and
    # only useful in a full-scan pass.
    RUNS_IN_QUICK = False

    SYSTEM_PROMPT = """/no_think

You are the WORDPRESS AGENT. Only dispatched when WordPress was detected.
Enumerate plugins/themes/users and match against known CVEs.

CRITICAL: use EXACTLY the `<target>` URL from the user message ("Target:").
That URL is the one where WordPress was detected. Do NOT substitute another
subdomain the prioritizer ranked higher — a cpanel or webmail host may have
scored above the WP host but WordPress does not live there.

Workflow (one tool_call per turn):

  0. PRE-CHECK — verify wpscan is installed:
       which wpscan            (POSIX-safe; `command -v` is blocked by allowlist)
     If exit ≠ 0 (wpscan not found), SKIP steps 1-2 and go straight to
     step 3. Do NOT retry wpscan — it will keep failing. Log that
     wpscan is missing so the operator installs it (`gem install wpscan`).

  0b. IMPORTANT — Cloudflare/WAF bypass:
     Use a REAL Chrome User-Agent (see the `--user-agent "…Chrome/128…"`
     flag in every wpscan step below). NEVER use `--random-user-agent`
     — it picks scanner-known UAs that Cloudflare / Sucuri / DataDome
     block on sight. Symptom of a WAF block: wpscan exit=4 with
     "does not seem to be running WordPress" while nuclei-wordpress-detect
     already confirmed the target IS WordPress. Retry only makes it worse;
     if steps 1-2 all return exit=4, jump straight to step 3 (nuclei).

  1. wpscan --url <target> --user-agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36" --no-banner \
       --format json -o /tmp/harness-wpscan.json \
       --disable-tls-checks [--api-token "$WPSCAN_API_TOKEN"]
       (JSON output — parsed deterministically by the harness. Do NOT
        use --format cli; the parser needs JSON.)
  2. wpscan --url <target> --enumerate p,u,t --plugins-detection aggressive \
       --user-agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36" --no-banner \
       --format json -o /tmp/harness-wpscan-full.json \
       --disable-tls-checks [--api-token "$WPSCAN_API_TOKEN"]
       (heavier; ok to skip if step 1 already listed plugins with versions)
  3. nuclei -u <target> -tags wordpress -severity medium,high,critical \
       -c 25 -rl 20 -timeout 5 -silent \
       -jsonl -o /tmp/harness-nuclei-wordpress.jsonl
       (tech-targeted, high concurrency — 900s timeout works comfortably)
  4. curl -s <target>/wp-json/wp/v2/users     (user disclosure via REST API)
  5. finish() with findings: plugins outdated, users leaked, CVEs matched

WPSCAN API TOKEN:
  If the user message says "WPScan API token: available", ADD the flag
  `--api-token "$WPSCAN_API_TOKEN"` to every wpscan call (steps 1 & 2).
  This unlocks CVE lookup against the WPScan Vulnerability DB — without
  it, wpscan enumerates plugins but returns 0 CVE match even when a
  plugin is outdated.
  If the user message says "WPScan API token: NOT configured" OR
  "WPScan API token: EXHAUSTED (daily limit reached)", OMIT the
  --api-token flag entirely — passing an empty/exhausted token makes
  wpscan exit with an error. The env var WPSCAN_API_TOKEN is already
  exported by the harness — you just need to reference it via
  "$WPSCAN_API_TOKEN".

QUOTA-EXHAUSTED AUTO-FALLBACK — CRITICAL:
  The WPScan free tier is 25 requests/day. If ANY wpscan call returns
  output containing any of these markers:
    "daily limit"
    "You have reached the maximum"
    "API request limit reached"
    "Api limit reached"
    "reached the daily"
  → the token is EXHAUSTED for today. Your VERY NEXT wpscan call MUST
  drop `--api-token "$WPSCAN_API_TOKEN"` and re-run the SAME wpscan
  command without it. Do NOT keep retrying with the token — every retry
  wastes a call to the LLM turn budget for zero value. Without the token
  wpscan still enumerates plugins/themes/users (which is useful); it
  just can't cross-match against the CVE database.

Rules:
  - One tool_call per turn.
  - If wpscan is not installed (step 0 fails), fall back to nuclei step 3.
  - NEVER attempt XMLRPC / login brute-force. Report the vector only.
  - EVERY http_get / curl / nuclei / wpscan MUST use the <target> exactly
    as given in the "Target:" line. Do NOT invent alternative hostnames.
"""

    def entry_condition(self, state) -> bool:
        return state.has_tech("wordpress") or state.has_tech("wp-")

    def build_objective(self, state) -> str:
        host = _target_with_wp_evidence(state)
        token_status = self._ensure_wpscan_token_env(state)
        if token_status == "available":
            token_note = ("WPScan API token: available (env $WPSCAN_API_TOKEN "
                          "exported — add --api-token \"$WPSCAN_API_TOKEN\" "
                          "to wpscan calls). If wpscan output says the daily "
                          "limit is reached, DROP the flag in your next call.")
        elif token_status == "exhausted":
            token_note = ("WPScan API token: EXHAUSTED (daily limit reached "
                          "on a previous run today — env NOT exported). "
                          "OMIT --api-token; wpscan enumerates plugins but "
                          "won't cross-match against the CVE DB.")
        else:  # "missing"
            token_note = ("WPScan API token: NOT configured (skip the "
                          "--api-token flag; wpscan still runs but without "
                          "CVE-DB lookup).")
        return (
            f"Target: {host}\n"
            f"Detected techs full list: {state.get('detected_techs', [])}\n"
            f"{token_note}\n\n"
            "Enumerate + CVE-match. Finish with findings."
        )

    def _ensure_wpscan_token_env(self, state=None) -> str:
        """Read wpscan.api_token from cfg (or its env var) and export it as
        os.environ['WPSCAN_API_TOKEN'] so subprocesses inherit it.

        Returns one of:
          - "available" : token exported, use --api-token in wpscan calls
          - "exhausted" : token EXISTS but a prior run in this session hit
                          the daily quota (state.wpscan_api_exhausted=True)
                          → env is UN-exported so wpscan calls skip the flag
          - "missing"   : no token in cfg or env → env un-exported
        Never raises; token-less mode is fully supported.
        """
        wp_cfg = (self.cfg.get("wpscan") or {})
        token = str(wp_cfg.get("api_token") or "").strip()
        if not token:
            env_name = str(wp_cfg.get("api_token_env")
                           or "WPSCAN_API_TOKEN").strip()
            token = os.environ.get(env_name, "").strip()

        # Session-sticky exhaustion: if any earlier run this session hit
        # the daily quota, keep the flag OFF for the rest of the session
        # (there's no point retrying — 25/day resets at midnight UTC).
        exhausted = bool(state and state.get("wpscan_api_exhausted"))

        if not token:
            os.environ.pop("WPSCAN_API_TOKEN", None)
            return "missing"
        if exhausted:
            # Token exists but is quota-locked; un-export so wpscan calls
            # via the LLM skip the flag entirely (the prompt directs the
            # LLM to check the token-note in the user message).
            os.environ.pop("WPSCAN_API_TOKEN", None)
            return "exhausted"
        os.environ["WPSCAN_API_TOKEN"] = token
        return "available"

    def after_run(self, state, transcript):
        # B5 fix pattern: parse nuclei JSONL sink if wordpress agent used
        # `-jsonl -o /tmp/harness-nuclei-wordpress.jsonl` (recommended in
        # the new system prompt). Independent of stdout survival.
        try:
            from agents.web_vuln import _parse_nuclei_jsonl_to_findings
            _parse_nuclei_jsonl_to_findings(
                state, self.NAME,
                glob_pattern="harness-nuclei-wordpress*.jsonl")
        except Exception as e:
            state.log(self.NAME, "warn",
                      f"nuclei JSONL parse failed: {type(e).__name__}: {e}")

        # W1: detect wpscan-missing so the meta-check in report.py can
        # surface it as a WARNING (auto-remediation hint for the operator).
        # W-Quota (2026-09-03): detect the WPScan API daily-limit reached
        # marker so subsequent wordpress agent runs this session skip the
        # --api-token flag automatically (see _ensure_wpscan_token_env).
        import re as _re
        _QUOTA_MARKERS = (
            "daily limit",
            "you have reached the maximum",
            "api request limit reached",
            "api limit reached",
            "reached the daily",
            "hello seeker man",           # subject/greeting of the email WPScan
                                          # sends when quota resets — appears in
                                          # some 403 body outputs too
        )
        for entry in transcript:
            if entry.get("tool") != "run_shell":
                continue
            cmd = str(entry.get("args", {}).get("command", ""))
            result = str(entry.get("result", ""))
            result_low = result.lower()
            # (a) wpscan not installed
            if (("command -v wpscan" in cmd
                 and _re.search(r"exit=1(?!\d)", result))
                or ("wpscan " in cmd
                    and _re.search(r"exit=127", result))):
                state.set("wpscan_missing", True)
                state.log(self.NAME, "warn",
                          "wpscan not installed — WordPress agent falls back "
                          "to nuclei. Install with `gem install wpscan` "
                          "(macOS: `brew install ruby && gem install wpscan`).")
            # (b) WPScan API daily quota exhausted — session-sticky flag
            if ("wpscan " in cmd
                and any(m in result_low for m in _QUOTA_MARKERS)):
                state.set("wpscan_api_exhausted", True)
                state.log(self.NAME, "warn",
                          "WPScan API daily quota reached (25/day free tier). "
                          "Subsequent wpscan calls this session will run "
                          "WITHOUT --api-token — plugin/theme/user enum still "
                          "works but the CVE-DB lookup is disabled until the "
                          "quota resets (midnight UTC).")

        # N3 fix (2026-09-03): parse wpscan JSON output FIRST — it's the
        # only reliable path (CLI format changes per version; regex-scraping
        # was near-useless). If /tmp/harness-wpscan*.json exists, iterate
        # every plugin/theme and every vulnerability inside → structured
        # findings with severity mapped from CVSS.
        try:
            _parse_wpscan_json_to_findings(state, self.NAME,
                                            "harness-wpscan*.json")
        except Exception as e:
            state.log(self.NAME, "warn",
                      f"wpscan JSON parse failed: {type(e).__name__}: {e}")

        # Legacy CLI parser kept as fallback for older prompts / --format cli.
        for entry in transcript:
            if entry.get("tool") != "run_shell":
                continue
            result = str(entry.get("result", ""))
            if "wpscan" in str(entry.get("args", {}).get("command", "")):
                for m in re.finditer(
                    r"^\[[+!]\]\s+(.+?)\n\s+\|\s+Version:\s+([\w.]+)",
                        result, re.MULTILINE):
                    plugin, version = m.group(1).strip(), m.group(2)
                    state.add_finding(
                        agent=self.NAME, severity="info",
                        title=f"WordPress plugin: {plugin} {version}",
                        evidence=m.group(0)[:400],
                        recommendation=("Match against WPScan DB CVEs; "
                                        "check for known issues"))
                for m in re.finditer(r"^\[!\]\s+Title:\s+(.+)$", result,
                                     re.MULTILINE):
                    state.add_finding(
                        agent=self.NAME, severity="high",
                        title=f"WordPress vuln: {m.group(1)[:150]}",
                        evidence="",
                        recommendation="Verify version and patch")
            # nuclei standard pattern
            for m in re.finditer(
                r"\[([\w\-]+)\]\s*\[\w+\]\s*\[(medium|high|critical)\]\s*(\S+)",
                    result):
                state.add_finding(
                    agent=self.NAME, severity=m.group(2),
                    title=f"nuclei/{m.group(1)} on {m.group(3)}",
                    evidence=m.group(0),
                    recommendation=f"Investigate {m.group(1)}")


def _cvss_to_severity(score) -> str:
    """Map a CVSS numeric score to nuclei-style severity buckets."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "info"


def _parse_wpscan_json_to_findings(state, agent_name: str,
                                     glob_pattern: str) -> int:
    """Parse every /tmp/<glob_pattern> wpscan JSON file into structured
    findings. Returns the count added.

    Schema (WPScan --format json, condensed):
      {
        "target_url": "...",
        "effective_url": "...",
        "interesting_findings": [...],
        "version":   {"number": "6.4.2", "vulnerabilities": [...]},
        "main_theme": {"slug": "divi", "version": {"number": "4.9.0"},
                       "vulnerabilities": [...]},
        "plugins": {
          "<slug>": {
            "slug": "...", "version": {"number": "1.2.3", "confidence": 100},
            "vulnerabilities": [
              {"title": "...", "cvss": {"score": 9.8, "severity": "critical"},
               "references": {"cve": ["2024-..."], "wpvulndb": ["..."]},
               "fixed_in": "1.2.4"}
            ]
          }
        }
      }
    """
    from pathlib import Path as _P
    import json as _j
    tmp = _P("/tmp")
    if not tmp.is_dir():
        return 0
    added = 0
    for path in sorted(tmp.glob(glob_pattern)):
        try:
            if path.stat().st_size < 2 or path.stat().st_size > 20 * 1024 * 1024:
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = _j.load(f)
        except Exception:
            continue
        target = data.get("effective_url") or data.get("target_url") or ""

        # WP core vulnerabilities
        version = (data.get("version") or {})
        for v in version.get("vulnerabilities", []) or []:
            _emit_wpscan_finding(state, agent_name, kind="WordPress core",
                                  slug="wordpress",
                                  version=version.get("number", "?"),
                                  vuln=v, target=target)
            added += 1

        # Main theme vulnerabilities
        theme = (data.get("main_theme") or {})
        theme_slug = theme.get("slug") or "theme"
        theme_ver = (theme.get("version") or {}).get("number", "?")
        for v in theme.get("vulnerabilities", []) or []:
            _emit_wpscan_finding(state, agent_name,
                                  kind="Theme", slug=theme_slug,
                                  version=theme_ver, vuln=v, target=target)
            added += 1

        # Plugin vulnerabilities — the meat of what WPScan API delivers
        plugins = data.get("plugins") or {}
        for slug, p in plugins.items():
            ver = (p.get("version") or {}).get("number", "?")
            vulns = p.get("vulnerabilities") or []
            if not vulns:
                # Still emit an INFO entry so the report shows what was
                # enumerated, even without CVE match (useful for op audit).
                state.add_finding(
                    agent=agent_name, severity="info",
                    title=f"WordPress plugin enumerated: {slug} {ver}",
                    evidence=f"wpscan detected {slug} v{ver} on {target}",
                    recommendation=("No known CVEs in WPScan DB for this "
                                     "version at scan time — verify manually."))
                added += 1
                continue
            for v in vulns:
                _emit_wpscan_finding(state, agent_name,
                                      kind="Plugin", slug=slug,
                                      version=ver, vuln=v, target=target)
                added += 1

    if added:
        state.log(agent_name, "info",
                   f"wpscan JSON parser: added {added} finding(s) from "
                   f"file(s) matching {glob_pattern}")
    return added


def _emit_wpscan_finding(state, agent_name: str, kind: str, slug: str,
                          version: str, vuln: dict, target: str) -> None:
    title = str(vuln.get("title") or "").strip()[:200]
    cvss = (vuln.get("cvss") or {})
    score = cvss.get("score")
    severity = str(cvss.get("severity") or "").lower() \
                or _cvss_to_severity(score)
    refs = (vuln.get("references") or {})
    cves = refs.get("cve") or []
    cve_str = ", ".join(f"CVE-{c}" if not str(c).startswith("CVE-") else c
                         for c in cves[:5])
    fixed_in = vuln.get("fixed_in") or "unknown"
    ev = f"{kind} {slug} v{version} on {target} — CVSS={score} · Fixed in: {fixed_in}"
    if cve_str:
        ev += f" · {cve_str}"
    rec = f"Upgrade {slug} to >= {fixed_in}."
    if cves:
        rec += (f" Reproduce/details: "
                f"https://nvd.nist.gov/vuln/detail/{list(cves)[0]}")
    state.add_finding(
        agent=agent_name, severity=severity or "medium",
        title=f"{kind} vuln: {slug} {version} — {title}",
        evidence=ev,
        recommendation=rec,
    )
    if severity in ("high", "critical"):
        state.append("cves_matched", {
            "cve": cves[0] if cves else f"WPVULN:{slug}:{title[:40]}",
            "target": target,
            "evidence": ev,
        })


def _target_with_wp_evidence(state):
    """Return the URL of a live_host where WordPress was detected — NOT
    the top-ranked sub from sub_prioritizer.

    Bug pattern: sub_prioritizer may rank a cpanel/webmail sub (score
    ~56 due to admin-panel keywords) ABOVE the WordPress host (score
    ~33). WordPress lives on the www host, but the old `_primary_url`
    returned `live_hosts[0]` = the top-ranked sub post-ranking →
    wordpress agent wasted many minutes scanning the wrong host
    (0 findings, expected).

    Preference order:
      1. Any live_host whose `tech` list contains a wordpress marker.
      2. Any endpoint URL that matched a wordpress-plugin-detect finding.
      3. The primary target (state.target) — always relevant when the
         wordpress tech was detected at all.
      4. live_hosts[0] fallback (previous behavior — last resort).
    """
    live = state.get("live_hosts", []) or []
    # 1) tech field carries "wordpress"
    for h in live:
        tech = [str(t).lower() for t in (h.get("tech") or h.get("technologies") or [])]
        if any("wordpress" in t or "wp-" in t for t in tech):
            scheme = h.get("scheme", "https")
            return f"{scheme}://{h.get('host')}"
    # 2) endpoint or finding evidence names a specific URL
    from urllib.parse import urlparse as _up
    for f in state.get("findings", []) or []:
        title = str(f.get("title", "")).lower()
        ev = str(f.get("evidence", "")).lower()
        if "wordpress" in title or "wordpress" in ev:
            for src in (f.get("evidence", ""), f.get("title", "")):
                import re as _re
                m = _re.search(r"https?://[^\s\"'<>)]+", str(src))
                if m:
                    p = _up(m.group(0))
                    if p.hostname:
                        return f"{p.scheme}://{p.hostname}"
    # 3) primary target (safest default — that's where fingerprint saw WP)
    tgt = state.get("target")
    if tgt:
        return tgt
    # 4) last resort
    if live:
        h = live[0]
        return f"{h.get('scheme', 'https')}://{h.get('host')}"
    return ""
