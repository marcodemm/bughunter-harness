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
        """PN18 iter 10 (2026-09-04): 4-signal entry so a WordPress-
        obvious target actually triggers the agent. Old form was
        `state.has_tech("wordpress")` alone — literal-substring match
        against the raw tech list. When nuclei's `wordpress-detect:
        version_by_css` detector fires, the raw list carries
        `version_by_css:7.0.4` (the DETECTOR name, not `wordpress`) →
        old check returned False → wordpress agent skipped even though
        `/wp-admin/install.php` sat in endpoints and fingerprint's
        narrative said 'running WordPress 7.0.4 with Elementor Pro
        3.20.0'. Signal 1 (has_tech) now applies the alias table via
        shared_state; signals 2-4 catch the case even if signal 1 miss.
        """
        # Signal 1: direct tech detection (alias-resolved inside has_tech)
        if state.has_tech("wordpress") or state.has_tech("wp-"):
            return True
        # Signal 2: any endpoint whose path matches a WordPress marker
        import re as _re
        _WP_PATH = _re.compile(r"/wp-(admin|content|includes|json|login)",
                                _re.IGNORECASE)
        for e in (state.get("endpoints_found") or []):
            url = str(e.get("url", ""))
            if _WP_PATH.search(url):
                return True
        for e in (state.get("endpoints_probed_negative") or []):
            url = str(e.get("url", ""))
            if _WP_PATH.search(url):
                return True
        # Signal 3: fingerprint agent's narrative summary mentions
        # `wordpress` literally (LLM told us so)
        for sm in (state.get("agent_summaries") or []):
            if str(sm.get("agent", "")) != "fingerprint":
                continue
            if "wordpress" in str(sm.get("summary", "")).lower():
                return True
        # Signal 4: any finding whose evidence carries `wordpress-detect`
        # or `wp-content/plugins` — these strings only appear in nuclei
        # WordPress-family template output or WP asset URLs.
        for f in (state.get("findings") or []):
            ev = str(f.get("evidence", "")).lower()
            if "wordpress-detect" in ev or "wp-content/plugins" in ev:
                return True
            title = str(f.get("title", "")).lower()
            if "wordpress" in title:
                return True
        return False

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
        wpscan_findings_added = 0
        try:
            wpscan_findings_added = _parse_wpscan_json_to_findings(
                state, self.NAME, "harness-wpscan*.json")
        except Exception as e:
            state.log(self.NAME, "warn",
                      f"wpscan JSON parse failed: {type(e).__name__}: {e}")

        # PN20 iter 11 (2026-09-04): if wpscan corrió N veces pero el
        # parser NO añadió findings, el agent está ciego. Diagnóstico
        # explícito: mira los outputs raw de cada wpscan call, distingue
        # entre (a) file no existe / size 0 → WAF challenge o network
        # error, (b) contains quota marker → API exhausted, (c) file OK
        # pero sin plugins/version → wpscan no reconoció WP en el target.
        # Publica flags a state para que report.py emita meta-check
        # warnings específicos por caso.
        _diagnose_wpscan_empty(state, self.NAME, transcript,
                                findings_added=wpscan_findings_added)

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


def _version_ge(a: str, b: str) -> bool:
    """True if version `a` >= version `b`. Best-effort tuple compare —
    strips non-digit chars per component. Returns False on empty/None
    (so callers can treat 'unknown' as 'don't skip'). Used by PN11 fix
    to skip CVEs where the detected version is already >= fixed_in."""
    if not a or not b or str(a) == "?" or str(b) == "?":
        return False

    def _tuple(v: str) -> tuple:
        parts: list[int] = []
        for p in str(v).replace("-", ".").split(".")[:5]:
            try:
                parts.append(int("".join(c for c in p if c.isdigit()) or "0"))
            except ValueError:
                parts.append(0)
        while len(parts) < 5:
            parts.append(0)
        return tuple(parts)
    try:
        return _tuple(a) >= _tuple(b)
    except Exception:
        return False


def _plugin_confirmation(state, slug: str, target: str) -> tuple[str | None, str]:
    """PN11 fix (2026-09-04): return (confirmation_source, version) for a
    plugin slug wpscan reported, or (None, '?') if there's no independent
    evidence the plugin actually exists on the target.

    Confirmation sources, in order:
      1. `fingerprint` — the fingerprint agent already emitted a finding
         `<slug> detected on <target>` (nuclei wordpress-plugin-detect
         or asset URL parse).
      2. `readme.txt` — a live HEAD/GET to `/wp-content/plugins/<slug>/
         readme.txt` returned 200 + WordPress plugin marker
         (`Contributors:`), with `Stable tag:` giving the version.
      3. None — probably a wpscan `--plugins-detection aggressive`
         brute-force false positive against a WAF that returns uniform
         status (Cloudflare) or a hosting that 403s all `/wp-content/
         plugins/` paths. CVEs of unknown-existence plugins are almost
         always noise.

    Only paths (1) and (2) get their CVEs emitted as findings. (3) goes
    into `state.wpscan_unconfirmed_plugins` for the report to list."""
    import re as _re
    slug_low = slug.lower()

    # (1) fingerprint agent finding with this slug
    for f in (state.get("findings") or []):
        if str(f.get("agent")) != "fingerprint":
            continue
        title = str(f.get("title", "")).lower()
        if title.startswith(f"{slug_low} ") or title.startswith(f"{slug_low}:"):
            return "fingerprint", "?"

    # (2) live readme.txt probe — throttled 1 req per plugin (short circuit
    # on any error). Uses `requests` from tools.py's stdlib chain to reuse
    # the custom_headers. If requests unavailable, no-op.
    try:
        import requests
    except Exception:
        return None, "?"
    base = target.rstrip("/")
    from urllib.parse import urlparse as _up
    if not _up(base).scheme:
        return None, "?"
    url = f"{base}/wp-content/plugins/{slug}/readme.txt"
    try:
        # PN11 note: no custom_headers injected here — the harness's
        # ToolRegistry.custom_headers isn't in scope for this agent-level
        # helper. Best-effort with a browser UA so CF doesn't 403-block.
        r = requests.get(url, timeout=8, allow_redirects=False,
                          verify=False,
                          headers={"User-Agent":
                                    "Mozilla/5.0 (compatible; bughunter-harness/1)"})
    except requests.RequestException:
        return None, "?"
    if r.status_code != 200:
        return None, "?"
    body = r.text[:2000]
    if "Contributors:" not in body:
        return None, "?"
    m = _re.search(r"Stable tag:\s*(\S+)", body)
    version = m.group(1).strip() if m else "?"
    return "readme.txt", version


def _parse_wpscan_json_to_findings(state, agent_name: str,
                                     glob_pattern: str) -> int:
    """Parse every /tmp/<glob_pattern> wpscan JSON file into structured
    findings, with PN11 confirmation gate + version filter applied.

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

        # PN11 fix (2026-09-04): plugin vulnerabilities pass through a
        # confidence gate BEFORE emit. `--plugins-detection aggressive`
        # brute-forces plugin slugs against `/wp-content/plugins/<slug>/`;
        # WAF/CF returning uniform status makes wpscan report every
        # dictionary slug as "present" with no version → 99 findings,
        # ~half likely FP. We now split plugins into:
        #   confirmed   → CVEs get emitted (with version-vs-fixed_in filter)
        #   unconfirmed → slug goes into state.wpscan_unconfirmed_plugins
        #                  (report lists them separately, no CVEs)
        plugins = data.get("plugins") or {}
        confirmed_plugins: list[dict] = []
        unconfirmed_plugins: list[str] = []
        cves_skipped_patched = 0
        for slug, p in plugins.items():
            ver_wpscan = (p.get("version") or {}).get("number", "?")
            source, ver_readme = _plugin_confirmation(state, slug, target)
            if not source:
                unconfirmed_plugins.append(slug)
                continue
            # readme.txt version is more authoritative than wpscan's ?
            resolved_ver = ver_readme if (ver_readme and ver_readme != "?") \
                                       else ver_wpscan
            confirmed_plugins.append({
                "slug": slug, "version": resolved_ver, "source": source,
                "vulns": p.get("vulnerabilities") or [],
            })
            vulns = p.get("vulnerabilities") or []
            if not vulns:
                # PN13 diagnostic iter 8 (2026-09-04): the wpscan output
                # can carry `vulnerabilities: []` for a confirmed plugin
                # for three separate reasons — no CVE in WPScan DB for
                # ANY version of the plugin (rare, but genuine — dead
                # plugins that no one audited), the WPScan API quota was
                # exhausted mid-file so the field wasn't populated, or
                # the file being parsed was the OTHER `harness-wpscan*.
                # json` (the pre-`--enumerate` basic run without vulns
                # payload). Iter 7 lost CVEs for gdpr-cookie-compliance,
                # sassy-social-share, table-of-contents-plus this way —
                # brave-popup-builder kept its 8 CVEs, so this is
                # per-plugin variability of the wpscan API. Log which
                # file this came from + whether the API-quota flag is
                # set so the next run tells us the cause without
                # re-reading the JSON manually.
                _quota = "exhausted" if state.get(
                    "wpscan_api_exhausted") else "ok"
                state.log(agent_name, "info",
                           f"wpscan: plugin '{slug}' confirmed via "
                           f"{source} v{resolved_ver} — but "
                           f"vulnerabilities:[] in {path.name} "
                           f"(WPScan API quota: {_quota}). Possible "
                           f"causes: (a) no CVE known for this plugin "
                           f"in WPScan DB, (b) file is the basic-scan "
                           f"variant without the vulns payload, "
                           f"(c) API quota hit mid-file. If plugin has "
                           f"known CVEs elsewhere and this is (b) or "
                           f"(c), re-run with a fresh API token.")
                state.add_finding(
                    agent=agent_name, severity="info",
                    title=f"WordPress plugin enumerated: {slug} "
                          f"{resolved_ver} (via {source})",
                    evidence=f"wpscan detected {slug} v{resolved_ver} "
                             f"on {target} — confirmed by {source}",
                    recommendation=("No known CVEs in WPScan DB for this "
                                     "version at scan time — verify manually."))
                added += 1
                continue
            for v in vulns:
                fixed_in = str(v.get("fixed_in") or "").strip()
                # PN11: skip CVEs where the resolved version is already
                # patched (only when we know both versions).
                if fixed_in and resolved_ver and resolved_ver != "?" \
                        and _version_ge(resolved_ver, fixed_in):
                    cves_skipped_patched += 1
                    continue
                _emit_wpscan_finding(
                    state, agent_name,
                    kind="Plugin", slug=slug,
                    version=resolved_ver, vuln=v, target=target,
                    confirmation_source=source)
                added += 1

        if unconfirmed_plugins:
            # Append to session-sticky list — report will render a
            # dedicated section with these.
            existing = state.get("wpscan_unconfirmed_plugins") or []
            merged = sorted(set(existing) | set(unconfirmed_plugins))
            state.set("wpscan_unconfirmed_plugins", merged)
            state.log(agent_name, "info",
                       f"wpscan reported {len(unconfirmed_plugins)} plugin "
                       f"slug(s) with NO independent evidence of presence "
                       f"(fingerprint miss + readme.txt not accessible) "
                       f"— CVEs of those slugs suppressed to avoid FP. "
                       f"See '## WordPress plugins brute-forced by wpscan "
                       f"(unconfirmed)' in REPORT.")

        if cves_skipped_patched:
            state.log(agent_name, "info",
                       f"wpscan JSON parser: skipped {cves_skipped_patched} "
                       f"CVE(s) already patched by the detected plugin "
                       f"version(s) — no need to alert.")

    if added:
        state.log(agent_name, "info",
                   f"wpscan JSON parser: added {added} finding(s) from "
                   f"file(s) matching {glob_pattern}")
    return added


def _emit_wpscan_finding(state, agent_name: str, kind: str, slug: str,
                          version: str, vuln: dict, target: str,
                          confirmation_source: str = "") -> None:
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
    conf_tag = f" · confirmed via {confirmation_source}" \
               if confirmation_source else ""
    ev = (f"{kind} {slug} v{version} on {target} — CVSS={score} · "
           f"Fixed in: {fixed_in}{conf_tag}")
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
    # CVE counter iter 8 fix (2026-09-04): append to cves_matched whenever
    # the finding carries a real CVE-id, regardless of severity. WPScan's
    # `cvss.score` field is None for many older CVEs → severity falls back
    # to `info` → the CVE would never reach the counter under the old
    # `severity in high/critical` gate. Iter 7 header said "CVE matches: 0"
    # while the body listed 8 brave-popup-builder CVEs — exactly this bug.
    # For non-CVE severity-flagged findings, keep the previous behaviour
    # so the counter still reflects them (uses a synthetic WPVULN: id).
    if cves:
        state.append("cves_matched", {
            "cve": (str(cves[0]) if str(cves[0]).startswith("CVE-")
                    else f"CVE-{cves[0]}"),
            "target": target,
            "evidence": ev,
        })
    elif severity in ("high", "critical"):
        state.append("cves_matched", {
            "cve": f"WPVULN:{slug}:{title[:40]}",
            "target": target,
            "evidence": ev,
        })


def _diagnose_wpscan_empty(state, agent_name: str, transcript,
                            findings_added: int) -> None:
    """PN20 iter 11 (2026-09-04): when the wpscan parser adds 0 findings
    while `wordpress` agent was clearly triggered and wpscan was run
    multiple times, emit a diagnostic that names the most likely root
    cause. Pushes flags to state so report.py's meta-check block can
    surface a specific warning to the operator instead of leaving the
    silent 0-finding wpscan pass.

    Classification (in order):
      1. state.wpscan_api_exhausted already set → already covered by
         existing meta-check "WPScan API daily quota reached"; nothing
         extra to add.
      2. Any wpscan output contains "does not seem to be running
         WordPress" AND fingerprint saw WordPress → WAF challenge is
         the most probable cause → set wpscan_waf_suspect + log.
      3. All wpscan output files are missing OR size 0 → shell wrapper
         may have truncated, or every call errored before producing a
         file → log.
      4. Files exist but parser saw 0 plugins/vulns → wpscan received
         a response but the JSON was empty (target has no plugins that
         wpscan recognises, or the parser's expected shape mismatched).
    """
    if findings_added > 0:
        return
    # Any wpscan call attempted at all?
    wpscan_calls = 0
    saw_waf_hint = False
    saw_quota_hint = False
    for e in transcript:
        cmd = str(e.get("args", {}).get("command", ""))
        if "wpscan " not in cmd:
            continue
        wpscan_calls += 1
        result_low = str(e.get("result", "")).lower()
        if ("does not seem to be running wordpress" in result_low
                or "target is not a wordpress site" in result_low
                or "not vulnerable" in result_low):
            saw_waf_hint = True
        if ("daily limit" in result_low
                or "api limit reached" in result_low
                or "reached the daily" in result_low):
            saw_quota_hint = True
    if wpscan_calls == 0:
        return  # agent skipped wpscan entirely — nothing to diagnose

    # State already carries wpscan_api_exhausted → existing meta-check
    # covers it.
    if state.get("wpscan_api_exhausted") or saw_quota_hint:
        state.set("wpscan_api_exhausted", True)
        state.log(agent_name, "warn",
                   f"wpscan JSON parser added 0 findings after "
                   f"{wpscan_calls} call(s). WPScan API daily quota is "
                   f"the most likely cause (free tier = 25 req/day). "
                   f"See existing meta-check warning.")
        return

    # Fingerprint saw WordPress but wpscan claims 'not WordPress' → WAF.
    techs = [str(t).lower() for t in state.get("detected_techs", []) or []]
    from tech_aliases import resolve_tech_alias
    resolved = [resolve_tech_alias(t) for t in techs]
    wp_confirmed_elsewhere = any("wordpress" in t for t in resolved)
    if saw_waf_hint and wp_confirmed_elsewhere:
        state.set("wpscan_waf_suspect", True)
        state.log(agent_name, "warn",
                   f"wpscan returned 'not a WordPress site' on {wpscan_calls} "
                   f"call(s) while fingerprint confirmed WordPress. Almost "
                   f"certainly a WAF (ModSecurity / Cloudflare / DataDome) "
                   f"blocking wpscan's fingerprint requests. See meta-check "
                   f"warning + suggested remediations in REPORT.")
        return

    # Files missing or empty — parser had nothing to eat.
    from pathlib import Path as _P
    tmp = _P("/tmp")
    wpscan_files = list(tmp.glob("harness-wpscan*.json")) if tmp.is_dir() else []
    empty_or_missing = 0
    for p in wpscan_files:
        try:
            if p.stat().st_size < 10:
                empty_or_missing += 1
        except Exception:
            empty_or_missing += 1
    if not wpscan_files or empty_or_missing == len(wpscan_files):
        state.set("wpscan_output_empty", True)
        state.log(agent_name, "warn",
                   f"wpscan ran {wpscan_calls} time(s) but produced NO "
                   f"parseable JSON output ({len(wpscan_files)} file(s), "
                   f"{empty_or_missing} empty). Every call may have errored "
                   f"pre-write. Check the per-agent Tool Activity for exit "
                   f"codes and stderr of the individual calls.")
        return

    # Files exist + non-empty but parser hit 0 findings. Could be
    # (a) target has no plugins wpscan recognises, or (b) JSON shape
    # unexpected. Emit a generic diagnostic so the operator knows.
    state.set("wpscan_zero_findings", True)
    state.log(agent_name, "warn",
               f"wpscan produced {len(wpscan_files)} JSON file(s) but "
               f"parser found 0 plugin/theme/core vulnerabilities. Either "
               f"the target genuinely has no known-CVE items, or the JSON "
               f"structure diverged from the parser's expectations. Verify "
               f"manually: `cat /tmp/harness-wpscan-full.json | jq '.plugins "
               f"| keys'` should list the plugin slugs wpscan detected.")


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
