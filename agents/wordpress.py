"""WordPress Agent — dispatched only if Fingerprint / Recon detected WordPress.
Uses wpscan (if installed) + nuclei -tags wordpress.
"""
from __future__ import annotations

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
       command -v wpscan
     If exit=1 (wpscan not found), SKIP steps 1-2 and go straight to step
     3. Do NOT retry wpscan — it will keep failing. Log that wpscan is
     missing so the operator installs it (`gem install wpscan`).

  1. wpscan --url <target> --random-user-agent --no-banner --format cli \
       --disable-tls-checks
  2. wpscan --url <target> --enumerate p,u,t --plugins-detection aggressive \
       --random-user-agent --no-banner --format cli
     (this can be slow; ok to skip if the earlier call already listed plugins)
  3. nuclei -u <target> -tags wordpress -severity medium,high,critical \
       -rl 5 -c 5 -silent -jsonl -o /tmp/harness-nuclei-wordpress.jsonl
     (the harness parses this JSONL after the run — see B5 fix pattern)
  4. curl -s <target>/wp-json/wp/v2/users     (user disclosure via REST API)
  5. finish() with findings: plugins outdated, users leaked, CVEs matched

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
        return (
            f"Target: {host}\n"
            f"Detected techs full list: {state.get('detected_techs', [])}\n\n"
            "Enumerate + CVE-match. Finish with findings."
        )

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
        for entry in transcript:
            if entry.get("tool") != "run_shell":
                continue
            cmd = str(entry.get("args", {}).get("command", ""))
            result = str(entry.get("result", ""))
            # Detect wpscan missing: "command -v wpscan" returns exit=1
            # OR the wpscan call returns "exit=127" (command not found)
            import re as _re
            if (("command -v wpscan" in cmd
                 and _re.search(r"exit=1(?!\d)", result))
                or ("wpscan " in cmd
                    and _re.search(r"exit=127", result))):
                state.set("wpscan_missing", True)
                state.log(self.NAME, "warn",
                          "wpscan not installed — WordPress agent falls back "
                          "to nuclei. Install with `gem install wpscan` "
                          "(macOS: `brew install ruby && gem install wpscan`).")

        for entry in transcript:
            if entry.get("tool") != "run_shell":
                continue
            result = str(entry.get("result", ""))
            # wpscan patterns
            if "wpscan" in str(entry.get("args", {}).get("command", "")):
                # Plugin lines: "[+] someplugin\n | Version: 1.2.3"
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
                # Vulnerability blocks: "[!] Title:  <cve description>"
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
