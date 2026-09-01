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

    SYSTEM_PROMPT = """/no_think

You are the WORDPRESS AGENT. Only dispatched when WordPress was detected.
Enumerate plugins/themes/users and match against known CVEs.

Workflow (one tool_call per turn):
  1. wpscan --url <target> --random-user-agent --no-banner --format cli \
       --disable-tls-checks
  2. wpscan --url <target> --enumerate p,u,t --plugins-detection aggressive \
       --random-user-agent --no-banner --format cli
     (this can be slow; ok to skip if the earlier call already listed plugins)
  3. nuclei -u <target> -tags wordpress -severity medium,high,critical \
       -rl 5 -c 5 -silent
  4. curl -s <target>/wp-json/wp/v2/users     (user disclosure via REST API)
  5. finish() with findings: plugins outdated, users leaked, CVEs matched

Rules:
  - One tool_call per turn.
  - If wpscan is not installed, fall back to nuclei -tags wordpress.
  - NEVER attempt XMLRPC / login brute-force. Report the vector only.
"""

    def entry_condition(self, state) -> bool:
        return state.has_tech("wordpress") or state.has_tech("wp-")

    def build_objective(self, state) -> str:
        host = _primary_url(state)
        return (
            f"WordPress detected at: {host}\n"
            f"Detected techs full list: {state.get('detected_techs', [])}\n\n"
            "Enumerate + CVE-match. Finish with findings."
        )

    def after_run(self, state, transcript):
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


def _primary_url(state):
    hosts = state.get("live_hosts", [])
    if hosts:
        h = hosts[0]
        return f"{h.get('scheme','https')}://{h.get('host')}"
    return state.get("target")
