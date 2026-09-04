"""Example extension agent — subdomain takeover check.

Copy this file, rename, edit the two-token identifiers (NAME, class name)
and the workflow. That is all the harness needs to auto-register the agent
in the pipeline.

Splice position:
    ENTRY_AFTER = "recon"   ← inserts right after the recon agent so the
                              subdomains it discovered are visible in state.

Removing this file (or setting extensions.enabled: false in config.yaml)
takes the agent out of the pipeline. No core code changes needed.
"""
from __future__ import annotations

import re

from agents.base import BaseAgent


class TakeoverAgent(BaseAgent):
    NAME = "takeover"
    DESCRIPTION = "Subdomain takeover check on discovered subs"
    # Position in the pipeline: right after the recon agent (which populates
    # state.subdomains). Any string matching an existing agent's NAME works.
    ENTRY_AFTER = "recon"
    MAX_ITERATIONS = 6
    TOOL_NAMES = ["run_shell", "finish"]

    SYSTEM_PROMPT = """/no_think

You are the SUBDOMAIN TAKEOVER AGENT. Your job: given a list of subdomains
already found by the recon agent, detect ones with dangling CNAMEs that
point to unclaimed third-party services (S3 buckets, GitHub Pages,
Heroku, Fastly, Netlify, Azure blob, etc.).

TAKEOVER TOOLING RULE — hard, non-negotiable (PN6 iter 7 + reinforce iter 9):

`nuclei -tags takeover` is the ONLY tool this agent runs. DO NOT try
`subjack`, `subzy`, `takeover`, or any other tool — nuclei-templates
ships an equivalent takeover fingerprint set that covers the same
services (S3, GitHub Pages, Heroku, Fastly, Netlify, Azure Blob, …).

Why other tools fail on this harness (do not try to "fall back"):
  - subjack     → requires `$(go env GOPATH)/…/fingerprints.json` and
                  `$( )` is on the shell denylist → rejected outright.
  - subzy       → not installed by default; `exit=127` burns a turn.
  - dnsx alone  → no takeover fingerprint DB; only resolves CNAMEs.

CRITICAL: ALWAYS include
      -jsonl -o /tmp/harness-nuclei-takeover.jsonl
so the harness parses the file (independent of stdout survival through
the shell wrapper).

Workflow (one tool_call per turn):
  1. Write subdomains to /tmp/harness-subs.txt (one per line, `cat > file
     << 'EOF' … EOF` style — the harness accepts heredocs).
  2. Run EXACTLY ONE nuclei call:
       nuclei -l /tmp/harness-subs.txt -tags takeover -silent -rl 5 -c 5 \
         -jsonl -o /tmp/harness-nuclei-takeover.jsonl
  3. finish() with any confirmed takeovers as:
       ["critical — <sub> — dangling CNAME to <service> — unclaimed"]
     If nuclei returned exit=0 with an empty JSONL, finish() with an
     empty findings list — do NOT try alternative tools "to be sure".

Rules:
  - Do NOT try to claim / register / take over the resource yourself.
    Just PROVE it is takeoverable and stop.
  - Do NOT run any tool other than the one nuclei call in step 2.
  - Do NOT retry nuclei with different flags on exit=0; a clean run is
    a clean run.
"""

    def entry_condition(self, state) -> bool:
        return bool(state.get("subdomains"))

    def build_objective(self, state) -> str:
        subs = state.get("subdomains", [])[:200]  # cap for prompt size
        return (
            f"Target apex: {state.get('target')}\n"
            f"Subdomains from recon ({len(subs)}):\n"
            + "\n".join(f"  {s}" for s in subs[:50])
            + (f"\n  … and {len(subs) - 50} more" if len(subs) > 50 else "")
            + "\n\nDetect takeovers. Finish with critical findings only "
              "(dangling CNAMEs to unclaimed third-party services)."
        )

    def after_run(self, state, transcript):
        """Parse subjack + nuclei-takeover output → structured findings.

        B6 fix (2026-09-03): parse nuclei JSONL file FIRST — nuclei is
        instructed to emit `-jsonl -o /tmp/harness-nuclei-takeover.jsonl`
        so the harness reads the file directly (independent of stdout
        survival through the shell wrapper — bug B3 was hiding stdout as
        "(no exit)" in run 20260903T094840Z).
        """
        try:
            # Reuse the parser from web_vuln (same JSONL schema).
            from agents.web_vuln import _parse_nuclei_jsonl_to_findings
            _parse_nuclei_jsonl_to_findings(
                state, self.NAME,
                glob_pattern="harness-nuclei-takeover*.jsonl")
        except Exception as e:
            state.log(self.NAME, "warn",
                      f"nuclei JSONL parse failed: {type(e).__name__}: {e}")

        # subjack: "[Vulnerable] example.foo.com -> unclaimed.s3.amazonaws.com"
        subjack_re = re.compile(
            r"\[Vulnerable\]\s+(\S+)\s+->\s+(\S+)", re.IGNORECASE)
        # nuclei: "[takeover-name] [http] [high] http://sub.example.com/"
        nuclei_re = re.compile(
            r"\[([\w\-]+)\]\s*\[\w+\]\s*\[(high|critical)\]\s*(\S+)")
        for entry in transcript:
            if entry.get("tool") != "run_shell":
                continue
            result = str(entry.get("result", ""))
            for m in subjack_re.finditer(result):
                sub, target = m.group(1), m.group(2)
                state.add_finding(
                    agent=self.NAME, severity="critical",
                    title=f"Subdomain takeover: {sub} → {target}",
                    evidence=f"Confirmed by subjack: {m.group(0)}",
                    recommendation=(
                        "Remove the dangling CNAME OR reclaim the resource. "
                        "This is a full-takeover primitive."))
            for m in nuclei_re.finditer(result):
                template, severity, url = m.group(1), m.group(2), m.group(3)
                if "takeover" in template.lower():
                    state.add_finding(
                        agent=self.NAME, severity=severity,
                        title=f"Takeover template {template} matched: {url}",
                        evidence=m.group(0),
                        recommendation=(
                            "Verify manually + remove CNAME OR reclaim."))
