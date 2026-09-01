"""Report Agent — always runs last. No LLM calls.
Consolidates shared_state into a Markdown report saved to the run dir.
"""
from __future__ import annotations

import time
from pathlib import Path

from agents.base import BaseAgent


class ReportAgent(BaseAgent):
    NAME = "report"
    DESCRIPTION = "Consolidate all findings into a Markdown report"
    MAX_ITERATIONS = 0
    TOOL_NAMES = ["finish"]  # unused, we short-circuit .run

    def entry_condition(self, state) -> bool:
        return True

    def run(self, state) -> str:
        """Override — no LLM turns; deterministic aggregation."""
        started = time.time()
        self._emit("start", description=self.DESCRIPTION,
                   max_iterations=1)
        try:
            md = self._render_markdown(state)
            out = self.run_dir / "REPORT.md"
            out.write_text(md, encoding="utf-8")
            state.set("report_path", str(out))
            self._append({"kind": "report_written", "path": str(out)})
            elapsed = time.time() - started
            self._emit("progress", turn=1, max_turns=1)
            self._emit("done", elapsed=elapsed, tool_calls=0, turns=1)
            state.mark_agent_run(self.NAME, "done", elapsed, 1, 0)
            return "done"
        except Exception as e:
            state.error(self.NAME, str(e))
            self._emit("error", err=str(e))
            state.mark_agent_run(self.NAME, "error",
                                 time.time() - started, 0, 0)
            return "error"

    def _render_markdown(self, state) -> str:
        s = state.snapshot()
        lines = []
        lines.append(f"# Bughunter Harness Report — {s.get('target')}")
        lines.append("")

        # Top-of-report alert if the pre-flight failed
        if s.get("target_unreachable"):
            reason = s.get("target_unreachable_reason", "(no reason recorded)")
            lines.append("> 🚨 **TARGET UNREACHABLE — pipeline aborted at pre-flight.**")
            lines.append(f"> Reason: `{reason}`")
            lines.append(">")
            lines.append("> No recon / fingerprint / vuln scanning was performed. "
                         "Retry once the target is reachable, or add "
                         "authentication headers / VPN / IP allowlisting if the "
                         "target requires them.")
            lines.append("")

        lines.append(f"- **Target:** `{s.get('target')}`")
        lines.append(f"- **In-scope hosts:** `{s.get('in_scope_hosts')}`")
        lines.append(f"- **Live hosts found:** {len(s.get('live_hosts', []))}")
        lines.append(f"- **Subdomains:** {len(s.get('subdomains', []))}")
        lines.append(f"- **Techs detected:** "
                     f"{', '.join(s.get('detected_techs', [])) or '(none)'}")
        lines.append(f"- **Endpoints:** {len(s.get('endpoints_found', []))}")
        lines.append(f"- **CVE matches:** {len(s.get('cves_matched', []))}")
        lines.append("")

        # Agents run
        lines.append("## Agents Run")
        for a in s.get("agents_run", []):
            lines.append(
                f"- **{a['agent']}** — {a['status']} · "
                f"{a['elapsed_sec']}s · {a['turns']} turns · "
                f"{a['tool_calls']} tool calls"
            )
        lines.append("")

        # Findings by severity
        findings = s.get("findings", [])
        by_sev = {}
        for f in findings:
            by_sev.setdefault(f.get("severity", "info"), []).append(f)
        lines.append("## Findings")
        for sev in ("critical", "high", "medium", "low", "info"):
            items = by_sev.get(sev, [])
            if not items:
                continue
            lines.append(f"### {sev.upper()} ({len(items)})")
            for f in items:
                lines.append(f"- **{f['title']}**  ")
                lines.append(f"  Agent: `{f['agent']}`")
                if f.get("evidence"):
                    ev = str(f["evidence"])[:600].replace("\n", " ")
                    lines.append(f"  Evidence: `{ev}`")
                if f.get("recommendation"):
                    lines.append(f"  Recommendation: {f['recommendation']}")
            lines.append("")

        if s.get("cves_matched"):
            lines.append("## CVE Matches")
            for c in s["cves_matched"]:
                lines.append(f"- **{c.get('cve')}** — {c.get('target')}  ")
                if c.get("evidence"):
                    ev = str(c["evidence"])[:400].replace("\n", " ")
                    lines.append(f"  `{ev}`")
            lines.append("")

        # Endpoints found (useful even without formal findings)
        endpoints = s.get("endpoints_found", [])
        if endpoints:
            lines.append(f"## Endpoints Discovered ({len(endpoints)})")
            for e in endpoints[:50]:
                url = e.get("url", "(no url)")
                via = e.get("via", "?")
                status = e.get("status")
                extra = f" · status {status}" if status else ""
                lines.append(f"- `{url}` (via `{via}`{extra})")
            if len(endpoints) > 50:
                lines.append(f"- … and {len(endpoints) - 50} more")
            lines.append("")

        # Subdomains
        subs = s.get("subdomains", [])
        if subs:
            lines.append(f"## Subdomains ({len(subs)})")
            for sub in subs[:100]:
                lines.append(f"- `{sub}`")
            if len(subs) > 100:
                lines.append(f"- … and {len(subs) - 100} more")
            lines.append("")

        # Live hosts detail
        live = s.get("live_hosts", [])
        if live:
            lines.append(f"## Live Hosts ({len(live)})")
            for h in live[:30]:
                scheme = h.get("scheme", "?")
                host = h.get("host", "?")
                port = h.get("port", "")
                port_s = f":{port}" if port else ""
                status = h.get("status", "")
                title = h.get("title", "")
                tech = h.get("tech", [])
                extras = []
                if status: extras.append(f"status {status}")
                if title: extras.append(f"title={title[:60]!r}")
                if tech: extras.append(f"tech={tech}")
                extra_str = f" — {', '.join(extras)}" if extras else ""
                lines.append(f"- `{scheme}://{host}{port_s}`{extra_str}")
            lines.append("")

        # Per-agent tool activity log — floor of visibility when findings empty
        logs = s.get("logs", [])
        if logs:
            lines.append("## Per-Agent Tool Activity")
            by_agent: dict[str, list] = {}
            for log_entry in logs:
                by_agent.setdefault(log_entry.get("agent", "?"),
                                    []).append(log_entry)
            for agent_name, entries in by_agent.items():
                lines.append(f"### {agent_name} ({len(entries)} calls)")
                for e in entries[:30]:
                    kind = e.get("kind", "?")
                    msg = str(e.get("msg", ""))[:200]
                    lines.append(f"- `[{kind}]` {msg}")
                if len(entries) > 30:
                    lines.append(f"- … and {len(entries) - 30} more calls")
                lines.append("")

        # Per-agent narrative summaries (from each agent's finish() call)
        summaries = s.get("agent_summaries", [])
        if summaries:
            lines.append("## Agent Narrative Summaries")
            for sm in summaries:
                lines.append(f"### {sm.get('agent', '?')}")
                lines.append(str(sm.get("summary", "")).strip())
                lines.append("")

        if s.get("errors"):
            lines.append("## Errors During Run")
            for e in s["errors"]:
                lines.append(f"- `{e['agent']}` — {e['err']}")
            lines.append("")

        # Executive summary at the end
        lines.append("## Executive Summary")
        if s.get("target_unreachable"):
            lines.append(
                f"🚨 **Pipeline aborted at pre-flight.** Target "
                f"`{s.get('target')}` was unreachable "
                f"(`{s.get('target_unreachable_reason', 'no reason')}`). "
                "No scanning was performed. Verify the target is up, that no "
                "geo-block / VPN / WAF is denying you access, and re-launch."
            )
            lines.append("")
            lines.append("---")
            lines.append("_Generated by bugbounty harness (autonomous local LLM agent)._")
            return "\n".join(lines) + "\n"
        total_findings = len(s.get("findings", []))
        by_sev_count = {}
        for f in s.get("findings", []):
            by_sev_count[f.get("severity", "info")] = \
                by_sev_count.get(f.get("severity", "info"), 0) + 1
        sev_summary = ", ".join(
            f"{v} {k}" for k, v in sorted(
                by_sev_count.items(),
                key=lambda kv: {"critical": 0, "high": 1, "medium": 2,
                                "low": 3, "info": 4}.get(kv[0], 5))
        ) or "no findings recorded"
        lines.append(
            f"Pipeline covered **{sum(1 for a in s.get('agents_run', []) if a.get('status') == 'done')}** "
            f"of **{len(s.get('agents_run', []))}** agents against "
            f"`{s.get('target')}`, discovering "
            f"**{len(s.get('subdomains', []))}** subdomains, "
            f"**{len(s.get('live_hosts', []))}** live hosts, "
            f"**{len(s.get('endpoints_found', []))}** endpoints, "
            f"and {sev_summary} ({total_findings} total)."
        )
        # Highlight the highest-severity items
        crit_high = [f for f in s.get("findings", [])
                     if f.get("severity") in ("critical", "high")]
        if crit_high:
            lines.append("")
            lines.append("**Immediate attention:**")
            for f in crit_high[:5]:
                lines.append(f"- **{f['severity'].upper()}** — {f['title']}")
        lines.append("")

        lines.append("---")
        lines.append("_Generated by bugbounty harness (autonomous local LLM agent)._")
        return "\n".join(lines) + "\n"
