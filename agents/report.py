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
        elif s.get("preflight_warning"):
            reason = s.get("preflight_warning_reason", "(no reason recorded)")
            lines.append("> ⚠️ **Pre-flight WARNING — python-requests probe failed, "
                         "pipeline continued anyway.**")
            lines.append(f"> Reason: `{reason}`")
            lines.append(">")
            lines.append("> The agents' Go/curl-based tools may have reached the "
                         "target where the probe couldn't. If findings below look "
                         "empty and every agent's tool_activity shows exit≠0, the "
                         "target is likely truly down or IP-blocking you — retry "
                         "from a different exit node, or pass `--strict-preflight` "
                         "next time to abort early on this class of failure.")
            lines.append("")

        # Quick-mode escalate suggested — displayed when quick_mode was on,
        # escalate criteria fired, and the operator declined (or was
        # non-interactive without --auto-escalate).
        if s.get("quick_escalate_suggested"):
            lines.append("> 💡 **Escalate suggested** — this run finished in "
                         "QUICK mode and detected signal that warrants a "
                         "FULL pass. Re-run with `--complete` to enable "
                         "login_probe / wordpress / api_fuzzer / auth + "
                         "adversarial review.")
            for r in (s.get("quick_escalate_reasons") or [])[:8]:
                lines.append(f"> - {r}")
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

        # Agents run — muestra `reason` cuando esta presente (importante
        # para skipped: sin reason no se sabia si el skip era por quick
        # mode, entry_condition, target unreachable, etc. Post-B7 fix).
        lines.append("## Agents Run")
        for a in s.get("agents_run", []):
            reason = str(a.get("reason", "")).strip()
            reason_str = f" · _reason:_ {reason}" if reason else ""
            lines.append(
                f"- **{a['agent']}** — {a['status']} · "
                f"{a['elapsed_sec']}s · {a['turns']} turns · "
                f"{a['tool_calls']} tool calls{reason_str}"
            )
        lines.append("")

        # Subdomain prioritization (only if sub_prioritizer ran)
        prioritized = s.get("prioritized_hosts") or []
        if prioritized:
            lines.append(f"## Subdomain Prioritization ({len(prioritized)} ranked)")
            lines.append("")
            lines.append("| # | Host | Score | Tier | Name | Status | Tech | Title | Ports |")
            lines.append("|---|------|-------|------|------|--------|------|-------|-------|")
            for i, p in enumerate(prioritized[:30], 1):
                c = p.get("components", {})
                lines.append(
                    f"| {i} | `{p.get('host','')}` | {p.get('score','')} | "
                    f"{p.get('tier','')} | {c.get('name',0)} | "
                    f"{c.get('status',0)} | {c.get('tech',0)} | "
                    f"{c.get('title',0)} | {c.get('ports',0)} |"
                )
            if len(prioritized) > 30:
                lines.append(f"| … | (+{len(prioritized)-30} more) |")
            # Whether multi-host mode was used
            scanned_subs = sorted({
                str(f.get("sub_scanned"))
                for f in s.get("findings", [])
                if f.get("sub_scanned")
            })
            if scanned_subs:
                lines.append("")
                lines.append(f"Multi-host mode was ON — scanned "
                              f"{len(scanned_subs)} sub(s) in loop: "
                              + ", ".join(f"`{h}`" for h in scanned_subs))
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
            # If any finding in this severity has sub_scanned, group by sub
            has_subs = any(f.get("sub_scanned") for f in items)
            if has_subs:
                by_sub: dict[str, list] = {}
                for f in items:
                    key = str(f.get("sub_scanned") or "(primary target)")
                    by_sub.setdefault(key, []).append(f)
                for sub, subitems in sorted(by_sub.items()):
                    lines.append(f"#### On `{sub}` ({len(subitems)})")
                    for f in subitems:
                        lines.append(f"- **{f['title']}**  ")
                        lines.append(f"  Agent: `{f['agent']}`")
                        if f.get("evidence"):
                            ev = str(f["evidence"])[:600].replace("\n", " ")
                            lines.append(f"  Evidence: `{ev}`")
                        if f.get("recommendation"):
                            lines.append(f"  Recommendation: {f['recommendation']}")
                    lines.append("")
            else:
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

        # Adversarial review section — shown when the reviewer processed any
        # findings. Both the rejected list and the full verdict table are
        # useful audit trail for the operator.
        verdicts = s.get("adversarial_verdicts") or []
        rejected = s.get("rejected_findings") or []
        if verdicts or rejected:
            lines.append("## Adversarial Review")
            passed = sum(1 for v in verdicts if v.get("verdict") == "PASS")
            rejected_count = sum(1 for v in verdicts if v.get("verdict") == "REJECT")
            lines.append(
                f"- **Reviewed:** {len(verdicts)}  · "
                f"**Passed:** {passed}  · "
                f"**Rejected:** {rejected_count}"
            )
            lines.append(
                "- Reviewer prompt: strict 7-question gate "
                "(specific / demonstrable / severity-matched / triager-reproducible "
                "/ in-scope / program-payable / not-a-known-duplicate). "
                "Findings that fail even one question are moved out of the "
                "notification path."
            )
            lines.append("")
            if rejected:
                lines.append(f"### Rejected findings ({len(rejected)})")
                for r in rejected[:20]:
                    reason = str(r.get("_adversarial_reason", ""))[:200]
                    lines.append(
                        f"- ~~[{str(r.get('severity','?')).upper()}] "
                        f"{r.get('title','')[:120]}~~  "
                    )
                    lines.append(f"  Rejected because: {reason}")
                if len(rejected) > 20:
                    lines.append(f"- … and {len(rejected) - 20} more rejected")
                lines.append("")

        if s.get("errors"):
            lines.append("## Errors During Run")
            for e in s["errors"]:
                lines.append(f"- `{e['agent']}` — {e['err']}")
            lines.append("")

        # ── Meta-check pre-summary (2026-09-03) ─────────────────────
        # Warnings condicionales antes de la Executive Summary — señales
        # cuando el pipeline probablemente perdio valor:
        #   (a) CMS detectado pero agent CMS-especifico skipeado
        #   (b) live_hosts==0 pero target seteado como http/s (fallo silencioso)
        #   (c) 0 findings + pipeline > 10 min (posible loop LLM sin exit code)
        _meta_warnings = []
        try:
            _agents_run = s.get("agents_run", []) or []
            _agents_by_name = {a.get("agent"): a for a in _agents_run}
            _techs = [str(t).lower() for t in s.get("detected_techs", []) or []]
            _cms_map = {
                "wordpress": "wordpress",
                "drupal": "drupal",  # no dedicated agent yet
                "joomla": "joomla",
            }
            for tech, agent_name in _cms_map.items():
                if any(tech in t for t in _techs):
                    ar = _agents_by_name.get(agent_name)
                    if ar and str(ar.get("status")) != "done":
                        reason = str(ar.get("reason", "no reason"))
                        _meta_warnings.append(
                            f"CMS **{tech}** was detected, but the "
                            f"`{agent_name}` agent did not run (status="
                            f"`{ar.get('status')}`, reason: _{reason}_). "
                            f"Consider re-running with `--complete` (full mode) "
                            f"to enable it — the CMS agent is the one that "
                            f"converts INFO plugin detections into HIGH/"
                            f"CRITICAL CVE findings via wpscan.")
            # (b) live_hosts silent-fail
            _live = s.get("live_hosts", []) or []
            _target = str(s.get("target", "")).lower()
            if not _live and (_target.startswith("http://")
                              or _target.startswith("https://")):
                _meta_warnings.append(
                    "**Live hosts is 0** but the target is an http(s) URL. "
                    "This usually means the recon agent's httpx tool call "
                    "was lost by the shell wrapper (bug B3 class). The B2 "
                    "fallback should have added the target of oficio — if "
                    "you see this warning, the fallback did NOT trigger; "
                    "check `state.json` and `logs` for the recon agent.")
            # (c) 0 findings + long duration
            _total_findings = len(s.get("findings", []) or [])
            _total_secs = sum(float(a.get("elapsed_sec", 0) or 0)
                              for a in _agents_run)
            if _total_findings == 0 and _total_secs > 600:
                _meta_warnings.append(
                    f"Pipeline ran for **{int(_total_secs)}s** ({_total_secs/60:.1f} "
                    f"min) but produced **0 findings**. Likely an LLM loop "
                    f"caused by exit-code parse failure (B3 class) or a "
                    f"silent tool wrapper truncation. Check per-agent "
                    f"tool activity for repeated identical commands.")
            # (d) frequent 'command timed out' — shell_timeout_sec too low
            _logs = s.get("logs", []) or []
            _timeout_hits = sum(
                1 for l in _logs
                if l.get("kind") == "shell"
                and "command timed out" in str(l.get("msg", "")).lower())
            if _timeout_hits >= 3:
                _meta_warnings.append(
                    f"Detected **{_timeout_hits} shell timeouts** during the "
                    f"run. Nuclei/wpscan/nikto scans against a live host "
                    f"often need more than the default 300s. Consider raising "
                    f"`shell_timeout_sec: 900` (or 1200) in config.yaml — "
                    f"otherwise each scan is truncated and the LLM retries, "
                    f"burning turns.")
            # (e) frequent 'forbidden token' — the LLM keeps hitting the
            # command denylist. Usually means the prompt taught a shell
            # trick that uses `&`, `$(...)`, or backticks — none of those
            # pass the tool wrapper. Rewrite the workflow to avoid them.
            _denylist_hits = sum(
                1 for l in _logs
                if l.get("kind") == "shell"
                and "forbidden token" in str(l.get("msg", "")).lower())
            if _denylist_hits >= 3:
                _meta_warnings.append(
                    f"Detected **{_denylist_hits} denylist rejections** "
                    f"(`forbidden token`). The LLM tried command patterns "
                    f"using `&`, `$( )`, backticks or other blocked chars. "
                    f"Rewrite the offending agent's workflow to use "
                    f"`; and `>` in place of `&&`/`&`, and split subshell "
                    f"substitutions across two shell calls.")
        except Exception:
            pass  # meta-check NEVER breaks the report

        if _meta_warnings:
            lines.append("## ⚠️ Meta-check warnings")
            lines.append("")
            lines.append("The report was generated with these caveats — they "
                         "usually mean the pipeline lost signal to a plumbing "
                         "issue, not to genuine absence of vulnerabilities:")
            lines.append("")
            for w in _meta_warnings:
                lines.append(f"- {w}")
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
            lines.append("_Generated by bughunter harness (autonomous local LLM agent)._")
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
        lines.append("_Generated by bughunter harness (autonomous local LLM agent)._")
        return "\n".join(lines) + "\n"
