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
        # PN7 restore iter 8 (2026-09-04): global dedup normalization at
        # render time. Multiple agents (recon httpx-python-fallback,
        # fingerprint nuclei tech-detect, wpscan) each `state.extend
        # ("detected_techs", ...)` from their own vocabularies — the same
        # tech shows up in slug form (`google-tag-manager`), display form
        # (`Google Tag Manager`) and version-tagged form (`wordpress:7.1`)
        # in the same list. Iter 7 run showed 6+ dup pairs in the header.
        # Dedup key: lowercased slug with hyphens normalized to spaces and
        # the `:version` suffix stripped. Highest-signal form kept per
        # slug (prefer the version-tagged one, else display, else slug).
        techs_display = _dedup_techs_for_display(
            s.get("detected_techs", []) or [])
        lines.append(f"- **Techs detected:** "
                     f"{', '.join(techs_display) or '(none)'}")
        lines.append(f"- **Endpoints:** {len(s.get('endpoints_found', []))}")
        # CVE count iter 8 fix (2026-09-04): reflects any finding whose
        # evidence carries a `CVE-YYYY-NNNNN` string, not just entries the
        # wordpress agent chose to append to state.cves_matched. Iter 7
        # header said "CVE matches: 0" while body listed 8 findings with
        # CVEs — `_emit_wpscan_finding` only appended to cves_matched when
        # severity was high/critical, but WPScan's CVSS field is often
        # None for older CVEs → severity falls back to `info` → the CVE
        # never made it to the counter. Count from the source of truth.
        _cve_count = _count_unique_cves_in_findings(s)
        lines.append(f"- **CVE matches:** {_cve_count}")
        lines.append("")

        # Agents run — muestra `reason` cuando esta presente (importante
        # para skipped: sin reason no se sabia si el skip era por quick
        # mode, entry_condition, target unreachable, etc. Post-B7 fix).
        #
        # 2026-09-03: dedup por agent-name. Si el mismo agent aparece 2x
        # (quick skipped + escalate done), mostrar UNA sola linea con el
        # status FINAL y una nota "(re-run post-quick)" que documenta el
        # intento previo. Antes se listaban ambos entries y confundia al
        # operador (parecia que `wordpress` estaba skipped cuando en
        # realidad escalo y termino OK).
        lines.append("## Agents Run")
        _agents_seen: dict[str, dict] = {}
        _agents_prior: dict[str, list] = {}
        for a in s.get("agents_run", []):
            name = a.get("agent", "?")
            if name in _agents_seen:
                _agents_prior.setdefault(name, []).append(_agents_seen[name])
            _agents_seen[name] = a
        for a in _agents_seen.values():
            name = a.get("agent", "?")
            reason = str(a.get("reason", "")).strip()
            reason_str = f" · _reason:_ {reason}" if reason else ""
            prior = _agents_prior.get(name, [])
            rerun_str = ""
            if prior:
                prev_statuses = ", ".join(
                    f"{p.get('status')}({p.get('reason','')[:40] or 'no reason'})"
                    for p in prior)
                rerun_str = f" · _prior:_ {prev_statuses}"
            lines.append(
                f"- **{name}** — {a['status']} · "
                f"{a['elapsed_sec']}s · {a['turns']} turns · "
                f"{a['tool_calls']} tool calls{reason_str}{rerun_str}"
            )
        lines.append("")

        # Subdomain prioritization (only if sub_prioritizer ran)
        prioritized = s.get("prioritized_hosts") or []
        if prioritized:
            lines.append(f"## Subdomain Prioritization ({len(prioritized)} ranked)")
            lines.append("")
            lines.append("| # | Host | Score | Tier | Name | Status | Tech | Title | Ports | Shodan |")
            lines.append("|---|------|-------|------|------|--------|------|-------|-------|--------|")
            for i, p in enumerate(prioritized[:30], 1):
                c = p.get("components", {})
                lines.append(
                    f"| {i} | `{p.get('host','')}` | {p.get('score','')} | "
                    f"{p.get('tier','')} | {c.get('name',0)} | "
                    f"{c.get('status',0)} | {c.get('tech',0)} | "
                    f"{c.get('title',0)} | {c.get('ports',0)} | "
                    f"{c.get('shodan',0)} |"
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

        # PN10 fix (2026-09-04): endpoints probed negative — separate
        # section from the "confirmed" endpoints_found. Prevents the
        # operator from opening dead URLs (404/500/000). Lists status
        # so they can spot patterns (e.g. all 500 = WP DB error).
        neg = s.get("endpoints_probed_negative") or []
        if neg:
            lines.append(f"## Endpoints probed negative "
                         f"({len(neg)} — status 4xx/5xx/000)")
            lines.append("")
            lines.append("These URLs were candidates from the crawl but a "
                         "HEAD probe returned a non-success status. Not "
                         "listed as `Endpoints Discovered` above so the "
                         "operator doesn't waste time opening dead pages. "
                         "Recurring 500s on the same host trigger a "
                         "short-circuit (DoS-avoidance).")
            lines.append("")
            for e in neg[:40]:
                st = e.get("status")
                st_str = f"HTTP {st}" if st else "connect fail (000)"
                reason = e.get("skipped_reason", "")
                reason_str = f" · skipped: {reason}" if reason else ""
                lines.append(f"- `{e.get('url','?')}` — {st_str}{reason_str}")
            if len(neg) > 40:
                lines.append(f"- … and {len(neg) - 40} more")
            lines.append("")

        # PN11 fix (2026-09-04): WordPress plugins brute-forced by wpscan
        # but with no independent evidence of presence (fingerprint miss
        # + readme.txt not accessible). Listed here in a dedicated
        # section so the operator sees them for reference but their CVEs
        # don't inflate the main findings list with likely FPs.
        unconfirmed = s.get("wpscan_unconfirmed_plugins") or []
        if unconfirmed:
            lines.append(f"## WordPress plugins brute-forced by wpscan "
                         f"(unconfirmed, {len(unconfirmed)})")
            lines.append("")
            lines.append("These plugin slugs came from wpscan's `--plugins-"
                         "detection aggressive` brute-force but neither the "
                         "`fingerprint` agent nor a live `/wp-content/plugins/"
                         "<slug>/readme.txt` probe corroborated their presence. "
                         "**CVEs of these plugins were NOT emitted as findings** "
                         "to avoid false positives from WAF/CDN uniform-status "
                         "responses. Investigate manually if any of these slugs "
                         "look plausible for this target's stack:")
            lines.append("")
            for slug in unconfirmed[:60]:
                lines.append(f"- `{slug}`")
            if len(unconfirmed) > 60:
                lines.append(f"- … and {len(unconfirmed) - 60} more")
            lines.append("")

        # N12 fix (2026-09-03): Shodan InternetDB Enrichment section.
        # Before this, the log line `[shodan] InternetDB enriched N host(s)`
        # was the only visible artifact. Now each host's ports/CVEs/tags
        # get a dedicated block in the report — critical intel for the
        # operator (CVE ids from Shodan match to nuclei/wpscan work).
        shodan_hosts = [h for h in (s.get("live_hosts") or [])
                        if h.get("shodan") and not
                        h["shodan"].get("not_indexed")]
        if shodan_hosts:
            lines.append(f"## Shodan InternetDB Enrichment "
                         f"({len(shodan_hosts)} host(s))")
            for h in shodan_hosts:
                sh = h["shodan"]
                host = h.get("host", "?")
                ip = sh.get("ip", "?")
                lines.append(f"- **`{host}` (IP: `{ip}`)**")
                ports = sh.get("ports") or []
                if ports:
                    lines.append(f"  - Open ports: {', '.join(str(p) for p in ports)}")
                vulns = sh.get("vulns") or []
                if vulns:
                    lines.append(f"  - Known CVEs (Shodan DB): "
                                 f"{', '.join(str(v) for v in vulns[:10])}"
                                 f"{'…' if len(vulns) > 10 else ''}")
                tags = sh.get("tags") or []
                if tags:
                    lines.append(f"  - Tags: {', '.join(tags[:8])}")
                cpes = sh.get("cpes") or []
                if cpes:
                    lines.append(f"  - CPEs: `{cpes[0]}`"
                                 f"{f' +{len(cpes)-1} more' if len(cpes) > 1 else ''}")
                hostnames = sh.get("hostnames") or []
                if hostnames and hostnames != [host]:
                    lines.append(f"  - Other hostnames: {', '.join(hostnames[:5])}")
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
            # (f) wpscan missing but WordPress detected — the WordPress
            # agent cannot enumerate plugin versions without wpscan, so
            # 0 CVE match on a WP target is expected but not desirable.
            # Detected by wordpress.after_run when it sees exit=127 or
            # `command -v wpscan` returning exit=1.
            if (s.get("wpscan_missing")
                and any("wordpress" in t for t in _techs)):
                _meta_warnings.append(
                    "**`wpscan` is not installed** on this host but "
                    "WordPress was detected on the target. Without wpscan "
                    "the WordPress agent falls back to nuclei alone — no "
                    "plugin-version enumeration → 0 CVE match on the plugins "
                    "that fingerprint identified. Install with "
                    "`gem install wpscan` (macOS: `brew install ruby && "
                    "gem install wpscan`) and re-run for meaningful WP "
                    "coverage.")
            # (g) WPScan API daily quota exhausted (25/day free tier).
            # The wordpress agent detected the quota marker in a wpscan
            # output and un-exported the env var for the rest of the
            # session. Report tells the operator so they know why any
            # subsequent WP scan today skips the CVE-DB lookup.
            if s.get("wpscan_api_exhausted"):
                _meta_warnings.append(
                    "**WPScan API daily quota reached** (25 req/day free "
                    "tier). Subsequent wpscan calls this session run "
                    "WITHOUT `--api-token` — plugin/theme/user enumeration "
                    "still works but there is NO CVE-DB cross-match. Quota "
                    "resets at midnight UTC, or upgrade the plan at "
                    "<https://wpscan.com/pricing>. To reduce quota use per "
                    "run, drop repeated wpscan calls (see anti-repeat "
                    "guardrail in base.py — one wpscan --enumerate per host "
                    "should suffice).")
            # (j) N6 (2026-09-04): implausible tech version detected in
            # aggregated tech list or live_hosts. e.g. `WordPress:7.1`
            # when WP core is 6.x, or `Yoast SEO:28.4` when 22-24 is
            # current. Warns without blocking — often it's a bad-detect
            # from httpx tech-detect confusing plugin version with core.
            # LAST REVIEWED 2026-09-04 (verified against official vendor
            # release pages — WordPress 7.1 stable, Drupal 11.4.6, Joomla
            # 6.1.3, Yoast SEO 28.4, PHP 8.5 available, nginx mainline
            # 1.31.5, Apache HTTP 2.4.68). Ceilings set well above the
            # current version to absorb 2-4 major releases before the
            # meta-check starts false-positiving. Iter-11 fix after two
            # confirmed FPs (wordpress:7.0.4 and yoast:28.4 were flagged
            # as bad-detects when they were the real current version).
            # RE-REVIEW every 6 months and update the numbers + this line.
            _IMPLAUSIBLE_TECH_RANGES = {
                "wordpress": ("3.0", "9.99"),   # current 7.1
                "drupal": ("6.0", "14.99"),      # current 11.4
                "joomla": ("2.0", "9.99"),       # current 6.1
                "yoast-seo": ("1.0", "34.99"),   # current 28.4 (fast-moving)
                "yoast seo": ("1.0", "34.99"),
                "php": ("5.0", "9.99"),          # current 8.5
                "nginx": ("0.7", "2.99"),        # current mainline 1.31
                "apache": ("1.3", "3.99"),       # current 2.4.68
            }
            def _tech_ver(t: str) -> tuple:
                parts = []
                for p in str(t).replace("-", ".").split(".")[:5]:
                    try:
                        parts.append(int("".join(c for c in p if c.isdigit()) or "0"))
                    except ValueError:
                        parts.append(0)
                while len(parts) < 5:
                    parts.append(0)
                return tuple(parts)
            # PN17 iter 10: alias-resolve so `version_by_css:7.0.4` gets
            # sanity-checked as `wordpress:7.0.4` — otherwise the check
            # never fires on nuclei-detector-named techs.
            from tech_aliases import resolve_tech_alias
            # PN17 completion iter 13 (2026-09-04): the sanity check
            # used to iterate only `state.detected_techs` (which lands
            # in kebab-case, deduped, sometimes without version). The
            # richer version-tagged tech strings (e.g. `WordPress:7.1`,
            # `Yoast SEO:28.4`) live in `live_hosts[i].tech` in display
            # form — populated by recon's httpx `-tech-detect` fallback.
            # Extending the check to also walk live_hosts.tech means an
            # implausible version like `WordPress:999.9` fires the
            # warning regardless of which source produced it.
            _live_techs = []
            for h in (s.get("live_hosts") or []):
                for t in (h.get("tech") or []):
                    _live_techs.append(str(t).lower())
            _all_techs = _techs + _live_techs
            _implausible: list[str] = []
            for t in _all_techs:
                t = resolve_tech_alias(t)
                if ":" not in t:
                    continue
                name, _, ver = t.partition(":")
                name = name.strip().lower()
                ver = ver.strip()
                rng = _IMPLAUSIBLE_TECH_RANGES.get(name)
                if not rng or not ver:
                    continue
                lo, hi = rng
                v = _tech_ver(ver)
                if not (_tech_ver(lo) <= v <= _tech_ver(hi)):
                    _implausible.append(f"`{name}:{ver}` (plausible range: "
                                         f"{lo} — {hi})")
            # Dedup — same (name:ver) can arrive twice, once from
            # detected_techs and once from live_hosts.tech.
            _implausible = sorted(set(_implausible))
            if _implausible:
                _meta_warnings.append(
                    "**Implausible tech version(s) detected**: "
                    + ", ".join(_implausible[:5])
                    + (f" (+{len(_implausible)-5} more)"
                       if len(_implausible) > 5 else "")
                    + ". Likely a bad-detect from httpx `-tech-detect` "
                    "confusing a plugin/theme version with the parent "
                    "product. Verify against `<meta name=\"generator\">` "
                    "in the page HTML or `curl <base>/readme.html`. "
                    "Downstream CVE lookups against these versions "
                    "return zero matches (version doesn't exist)."
                )
            # (i) PN1 (2026-09-04): wpscan exit=4 while WordPress was
            # detected by nuclei. Almost always a WAF (Cloudflare /
            # DataDome / Sucuri) blocking wpscan's request signature.
            if (s.get("wpscan_waf_suspect")
                and any("wordpress" in t for t in _techs)):
                _meta_warnings.append(
                    "**wpscan reported the target as 'not a WordPress "
                    "site' (exit=4) while nuclei-wordpress-detect "
                    "confirmed it IS WordPress.** This is almost always "
                    "a WAF (Cloudflare / DataDome / Sucuri) fingerprinting "
                    "wpscan's TLS/JA3 or User-Agent and returning a "
                    "challenge page. Try (in order): (a) verify the "
                    "attribution header made it through — the harness "
                    "auto-injects `custom_headers` on wpscan via "
                    "`--headers`; (b) run wpscan manually with "
                    "`--verbose --debug --user-agent 'Mozilla/5.0 …'` "
                    "and inspect the first response; (c) use a browser-"
                    "fingerprint impersonator such as `curl-impersonate` "
                    "for the initial WP-existence probe."
                    + _curl_impersonate_hint(s))
            # (h) Shodan Pro credits exhausted (paid plan monthly limit).
            # ToolRegistry marks state.shodan_pro_exhausted=True on 402 or
            # any 'credits' marker; subsequent shodan_search calls this
            # session short-circuit. The LLM sees the ERROR and falls back
            # to shodan_internetdb (still free).
            if s.get("shodan_pro_exhausted"):
                _meta_warnings.append(
                    "**Shodan Pro credits exhausted** (monthly query "
                    "quota reached). Subsequent `shodan_search` calls "
                    "this session short-circuit to ERROR — the LLM is "
                    "directed to fall back to `shodan_internetdb` "
                    "(free, no quota, always available). Top up at "
                    "<https://account.shodan.io> or wait for the monthly "
                    "reset.")
            # (k) PN20 iter 11 (2026-09-04): wpscan JSON output empty
            # despite wpscan being called. Likely target-connection
            # failure or wpscan aborted pre-write.
            if s.get("wpscan_output_empty"):
                _meta_warnings.append(
                    "**wpscan ran but produced NO parseable JSON output**. "
                    "Every wpscan call errored before writing the file, or "
                    "the shell wrapper truncated the write. Check the "
                    "`### wordpress` per-agent Tool Activity for exit codes "
                    "on the wpscan calls — a `429` / `403` / `exit=4` "
                    "usually points at rate-limiting or WAF; a `timeout` "
                    "points at a hung wpscan process. Re-run manually "
                    "with `--verbose --debug` to inspect.")
            # (l) PN20 iter 11: wpscan JSON files exist AND non-empty
            # but parser found 0 plugin/theme/core CVEs.
            if s.get("wpscan_zero_findings"):
                _meta_warnings.append(
                    "**wpscan JSON output parsed but produced 0 CVE "
                    "findings**. Either the target genuinely has no "
                    "plugins/themes with known CVEs in the WPScan DB, "
                    "or the JSON shape diverged from the parser. Sanity "
                    "check manually: `cat /tmp/harness-wpscan-full.json "
                    "| jq '.plugins | keys'` should list the plugin "
                    "slugs — if that returns empty or errors, wpscan "
                    "itself didn't detect plugins (probable WAF)."
                    " If the list is populated but the CVE fields are "
                    "empty, the WPScan API token may be missing / "
                    "unauthorised.")
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


def _dedup_techs_for_display(raw: list) -> list[str]:
    """Global dedup for the `Techs detected` line — PN7 restore iter 8,
    PN17 alias-aware iter 10.

    Multiple agents contribute to `state.detected_techs` from different
    vocabularies:
      recon httpx-python  → 'Google Tag Manager' (display form)
      fingerprint nuclei  → 'google-tag-manager' (slug form)
      wpscan JSON parser  → 'wordpress:7.1'      (version-tagged form)
      nuclei detector alias → 'version_by_css:7.0.4' (detector name, not tech)

    Without dedup the header carries all forms of the same tech. Iter 10
    additionally passes every entry through the alias table so a
    detector-named tech (`version_by_css`, `favicon-detect:plesk`) is
    collapsed onto its canonical product name and the operator sees
    `wordpress:7.0.4` in the header instead of `version_by_css:7.0.4`.

    Key = lowercased slug with hyphens normalized to spaces and any
    `:version` suffix stripped. For each key keep the form with most
    signal: prefer version-tagged, else display form, else raw slug.
    Result is sorted alphabetically by display form for stable output.
    """
    if not raw:
        return []
    # PN17: alias-resolve first so `version_by_css:7.0.4` collapses onto
    # `wordpress:7.0.4` before dedup.
    from tech_aliases import resolve_tech_alias
    raw = [resolve_tech_alias(t) for t in raw]

    def _key(t: str) -> str:
        base = str(t).lower().split(":", 1)[0]
        return base.replace("-", " ").strip()

    def _rank(t: str) -> int:
        # Higher rank = more signal, kept when we see multiple forms
        # of the same tech. Version-tagged wins outright; among the
        # non-version forms, the one with any uppercase letter is
        # treated as the human display form (title-cased).
        s = str(t)
        if ":" in s and any(c.isdigit() for c in s.split(":", 1)[1]):
            return 3
        if s != s.lower():
            return 2
        if "-" in s:
            return 0  # raw slug — lowest rank
        return 1

    by_key: dict[str, str] = {}
    for t in raw:
        if not t:
            continue
        k = _key(t)
        if not k:
            continue
        prev = by_key.get(k)
        if prev is None or _rank(t) > _rank(prev):
            by_key[k] = str(t)

    return sorted(by_key.values(), key=lambda x: x.lower())


def _count_unique_cves_in_findings(snapshot: dict) -> int:
    """CVE counter iter 8 fix — count unique CVE-YYYY-NNNNN identifiers
    referenced anywhere in findings evidence, not just the ones the
    wordpress agent chose to append to `state.cves_matched`.

    Iter 7 header said "CVE matches: 0" while the body listed 8 real
    findings with CVE ids (all `severity=info` because WPScan's CVSS
    field was None for older CVEs). Counting from evidence text is the
    source of truth — matches what the reader actually sees in the body.
    """
    import re as _re
    seen: set[str] = set()
    # Cover both the wordpress-agent-populated list AND the finding
    # evidence — either alone would miss a class of match.
    for c in (snapshot.get("cves_matched") or []):
        cid = str(c.get("cve") or "").upper()
        if cid.startswith("CVE-"):
            seen.add(cid)
    for f in (snapshot.get("findings") or []):
        for src in (f.get("evidence"), f.get("title")):
            if not src:
                continue
            for m in _re.finditer(r"CVE-\d{4}-\d{4,7}", str(src),
                                    _re.IGNORECASE):
                seen.add(m.group(0).upper())
    return len(seen)


def _curl_impersonate_hint(snapshot: dict) -> str:
    """PN22 iter 13 (2026-09-04): return a one-line hint about
    curl-impersonate availability, appended to the wpscan-WAF-suspect
    meta-check warning. Reads `state.missing_tools` published by
    orchestrator._precheck_optional_tools() to tell the operator
    whether the tool is installed (recommend running it manually)
    or missing (give the install pointer)."""
    missing = snapshot.get("missing_tools") or []
    missing_low = [str(m).lower() for m in missing]
    variants = ("curl-impersonate", "curl_chrome116",
                "curl-impersonate-chrome")
    installed = not any(v in missing_low for v in variants)
    if installed:
        return (" `curl-impersonate` is installed on this host — try "
                "`curl_chrome116 -sI <target>/wp-login.php` manually "
                "to confirm the WAF blocks wpscan's fingerprint but not "
                "a real Chrome one.")
    return (" `curl-impersonate` is NOT installed — the recommended "
            "way to test the WAF-bypass theory. Install on macOS: "
            "`brew install curl-impersonate` (installs `curl_chrome116`, "
            "`curl_ff109`, …). Then: `curl_chrome116 -sI "
            "<target>/wp-login.php`.")
