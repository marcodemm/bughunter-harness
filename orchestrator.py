"""Orchestrator — sequentially runs the pipeline of specialist agents.

Fixed order (each agent evaluates its own entry_condition against shared_state):

  1. recon              → subs + live hosts + ports          (always)
  2. fingerprint        → detected_techs                     (if live http)
  3. content_discovery  → endpoints_found                    (if live http)
  4. web_vuln           → nuclei + nikto CVEs                (if live http)
  5. wordpress          → wpscan                              (if wordpress)
  6. api_fuzzer         → API surface + BOLA/BFLA hints      (if /api/)
  7. auth               → auth-bypass, SSO/OAuth misconfig   (if login)
  8. report             → Markdown report from shared_state  (always, last)

The report path is written to shared_state.report_path so main can attach it
to the mailer body.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from urllib.parse import urlparse

import requests
# Silence "unverified HTTPS" warnings from pre-flight verify=False checks.
# We only skip cert verify for the pre-flight probe (targets often have
# self-signed / expired / mismatched certs); the LLM's real tool calls
# use whatever cert policy `requests` defaults to.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

from agents.api_fuzzer import ApiFuzzerAgent
from agents.auth import AuthAgent
from agents.content_discovery import ContentDiscoveryAgent
from agents.fingerprint import FingerprintAgent
from agents.login_probe import LoginProbeAgent
from agents.recon import ReconAgent
from agents.report import ReportAgent
from agents.sub_prioritizer import SubPrioritizerAgent
from agents.web_vuln import WebVulnAgent
from agents.wordpress import WordPressAgent
from shared_state import SharedState
import telegram_notifier
import tempcleaner
import extension_loader
from adversarial_reviewer import AdversarialReviewer
from ui import MultiAgentUI


# Order matters:
#   - sub_prioritizer runs right after recon (ranks state.live_hosts so
#     the rest of the pipeline sees the juiciest sub at [0]);
#   - login_probe runs BEFORE web_vuln so its captured cookie is
#     auto-injected into the sqlmap/dalfox/nuclei calls that follow.
AGENT_ORDER = [
    ReconAgent,
    SubPrioritizerAgent,   # deterministic ranker — reorders live_hosts
    FingerprintAgent,
    ContentDiscoveryAgent,
    LoginProbeAgent,       # lab-only default-creds → session_cookies
    WebVulnAgent,          # sqlmap + dalfox using the harvested cookie
    WordPressAgent,
    ApiFuzzerAgent,
    AuthAgent,
    ReportAgent,
]

# Agents repeated once per prioritized sub in multi-host mode. Everything
# up to (and including) sub_prioritizer runs ONCE against the primary target;
# these run again per selected sub; ReportAgent runs ONCE at the end.
_MULTI_HOST_REPEATED_DEFAULT = [
    "fingerprint",
    "content_discovery",
    "login_probe",
    "web_vuln",
    "wordpress",
    "api_fuzzer",
    "auth",
]


def _apply_extension_agents(base_order: list, cfg: dict) -> list:
    """Discover extensions/agents/*.py and splice them into `base_order`
    at the position declared by each agent's `ENTRY_AFTER` class attr.
    Agents without ENTRY_AFTER go right before ReportAgent."""
    ext_cfg = (cfg or {}).get("extensions") or {}
    if not ext_cfg.get("enabled", True):
        return list(base_order)
    dirs = [Path(__file__).resolve().parent / "extensions"]
    for extra in ext_cfg.get("extra_dirs") or []:
        p = Path(extra).expanduser()
        if p.is_dir():
            dirs.append(p)
    result = list(base_order)
    for d in dirs:
        for cls in extension_loader.discover_agents(d):
            entry_after = getattr(cls, "ENTRY_AFTER", None)
            if entry_after:
                inserted = False
                for i, existing in enumerate(result):
                    if getattr(existing, "NAME", "") == entry_after:
                        result.insert(i + 1, cls)
                        inserted = True
                        break
                if not inserted:
                    # ENTRY_AFTER points to an unknown agent — put before report
                    _insert_before_report(result, cls)
            else:
                _insert_before_report(result, cls)
            print(f"[+] extension agent loaded: {cls.NAME} "
                  f"(from {d.name}/agents/)")
    return result


def _insert_before_report(order: list, cls) -> None:
    report_idx = next((i for i, a in enumerate(order)
                       if getattr(a, "NAME", "") == "report"), len(order))
    order.insert(report_idx, cls)


class Orchestrator:
    def __init__(self, cfg: dict, tool_registry,
                 target: str, in_scope: list[str] | None,
                 sessions_root: Path,
                 telegram_chat_id: str | None = None,
                 skip_preflight: bool = False,
                 strict_preflight: bool = False):
        self.cfg = cfg
        self.tools = tool_registry
        self.target = target
        self.telegram_chat_id = telegram_chat_id
        self.skip_preflight = skip_preflight
        # When True, a pre-flight failure ABORTS the pipeline (previous
        # behavior). When False (default), it's a WARN + continue — the
        # LLM agents may reach the target with tools that use different
        # TLS/HTTP stacks than python-requests.
        self.strict_preflight = strict_preflight
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.run_dir = sessions_root / run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.state = SharedState(run_dir=self.run_dir, target=target,
                                 in_scope_hosts=in_scope or [])
        # Give the ToolRegistry a handle on SharedState so http_get/http_post
        # can auto-inject session cookies captured by login_probe.
        try:
            self.tools.attach_state(self.state)
        except AttributeError:
            pass  # backwards compat with a registry that pre-dates attach_state
        # Splice in any extension agents declared under extensions/agents/
        self.agent_order = _apply_extension_agents(AGENT_ORDER, cfg)
        self.agent_names = [cls.NAME for cls in self.agent_order]
        self.started = 0.0
        # Adversarial reviewer — lazy-instantiated in run() to avoid
        # building an OpenAI client if the run aborts pre-flight.
        self._adversarial_reviewer: AdversarialReviewer | None = None

    def run(self) -> SharedState:
        self.started = time.time()
        print(f"[+] Orchestrator run: {self.run_dir.name}")
        print(f"[+] Target: {self.target}")
        print(f"[+] Agents queued: {', '.join(self.agent_names)}")

        # Pre-flight — three modes:
        #   1) --skip-preflight   → do not probe (VPN/allowlist targets)
        #   2) default (soft)     → probe; if unreachable, WARN + continue
        #                            (agent tools may use different TLS
        #                            libraries — curl-LibreSSL, Go stdlib,
        #                            openssl — and get further than the
        #                            python-requests probe used here).
        #   3) preflight.strict   → probe; if unreachable, ABORT pipeline
        #                            (previous behavior; useful when you
        #                            want to save LLM turns on truly dead
        #                            targets).
        # Strict mode is picked from cfg.preflight.strict OR the
        # `strict_preflight` attribute set by harness.py from
        # --strict-preflight.
        pf_cfg = self.cfg.get("preflight") or {}
        pf_strict = bool(getattr(self, "strict_preflight", False)
                          or pf_cfg.get("strict", False))
        if self.skip_preflight:
            print("[+] Pre-flight skipped (--skip-preflight)")
            alive, reason = True, "pre-flight skipped by --skip-preflight"
        else:
            alive, reason = self._target_reachable(self.target)
            print(f"[+] Pre-flight: {'ALIVE' if alive else 'UNREACHABLE'} · {reason}")
        if not alive:
            if pf_strict:
                print(f"\n[!] TARGET UNREACHABLE — aborting pipeline "
                      f"(preflight.strict / --strict-preflight).")
                print(f"    Reason: {reason}")
                print(f"    Only the report agent will run to document the failure.")
                self.state.set("target_unreachable", True)
                self.state.set("target_unreachable_reason", reason)
                self.state.error("orchestrator",
                                  f"target unreachable pre-flight: {reason}")
            else:
                print(f"\n[!] Pre-flight WARNING — target didn't answer the "
                      f"HTTP probe, but continuing anyway (agents may use "
                      f"different TLS/HTTP tools that pass through).")
                print(f"    Reason: {reason}")
                print(f"    Pass --strict-preflight to abort instead.")
                # Non-abort path: expose the warning so REPORT.md can show it,
                # but DO NOT set target_unreachable → agents run normally.
                self.state.set("preflight_warning", True)
                self.state.set("preflight_warning_reason", reason)
                self.state.error("orchestrator",
                                  f"preflight warning (soft): {reason}")

        mh_cfg = self.cfg.get("multi_host") or {}
        multi_host_enabled = bool(mh_cfg.get("enabled", False))

        with MultiAgentUI(self.agent_names) as ui:
            if multi_host_enabled and not self.state.get("target_unreachable"):
                self._run_multi_host(mh_cfg, ui)
            else:
                self._run_single_host(ui)

        elapsed = int(time.time() - self.started)
        print(f"[+] Pipeline complete in {elapsed}s. "
              f"State: {self.state.path}")
        # Adversarial review — gate findings BEFORE regenerating the report
        # and BEFORE notifying. Skipped when target was unreachable (nothing
        # to review) or when the operator disabled it via config / CLI.
        if not self.state.get("target_unreachable"):
            self._maybe_run_adversarial_review()
        report = self.state.get("report_path")
        if report:
            print(f"[+] Report: {report}")
            self._print_report_inline(report)
        # Telegram notification (before cleanup so REPORT.md still exists)
        self._maybe_send_telegram(report)
        # Housekeeping: wipe /tmp/harness-*, /tmp/gau_*, etc. left by agents.
        # Bounded to a narrow set of patterns — see tempcleaner.py.
        if self.cfg.get("cleanup_tempfiles", True):
            removed = tempcleaner.cleanup(verbose=True)
            if removed:
                self.state.append("cleanup_summary",
                                  {"removed_count": len(removed),
                                   "removed": removed[:50]})
        return self.state

    def _target_reachable(self, target: str,
                          timeout_sec: int = 10) -> tuple[bool, str]:
        """Best-effort pre-flight check. Returns (alive, reason).

        Any HTTP response (200/301/401/403/500…) counts as ALIVE — the server
        is up, just the endpoint may be protected. Only network-level failures
        (DNS resolution, connect timeout, connection refused) count as DEAD.

        Works with a full URL (https://host/path) or a bare host. For a bare
        host, tries https:// then http://.
        """
        # Extract URL candidates
        urls: list[str] = []
        t = (target or "").strip()
        if not t:
            return False, "empty target"
        if t.startswith("http://") or t.startswith("https://"):
            urls.append(t)
        else:
            # bare host or host:port
            urls.append(f"https://{t}")
            urls.append(f"http://{t}")

        headers = dict(self.tools.custom_headers)  # honour attribution headers
        last_err = "no error"
        for url in urls:
            try:
                r = requests.get(url, headers=headers,
                                 timeout=timeout_sec,
                                 allow_redirects=False,
                                 verify=False)
                # Any HTTP status counts as reachable — server responded.
                return True, f"HTTP {r.status_code} from {url}"
            except requests.exceptions.SSLError as e:
                # SSL error still means the server is up on that port
                return True, f"SSL error from {url} (server is up): {str(e)[:120]}"
            except requests.exceptions.ConnectTimeout:
                last_err = f"connect timeout ({timeout_sec}s) to {url}"
            except requests.exceptions.ReadTimeout:
                # Server accepted the connection but is slow — count as alive
                return True, f"slow response from {url} (server is up)"
            except requests.exceptions.ConnectionError as e:
                # DNS failure, connection refused, host unreachable
                last_err = f"connection error to {url}: {type(e).__name__}: {str(e)[:120]}"
            except Exception as e:
                last_err = f"{type(e).__name__}: {str(e)[:120]}"
        return False, last_err

    # ── single-host pipeline (default) ──────────────────────────────
    def _run_single_host(self, ui) -> None:
        for AgentCls in self.agent_order:
            self._run_one_agent(AgentCls, self.state, ui)

    # ── multi-host pipeline ─────────────────────────────────────────
    def _run_multi_host(self, mh_cfg: dict, ui) -> None:
        """Run the pipeline in 3 phases against ranked subs:

          Phase 1 (once, on primary target):
              recon → sub_prioritizer → (any extension agent NOT in the
              repeated set, e.g. `takeover` — which itself iterates subs)
          Phase 2 (repeated, once per top-N sub):
              fingerprint → content_discovery → login_probe → web_vuln →
              wordpress → api_fuzzer → auth
          Phase 3 (once, at the end):
              report

        Selection of subs to loop over: top_n hosts from
        `state.prioritized_hosts`, filtered by min_score. If no host meets
        min_score, we still loop the top_n (better to scan something than
        nothing). If sub_prioritizer didn't run (single live host), we
        fall back to single-host mode automatically."""
        top_n = int(mh_cfg.get("top_n", 3))
        min_score = int(mh_cfg.get("min_score", 30))
        repeated_names = set(mh_cfg.get(
            "agents_to_repeat", _MULTI_HOST_REPEATED_DEFAULT))
        pre_phase_names = {ReportAgent.NAME}

        # ── PHASE 1 ────────────────────────────────────────────────
        for AgentCls in self.agent_order:
            name = getattr(AgentCls, "NAME", "")
            if name in repeated_names or name in pre_phase_names:
                continue
            self._run_one_agent(AgentCls, self.state, ui)

        # ── Select subs to loop over ───────────────────────────────
        prioritized = self.state.get("prioritized_hosts") or []
        if not prioritized:
            # sub_prioritizer skipped (only 1 live host) → single-host loop
            ui.notify("multi-host: only 1 live host, falling back to single-host")
            for AgentCls in self.agent_order:
                name = getattr(AgentCls, "NAME", "")
                if name in repeated_names:
                    self._run_one_agent(AgentCls, self.state, ui)
            # report
            for AgentCls in self.agent_order:
                if AgentCls is ReportAgent:
                    self._run_one_agent(AgentCls, self.state, ui)
                    break
            return

        selected = [p for p in prioritized[:top_n] if p["score"] >= min_score]
        if not selected:
            # Nothing meets min_score — better to loop top-N than nothing
            selected = prioritized[:top_n]
        ui.notify(f"multi-host: iterating {len(selected)} sub(s) "
                  f"(top_n={top_n}, min_score={min_score})")

        # ── PHASE 2 ────────────────────────────────────────────────
        for i, host_pri in enumerate(selected):
            self._loop_repeated_agents_on_sub(
                host_pri=host_pri, repeated_names=repeated_names,
                ui=ui, index=i, total=len(selected))

        # ── PHASE 3 ────────────────────────────────────────────────
        for AgentCls in self.agent_order:
            if AgentCls is ReportAgent:
                self._run_one_agent(AgentCls, self.state, ui)
                break

    def _loop_repeated_agents_on_sub(self, host_pri: dict,
                                       repeated_names: set,
                                       ui, index: int, total: int) -> None:
        """Run every agent whose NAME is in `repeated_names` against a
        single sub. Preserves the original global state around the pass:

          - snapshot `target`, `live_hosts`, `endpoints_found`, `detected_techs`
          - narrow state.live_hosts to [this_sub_record] + set state.target
          - reset endpoints_found so content_discovery works on this sub only
          - run each repeated agent in order
          - tag every finding added during the pass with sub_scanned=<host>
          - restore global state (merging endpoints + techs) so the next
            sub starts clean but nothing is lost from prior passes
        """
        host = str(host_pri.get("host", ""))
        if not host:
            return

        # Rebuild the URL for this sub. Prefer the scheme discovered by httpx,
        # fall back to https.
        orig_live = list(self.state.get("live_hosts") or [])
        this_record = next(
            (h for h in orig_live if str(h.get("host", "")) == host),
            {"host": host, "scheme": "https"})
        scheme = this_record.get("scheme", "https") or "https"
        sub_url = f"{scheme}://{host}"
        ui.notify(f"── multi-host {index+1}/{total}: {sub_url} "
                  f"(score={host_pri.get('score')} "
                  f"tier={host_pri.get('tier','?')}) ──")

        # Snapshot state we're about to override
        orig_target = self.state.get("target")
        orig_endpoints = list(self.state.get("endpoints_found") or [])
        orig_techs = list(self.state.get("detected_techs") or [])
        findings_before = len(self.state.get("findings") or [])

        # Override for the pass
        self.state.set("target", sub_url)
        self.state.set("live_hosts", [this_record])
        self.state.set("endpoints_found", [])
        # Seed detected_techs with this sub's tech only (fingerprint will refill)
        seed_techs = this_record.get("tech") or this_record.get("technologies") or []
        self.state.set("detected_techs",
                        sorted({str(t).lower() for t in seed_techs}))

        try:
            for AgentCls in self.agent_order:
                if getattr(AgentCls, "NAME", "") in repeated_names:
                    self._run_one_agent(AgentCls, self.state, ui)
        finally:
            # Tag findings added during this pass with sub_scanned=host
            all_findings = list(self.state.get("findings") or [])
            for f in all_findings[findings_before:]:
                # Mutating dicts in-place is fine — they came from state.append
                f["sub_scanned"] = host
            # Restore global target + live_hosts; MERGE endpoints + techs
            self.state.set("target", orig_target)
            self.state.set("live_hosts", orig_live)
            merged_endpoints = list(orig_endpoints)
            seen_urls = {e.get("url") for e in merged_endpoints if e.get("url")}
            for e in (self.state.get("endpoints_found") or []):
                if e.get("url") and e.get("url") not in seen_urls:
                    merged_endpoints.append(e)
                    seen_urls.add(e.get("url"))
            self.state.set("endpoints_found", merged_endpoints)
            merged_techs = sorted({*orig_techs,
                                    *(self.state.get("detected_techs") or [])})
            self.state.set("detected_techs", merged_techs)

    def _run_one_agent(self, AgentCls, state, ui) -> None:
        """Instantiate + run a single agent, honouring pre-flight abort +
        entry_condition + catching errors. Shared body of the single-host
        loop AND the multi-host per-sub loop."""
        if state.get("target_unreachable") and AgentCls is not ReportAgent:
            ui.hook(AgentCls.NAME, "skipped", reason="target unreachable")
            state.mark_agent_run(AgentCls.NAME, "skipped", 0.0)
            ui.notify(f"skipped {AgentCls.NAME} (target unreachable)")
            return
        agent = AgentCls(cfg=self.cfg, tool_registry=self.tools,
                         run_dir=self.run_dir, progress_hook=ui.hook)
        if not agent.entry_condition(state):
            ui.hook(agent.NAME, "skipped", reason="entry condition false")
            state.mark_agent_run(agent.NAME, "skipped", 0.0)
            ui.notify(f"skipped {agent.NAME}")
            return
        ui.notify(f"starting {agent.NAME}")
        try:
            result = agent.run(state)
            ui.notify(f"{agent.NAME} → {result}")
        except Exception as e:
            state.error(agent.NAME, str(e))
            ui.hook(agent.NAME, "error", err=str(e))
            ui.notify(f"{agent.NAME} raised: {e}")

    def _maybe_run_adversarial_review(self) -> None:
        """Run adversarial reviewer over findings (if enabled) and
        regenerate REPORT.md with the reviewed set.

        Reviewer errors NEVER abort the pipeline — worst case is that all
        findings pass through untouched (fail-open)."""
        try:
            reviewer = AdversarialReviewer(self.cfg)
        except Exception as e:
            print(f"[!] Adversarial reviewer init failed: "
                  f"{type(e).__name__}: {e} — findings not gated.")
            return
        self._adversarial_reviewer = reviewer
        if not reviewer.enabled:
            return
        print(f"[+] Adversarial review starting "
              f"(model={reviewer.model or 'auto'}, "
              f"min_severity={reviewer.min_severity}, "
              f"max={reviewer.max_findings})")
        try:
            summary = reviewer.review(self.state)
        except Exception as e:
            print(f"[!] Adversarial review failed: "
                  f"{type(e).__name__}: {e} — findings not gated.")
            return
        if summary.get("skipped_reason"):
            print(f"[+] Adversarial review skipped: "
                  f"{summary['skipped_reason']}")
            return
        print(f"[+] Adversarial review done: "
              f"reviewed={summary.get('reviewed', 0)}, "
              f"passed={summary.get('passed', 0)}, "
              f"rejected={summary.get('rejected', 0)}")
        # Regenerate REPORT.md so the rejected findings section reflects the review
        try:
            for AgentCls in self.agent_order:
                if AgentCls is ReportAgent:
                    ReportAgent(cfg=self.cfg, tool_registry=self.tools,
                                 run_dir=self.run_dir,
                                 progress_hook=None).run(self.state)
                    break
        except Exception as e:
            print(f"[!] Report regeneration after review failed: "
                  f"{type(e).__name__}: {e}")

    def _maybe_send_telegram(self, report_path):
        """Send REPORT.md + executive summary via Telegram if configured.

        Gated by notify_only_if_findings — if set (default True), skip when
        the run produced no medium/high/critical findings.
        """
        tcfg = self.cfg.get("telegram") or {}
        # Enabled if config says so, OR if --telegram was passed via CLI/REPL
        if not tcfg.get("enabled") and not self.telegram_chat_id:
            return
        if not report_path:
            return
        # Gate by findings if configured
        if self.cfg.get("notify_only_if_findings", True):
            findings = self.state.get("findings", []) or []
            has_meaningful = any(
                str(f.get("severity", "")).lower() in ("medium", "high", "critical")
                for f in findings
            )
            if not has_meaningful:
                print("[+] No meaningful findings — Telegram skipped "
                      "(disable with notify_only_if_findings: false).")
                return
        summary = self._compose_telegram_summary()
        try:
            telegram_notifier.send_report(
                cfg=self.cfg,
                report_path=Path(report_path),
                summary_text=summary,
                chat_id_override=self.telegram_chat_id,
            )
            print("[+] Report sent to Telegram")
        except telegram_notifier.TelegramError as e:
            print(f"[!] Telegram not sent: {e}")
        except Exception as e:
            print(f"[!] Telegram failed: {type(e).__name__}: {e}")

    def _compose_telegram_summary(self) -> str:
        s = self.state.snapshot()
        elapsed = int(time.time() - self.started)
        subs = len(s.get("subdomains", []))
        live = len(s.get("live_hosts", []))
        techs = s.get("detected_techs", [])
        eps = len(s.get("endpoints_found", []))
        findings = s.get("findings", [])
        agents_done = sum(1 for a in s.get("agents_run", [])
                          if a.get("status") == "done")
        agents_total = len(s.get("agents_run", []))
        lines = [
            "🎯 Bughunter Harness — pipeline complete",
            "",
            f"Target: {s.get('target')}",
            f"Duration: {elapsed}s",
            f"Agents: {agents_done}/{agents_total} done",
            f"Subs: {subs} · Live: {live} · Endpoints: {eps}",
            f"Techs: {', '.join(techs) or '(none)'}",
            f"Findings: {len(findings)}",
        ]
        crit_high = [f for f in findings
                     if f.get("severity") in ("critical", "high")]
        if crit_high:
            lines.append("")
            lines.append(f"⚠️ HIGH/CRITICAL ({len(crit_high)}):")
            for f in crit_high[:8]:
                lines.append(f"  • [{f['severity'].upper()}] {f['title'][:120]}")
        return "\n".join(lines)

    def _print_report_inline(self, report_path: str) -> None:
        """Echo the REPORT.md to the terminal so the operator sees it without
        opening the file. Rendered via rich if available, plain otherwise."""
        try:
            content = Path(report_path).read_text(encoding="utf-8")
        except Exception:
            return
        try:
            from rich.console import Console
            from rich.markdown import Markdown
            Console().print(Markdown(content))
        except Exception:
            print("─" * 68)
            print(content)
            print("─" * 68)
