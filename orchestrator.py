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
from agents.web_vuln import WebVulnAgent
from agents.wordpress import WordPressAgent
from shared_state import SharedState
import telegram_notifier
import tempcleaner
from ui import MultiAgentUI


# Order matters — login_probe runs BEFORE web_vuln so its captured cookie
# is auto-injected into the sqlmap/dalfox/nuclei calls that follow. It also
# runs BEFORE a second (implicit) content_discovery pass, but we don't
# re-run content_discovery — instead it's given a cookie note upfront and
# an "if a cookie appears later, use it" instruction (see agent prompt).
AGENT_ORDER = [
    ReconAgent,
    FingerprintAgent,
    ContentDiscoveryAgent,
    LoginProbeAgent,       # lab-only default-creds → session_cookies
    WebVulnAgent,          # sqlmap + dalfox using the harvested cookie
    WordPressAgent,
    ApiFuzzerAgent,
    AuthAgent,
    ReportAgent,
]


class Orchestrator:
    def __init__(self, cfg: dict, tool_registry,
                 target: str, in_scope: list[str] | None,
                 sessions_root: Path,
                 telegram_chat_id: str | None = None,
                 skip_preflight: bool = False):
        self.cfg = cfg
        self.tools = tool_registry
        self.target = target
        self.telegram_chat_id = telegram_chat_id
        self.skip_preflight = skip_preflight
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
        self.agent_names = [cls.NAME for cls in AGENT_ORDER]
        self.started = 0.0

    def run(self) -> SharedState:
        self.started = time.time()
        print(f"[+] Orchestrator run: {self.run_dir.name}")
        print(f"[+] Target: {self.target}")
        print(f"[+] Agents queued: {', '.join(self.agent_names)}")

        # Pre-flight: bail out if the target is not reachable (unless
        # explicitly disabled with --skip-preflight, e.g. target needs VPN).
        # Prevents wasting 20-30 minutes of agent turns on a dead host.
        if self.skip_preflight:
            print("[+] Pre-flight skipped (--skip-preflight)")
            alive, reason = True, "pre-flight skipped by --skip-preflight"
        else:
            alive, reason = self._target_reachable(self.target)
            print(f"[+] Pre-flight: {'ALIVE' if alive else 'UNREACHABLE'} · {reason}")
        if not alive:
            print(f"\n[!] TARGET UNREACHABLE — aborting pipeline.")
            print(f"    Reason: {reason}")
            print(f"    Only the report agent will run to document the failure.")
            self.state.set("target_unreachable", True)
            self.state.set("target_unreachable_reason", reason)
            self.state.error("orchestrator",
                             f"target unreachable pre-flight: {reason}")

        with MultiAgentUI(self.agent_names) as ui:
            for AgentCls in AGENT_ORDER:
                # If pre-flight failed, skip everything except the report agent
                if self.state.get("target_unreachable") and \
                   AgentCls is not ReportAgent:
                    ui.hook(AgentCls.NAME, "skipped",
                            reason="target unreachable")
                    self.state.mark_agent_run(AgentCls.NAME, "skipped", 0.0)
                    ui.notify(f"skipped {AgentCls.NAME} (target unreachable)")
                    continue
                agent = AgentCls(cfg=self.cfg, tool_registry=self.tools,
                                 run_dir=self.run_dir, progress_hook=ui.hook)
                # Pre-check: skip cheaply if entry condition false
                if not agent.entry_condition(self.state):
                    ui.hook(agent.NAME, "skipped",
                            reason="entry condition false")
                    self.state.mark_agent_run(agent.NAME, "skipped", 0.0)
                    ui.notify(f"skipped {agent.NAME}")
                    continue
                ui.notify(f"starting {agent.NAME}")
                try:
                    result = agent.run(self.state)
                    ui.notify(f"{agent.NAME} → {result}")
                except Exception as e:
                    self.state.error(agent.NAME, str(e))
                    ui.hook(agent.NAME, "error", err=str(e))
                    ui.notify(f"{agent.NAME} raised: {e}")

        elapsed = int(time.time() - self.started)
        print(f"[+] Pipeline complete in {elapsed}s. "
              f"State: {self.state.path}")
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
