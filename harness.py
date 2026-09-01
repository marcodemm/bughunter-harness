"""Autonomous bugbounty harness for local LLM (LM Studio / OpenAI-compat).

Design: single loop, function-calling via OpenAI SDK, hard rate limits and
scope checks enforced at the tool layer (never trust the model prompt).

Kill switches: max_iterations, max_wall_time_sec, per-tool call rate limit,
per-command allowlist, in-scope host check.
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml
from openai import OpenAI

import llm_backend
from mailer import MailerError, send_report
from orchestrator import Orchestrator
from scope import ScopeChecker
from throttle import RateLimiter
import tempcleaner
from tools import ToolRegistry
from redact import redact


HERE = Path(__file__).resolve().parent
SESSIONS_DIR = HERE / "sessions"
SESSIONS_DIR.mkdir(exist_ok=True)

SYSTEM_PROMPT = """/no_think

You are a bug-bounty pentest agent working via tool calls.

CRITICAL FORMAT REQUIREMENT
Every response MUST contain EXACTLY ONE tool_call and nothing else.
- NEVER emit two <tool_call> blocks in the same response, even if you
  reorder the parameters. That crashes the LM Studio parser.
- NEVER emit the same tool_call twice.
- NEVER reply with plain text alone. If you are ready to stop, call finish()
  ONCE with summary and findings, then STOP generating.

DO NOT use <think> tags or reasoning blocks. Skip internal deliberation and
emit the tool_call directly. Any thinking you do consumes your output budget
and prevents you from making the tool_call the harness needs.

Rules (enforced at the tool layer — the harness will reject calls that break them):
1. Every network action must go through http_get / http_post / run_shell tools.
   Direct URLs in your message text are ignored.
2. Only targets whose host matches the operator's scope allowlist will be executed.
3. Rate limit is enforced per request; if you request bursts you will be throttled.
4. The shell command allowlist is: nmap, nuclei, ffuf, curl, dig, httpx, subfinder,
   gau, waybackurls, katana, whois, host. Flags that require root, that are
   destructive, or that generate high traffic (nmap -T5, nmap -sS) are blocked.
5. Report progress after each tool call. When the objective is met OR you have
   no productive next step, call finish() with a short summary.
6. Never propose destructive actions (rm, DROP, DELETE, factory reset).
   Never test credentials from third parties. Never exfiltrate real user data;
   redact anything sensitive in your reasoning.

REQUIRED FOLLOW-UP PLAYBOOK (this is what separates a real audit from a demo):

A. When you fingerprint a technology, product name, or CMS/panel (Wordpress,
   Dokploy, GitLab, Jenkins, Grafana, phpMyAdmin, Adminer, Bitrix, Confluence,
   Jira, Coolify, Portainer, Traefik, n8n, Strapi, Next.js, Nuxt, Rails,
   Directus, Payload, Keycloak, Vault, Consul, Nomad, MinIO, RabbitMQ,
   ElasticSearch, Kibana, Airflow, Metabase, ANY named product) — the very
   next tool_call MUST be a nuclei scan for that SPECIFIC tech.
   IMPORTANT: use ONE or AT MOST 2-3 tags per nuclei invocation. NEVER pass
   20+ tags in a single call — it will time out. Split into multiple calls:
     run_shell({"command": "nuclei -u <target> -tags <tech1> -rl 5 -c 5 -silent"})
     run_shell({"command": "nuclei -u <target> -tags <tech2> -rl 5 -c 5 -silent"})
   Also try:
     run_shell({"command": "nuclei -u <target> -id <cve-id-if-known> -silent"})
   Do NOT stop at "detected Dokploy". Always follow up with the nuclei scan
   for that exact tech.

B. When you find a login/auth endpoint, do NOT test guessed credentials
   (admin/admin, admin/admin123). That's a duplicate/won't-fix in every
   program. Instead:
     - Check for default paths of that product (e.g. /api/version, /api/health,
       /admin/api/config, /.well-known/…)
     - Look for auth bypass CVEs specific to that product's version
     - Look for open registration or IDOR primitives

C. When you get repeated 401/404 on the same path, STOP retrying it. Move on
   to another surface (subdomains, JS bundles, /robots.txt, /sitemap.xml,
   git/env exposure, JS map files).

D. Before calling finish(), you MUST have at least ONE nuclei scan run if you
   fingerprinted a product, OR document why nuclei was not applicable.

Response style: one short reasoning sentence (optional) + exactly ONE tool_call.
Do not restate the plan every turn; act on it.
"""

# Max consecutive turns where the model replies without a tool_call.
# The harness sends a nudge asking for a tool_call each time; if the limit is
# hit, the session ends (safer than looping forever on a broken template).
MAX_NO_TOOL_RETRIES = 3


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Harness:
    def __init__(self, cfg: dict, objective: str,
                 scope_override: list[str] | None = None,
                 output_override: str | None = None,
                 email_to: str | None = None):
        self.cfg = cfg
        self.objective = objective
        self.iterations = 0
        self.max_iters = int(cfg.get("max_iterations", 50))
        self.max_wall_sec = int(cfg.get("max_wall_time_sec", 1800))
        self.start_ts = time.time()
        # Email destination: explicit --email wins; fallback to config
        # smtp.default_to so operator doesn't need the flag every run.
        if not email_to:
            email_to = str(((cfg.get("smtp") or {}).get("default_to")) or "").strip() or None
        self.email_to = email_to
        # Collect finish() args so end-of-session mail can include them
        self.finish_summary: str | None = None
        self.finish_findings: list[str] = []
        self.tool_calls_count = 0

        # Scope: CLI --scope wins over config's scope_file
        if scope_override:
            self.scope = ScopeChecker(patterns=scope_override)
        else:
            self.scope = ScopeChecker(scope_file=cfg.get("scope_file",
                                                         "scope.txt"))
        self.limiter = RateLimiter(
            min_interval_sec=float(cfg.get("min_request_interval_sec", 1.0))
        )
        self.tools = ToolRegistry(scope=self.scope, limiter=self.limiter, cfg=cfg)

        # Resolve LLM backend (lmstudio / ollama / llamacpp / custom)
        backend = llm_backend.resolve(cfg)
        self.client = OpenAI(
            base_url=backend.base_url,
            api_key=backend.api_key or "placeholder",
        )
        self.model = backend.model or cfg.get("model", "")
        self.backend = backend

        session_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        # --output wins; else default to SESSIONS_DIR/<id>.jsonl
        if output_override:
            out_path = Path(output_override)
            if out_path.is_dir() or str(output_override).endswith("/"):
                out_path.mkdir(parents=True, exist_ok=True)
                self.session_file = out_path / f"{session_id}.jsonl"
            else:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                self.session_file = out_path
        else:
            self.session_file = SESSIONS_DIR / f"{session_id}.jsonl"
        self._append({"kind": "session_start", "ts": now_iso(),
                      "objective": objective, "config": {
                          k: v for k, v in cfg.items() if k != "api_key"
                      }})

        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Objective: {objective}"},
        ]
        self.no_tool_retries = 0
        self._install_signal_handler()

    def _append(self, entry: dict) -> None:
        with open(self.session_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _install_signal_handler(self) -> None:
        def handler(signum, frame):
            print("\n[!] SIGINT received. Saving session and exiting.")
            self._append({"kind": "sigint", "ts": now_iso(),
                          "iterations": self.iterations})
            # Best-effort tempfile cleanup before dying
            try:
                if self.cfg.get("cleanup_tempfiles", True):
                    tempcleaner.cleanup(verbose=True)
            except Exception:
                pass
            sys.exit(130)
        signal.signal(signal.SIGINT, handler)

    def _call_llm_with_fallback(self):
        """Call the LLM. If LM Studio rejects tool_choice=required with a PEG
        grammar error (500 / 400), transparently retry with tool_choice=auto.

        Some builds of LM Studio + Qwen MoE break when the model output does
        not fit the strict tool_call grammar. `auto` relaxes the constraint;
        the SYSTEM_PROMPT still asks the model for a tool_call and the
        retry-with-nudge loop still catches text-only replies.
        """
        temp = float(self.cfg.get("temperature", 0.3))
        max_tok = int(self.cfg.get("max_response_tokens", 2048))
        tools = self.tools.openai_schemas()
        # Default is "auto" — "required" imposes a strict PEG grammar in LM
        # Studio that some fine-tuned models (e.g. Qwen MoE bughunter-v8)
        # violate by emitting duplicate <tool_call> blocks, crashing parsing.
        primary_choice = self.cfg.get("tool_choice", "auto")

        try:
            return self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
                tools=tools,
                tool_choice=primary_choice,
                temperature=temp,
                max_tokens=max_tok,
            )
        except Exception as e1:
            err_str = str(e1)
            peg_bug = ("peg-native" in err_str
                       or "400" in err_str
                       or "500" in err_str)
            if not peg_bug or primary_choice == "auto":
                # Either not a grammar issue, or we already tried the relaxed
                # mode; nothing left to fall back to.
                print(f"[!] LLM error: {e1}")
                self._append({"kind": "llm_error", "err": err_str,
                              "ts": now_iso()})
                return None
            # Primary was "required" and failed — retry with "auto".
            print("[!] LM Studio rejected tool_choice=required "
                  "(grammar/PEG error). Retrying with tool_choice=auto.")
            self._append({"kind": "llm_grammar_fallback", "err": err_str,
                          "ts": now_iso()})
            try:
                return self.client.chat.completions.create(
                    model=self.model,
                    messages=self.messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=temp,
                    max_tokens=max_tok,
                )
            except Exception as e2:
                print(f"[!] LLM error even with tool_choice=auto: {e2}")
                self._append({"kind": "llm_error", "err": str(e2),
                              "ts": now_iso()})
                return None

    def _kill_switch_hit(self) -> str | None:
        if self.iterations >= self.max_iters:
            return f"max_iterations ({self.max_iters}) reached"
        elapsed = time.time() - self.start_ts
        if elapsed >= self.max_wall_sec:
            return f"max_wall_time_sec ({self.max_wall_sec}) reached"
        return None

    def run(self) -> None:
        print(f"[+] Session: {self.session_file.name}")
        print(f"[+] Objective: {self.objective}")
        print(f"[+] Kill switches: iters={self.max_iters} wall={self.max_wall_sec}s")

        while True:
            reason = self._kill_switch_hit()
            if reason:
                print(f"[!] Kill switch: {reason}")
                self._append({"kind": "kill_switch", "reason": reason,
                              "ts": now_iso()})
                break

            self.iterations += 1
            print(f"\n=== turn {self.iterations} ===")

            resp = self._call_llm_with_fallback()
            if resp is None:
                break
            msg = resp.choices[0].message
            self._append({"kind": "llm_response", "ts": now_iso(),
                          "content": msg.content,
                          "tool_calls": [tc.model_dump() for tc in
                                         (msg.tool_calls or [])]})

            if msg.content:
                print(f"[model] {msg.content[:500]}")

            self.messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [tc.model_dump() for tc in (msg.tool_calls or [])],
            })

            # Some fine-tuned models emit the same tool_call twice; take the
            # first, drop the rest. Avoids running duplicate side-effects
            # (double scans, double POSTs) and confusing the model with two
            # tool responses.
            if msg.tool_calls and len(msg.tool_calls) > 1:
                first = msg.tool_calls[0]
                dupes = [tc for tc in msg.tool_calls[1:]
                         if tc.function.name == first.function.name
                         and tc.function.arguments == first.function.arguments]
                if len(dupes) == len(msg.tool_calls) - 1:
                    print(f"[!] Model emitted {len(msg.tool_calls)} identical "
                          f"tool_calls — keeping the first, dropping the rest.")
                    msg.tool_calls = [first]

            if not msg.tool_calls:
                self.no_tool_retries += 1
                if self.no_tool_retries > MAX_NO_TOOL_RETRIES:
                    print(f"[!] Model returned no tool call after "
                          f"{MAX_NO_TOOL_RETRIES} retries. Ending session. "
                          "Check that LM Studio 'Tool Use' is enabled for this "
                          "model and that the chat template supports functions.")
                    self._append({"kind": "no_tool_call_giveup",
                                  "retries": self.no_tool_retries,
                                  "ts": now_iso()})
                    break
                print(f"[!] No tool_call in response "
                      f"(retry {self.no_tool_retries}/{MAX_NO_TOOL_RETRIES}). "
                      "Nudging model.")
                self._append({"kind": "no_tool_call_retry",
                              "retry": self.no_tool_retries,
                              "ts": now_iso()})
                # Nudge the model to comply with the tool_call requirement.
                self.messages.append({
                    "role": "user",
                    "content": ("You replied with text but no tool_call. "
                                "You MUST emit exactly one tool_call now. If "
                                "there is nothing productive to do, call "
                                "finish() with a short summary. Do not reply "
                                "with plain text again."),
                })
                continue

            # Reset the counter on successful tool call
            self.no_tool_retries = 0

            for tc in msg.tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}

                print(f"[tool] {name}({redact(json.dumps(args))[:200]})")
                self._append({"kind": "tool_call_start",
                              "tool": name, "args": args,
                              "ts": now_iso()})

                if name == "finish":
                    summary = args.get("summary", "(no summary)")
                    findings = args.get("findings", []) or []
                    self.finish_summary = summary
                    self.finish_findings = list(findings)
                    print(f"[+] finish() called. Summary: {summary}")
                    self._append({"kind": "finish", "summary": summary,
                                  "findings": findings, "ts": now_iso()})
                    self._maybe_send_mail(kind="finish")
                    return

                self.tool_calls_count += 1
                result = self.tools.dispatch(name, args)
                red_result = redact(result)
                print(f"[tool←] {red_result[:400]}")
                self._append({"kind": "tool_call_result",
                              "tool": name,
                              "result_redacted": red_result,
                              "ts": now_iso()})

                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": red_result,
                })

        self._append({"kind": "session_end", "ts": now_iso(),
                      "iterations": self.iterations})
        print(f"[+] Done. Session log: {self.session_file}")
        self._maybe_send_mail(kind="session_end")

    def _maybe_send_mail(self, kind: str) -> None:
        """Send the end-of-session report if --email was given."""
        if not self.email_to:
            return
        smtp_cfg = self.cfg.get("smtp") or {}
        elapsed = int(time.time() - self.start_ts)
        subject = (f"[harness] {kind} · {self.iterations} turns · "
                   f"{self.tool_calls_count} tool calls · {elapsed}s")
        lines = [
            f"Objective : {self.objective}",
            f"Kind      : {kind}",
            f"Iterations: {self.iterations}",
            f"Tool calls: {self.tool_calls_count}",
            f"Duration  : {elapsed}s",
            f"Log file  : {self.session_file}",
            "",
        ]
        if self.finish_summary:
            lines += ["--- Agent summary ---", self.finish_summary, ""]
        if self.finish_findings:
            lines += ["--- Findings ---"]
            for f in self.finish_findings:
                lines.append(f"- {f}")
            lines.append("")
        body = "\n".join(lines)
        try:
            send_report(smtp_cfg, self.email_to, subject, body)
            print(f"[+] End-of-session report sent to {self.email_to}")
        except MailerError as e:
            print(f"[!] Mail not sent: {e}")
        except Exception as e:
            print(f"[!] Mail send failed: {type(e).__name__}: {e}")


HELP_TEXT = r"""
════════════════════════════════════════════════════════════════════
 BUGBOUNTY HARNESS · Autonomous local LLM agent
 Model: qwen3.5-35b-a3b-uncensored-bughunter-v8 (LM Studio)
════════════════════════════════════════════════════════════════════

USAGE
  python harness.py                          → prompt for target (REPL mode)
  python harness.py --objective "..."        → first target from CLI
  python harness.py --scope "*.example.com"  → inline scope (repeatable)
  python harness.py --header "N: V"          → custom HTTP header (repeatable)
  python harness.py -o /path/to/logs/        → session log root
  python harness.py --email me@example.com   → mail report at end of pipeline
  python harness.py --telegram 12345678      → send REPORT.md via Telegram bot
  python harness.py --servertype anthropic   → LLM backend (auto|lmstudio|
                                                 ollama|llamacpp|openai|
                                                 anthropic|nvidia|gemini)
  python harness.py --model qwen3:8b         → LLM model id (auto if omitted)
  python harness.py --base-url URL           → custom OpenAI-compatible URL
  python harness.py --legacy                 → single-agent classic loop
  python harness.py --skip-preflight         → do not check target liveness first
  python harness.py --one-shot               → single run then exit
  python harness.py --config <file.yaml>     → override config path
  python harness.py --help                   → show this help

  Flags can combine, e.g.
    python harness.py --scope "*.example.com" --scope "10.0.0.0/24" \
                      --header "X-HackerOne-Researcher: yourhandle" \
                      -o ~/bugbounty-runs/2026-09-01/ \
                      --email me@example.com \
                      --objective "Recon *.example.com, stop after 15 calls."

REPL COMMANDS
  After each session the harness prompts for a new objective:
    <free text>         → start a new session with that objective
    /quit /bye /exit    → leave the harness (also: quit / bye / exit)
    Ctrl+C              → cancel current session and exit

  Sticky inline flags accepted in the prompt (persist across sessions):
    --email ADDR                     mail report destination
    --scope PAT (repeatable)         in-scope allowlist
    --header "NAME: VALUE" (repeat)  custom HTTP header
    --telegram CHAT_ID               Telegram chat_id for the notification
    --servertype {auto,lmstudio,ollama,llamacpp,openai,anthropic,nvidia,gemini}
    --model MODEL_ID                 LLM model id (auto-detect if empty)
    --base-url URL                   OpenAI-compatible endpoint override
    -o PATH                          session log destination
  Pass an empty value to clear a sticky:  --header ""    --scope ""    --email ""

SCOPE (in-scope allowlist)
  Two ways to define what hosts the agent is allowed to touch:

  1) File on disk (default): scope.txt in the harness folder, one entry per
     line. Path overridable via config.yaml → scope_file.
  2) Inline via CLI: --scope PATTERN (repeatable). Overrides scope.txt for
     that run.

  Entry formats (both file and --scope):
    example.com          exact host (apex only)
    *.example.com        wildcard subdomain (a.example.com, a.b.example.com …)
    10.0.0.0/24          CIDR range
    10.0.0.1             exact IP
    127.0.0.1            loopback
    # ... a comment      lines starting with # are ignored (file only)

  Enforcement is controlled by config.yaml → scope_enforcement
  (see OPERATIONAL RULES below).

OBJECTIVE EXAMPLES  (copy-paste one)

  Enumerate open ports on 127.0.0.1 and fingerprint HTTP.
  Stop after 5 tool calls.

  Recon https://target.example.com : subs, live paths under /api/,
  exposed .git/.env, secrets in JS bundles. Stop after 20 tool calls.

  Fingerprint tech versions on <host in scope> via response headers
  and match against known CVEs. Report matches only.

  Fuzz endpoints under https://api.target.example.com/v1/ . Report
  anything returning 200 with sensitive-looking JSON. Non-destructive.

ORCHESTRATED PIPELINE (default mode)
  The harness runs a fixed sequence of specialist agents. Each agent has its
  own focused system prompt, a subset of tools, and an entry_condition that
  skips it when not applicable. Agents run SEQUENTIALLY (LM Studio single-slot)
  and share findings via a common state.json.

    1. recon              subdomains, DNS, live hosts, open ports    (always)
    2. fingerprint        deep tech-stack detection                  (if live)
    3. content_discovery  dir/file brute-force + historical URLs     (if live)
    4. web_vuln           nuclei + nikto scan per detected tech      (if live)
    5. wordpress          wpscan + WP-specific CVEs                  (if WP)
    6. api_fuzzer         API/GraphQL surface + BOLA/BFLA hints      (if /api)
    7. auth               auth-bypass, SSO/OAuth misconfig checks    (if login)
    8. report             consolidated Markdown report               (always)

  Each agent writes its own JSONL to sessions/<run-id>/agents/<name>.jsonl,
  and the run's shared_state at sessions/<run-id>/state.json. Final report:
  sessions/<run-id>/REPORT.md

  Progress: a live table shows per-agent status (QUEUED / RUNNING / DONE /
  SKIPPED / ERROR) with a per-agent progress bar and elapsed timer.

  --legacy switches back to the single-agent classic loop (for debugging).

TOOLS AVAILABLE TO THE AGENT
  http_get             GET request, throttled + in-scope
  http_post            POST request, throttled + in-scope
  run_shell            command line with pipes/redirects allowed. Each stage's
                       first token must be in the allowlist:
                         offensive: nmap nuclei nikto ffuf feroxbuster wpscan
                                    curl dig host whois httpx subfinder dnsx
                                    naabu gau waybackurls katana
                         helpers  : ls cat head tail wc sort uniq grep egrep
                                    fgrep awk cut tr sed tee xargs find which
                                    file echo base64 jq yq
                       Example one-liner:
                         subfinder -d target.com -silent | httpx -title -status
  oob_generate_token   callback URL for blind bugs (SSRF / XSS / XXE)
  finish               end the session with a summary and findings

CUSTOM HTTP HEADERS  (researcher attribution)
  Every HTTP request the harness sends can carry attribution headers so the
  target's security team recognises the traffic as authorized research.
  Two sources, merged (CLI wins on conflict):

  1) Config file — config.yaml → custom_headers dict:
       custom_headers:
         X-HackerOne-Researcher: yourhandle
         X-Bugcrowd-Researcher:  yourhandle

  2) Command line / REPL — --header "NAME: VALUE" (repeatable, sticky):
       python harness.py --header "X-HackerOne-Researcher: yourhandle"
       > --header "X-Bug-Bounty: research" http://target.com/

  Injected automatically on http_get / http_post. The model is also told
  to add them via -H flags on curl / nuclei / ffuf / httpx / katana /
  nikto / wpscan / feroxbuster shell commands.

  Clear all with an empty value:  --header ""

PRE-FLIGHT REACHABILITY CHECK
  Before spawning any agent, the orchestrator sends a single HTTP GET to the
  target (10 s timeout, honours --header attribution). Any HTTP response
  (200, 301, 401, 403, 500 …) counts as ALIVE — the server is up, endpoints
  may just be protected. Only network-level failures (DNS fail, connect
  timeout, connection refused) count as UNREACHABLE.

  On UNREACHABLE:
    * The pipeline is ABORTED — recon / fingerprint / vuln agents skipped.
    * The report agent still runs and produces a REPORT.md whose first line
      is a 🚨 TARGET UNREACHABLE alert with the exact network error.
    * No wasted LLM turns against a dead host.

  Skip the pre-flight with --skip-preflight if the target requires VPN,
  IP allowlisting or attribution headers before it will answer.

LLM BACKEND  (7 backends: 3 local + 4 cloud)
  All backends speak the OpenAI-compatible chat.completions protocol.

  LOCAL (auto-probed in order, no API key, no cost):
    lmstudio   http://127.0.0.1:1234/v1                 (LM Studio Local Server)
    ollama     http://127.0.0.1:11434/v1                (Ollama serve)
    llamacpp   http://127.0.0.1:8080/v1                 (llama-server)

  CLOUD (never auto-probed; requires --servertype explicit + API key + $$$):
    openai     https://api.openai.com/v1                             OPENAI_API_KEY
    anthropic  https://api.anthropic.com/v1                          ANTHROPIC_API_KEY
    nvidia     https://integrate.api.nvidia.com/v1                   NVIDIA_API_KEY
    gemini     https://generativelanguage.googleapis.com/v1beta/openai  GEMINI_API_KEY

  'auto' probes local backends only; the first that responds wins. Cloud
  backends must be selected explicitly so you never spend money by accident.

  Model auto-detection:
    lmstudio   GET /v1/models  → first entry
    ollama     GET /api/ps     → currently loaded model (fallback /api/tags)
    llamacpp   GET /v1/models  → the single served model
    openai / nvidia / gemini   GET /v1/models  → first entry (huge list!
                                                 explicit --model recommended)
    anthropic  no public /models endpoint      → --model REQUIRED
                                                 (e.g. claude-sonnet-4-6)

  API key sourcing (cloud only), precedence highest first:
    1. cfg.llm.api_key       (direct value in config.yaml)
    2. env var cfg.llm.api_key_env
    3. backend default env var (OPENAI_API_KEY / ANTHROPIC_API_KEY /
                                NVIDIA_API_KEY / GEMINI_API_KEY)
  Missing key on a cloud servertype → the harness aborts with a clear
  error (no silent 401s).

  Configure via config.yaml (recommended):

    llm:
      servertype: "auto"     # auto|lmstudio|ollama|llamacpp|openai|anthropic|
                             # nvidia|gemini
      base_url:   ""         # empty = servertype default
      api_key:    ""         # direct API key (cloud) — leave empty if using env
      api_key_env: ""        # env var name (default: backend-specific)
      model:      ""         # empty = auto-detect (except anthropic)

  CLI / REPL overrides (sticky in REPL, clear with empty string):
    --servertype anthropic
    --model claude-sonnet-4-6
    --base-url https://gateway.example.com/v1       (custom / self-hosted)

  Examples:
    export ANTHROPIC_API_KEY=sk-ant-...
    python harness.py --servertype anthropic --model claude-sonnet-4-6

    python harness.py --servertype openai --model gpt-5.5

    export NVIDIA_API_KEY=nvapi-...
    python harness.py --servertype nvidia \
                      --model qwen/qwen2.5-coder-32b-instruct

    export GEMINI_API_KEY=AIza...
    python harness.py --servertype gemini --model gemini-2.5-flash

    > --servertype ollama --model qwen2.5-coder:14b http://target.com/
    > --servertype anthropic --model claude-sonnet-4-6 http://target.com/
    > --model ""    # clear sticky, revert to auto-detect

  ⚠️ Tool-calling caveats on cloud backends via the OpenAI-compat endpoint:
    - openai:    native support, works perfectly.
    - anthropic: OpenAI-compat since 2025, generally works but some tool_use
                 features may differ; complex chains may need adjustment.
    - nvidia:    supported on most NIM models; check the model card.
    - gemini:    function_calling mapped to tools; may reject strict grammar.
    If a cloud backend's tool calls misbehave, the auto-fallback to
    tool_choice=auto (see config.tool_choice) usually resolves it.

TELEGRAM NOTIFICATION  (end-of-pipeline delivery)
  At the end of the pipeline, the harness can send the REPORT.md via
  Telegram Bot API: an executive-summary text message + the REPORT.md
  file as a document attachment (up to 50 MB per Bot API limits).

  One-time setup:
    1. Talk to @BotFather in Telegram → /newbot → save the token
    2. Start a chat with your bot (send it /start or anything)
    3. curl https://api.telegram.org/bot<TOKEN>/getUpdates
       → look for  "chat":{"id":<CHAT_ID>,...}
    4. Export the token — NEVER put it in config.yaml:
         export TELEGRAM_BOT_TOKEN='123456:ABC-DEF...'
    5. Put the chat_id in config.yaml → telegram.chat_id
       or export $TELEGRAM_CHAT_ID as fallback
    6. Set config.yaml → telegram.enabled: true

  Override chat_id per session (also enables telegram implicitly):
       python harness.py --telegram 12345678 --objective "..."
       > --telegram 12345678 http://target.com/

  Toggles in config.yaml → telegram.*:
    enabled            master switch
    send_summary_text  post the executive summary as a text message (true)
    send_report_file   attach REPORT.md as a document              (true)

CLEANUP  (temp files)
  After the report is generated (or on Ctrl+C / /quit), the harness wipes
  its own tempfiles from /tmp — narrow patterns only:
    /tmp/harness-*   /tmp/gau_*   /tmp/subfinder-*   /tmp/nuclei_*
    /tmp/ffuf_*      /tmp/katana_*   /tmp/wayback_*   /tmp/f.txt   etc.
  Nothing outside those patterns is ever touched. Disable with
  config.yaml → cleanup_tempfiles: false

KILL SWITCHES
  Ctrl+C                    save session and exit cleanly
  max_iterations: 40        config.yaml — hard stop after N turns
  max_wall_time_sec: 1800   config.yaml — hard stop after N seconds
  min_request_interval_sec  config.yaml — rate limit enforced on EVERY
                            tool call (cannot be bypassed by the model)
  shell_timeout_sec: 300    config.yaml — per-command timeout (default 5 min)
  http_timeout_sec: 30      config.yaml — per HTTP request timeout

PROGRESS
  While a tool runs, stderr shows a live spinner:
    ⠋ nmap: nmap -sV -p 22,80,443 target.com · 12s / 300s
  The spinner disappears when the tool returns; the [tool←] line follows.

OPERATIONAL RULES
  1) scope.txt is the last line of defence. Review it before every run.
  2) scope_enforcement in config.yaml — 3 modes:
       strict → reject everything not in scope.txt  (recommended)
       warn   → allow but flag every off-scope request in the output
       off    → do not validate (use only with explicit authorization)
     If the mode is not strict, a warning is printed at startup.
  3) Shell hard denylist: sudo / rm / mv / chmod / chown / backticks /
     $(...) / background & / -T4 / -T5 / -sS / -X DELETE.
     Pipes, ;, &&, ||, redirects (>, >>, 2>&1, <) are ALLOWED.
  4) OOB callback → always your own (config.yaml oob_host). NEVER xss0r
     or third parties.
  5) All tool output is passed through redact() before being returned to
     the model (JWT / AWS / GitHub / Stripe / cookies / emails).
  6) In-scope: every request is checked against scope.txt.

SESSIONS
  Every run writes a JSONL log of the whole conversation:
    - objective + config used
    - LLM responses (content + tool_calls)
    - redacted result of each tool call
    - kill switch / sigint / finish, if any

  Default location:
    <harness-dir>/sessions/YYYYMMDDTHHMMSSZ.jsonl

  Override with -o / --output:
    -o /path/to/dir/           writes  /path/to/dir/<timestamp>.jsonl
    -o /path/to/run.jsonl      writes  that exact file
    (dir is auto-created)

  Review after every engagement to audit what the agent tried.

MAIL REPORT
  Two ways to trigger the end-of-pipeline email:
    1. Pass --email ADDR on the CLI/REPL (wins, overrides config)
    2. Set config.yaml → smtp.default_to = "you@example.com" (auto-send,
       no flag needed — the recipient is the value from default_to)
  If NEITHER is set, no email is sent.

  The report contains: objective, kind (finish / session_end), iterations,
  tool_call count, duration, session log path, agent summary (if finish()
  was called) and findings list (if any).

  Two modes, auto-selected from config.yaml → smtp.*:

  1) AUTHENTICATED SMTP  (Gmail, Outlook, any provider)
     Trigger: both smtp.host AND smtp.username are set.
     Password is read from env var named by smtp.password_env
     (default SMTP_PASSWORD) — NEVER stored in the YAML.

     Example (Gmail App Password):
       export SMTP_PASSWORD='xxxx xxxx xxxx xxxx'
       python harness.py --email me@gmail.com --objective "..."
     App Password: https://myaccount.google.com/apppasswords

  2) LOCAL RELAY, NO AUTH  (fallback)
     Trigger: smtp.host or smtp.username empty/missing.
     Connects to 127.0.0.1:25 by default (or smtp.host:smtp.port if partially
     set). No STARTTLS, no auth. Requires a local MTA listening.

     macOS has NO MTA on :25 by default. Fastest option for local testing:
       brew install mailpit && mailpit
       # then in config.yaml:
       # smtp:
       #   host: 127.0.0.1
       #   port: 1025
       #   from: harness@localhost
       #   username: ""    # empty → local mode
     Open http://localhost:8025 to read the captured mail.

════════════════════════════════════════════════════════════════════
"""


QUIT_COMMANDS = {"/quit", "/bye", "/exit", "quit", "bye", "exit"}


def parse_repl_line(line: str) -> tuple[str, dict]:
    """Parse a REPL objective line, stripping inline flags.

    Supports (all sticky across sessions once set):
      --email ADDR             (or --email=ADDR)      → overrides['email']
      --scope PATTERN          (or --scope=PATTERN)   → overrides['scope'] (list, repeatable)
      -o PATH / --output PATH  (or --output=PATH)     → overrides['output']

    Pass an empty value to CLEAR a sticky setting:
      --email ""    → clears email
      --scope ""    → clears scope list (revert to scope.txt)
      -o ""         → clears output override

    Example:
      '--email me@x.com --scope *.foo.com recon foo.com'
        → ('recon foo.com',
           {'email': 'me@x.com', 'scope': ['*.foo.com']})
    """
    import shlex
    try:
        tokens = shlex.split(line)
    except ValueError:
        # Unmatched quotes etc — fall back to raw string, no flag parsing
        return line, {}

    overrides: dict = {}
    remaining: list[str] = []
    i = 0

    def _push_scope(v: str) -> None:
        overrides.setdefault("scope", []).append(v)

    while i < len(tokens):
        t = tokens[i]
        # --email
        if t == "--email" and i + 1 < len(tokens):
            overrides["email"] = tokens[i + 1]
            i += 2; continue
        if t.startswith("--email="):
            overrides["email"] = t.split("=", 1)[1]
            i += 1; continue
        # --scope (repeatable)
        if t == "--scope" and i + 1 < len(tokens):
            _push_scope(tokens[i + 1])
            i += 2; continue
        if t.startswith("--scope="):
            _push_scope(t.split("=", 1)[1])
            i += 1; continue
        # -o / --output
        if t in ("-o", "--output") and i + 1 < len(tokens):
            overrides["output"] = tokens[i + 1]
            i += 2; continue
        if t.startswith("--output="):
            overrides["output"] = t.split("=", 1)[1]
            i += 1; continue
        # --header (repeatable)
        if t == "--header" and i + 1 < len(tokens):
            overrides.setdefault("header", []).append(tokens[i + 1])
            i += 2; continue
        if t.startswith("--header="):
            overrides.setdefault("header", []).append(t.split("=", 1)[1])
            i += 1; continue
        # --telegram CHAT_ID
        if t == "--telegram" and i + 1 < len(tokens):
            overrides["telegram"] = tokens[i + 1]
            i += 2; continue
        if t.startswith("--telegram="):
            overrides["telegram"] = t.split("=", 1)[1]
            i += 1; continue
        # --servertype auto|lmstudio|ollama|llamacpp
        if t == "--servertype" and i + 1 < len(tokens):
            overrides["servertype"] = tokens[i + 1]
            i += 2; continue
        if t.startswith("--servertype="):
            overrides["servertype"] = t.split("=", 1)[1]
            i += 1; continue
        # --model MODEL_ID
        if t == "--model" and i + 1 < len(tokens):
            overrides["model"] = tokens[i + 1]
            i += 2; continue
        if t.startswith("--model="):
            overrides["model"] = t.split("=", 1)[1]
            i += 1; continue
        # --base-url URL
        if t == "--base-url" and i + 1 < len(tokens):
            overrides["base_url"] = tokens[i + 1]
            i += 2; continue
        if t.startswith("--base-url="):
            overrides["base_url"] = t.split("=", 1)[1]
            i += 1; continue
        remaining.append(t)
        i += 1
    return " ".join(remaining), overrides


def prompt_for_objective(is_first: bool) -> str | None:
    """Pide objective por stdin. Devuelve el texto, o None si el user sale."""
    try:
        if is_first:
            print("\nObjective (one-line goal for the agent). "
                  "Type /quit or /bye to exit.")
            print("Inline flags (sticky): --email ADDR  --scope PAT (repeat)  -o PATH")
        else:
            print("\n─── Previous session ended ───")
            print("New objective (or /quit / /bye to exit).")
            print("Inline flags (sticky): --email ADDR  --scope PAT (repeat)  -o PATH")
        line = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Cancelled.")
        return None
    if not line:
        print("[!] Empty objective — enter some text, or /quit to exit.")
        return prompt_for_objective(is_first=is_first)
    if line.lower() in QUIT_COMMANDS:
        return None
    return line


def _should_notify(cfg: dict, state) -> bool:
    """Decide whether to send end-of-pipeline notifications.

    If cfg.notify_only_if_findings is True (default), only notify when the
    run produced at least one finding of severity medium/high/critical.
    Set to False to always notify (useful for debugging the pipeline).
    """
    if not cfg.get("notify_only_if_findings", True):
        return True
    findings = state.get("findings", []) or []
    for f in findings:
        if str(f.get("severity", "")).lower() in ("medium", "high", "critical"):
            return True
    return False


def _run_orchestrated(cfg: dict, objective: str,
                      scope_override, output_override, email_to,
                      telegram_chat_id: str | None = None,
                      skip_preflight: bool = False):
    """Run the multi-agent Orchestrator for one objective."""
    # Scope: same precedence as single-agent
    if scope_override:
        scope = ScopeChecker(patterns=scope_override)
    else:
        scope = ScopeChecker(scope_file=cfg.get("scope_file", "scope.txt"))
    limiter = RateLimiter(
        min_interval_sec=float(cfg.get("min_request_interval_sec", 1.0))
    )
    tool_registry = ToolRegistry(scope=scope, limiter=limiter, cfg=cfg)

    # Sessions root override (default: <harness-dir>/sessions/)
    if output_override:
        out_path = Path(output_override)
        if out_path.suffix == ".jsonl":
            sessions_root = out_path.parent
        else:
            sessions_root = out_path
    else:
        sessions_root = SESSIONS_DIR
    sessions_root.mkdir(parents=True, exist_ok=True)

    orch = Orchestrator(cfg=cfg, tool_registry=tool_registry,
                        target=objective,
                        in_scope=scope_override or None,
                        sessions_root=sessions_root,
                        telegram_chat_id=telegram_chat_id,
                        skip_preflight=skip_preflight)
    state = orch.run()

    # Resolve final email destination:
    #   1. --email flag from CLI/REPL (wins)
    #   2. config.yaml → smtp.default_to  (auto-send if configured)
    if not email_to:
        email_to = str(((cfg.get("smtp") or {}).get("default_to")) or "").strip() or None

    # End-of-run mail — attach REPORT.md, gate by "has findings" if configured
    if email_to:
        if _should_notify(cfg, state):
            smtp_cfg = cfg.get("smtp") or {}
            subject = f"[harness] pipeline done · {objective}"
            body = _compose_orchestrated_mail_body(state, objective)
            # Attach REPORT.md so the recipient has the full details
            attachments = []
            report_path = state.get("report_path")
            if report_path and Path(report_path).is_file():
                attachments.append(Path(report_path))
            try:
                send_report(smtp_cfg, email_to, subject, body,
                            attachments=attachments)
                print(f"[+] Report mailed to {email_to} "
                      f"(with {len(attachments)} attachment(s))")
            except MailerError as e:
                print(f"[!] Mail not sent: {e}")
            except Exception as e:
                print(f"[!] Mail failed: {type(e).__name__}: {e}")
        else:
            print("[+] No meaningful findings — email skipped "
                  "(disable with notify_only_if_findings: false).")


def _compose_orchestrated_mail_body(state, objective: str) -> str:
    snap = state.snapshot()
    lines = [
        f"Objective : {objective}",
        f"Target    : {snap.get('target')}",
        f"Subdomains: {len(snap.get('subdomains', []))}",
        f"Live hosts: {len(snap.get('live_hosts', []))}",
        f"Techs     : {', '.join(snap.get('detected_techs', [])) or '(none)'}",
        f"Endpoints : {len(snap.get('endpoints_found', []))}",
        f"Findings  : {len(snap.get('findings', []))}",
        f"State     : {state.path}",
    ]
    report = snap.get("report_path")
    if report:
        lines.append(f"Report    : {report}")
    lines.append("")
    lines.append("--- Agents Run ---")
    for a in snap.get("agents_run", []):
        lines.append(f"  [{a['status']:>7s}] {a['agent']} · "
                     f"{a['elapsed_sec']}s · {a['turns']} turns · "
                     f"{a['tool_calls']} tool calls")
    critical = [f for f in snap.get("findings", [])
                if f.get("severity") in ("critical", "high")]
    if critical:
        lines.append("")
        lines.append("--- High/Critical Findings ---")
        for f in critical[:20]:
            lines.append(f"  [{f['severity'].upper()}] {f['title']}")
    return "\n".join(lines)


def main():
    # --help custom — se muestra ANTES de argparse para que se vea el
    # bloque completo con ejemplos, tools, kill switches y reglas.
    # argparse.--help built-in solo listaría los flags.
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print(HELP_TEXT)
        sys.exit(0)

    ap = argparse.ArgumentParser(add_help=False,
                                 description="Autonomous local bugbounty harness.")
    ap.add_argument("--config", default=str(HERE / "config.yaml"),
                    help="YAML config path")
    ap.add_argument("--objective", default=None,
                    help="Concrete goal for the agent (one sentence)")
    ap.add_argument("--one-shot", action="store_true",
                    help="Run a single session then exit (classic behaviour). "
                         "Without this flag: REPL — prompts for a new objective "
                         "after each session until /quit or /bye.")
    ap.add_argument("--scope", action="append", metavar="PATTERN",
                    help="Inline scope pattern (repeatable). Overrides "
                         "scope.txt. Formats: exact host / *.wildcard / "
                         "CIDR / IP. Example: --scope '*.example.com' "
                         "--scope 10.0.0.0/24")
    ap.add_argument("-o", "--output", metavar="PATH",
                    help="Session log destination. If PATH ends with '/' or "
                         "is an existing directory, writes "
                         "<PATH>/<timestamp>.jsonl. Otherwise writes to that "
                         "exact filename. Default: harness/sessions/<ts>.jsonl")
    ap.add_argument("--header", action="append", metavar="NAME:VALUE",
                    help="Custom HTTP header injected on every request "
                         "(repeatable). Also hinted to the model for shell "
                         "tools (curl/nuclei/ffuf/httpx/katana). Use for "
                         "researcher-attribution, e.g. "
                         "--header 'X-HackerOne-Researcher: yourhandle'. "
                         "Overrides / adds to config.yaml → custom_headers.")
    ap.add_argument("--email", metavar="ADDR",
                    help="Send an end-of-session report to ADDR. Requires "
                         "config.yaml → smtp.* filled and the password in the "
                         "env var named by smtp.password_env "
                         "(default SMTP_PASSWORD).")
    ap.add_argument("--telegram", metavar="CHAT_ID",
                    help="Send the REPORT.md via Telegram Bot API to CHAT_ID. "
                         "Requires $TELEGRAM_BOT_TOKEN in env. Overrides "
                         "config.yaml → telegram.chat_id for this run. "
                         "Also implicitly enables telegram delivery even if "
                         "telegram.enabled is false in config.")
    ap.add_argument("--servertype",
                    choices=("auto", "lmstudio", "ollama", "llamacpp",
                             "openai", "anthropic", "nvidia", "gemini"),
                    help="LLM backend to use. LOCAL: lmstudio(1234) / "
                         "ollama(11434) / llamacpp(8080). CLOUD (requires "
                         "API key): openai / anthropic / nvidia / gemini. "
                         "'auto' (default) probes local backends only; "
                         "cloud must be selected explicitly to avoid "
                         "unintended paid calls. Overrides "
                         "config.yaml → llm.servertype.")
    ap.add_argument("--model", metavar="MODEL_ID",
                    help="Model id to use. If omitted, auto-detects the "
                         "first loaded model on the chosen backend. "
                         "Overrides config.yaml → llm.model.")
    ap.add_argument("--base-url", dest="base_url", metavar="URL",
                    help="Explicit OpenAI-compatible base URL (e.g. "
                         "http://192.168.1.10:1234/v1). Bypasses auto-probe. "
                         "Overrides config.yaml → llm.base_url.")
    ap.add_argument("--legacy", action="store_true",
                    help="Use the classic single-agent loop instead of the "
                         "multi-agent orchestrator. Useful for debugging.")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="Skip the pre-flight reachability check on the "
                         "target. Use when the target requires VPN / custom "
                         "headers / IP allowlisting that only the agents "
                         "would satisfy. Without this flag the orchestrator "
                         "aborts if the target does not respond within 10s.")
    args = ap.parse_args()

    cfg = load_config(args.config)

    # Scope-mode notice if not strict — operator must see this each launch
    mode = cfg.get("scope_enforcement", "strict").lower()
    if mode != "strict":
        print(f"\n[!] scope_enforcement = {mode.upper()} "
              "— scope gate will NOT block. Audit manually.\n")

    # REPL state — every flag is "sticky": set once (via CLI or inline in
    # the prompt) and applies to every subsequent session until changed or
    # cleared with `--<flag> ""`.
    session_email = args.email
    session_scope = args.scope       # list[str] | None
    session_output = args.output     # str | None
    # session_headers: merged dict starting from config.yaml + CLI --header
    session_headers: dict = dict(cfg.get("custom_headers") or {})
    for h in (args.header or []):
        if ":" in h:
            n, v = h.split(":", 1)
            session_headers[n.strip()] = v.strip()
    session_telegram: str | None = args.telegram  # chat_id override
    # LLM backend sticky overrides
    session_servertype: str | None = args.servertype
    session_model: str | None = args.model
    session_base_url: str | None = args.base_url
    pending_objective = args.objective  # first-turn seed from CLI, if any
    is_first = True

    while True:
        # 1. Get the input line: either the CLI seed (once) or an interactive prompt
        if pending_objective is not None:
            line = pending_objective
            pending_objective = None
        else:
            line = prompt_for_objective(is_first=is_first)
            if line is None:
                # Final tempfile cleanup before leaving the REPL
                try:
                    if cfg.get("cleanup_tempfiles", True):
                        tempcleaner.cleanup(verbose=True)
                except Exception:
                    pass
                print("Bye.")
                return
            is_first = False

        # 2. Parse inline flags (--email, --scope, -o/--output)
        objective, overrides = parse_repl_line(line)

        if "email" in overrides:
            v = overrides["email"] or None
            session_email = v
            print(f"[+] Email set (sticky): {v}" if v else "[+] Email cleared.")

        if "scope" in overrides:
            # If any inline --scope had an empty value, treat as CLEAR.
            if any(s == "" for s in overrides["scope"]):
                session_scope = None
                print("[+] Scope cleared (reverting to scope.txt).")
            else:
                session_scope = overrides["scope"]
                print(f"[+] Scope set (sticky): {session_scope}")

        if "output" in overrides:
            v = overrides["output"] or None
            session_output = v
            print(f"[+] Output set (sticky): {v}"
                  if v else "[+] Output cleared (default sessions/ dir).")

        if "header" in overrides:
            # Special empty-string entry = clear all custom headers
            if any(h == "" for h in overrides["header"]):
                session_headers = {}
                print("[+] Custom headers cleared.")
            else:
                for h in overrides["header"]:
                    if ":" in h:
                        n, v = h.split(":", 1)
                        session_headers[n.strip()] = v.strip()
                print(f"[+] Custom headers set (sticky): {session_headers}")

        if "telegram" in overrides:
            v = overrides["telegram"] or None
            session_telegram = v
            print(f"[+] Telegram chat_id set (sticky): {v}"
                  if v else "[+] Telegram override cleared "
                            "(uses config.yaml value).")

        if "servertype" in overrides:
            v = overrides["servertype"] or None
            session_servertype = v
            print(f"[+] Servertype set (sticky): {v}"
                  if v else "[+] Servertype cleared (auto-probe again).")
        if "model" in overrides:
            v = overrides["model"] or None
            session_model = v
            print(f"[+] Model set (sticky): {v}"
                  if v else "[+] Model cleared (auto-detect on backend).")
        if "base_url" in overrides:
            v = overrides["base_url"] or None
            session_base_url = v
            print(f"[+] base_url set (sticky): {v}"
                  if v else "[+] base_url cleared (backend default).")

        # 3. If line was just flags (no objective text), re-prompt without exiting
        if not objective:
            print("[!] Give me an objective, or /quit to leave.")
            continue

        # 4. Run one session — pass merged headers + LLM backend overrides
        # via a config copy so the ToolRegistry and agents pick them up
        # without touching the on-disk YAML.
        cfg_run = dict(cfg)
        cfg_run["custom_headers"] = dict(session_headers)
        # Merge llm.* overrides (sticky CLI/REPL wins over on-disk yaml)
        llm_run = dict(cfg.get("llm") or {})
        if session_servertype:
            llm_run["servertype"] = session_servertype
        if session_model:
            llm_run["model"] = session_model
        if session_base_url:
            llm_run["base_url"] = session_base_url
        cfg_run["llm"] = llm_run
        # Resolve + print banner so the operator sees which backend/model runs.
        # Catch config errors (e.g. cloud without API key) so we don't leak
        # tracebacks and can re-prompt the user in the REPL.
        try:
            resolved = llm_backend.resolve(cfg_run)
            llm_backend.print_backend_banner(resolved)
        except llm_backend.BackendConfigError as e:
            print(f"[!] LLM backend config error: {e}")
            if args.one_shot:
                return
            continue  # back to REPL prompt
        try:
            if args.legacy:
                Harness(cfg_run, objective,
                        scope_override=session_scope,
                        output_override=session_output,
                        email_to=session_email).run()
            else:
                _run_orchestrated(cfg_run, objective, session_scope,
                                  session_output, session_email,
                                  telegram_chat_id=session_telegram,
                                  skip_preflight=args.skip_preflight)
        except Exception as e:
            print(f"[!] Session error: {e}")

        if args.one_shot:
            return


if __name__ == "__main__":
    main()
