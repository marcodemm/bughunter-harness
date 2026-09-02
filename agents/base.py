"""BaseAgent — encapsulates the LLM-driven tool_call loop used by every
specialist agent.

Design contract:
  * Each concrete agent subclasses BaseAgent, overrides:
      NAME               short identifier for logs and the UI
      DESCRIPTION        one-liner shown in the progress panel
      SYSTEM_PROMPT      focused prompt for this vertical
      MAX_ITERATIONS     hard turn cap (per agent, not per session)
      TOOL_NAMES         allowed tool names (subset of tools.py registry)
      entry_condition(state)  → bool (skip if False)
      build_objective(state)  → str (the initial user turn for this agent)
      after_run(state, transcript) → None (parse findings into shared_state)

  * The orchestrator instantiates agents lazily and calls .run(state).
  * Each agent writes its own JSONL to <run_dir>/agents/<NAME>.jsonl and
    also updates shared_state with structured findings.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openai import OpenAI

import llm_backend
from redact import redact


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


MAX_NO_TOOL_RETRIES = 3


def _extract_embedded_findings(summary: str) -> list[str]:
    """Recover findings that Qwen sometimes embeds inside the summary as
    <parameter=findings>[...JSON list...]</parameter> instead of the proper
    tool_call argument."""
    import re as _re
    import json as _json
    findings: list[str] = []
    for m in _re.finditer(
        r"<parameter=findings>\s*(\[.*?\])\s*</parameter>",
            summary, _re.DOTALL):
        blob = m.group(1)
        try:
            arr = _json.loads(blob)
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, str) and item.strip():
                        findings.append(item.strip())
        except Exception:
            pass
    return findings


def _strip_embedded_params(text: str) -> str:
    """Remove any <parameter=...>...</parameter> XML the model leaked into
    the summary. Leaves the natural-language prose intact."""
    import re as _re
    return _re.sub(r"<parameter=[^>]+>.*?</parameter>", "",
                   text or "", flags=_re.DOTALL)


_SEVERITY_PREFIX_RE = None


def _parse_severity_prefix(text: str) -> tuple[str, str]:
    """If `text` starts with a severity label followed by a separator
    (— · - : | =), extract the severity and return (severity, rest).
    Otherwise return ('info', text).

    Accepts common shapes the model uses to communicate severity when it
    can't cram it into the schema:
      'critical — dvwa-default-login on http://... — evidence'
      '[HIGH] Admin panel accessible without auth: ...'
      'medium: nginx.conf readable'
      'CRITICAL - SQL injection in id at ...'
    """
    global _SEVERITY_PREFIX_RE
    if _SEVERITY_PREFIX_RE is None:
        import re as _re
        # Two alternatives:
        #   (a) bracketed label:  "[HIGH] rest" or "(critical) rest"
        #       — the closing bracket alone is enough of a separator.
        #   (b) bare label + separator:  "critical — rest" / "medium: rest" /
        #       "high - rest" / "low | rest"
        _SEVERITY_PREFIX_RE = _re.compile(
            r"^\s*(?:"
            r"[\[\(]\s*(critical|high|medium|low|info)\s*[\]\)]\s*[:\-—·|=]?\s*"
            r"|"
            r"(critical|high|medium|low|info)\s*[—\-:·|=]\s+"
            r")(.+)$",
            _re.IGNORECASE | _re.DOTALL,
        )
    m = _SEVERITY_PREFIX_RE.match(text or "")
    if not m:
        return "info", (text or "")
    sev = (m.group(1) or m.group(2) or "info").lower()
    return sev, m.group(3).strip()


def _headers_reminder(custom_headers: dict[str, str]) -> str:
    """Build the system-prompt fragment that tells the model to attach the
    configured custom headers to every HTTP-based shell command it runs.
    Empty when no custom_headers are configured — no extra tokens wasted."""
    if not custom_headers:
        return ""
    lines = ["\n\nCUSTOM HTTP HEADERS (attribution — MANDATORY)",
             "The operator has configured attribution headers that MUST reach the",
             "target on every HTTP request. The harness injects them automatically",
             "on http_get / http_post — you do NOT need to add them there.",
             "",
             "For every run_shell command that hits HTTP (curl, nuclei, ffuf, httpx,",
             "katana, nikto, wpscan, feroxbuster), you MUST include these -H flags:"]
    for name, value in custom_headers.items():
        lines.append(f'  -H "{name}: {value}"')
    lines.append("")
    lines.append("Examples:")
    hdrs = " ".join(f'-H "{n}: {v}"' for n, v in custom_headers.items())
    lines.append(f'  curl -sI {hdrs} https://target.com/')
    lines.append(f'  nuclei -u https://target.com {hdrs} -tags cve -silent')
    lines.append(f'  ffuf -u https://target.com/FUZZ {hdrs} -w wl.txt')
    return "\n".join(lines)


FINISH_FORMAT_REMINDER = """

TOOL CALL FORMAT — CRITICAL:
When you call finish(), pass arguments as pure JSON:
  finish({"summary": "one paragraph", "findings": ["a", "b", "c"]})
NEVER embed <parameter=...>...</parameter> XML tags inside the summary
string. Findings must go in the "findings" JSON array, not inside summary.
Same for every other tool_call — pure JSON args, no XML.
"""


class BaseAgent:
    NAME: str = "base"
    DESCRIPTION: str = "Base agent"
    SYSTEM_PROMPT: str = ""
    MAX_ITERATIONS: int = 20
    TOOL_NAMES: list[str] = ["http_get", "http_post", "run_shell",
                             "oob_generate_token", "finish"]

    def __init__(self, cfg: dict, tool_registry, run_dir: Path,
                 progress_hook=None):
        self.cfg = cfg
        self.tool_registry = tool_registry
        self.run_dir = Path(run_dir)
        self.agents_dir = self.run_dir / "agents"
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.agents_dir / f"{self.NAME}.jsonl"
        self.progress_hook = progress_hook  # callable(name, event, **kw)

        # Resolve LLM backend (lmstudio / ollama / llamacpp / custom)
        # honouring cfg.llm.* first, top-level fields second, auto-probe last.
        backend = llm_backend.resolve(cfg)
        self.client = OpenAI(
            base_url=backend.base_url,
            api_key=backend.api_key or "placeholder",
        )
        self.model = backend.model or cfg.get("model", "")
        self.backend = backend

        self.turns = 0
        self.tool_calls = 0
        self.finish_summary: str | None = None
        self.finish_findings: list[str] = []

    # ── extension-technique injection ───────────────────────────────
    def _extension_techniques_block(self, state) -> str:
        """Load techniques whose frontmatter matches current context and
        render them as a system-prompt block. Returns '' if none or on any
        error (extension loading NEVER breaks a run)."""
        try:
            import extension_loader
            from pathlib import Path as _P
            ext_cfg = self.cfg.get("extensions") or {}
            if not ext_cfg.get("enabled", True):
                return ""
            dirs = [_P(__file__).resolve().parent.parent / "extensions"]
            for extra in ext_cfg.get("extra_dirs") or []:
                p = _P(extra).expanduser()
                if p.is_dir():
                    dirs.append(p)
            all_techs: list[dict] = []
            for d in dirs:
                all_techs.extend(extension_loader.discover_techniques(d))
            if not all_techs:
                return ""
            detected = state.get("detected_techs", []) or []
            endpoints = [e.get("url", "")
                         for e in (state.get("endpoints_found", []) or [])]
            applicable = extension_loader.techniques_applicable_for(
                all_techs, self.NAME, detected, endpoints)
            return extension_loader.render_techniques_for_prompt(applicable)
        except Exception:
            return ""

    # ── overridable ─────────────────────────────────────────────────
    def entry_condition(self, state) -> bool:
        return True

    def build_objective(self, state) -> str:
        return f"Target: {state.get('target')}"

    def after_run(self, state, transcript: list[dict]) -> None:
        """Post-processing hook. Subclasses parse tool outputs from
        `transcript` and update `state` with findings/techs/endpoints."""
        pass

    # ── shared machinery ────────────────────────────────────────────
    def _append(self, entry: dict) -> None:
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _emit(self, event: str, **kw):
        if self.progress_hook:
            try:
                self.progress_hook(self.NAME, event, **kw)
            except Exception:
                pass

    def _filtered_tool_schemas(self):
        all_schemas = self.tool_registry.openai_schemas()
        if not self.TOOL_NAMES:
            return all_schemas
        return [s for s in all_schemas
                if s.get("function", {}).get("name") in self.TOOL_NAMES]

    def _call_llm(self, messages, tools):
        temp = float(self.cfg.get("temperature", 0.3))
        max_tok = int(self.cfg.get("max_response_tokens", 2048))
        primary = self.cfg.get("tool_choice", "auto")
        try:
            return self.client.chat.completions.create(
                model=self.model, messages=messages, tools=tools,
                tool_choice=primary, temperature=temp, max_tokens=max_tok,
            )
        except Exception as e1:
            err = str(e1)
            if primary != "auto" and any(k in err for k in
                                         ("peg-native", "400", "500")):
                self._append({"kind": "llm_grammar_fallback", "err": err,
                              "ts": _now_iso()})
                try:
                    return self.client.chat.completions.create(
                        model=self.model, messages=messages, tools=tools,
                        tool_choice="auto",
                        temperature=temp, max_tokens=max_tok,
                    )
                except Exception as e2:
                    self._append({"kind": "llm_error", "err": str(e2),
                                  "ts": _now_iso()})
                    return None
            self._append({"kind": "llm_error", "err": err, "ts": _now_iso()})
            return None

    # ── main loop ───────────────────────────────────────────────────
    def run(self, state) -> str:
        """Returns one of: 'done' | 'skipped' | 'error'."""
        started = time.time()
        if not self.entry_condition(state):
            self._emit("skipped", reason="entry condition false")
            state.mark_agent_run(self.NAME, "skipped", 0.0)
            return "skipped"

        self._emit("start", description=self.DESCRIPTION,
                   max_iterations=self.MAX_ITERATIONS)
        self._append({"kind": "agent_start", "ts": _now_iso(),
                      "name": self.NAME, "target": state.get("target")})

        objective = self.build_objective(state)
        # If custom_headers are configured, tell the model to attach them
        # to every shell tool that takes HTTP requests. http_get/http_post
        # get them auto-injected by the harness.
        headers_reminder = _headers_reminder(
            self.tool_registry.custom_headers)
        # Extension tools/techniques — inject prompt hints so the model
        # knows the extended toolbox available in run_shell + any playbooks
        # that match the current target context.
        ext_tools_hint = ""
        ext_techniques_block = ""
        try:
            ext_tools_hint = self.tool_registry.extension_tools_prompt_hint()
        except AttributeError:
            pass
        try:
            ext_techniques_block = self._extension_techniques_block(state)
        except Exception:
            pass
        messages = [
            {"role": "system",
             "content": (self.SYSTEM_PROMPT
                         + FINISH_FORMAT_REMINDER
                         + headers_reminder
                         + ext_tools_hint
                         + ext_techniques_block)},
            {"role": "user", "content": objective},
        ]
        tools = self._filtered_tool_schemas()
        transcript: list[dict] = []
        no_tool_retries = 0

        while self.turns < self.MAX_ITERATIONS:
            self.turns += 1
            self._emit("progress", turn=self.turns,
                       max_turns=self.MAX_ITERATIONS)

            resp = self._call_llm(messages, tools)
            if resp is None:
                self._emit("error", err="LLM error")
                state.error(self.NAME, "LLM error")
                state.mark_agent_run(self.NAME, "error",
                                     time.time() - started,
                                     self.turns, self.tool_calls)
                return "error"

            msg = resp.choices[0].message
            self._append({"kind": "llm_response", "ts": _now_iso(),
                          "content": msg.content,
                          "tool_calls": [tc.model_dump()
                                         for tc in (msg.tool_calls or [])]})

            # Dedupe identical tool_calls
            if msg.tool_calls and len(msg.tool_calls) > 1:
                first = msg.tool_calls[0]
                dupes = [tc for tc in msg.tool_calls[1:]
                         if tc.function.name == first.function.name
                         and tc.function.arguments == first.function.arguments]
                if len(dupes) == len(msg.tool_calls) - 1:
                    msg.tool_calls = [first]

            messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [tc.model_dump()
                               for tc in (msg.tool_calls or [])],
            })

            if not msg.tool_calls:
                no_tool_retries += 1
                if no_tool_retries > MAX_NO_TOOL_RETRIES:
                    self._append({"kind": "no_tool_call_giveup",
                                  "ts": _now_iso()})
                    break
                messages.append({
                    "role": "user",
                    "content": ("You replied with text but no tool_call. "
                                "You MUST emit one tool_call now, or call "
                                "finish() to end this agent."),
                })
                continue
            no_tool_retries = 0

            for tc in msg.tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                self._append({"kind": "tool_call_start", "ts": _now_iso(),
                              "tool": name, "args": args})

                if name == "finish":
                    self.finish_summary = args.get("summary", "")
                    self.finish_findings = list(args.get("findings", []) or [])
                    self._append({"kind": "finish", "ts": _now_iso(),
                                  "summary": self.finish_summary,
                                  "findings": self.finish_findings})
                    transcript.append({"tool": "finish", "args": args})
                    elapsed = time.time() - started
                    self._process_finish_findings(state)
                    self.after_run(state, transcript)
                    self._emit("done", elapsed=elapsed,
                               tool_calls=self.tool_calls, turns=self.turns)
                    state.mark_agent_run(self.NAME, "done", elapsed,
                                         self.turns, self.tool_calls)
                    return "done"

                self.tool_calls += 1
                result = self.tool_registry.dispatch(name, args)
                red = redact(result)
                transcript.append({"tool": name, "args": args, "result": red})
                self._append({"kind": "tool_call_result", "ts": _now_iso(),
                              "tool": name, "result_redacted": red})
                # Log every tool call in shared_state so the REPORT always
                # has content even if the agent forgets to call finish()
                # with an explicit findings list.
                self._record_tool_activity(state, name, args, red)
                messages.append({
                    "role": "tool", "tool_call_id": tc.id, "content": red,
                })

        # loop exit without finish() → treat as done anyway
        elapsed = time.time() - started
        self.after_run(state, transcript)
        self._emit("done", elapsed=elapsed, tool_calls=self.tool_calls,
                   turns=self.turns)
        state.mark_agent_run(self.NAME, "done", elapsed,
                             self.turns, self.tool_calls)
        return "done"

    def _process_finish_findings(self, state):
        """Convert the model's finish(findings=[...]) list into shared_state.

        Also handles a common Qwen template bug: the model sometimes emits
        <parameter=findings>[...]</parameter> INSIDE the summary string
        instead of as a proper JSON field. We extract those too.
        """
        # 1) Normal path: real findings list
        collected = list(self.finish_findings)

        # 2) Fallback: extract embedded <parameter=findings>[...]</parameter>
        #    from the summary text (Qwen template bug workaround).
        if self.finish_summary:
            extra = _extract_embedded_findings(self.finish_summary)
            for e in extra:
                if e not in collected:
                    collected.append(e)

        # 3) Log the summary itself as an agent narrative (always shown in
        #    the REPORT even when findings is empty).
        clean_summary = _strip_embedded_params(self.finish_summary or "").strip()
        if clean_summary:
            state.append("agent_summaries", {
                "agent": self.NAME,
                "summary": clean_summary[:2000],
                "ts": _now_iso(),
            })

        for f in collected:
            # Extract severity from prefix "critical — ...", "[HIGH] ...",
            # "medium: ...", etc. Fallback to 'info' when the model didn't
            # include a severity label.
            severity, cleaned = _parse_severity_prefix(str(f))
            state.add_finding(
                agent=self.NAME,
                severity=severity,
                title=cleaned[:200],
                evidence="",
                recommendation="",
            )

    def _record_tool_activity(self, state, tool: str, args: dict, result: str):
        """Log every tool call as a low-signal breadcrumb.

        Guarantees the final REPORT.md always has activity per agent, even
        when the model forgets to call finish() with explicit findings.
        Heavy parsing (CVE match, plugin version, etc.) lives in the
        subclass `after_run` — this is just a floor of visibility.
        """
        if tool == "http_get" or tool == "http_post":
            url = args.get("url", "")
            status = ""
            # Result starts with 'HTTP <code>\n' from tools.py
            if result.startswith("HTTP "):
                status = result.split("\n", 1)[0]
            state.log(self.NAME, "http",
                      f"{tool} {url} → {status[:40]}")
        elif tool == "run_shell":
            cmd = str(args.get("command", ""))[:120]
            exit_code = ""
            for line in result.splitlines()[:3]:
                if line.startswith("exit="):
                    exit_code = line.strip()
                    break
            state.log(self.NAME, "shell",
                      f"{cmd} → {exit_code[:40] or '(no exit)'}")
        elif tool == "oob_generate_token":
            state.log(self.NAME, "oob",
                      f"generated token for {args.get('vector', '?')}"
                      f"/{args.get('label', '?')}")
