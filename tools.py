"""Tool implementations exposed to the LLM via OpenAI function calling.

Each tool enforces its own gates. The model can request anything; only what
passes the gates actually runs.
"""
from __future__ import annotations

import shlex
import subprocess
from typing import Any
from urllib.parse import urlparse

import requests

from progress import Spinner

# Primary offensive-tool allowlist. Each pipeline stage's first token must be
# in either this set or SHELL_HELPERS.
SHELL_ALLOWLIST = {
    "nmap", "nuclei", "nikto", "ffuf", "feroxbuster", "wpscan",
    "curl", "dig", "host", "whois",
    "httpx", "subfinder", "dnsx", "naabu", "gau", "waybackurls", "katana",
    # Active parameter scanners
    "sqlmap", "dalfox",
}

# Coreutils/helpers commonly used as later pipeline stages, or standalone
# for local recon (listing wordlists, filtering results). Read-only by nature.
SHELL_HELPERS = {
    "ls", "cat", "head", "tail", "wc", "sort", "uniq",
    "grep", "egrep", "fgrep", "awk", "cut", "tr", "sed",
    "tee", "xargs", "find", "which", "file", "echo",
    "base64", "jq", "yq",
}

# Hard-forbidden substrings anywhere in the full command line. These win over
# the pipeline allowlist and abort execution.
SHELL_HARD_DENY = [
    # Auth-elevation / destructive filesystem
    "sudo", " su ", " rm ", " rm\t", "rm -", "mv -", "mkfs", "dd if=",
    "chmod ", "chown ", "chgrp ", "shred", "wipe",
    # Command substitution (would bypass allowlist)
    "$(", "`", "$<",
    # Backgrounding / job control
    " & ", " &\n", "& ", "&\n", "nohup", "disown",
    # nmap noisy/aggressive
    "-T4", "-T5", "-sS", "-sU", "-sN", "-sF", "-sX", "--script=vuln",
    "--min-rate", "--max-rate",
    # HTTP destructive verbs
    "-X DELETE", "-X PUT", "-X PATCH",
]

# Chars that split the command into pipeline stages — allowed, each stage
# validated. Anything NOT in this set is left to bash.
PIPE_SEPARATORS = ("|", ";", "&&", "||")

# Max seconds per shell command. Overridable via config.yaml → shell_timeout_sec.
# 300s (5 min) accommodates long nuclei/nmap scans; the model can still finish
# the session with a kill switch if it goes wild.
SHELL_TIMEOUT_SEC_DEFAULT = 300
HTTP_TIMEOUT_SEC_DEFAULT = 30


def _looks_like_host(tok: str) -> bool:
    """Heuristic: is `tok` a hostname or URL we should scope-check?
    Excludes local filesystem paths, flags, wordlists, plain filenames."""
    if not tok:
        return False
    # Absolute / relative / home paths → local file, not a host
    if tok.startswith(("/", "./", "../", "~", "\\")):
        return False
    # Flag
    if tok.startswith("-"):
        return False
    # URL with scheme → definitely a host
    if "://" in tok:
        return True
    # Contains / but not a URL → treat as path fragment, skip
    if "/" in tok:
        return False
    # host:port or host.domain — must be all valid hostname chars
    import re as _re
    if _re.match(r"^[a-zA-Z0-9._-]+(:\d+)?$", tok) and "." in tok:
        # Exclude file-like tokens by extension
        low = tok.lower()
        for ext in (".txt", ".json", ".yaml", ".yml", ".py", ".sh",
                    ".md", ".log", ".xml", ".html", ".csv", ".tsv",
                    ".conf", ".cfg", ".ini", ".pem", ".key", ".crt"):
            if low.endswith(ext):
                return False
        return True
    return False


def _split_pipeline_stages(cmd: str) -> list[str]:
    """Split on top-level |, ;, &&, || respecting single/double quotes.
    Returns each stage as a string (not tokenised)."""
    stages: list[str] = []
    buf: list[str] = []
    i, n = 0, len(cmd)
    in_s = in_d = False
    while i < n:
        c = cmd[i]
        # Track quotes so we don't split inside them
        if c == "'" and not in_d:
            in_s = not in_s
            buf.append(c); i += 1; continue
        if c == '"' and not in_s:
            in_d = not in_d
            buf.append(c); i += 1; continue
        if not in_s and not in_d:
            # 2-char separators first
            if cmd[i:i+2] in ("&&", "||"):
                stages.append("".join(buf).strip())
                buf = []; i += 2; continue
            if c in ("|", ";"):
                stages.append("".join(buf).strip())
                buf = []; i += 1; continue
        buf.append(c); i += 1
    tail = "".join(buf).strip()
    if tail:
        stages.append(tail)
    return [s for s in stages if s]


class ToolRegistry:
    def __init__(self, scope, limiter, cfg: dict):
        self.scope = scope
        self.limiter = limiter
        self.oob_host = cfg.get("oob_host", "")
        self.oob_token_prefix = cfg.get("oob_token_prefix", "harness")
        # Modo de enforcement del scope: strict (default) / warn / off
        self.scope_mode = cfg.get("scope_enforcement", "strict").lower()
        if self.scope_mode not in ("strict", "warn", "off"):
            self.scope_mode = "strict"
        # Timeouts (overridable from config)
        self.shell_timeout = int(cfg.get("shell_timeout_sec",
                                         SHELL_TIMEOUT_SEC_DEFAULT))
        self.http_timeout = int(cfg.get("http_timeout_sec",
                                        HTTP_TIMEOUT_SEC_DEFAULT))
        # SharedState — attached by orchestrator after init so we can
        # auto-inject session cookies captured by login_probe agent.
        self.state = None
        # Custom headers auto-injected on every http_get / http_post.
        # Normalized to dict[str,str], skipping empty values.
        raw = cfg.get("custom_headers") or {}
        self.custom_headers: dict[str, str] = {}
        if isinstance(raw, dict):
            for k, v in raw.items():
                if k and v is not None:
                    self.custom_headers[str(k)] = str(v)
        elif isinstance(raw, list):
            # Accept ["Name: value", ...] form too
            for item in raw:
                if ":" in str(item):
                    n, v = str(item).split(":", 1)
                    n, v = n.strip(), v.strip()
                    if n and v:
                        self.custom_headers[n] = v
        # Extension tools — discovered by extension_loader.discover_tools()
        # at ToolRegistry construction. Adds binaries to SHELL_ALLOWLIST and
        # exposes prompt hints to agents via extension_tools_prompt_hint().
        self.extension_tools: list[dict] = []
        try:
            import extension_loader
            from pathlib import Path as _P
            ext_cfg = cfg.get("extensions") or {}
            if ext_cfg.get("enabled", True):
                dirs = [_P(__file__).resolve().parent / "extensions"]
                for extra in ext_cfg.get("extra_dirs") or []:
                    p = _P(extra).expanduser()
                    if p.is_dir():
                        dirs.append(p)
                for d in dirs:
                    for spec in extension_loader.discover_tools(d):
                        self.extension_tools.append(spec)
                        SHELL_ALLOWLIST.add(str(spec.get("binary", "")))
        except Exception as _e:
            print(f"[!] extension tools load skipped: "
                  f"{type(_e).__name__}: {_e}")

    def extension_tools_prompt_hint(self) -> str:
        """Return the combined `prompt_hint` block for all extension tools —
        used by agents to know how to invoke them via run_shell."""
        try:
            import extension_loader
            return extension_loader.render_tools_hint_for_prompt(
                self.extension_tools)
        except Exception:
            return ""

    def attach_state(self, state) -> None:
        """Attach the SharedState so http_get/http_post can auto-inject
        session cookies harvested by the login_probe agent."""
        self.state = state

    def _session_cookie_for(self, host: str) -> str:
        """Return the Cookie header value stored by login_probe for `host`,
        or empty string if none / no state attached."""
        if not self.state or not host:
            return ""
        try:
            cookies = self.state.get("session_cookies", {}) or {}
        except Exception:
            return ""
        # Try exact host, then hostname-only stripped of :port
        c = cookies.get(host) or cookies.get(host.split(":", 1)[0])
        return c or ""

    def _scope_gate(self, host: str, context: str) -> tuple[bool, str]:
        """Decide si el host pasa el gate según scope_mode.
        Returns (allowed, message_prefix). message_prefix se añade al output."""
        if not host:
            return (True, "")
        if self.scope.is_in_scope(host):
            return (True, "")
        if self.scope_mode == "strict":
            return (False, f"ERROR: host '{host}' not in scope. Check scope.txt.")
        if self.scope_mode == "warn":
            return (True, f"[WARN] host '{host}' not in scope.txt "
                           f"(scope_enforcement=warn — allowed, audit manually). ")
        return (True, "")

    def openai_schemas(self) -> list[dict]:
        return [
            {"type": "function", "function": {
                "name": "http_get",
                "description": ("Perform an HTTP GET request against an in-scope "
                                "host. Rate-limited. Returns status + first 4KB "
                                "of body (redacted)."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string",
                                "description": "Full URL including scheme"},
                        "headers": {"type": "object",
                                    "description": "Optional headers dict",
                                    "additionalProperties": {"type": "string"}},
                    },
                    "required": ["url"],
                },
            }},
            {"type": "function", "function": {
                "name": "http_post",
                "description": ("Perform an HTTP POST against an in-scope host. "
                                "Rate-limited."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "body": {"type": "string",
                                 "description": "Raw request body"},
                        "headers": {"type": "object",
                                    "additionalProperties": {"type": "string"}},
                        "content_type": {"type": "string",
                                         "default": "application/json"},
                    },
                    "required": ["url", "body"],
                },
            }},
            {"type": "function", "function": {
                "name": "run_shell",
                "description": (
                    "Run a shell command line. Pipes (|), sequential (;) and "
                    "conditional (&&, ||) are ALLOWED — feel free to use "
                    "one-liners like 'subfinder -d X -silent | httpx -silent "
                    "-title -status -tech-detect'. Each pipeline stage's first "
                    "token must be in the allowlist. Offensive tools: "
                    f"{', '.join(sorted(SHELL_ALLOWLIST))}. Helpers (later "
                    f"stages / recon): {', '.join(sorted(SHELL_HELPERS))}. "
                    "Redirects >, >>, 2>&1, < are allowed. Any target host in "
                    "the command is scope-checked. Rate-limited. Timeout 60s."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string",
                                    "description": "Full command including args"},
                    },
                    "required": ["command"],
                },
            }},
            {"type": "function", "function": {
                "name": "oob_generate_token",
                "description": ("Generate a unique OOB callback token URL for "
                                "blind vulnerability payloads (SSRF, XSS, XXE). "
                                "Use this URL inside your payloads."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vector": {"type": "string",
                                   "description": ("Short slug: ssrf, xss, "
                                                   "xxe, blind, etc.")},
                        "label": {"type": "string",
                                  "description": "Short label for the token"},
                    },
                    "required": ["vector", "label"],
                },
            }},
            {"type": "function", "function": {
                "name": "finish",
                "description": ("Call when the objective is met or when no "
                                "productive next step exists. Ends the session."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "summary": {"type": "string",
                                    "description": "One-paragraph summary"},
                        "findings": {"type": "array",
                                     "items": {"type": "string"},
                                     "description": "List of concrete findings"},
                    },
                    "required": ["summary"],
                },
            }},
        ]

    def dispatch(self, name: str, args: dict) -> str:
        try:
            if name == "http_get":
                return self._http("GET", args["url"],
                                  headers=args.get("headers") or {})
            if name == "http_post":
                return self._http("POST", args["url"],
                                  body=args.get("body", ""),
                                  headers=args.get("headers") or {},
                                  content_type=args.get("content_type",
                                                        "application/json"))
            if name == "run_shell":
                return self._shell(args["command"])
            if name == "oob_generate_token":
                return self._oob_token(args["vector"], args["label"])
            return f"ERROR: unknown tool '{name}'"
        except Exception as e:
            return f"ERROR: tool exception: {type(e).__name__}: {e}"

    def _http(self, method: str, url: str, headers: dict[str, str],
              body: str = "", content_type: str = "application/json") -> str:
        try:
            parsed = urlparse(url)
        except Exception:
            return "ERROR: invalid URL"
        if parsed.scheme not in ("http", "https"):
            return f"ERROR: scheme '{parsed.scheme}' not allowed"
        allowed, warn_prefix = self._scope_gate(parsed.hostname or "", "http")
        if not allowed:
            return warn_prefix

        # Merge custom headers from config — model-supplied headers win on collision
        merged_headers = dict(self.custom_headers)
        merged_headers.update(headers)

        # Auto-inject session cookie captured by login_probe, if any.
        # Model-supplied Cookie header still wins (someone may need to override).
        session_cookie = self._session_cookie_for(parsed.hostname or "")
        if session_cookie and not any(k.lower() == "cookie"
                                       for k in merged_headers):
            merged_headers["Cookie"] = session_cookie

        self.limiter.wait()
        label = f"{method} {url[:60]}"
        with Spinner(label, self.http_timeout):
            try:
                if method == "GET":
                    r = requests.get(url, headers=merged_headers,
                                     timeout=self.http_timeout,
                                     allow_redirects=False)
                else:
                    if "Content-Type" not in merged_headers:
                        merged_headers["Content-Type"] = content_type
                    r = requests.post(url, headers=merged_headers,
                                      data=body.encode(),
                                      timeout=self.http_timeout,
                                      allow_redirects=False)
            except requests.RequestException as e:
                return f"ERROR: request failed: {type(e).__name__}: {e}"

        body_preview = r.text[:4096]
        head_preview = {k: v for k, v in r.headers.items()
                        if k.lower() in ("server", "content-type",
                                         "location", "set-cookie",
                                         "www-authenticate", "x-powered-by",
                                         "cache-control")}
        return (f"{warn_prefix}HTTP {r.status_code}\n"
                f"Headers: {head_preview}\n"
                f"Body ({len(r.text)} bytes total, first 4KB shown):\n"
                f"{body_preview}")

    def _shell(self, command: str) -> str:
        if not command or not command.strip():
            return "ERROR: empty command"

        # Hard denylist first — always wins.
        lower_cmd = " " + command.lower() + " "
        for bad in SHELL_HARD_DENY:
            if bad.lower() in lower_cmd:
                return (f"ERROR: forbidden token '{bad.strip()}' in command "
                        "(hard denylist — no bypass)")

        # Split into pipeline stages and validate the first token of each.
        stages = _split_pipeline_stages(command)
        if not stages:
            return "ERROR: empty command"

        allowed_tokens = SHELL_ALLOWLIST | SHELL_HELPERS
        seen_hosts: list[str] = []
        for stage in stages:
            try:
                toks = shlex.split(stage)
            except ValueError as e:
                return f"ERROR: invalid shell stage '{stage}': {e}"
            if not toks:
                continue
            first = toks[0]
            if first not in allowed_tokens:
                return (f"ERROR: '{first}' not in shell allowlist. "
                        f"Offensive tools: {sorted(SHELL_ALLOWLIST)}. "
                        f"Helpers: {sorted(SHELL_HELPERS)}.")
            # Collect host-looking args of this stage for the scope gate.
            for t in toks[1:]:
                if _looks_like_host(t):
                    seen_hosts.append(t)

        # Scope-gate every host-looking token.
        warn_msgs = []
        for hc in seen_hosts:
            host = hc
            if "://" in host:
                try:
                    host = urlparse(host).hostname or host
                except Exception:
                    pass
            elif ":" in host and not host.startswith("["):
                host = host.split(":", 1)[0]
            allowed, warn = self._scope_gate(host, "shell")
            if not allowed:
                return warn
            if warn:
                warn_msgs.append(warn)
        warn_prefix = "".join(warn_msgs)

        self.limiter.wait()
        # Execute via bash so |, ;, &&, ||, > , 2>&1, etc. work as expected.
        # `set -o pipefail` propagates the exit code of any failed stage.
        wrapped = "set -o pipefail; " + command
        # Spinner label: first stage's first token (nmap / nuclei / ...) + args
        try:
            first_stage_tokens = shlex.split(stages[0])
            first_tool = first_stage_tokens[0]
            snippet = " ".join(first_stage_tokens[:6])
        except Exception:
            first_tool, snippet = "shell", command[:60]
        pipe_note = f" (+{len(stages) - 1} pipe stages)" if len(stages) > 1 else ""
        label = f"{first_tool}: {snippet}{pipe_note}"
        with Spinner(label, self.shell_timeout):
            try:
                proc = subprocess.run(
                    ["bash", "-c", wrapped],
                    capture_output=True, text=True,
                    timeout=self.shell_timeout,
                )
            except subprocess.TimeoutExpired:
                return (f"ERROR: command timed out after {self.shell_timeout}s. "
                        "Reduce scope (fewer -tags for nuclei, smaller wordlist "
                        "for ffuf, single target for nmap) or raise "
                        "shell_timeout_sec in config.yaml.")
            except FileNotFoundError:
                return "ERROR: bash not found on this system"

        out = proc.stdout[:8192]
        err = proc.stderr[:2048]
        return (f"{warn_prefix}exit={proc.returncode}\n"
                f"--- stdout (first 8KB) ---\n{out}\n"
                f"--- stderr (first 2KB) ---\n{err}")

    def _oob_token(self, vector: str, label: str) -> str:
        if not self.oob_host:
            return ("ERROR: oob_host not configured in config.yaml. "
                    "Set oob_host to your self-hosted OOB catcher domain.")
        token = f"{self.oob_token_prefix}-{vector}-{label}"[:64]
        url = f"https://{self.oob_host}/oob/{token}"
        return (f"OOB token URL: {url}\n"
                "Use this in blind payloads (SSRF/XXE/XSS). Check the panel "
                "for hits.")
