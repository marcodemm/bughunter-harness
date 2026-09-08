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
    # Iter 14 (2026-09-04): visual/OSINT extension binaries invoked by
    # the deterministic `screenshot` + `typosquat` extension agents.
    # Guarded by state.missing_tools — the agents skip themselves when
    # the binary isn't installed, so allowlisting them is safe.
    "gowitness", "dnstwist",
    # C4 fix (2026-09-08): curl-impersonate binaries. Auto-fallback from
    # wpscan/nuclei when WAF blocks the default TLS fingerprint (JA3).
    # Two upstreams (both ship the same wrapper naming):
    #   - lwthiker/curl-impersonate (v0.6.x, x86_64-macos only, x86_64
    #     Linux + arm64 Linux, abandoned in 2024). `brew install
    #     curl-impersonate` from Homebrew's `curl-impersonate` formula
    #     (shakacode tap) tries to build this from source and often
    #     FAILS on modern macOS (CMake < 3.5 removed, requires exact
    #     Xcode version).
    #   - lexiforest/curl-impersonate (v2.x, arm64-macos native, active
    #     since 2025). Recommended install path is downloading the
    #     precompiled tarball from GitHub Releases (no brew, no
    #     compile). See agents/wordpress.py step 2b for the workflow.
    # Iter 18b (2026-09-08) — added the Firefox variants shipped by the
    # v2.x fork. Old `curl_ff109` (v0.6.x naming) is retained for
    # backwards compat but does not exist in v2.x, so the effective
    # binary is `curl_firefox144` (Firefox 144).
    "curl_chrome116", "curl_ff109",
    "curl_firefox133", "curl_firefox135", "curl_firefox144",
    "curl_firefox147",
    "curl-impersonate", "curl-impersonate-chrome", "curl-impersonate-ff",
}

# Coreutils/helpers commonly used as later pipeline stages, or standalone
# for local recon (listing wordlists, filtering results). Read-only by nature.
SHELL_HELPERS = {
    "ls", "cat", "head", "tail", "wc", "sort", "uniq",
    "grep", "egrep", "fgrep", "awk", "cut", "tr", "sed",
    "tee", "xargs", "find", "which", "file", "echo",
    "base64", "jq", "yq",
    # PN20 iter 10 (2026-09-04): POSIX-safe read-only builtins the LLM
    # commonly used and hit the allowlist wall (`pwd`, `command -v`,
    # `printf`, `test`). None mutate state; all are safe helpers.
    "pwd", "command", "type", "test", "printf",
}

# Hard-forbidden PLAIN SUBSTRINGS anywhere in the full command line. These
# win over the pipeline allowlist and abort execution. Case-insensitive.
# Use this list ONLY for tokens that are safe to match as raw substrings
# (they can't appear inside legitimate paths / other flags).
SHELL_HARD_DENY = [
    # Auth-elevation / destructive filesystem
    "sudo", " su ", " rm ", " rm\t", "rm -", "mv -", "mkfs", "dd if=",
    "chmod ", "chown ", "chgrp ", "shred", "wipe",
    # Command substitution (would bypass allowlist)
    "$(", "`", "$<",
    # Backgrounding / job control
    " & ", " &\n", "& ", "&\n", "nohup", "disown",
    # nmap noisy/aggressive
    "-T4", "-T5", "--script=vuln",
    "--min-rate", "--max-rate",
    # HTTP destructive verbs
    "-X DELETE", "-X PUT", "-X PATCH",
]

# Hard-forbidden SHORT FLAG TOKENS that require WORD-BOUNDARY matching to
# avoid false positives against legitimate paths / other flags.
#
# Bug seen in run 20260903T133821Z (2026-09-03): `subfinder -o
# /tmp/harness-recon-subfinder.txt` was rejected because the path contains
# `-subfinder` → substring `-sU` matches → recon returned 0 subs → cascade
# to takeover skip. The fix is to require a non-word boundary around the
# forbidden token so `-sU` only matches when it is a stand-alone flag, not
# a substring inside another word.
SHELL_HARD_DENY_FLAGS = [
    "-sS", "-sU", "-sN", "-sF", "-sX",   # nmap scan-type flags
]

# ─────────────────────────────────────────────────────────────────────────
# GUARDRAIL A (2026-09-08) — nuclei anti-write-verb enforcement.
#
# INCIDENT that triggered this: the harness scanned a WordPress target with
# `nuclei -tags wordpress`. One of the templates loaded was for the Breeze
# cache plugin; its detection logic issues `POST /wp-comments-post.php`.
# The plugin was NOT installed on the target, but WordPress core processed
# the POST anyway → an anonymous comment was legitimately persisted into
# the moderation queue on the researcher's own site.
#
# Root cause: `-tags wordpress` (and other broad tags) can silently include
# templates that verify a vulnerability by writing state — form submissions,
# comment posts, cache warmups, low-privilege user registrations, etc.
# From an offensive-safety standpoint these are indistinguishable from
# genuine user traffic and MUST NOT run against a bug-bounty target
# without explicit `--allow-writes` opt-in from the operator.
#
# The fix is belt-and-suspenders:
#   (1) SYSTEM_PROMPT of every nuclei-driving agent documents the rule.
#   (2) THIS module auto-injects `-exclude-tags` into every nuclei
#       invocation that lacks the required exclusions. The LLM cannot
#       forget or skip it. See `_inject_nuclei_safe_flags` below.
#   (3) A blocklist of known-writing template IDs is enforced when the
#       LLM uses `-id <template>` directly.
#
# Tags to exclude (offensive-write-verb families in nuclei-templates):
#   - dast              : DAST-style active fuzzing templates
#   - fuzz / fuzzing    : parameter/header/body fuzzers
#   - intrusive         : templates the nuclei authors flag as intrusive
#   - brute-force       : credential/token brute-forcers
#   - form-fuzz         : form-field fuzzing (POST-heavy)
#   - injection         : injection templates that submit payloads
#   - unauth-write      : community tag for unauth mutating operations
#   - dos               : denial-of-service templates
#
# If the operator legitimately needs to run a write-verb scan (own lab
# environment, ROE explicitly allows it), they can override at the shell
# layer by adding a literal `# harness-allow-writes` comment after the
# nuclei command. That comment is scanned for; when present, the injector
# skips this stage. Never add that override in a SYSTEM_PROMPT — it must
# be an explicit per-invocation opt-in typed by the human.
NUCLEI_SAFE_TAG_EXCLUDES: tuple[str, ...] = (
    "dast", "fuzz", "fuzzing", "intrusive", "brute-force",
    "form-fuzz", "injection", "unauth-write", "dos",
)

# Template IDs proven to write against production targets. Nuclei author-
# provided IDs; extend as new incidents surface. If the LLM emits
# `nuclei -id <blocked-id>` the invocation is rejected with a helpful
# error explaining WHY, so the LLM adapts on the next turn.
NUCLEI_BLOCKED_TEMPLATE_IDS: frozenset[str] = frozenset({
    # WordPress comments-post-based detectors (the Breeze family that
    # triggered this guardrail). Add here any nuclei ID whose template
    # body issues POST /wp-comments-post.php as part of its detection.
    "wordpress-comments-post",
    "wordpress-breeze",
    "wordpress-breeze-lfi",
    # Add more as new incidents surface. Keep this list narrow and cite
    # the incident that motivated each entry.
})

# Sentinel comment the operator can add to a nuclei command to
# opt-out of the auto-inject (their own lab / ROE allows writes).
NUCLEI_ALLOW_WRITES_SENTINEL = "# harness-allow-writes"

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


# N10/PN1 fix (2026-09-04): plumbing-level auto-injection of custom
# headers into HTTP-aware tool invocations. Each entry: tool binary
# → (flag_syntax, join_char).
#   dash-h: repeat `-H "N: V"` per header (curl-family)
#   wpscan: single `--headers "N: V; N2: V2"` (semicolon join)
#   sqlmap: single `--headers="N: V\nN2: V2"` (newline join)
#   header: alias for hakrawler
_HEADER_TOOLS: dict[str, str] = {
    "curl": "dash-h",
    "nuclei": "dash-h",
    "httpx": "dash-h",
    "ffuf": "dash-h",
    "nikto": "dash-h",
    "feroxbuster": "dash-h",
    "dalfox": "dash-h",
    "katana": "dash-h",
    "hakrawler": "dash-h-lower",  # hakrawler uses -h not -H
    "gobuster": "dash-h",
    "wfuzz": "dash-h",
    "wpscan": "wpscan",
    "sqlmap": "sqlmap",
}


def _inject_nuclei_safe_flags(command: str) -> tuple[str, str, str | None]:
    """GUARDRAIL A (2026-09-08) — enforce anti-write-verb defaults on nuclei.

    Walks each pipeline stage; for every stage whose first token is
    `nuclei`, ensures `-exclude-tags` covers `NUCLEI_SAFE_TAG_EXCLUDES`.
    Also refuses any stage that requests a blocked template via `-id`.

    Returns a 3-tuple:
      (new_command, log_note, hard_error_or_None)

    - `new_command`  — the (possibly modified) command string.
    - `log_note`     — one-line human summary of what was auto-added.
                        Empty string when nothing was injected.
    - `hard_error`   — non-None only when the invocation MUST be
                        refused (blocked template ID). Callers should
                        return this string as the tool result so the
                        LLM sees WHY and adapts.

    The operator can bypass the auto-inject on a per-invocation basis by
    appending the sentinel comment `# harness-allow-writes` to the
    command. Never put that sentinel in a SYSTEM_PROMPT — it MUST be a
    human-typed opt-in for lab-only / ROE-authorised runs.
    """
    if not command or not command.strip():
        return command, "", None

    # Operator opt-out sentinel.
    if NUCLEI_ALLOW_WRITES_SENTINEL in command:
        return command, "", None

    stages = _split_pipeline_stages(command)
    if not stages:
        return command, "", None

    notes: list[str] = []
    rebuilt: list[str] = []
    remaining = command
    for stage in stages:
        idx = remaining.find(stage)
        if idx < 0:
            return command, "", None
        prefix = remaining[:idx]
        remaining = remaining[idx + len(stage):]
        try:
            toks = shlex.split(stage)
        except ValueError:
            rebuilt.append(prefix + stage)
            continue
        if not toks or toks[0].lower() != "nuclei":
            rebuilt.append(prefix + stage)
            continue

        # (a) Blocked template ID check.
        for i, t in enumerate(toks):
            if t in ("-id", "--id") and i + 1 < len(toks):
                ids = {x.strip() for x in toks[i + 1].split(",")}
                blocked = ids & NUCLEI_BLOCKED_TEMPLATE_IDS
                if blocked:
                    blocked_str = ", ".join(sorted(blocked))
                    err = (
                        f"ERROR: nuclei -id {blocked_str} is on the "
                        f"harness write-verb blocklist. This template's "
                        f"detection logic issues POST/PUT/DELETE against "
                        f"the target and can persist state (e.g. leaving "
                        f"comments in a WordPress moderation queue as in "
                        f"the 2026-09-08 write-verb incident). If you "
                        f"MUST run this template (own lab / ROE authorises "
                        f"writes), append the literal comment "
                        f"`{NUCLEI_ALLOW_WRITES_SENTINEL}` at the end of "
                        f"the nuclei command line to opt out per-run — "
                        f"but never for a bounty target you do not own. "
                        f"Otherwise use a passive detection alternative "
                        f"(wappalyzer / httpx headers / wpscan --enumerate).")
                    return command, "", err

        # (b) Auto-inject -exclude-tags if missing / incomplete.
        existing_excludes: set[str] = set()
        for i, t in enumerate(toks):
            if t in ("-exclude-tags", "--exclude-tags") and i + 1 < len(toks):
                for x in toks[i + 1].split(","):
                    existing_excludes.add(x.strip())
            elif t.startswith(("-exclude-tags=", "--exclude-tags=")):
                val = t.split("=", 1)[1]
                for x in val.split(","):
                    existing_excludes.add(x.strip())

        required = set(NUCLEI_SAFE_TAG_EXCLUDES)
        missing = required - existing_excludes
        if not missing:
            rebuilt.append(prefix + stage)
            continue

        # Build the merged exclude list. Preserve any existing custom
        # excludes the LLM added intentionally.
        merged = sorted(existing_excludes | required)
        merged_str = ",".join(merged)

        # Rewrite the stage: remove any existing -exclude-tags flag(s)
        # and append a fresh one at the end.
        new_toks: list[str] = []
        i = 0
        while i < len(toks):
            t = toks[i]
            if t in ("-exclude-tags", "--exclude-tags"):
                # skip flag + its argument
                i += 2
                continue
            if t.startswith(("-exclude-tags=", "--exclude-tags=")):
                i += 1
                continue
            new_toks.append(t)
            i += 1
        # Quote the value if it looks safe (no spaces — kebab-case only).
        new_toks.extend(["-exclude-tags", merged_str])
        # Re-join preserving simple quoting; for tokens with special
        # chars, shlex.quote handles it.
        quoted = " ".join(shlex.quote(t) if any(c.isspace() or c in "&|;<>()"
                                                for c in t) else t
                          for t in new_toks)
        rebuilt.append(prefix + quoted)
        added = ",".join(sorted(missing))
        notes.append(f"nuclei stage: injected -exclude-tags {added}")

    rebuilt.append(remaining)
    new_cmd = "".join(rebuilt)
    note = "; ".join(notes) if notes else ""
    return new_cmd, note, None


def _cmd_already_has_header(cmd: str, name: str) -> bool:
    """True if the command line already carries the header `name` in any
    of the supported flag forms."""
    # curl-family: -H "X-Foo: bar"  or  -H 'X-Foo: bar'  or  -H X-Foo:...
    # (case-insensitive check on the header name only)
    lo = cmd.lower()
    n_lo = name.lower()
    for marker in (f"-h \"{n_lo}", f"-h '{n_lo}", f"-h {n_lo}",
                   f"--header \"{n_lo}", f"--header '{n_lo}",
                   f"--header={n_lo}", f"--headers \"{n_lo}",
                   f"--headers '{n_lo}", f"--headers=\"{n_lo}",
                   f"--headers='{n_lo}"):
        if marker in lo:
            return True
    return False


def _inject_headers_into_command(command: str,
                                   headers: dict[str, str]) -> str:
    """Walk each pipeline stage; if the first token is an HTTP-aware
    tool AND the required headers are not already present in that
    stage, append the flag(s) at the end of that stage.

    Never modifies stages whose first token isn't in _HEADER_TOOLS
    (grep/awk/cat/sort/etc stay untouched)."""
    if not headers or not command.strip():
        return command
    stages = _split_pipeline_stages(command)
    if not stages:
        return command
    # Preserve original separators between stages. Rebuild by scanning
    # `command` for the same separators in order.
    rebuilt: list[str] = []
    remaining = command
    for stage in stages:
        # Find this stage in the remaining string (it starts wherever
        # remaining currently starts, modulo leading whitespace).
        idx = remaining.find(stage)
        if idx < 0:
            # Shouldn't happen; play safe and skip transformation
            return command
        prefix = remaining[:idx]
        remaining = remaining[idx + len(stage):]
        try:
            toks = shlex.split(stage)
        except ValueError:
            rebuilt.append(prefix + stage)
            continue
        if not toks:
            rebuilt.append(prefix + stage)
            continue
        first = toks[0].lower()
        syntax = _HEADER_TOOLS.get(first)
        if syntax is None:
            rebuilt.append(prefix + stage)
            continue
        new_stage = _append_headers_to_stage(stage, headers, syntax)
        rebuilt.append(prefix + new_stage)
    rebuilt.append(remaining)  # trailing whitespace / anything after
    return "".join(rebuilt)


def _append_headers_to_stage(stage: str, headers: dict[str, str],
                              syntax: str) -> str:
    """Append missing header flags to a single pipeline stage."""
    additions: list[str] = []
    if syntax in ("dash-h", "dash-h-lower"):
        flag = "-h" if syntax == "dash-h-lower" else "-H"
        for name, value in headers.items():
            if not _cmd_already_has_header(stage, name):
                # Escape any embedded double quotes
                v = str(value).replace('"', '\\"')
                additions.append(f'{flag} "{name}: {v}"')
    elif syntax == "wpscan":
        # wpscan concatenates multiple headers with `; ` under one --headers
        missing = [(n, v) for n, v in headers.items()
                   if not _cmd_already_has_header(stage, n)]
        if missing:
            joined = "; ".join(f"{n}: {v}" for n, v in missing)
            joined = joined.replace('"', '\\"')
            additions.append(f'--headers "{joined}"')
    elif syntax == "sqlmap":
        # sqlmap wants headers joined with an actual newline inside quotes
        missing = [(n, v) for n, v in headers.items()
                   if not _cmd_already_has_header(stage, n)]
        if missing:
            joined = "\\n".join(f"{n}: {v}" for n, v in missing)
            joined = joined.replace('"', '\\"')
            additions.append(f'--headers="{joined}"')
    if not additions:
        return stage
    return stage.rstrip() + " " + " ".join(additions)


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
        # ── Shodan (2026-09-03) ────────────────────────────────────
        # InternetDB (free, no key, no throttle) is ALWAYS available.
        # Pro (https://api.shodan.io/shodan/host/search) requires an API
        # key AND has a per-run throttle to protect the operator's quota.
        shodan_cfg = cfg.get("shodan") or {}
        self.shodan_api_key = str(shodan_cfg.get("api_key") or "").strip()
        if not self.shodan_api_key:
            import os as _os
            env_name = str(shodan_cfg.get("api_key_env")
                           or "SHODAN_API_KEY").strip()
            self.shodan_api_key = _os.environ.get(env_name, "").strip()
        try:
            self.shodan_max_pro_calls = int(
                shodan_cfg.get("max_pro_calls_per_run", 2))
        except (TypeError, ValueError):
            self.shodan_max_pro_calls = 2
        self.shodan_pro_calls_made = 0
        self.shodan_internetdb_enabled = bool(
            shodan_cfg.get("internetdb_enabled", True))
        # 2026-09-03: session-sticky exhaustion flag — set to True when
        # the Shodan API returns 402 (no credits) or an error mentioning
        # quota. Future _shodan_search calls short-circuit to ERROR:
        # exhausted without spending another attempt.
        self.shodan_pro_exhausted = False

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
                "name": "shodan_internetdb",
                "description": (
                    "Query Shodan's free InternetDB service (NO API key, "
                    "no per-account rate limit). Given an IPv4/IPv6 "
                    "address, returns known open ports, CVE ids, tags "
                    "(admin, database, iot, vpn, …) and hostnames. "
                    "Zero-cost passive intel — prefer this over active "
                    "nmap/nuclei when all you need is 'what does this "
                    "host look like from the outside?'. Returns 404 if "
                    "the IP is not indexed by Shodan yet."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string",
                                "description": "IPv4 or IPv6 (no hostname, no port)"},
                    },
                    "required": ["ip"],
                },
            }},
            {"type": "function", "function": {
                "name": "shodan_search",
                "description": (
                    "Query the Shodan Pro search API (paid quota — use "
                    "SPARINGLY). Runs a Shodan dork like "
                    "`http.favicon.hash:-1234567890`, `org:\"Acme Corp\"`, "
                    "`ssl.jarm:xxx`, `product:jenkins country:US`. Only "
                    "useful for pivots that InternetDB cannot answer (asset "
                    "discovery by favicon, JARM fingerprint, org filter, "
                    "cert SAN, …). The harness enforces a MAX of N calls "
                    "per run (config.shodan.max_pro_calls_per_run, default "
                    "2) to protect the operator's quota. Returns ERROR if "
                    "no API key is configured — fall back to shodan_internetdb "
                    "in that case."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string",
                                   "description": "Shodan dork syntax"},
                        "limit": {"type": "integer",
                                   "description": "Max hits (1-20, default 5)"},
                    },
                    "required": ["query"],
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
            if name == "shodan_internetdb":
                return self._shodan_internetdb(args.get("ip", ""))
            if name == "shodan_search":
                return self._shodan_search(
                    args.get("query", ""),
                    args.get("limit", 5))
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

    # PN9 reinforce (2026-09-04): the web_vuln prompt already lists techs
    # that have no server-side CVE templates in nuclei-templates and asks
    # the LLM not to combine `cve,<tech>` with them, but in run 20260903T234439Z
    # the LLM still emitted `-tags cve,cloudflare` and 4 other zero-hit
    # scans that burnt ~5 min. Backstop at the shell level: intercept any
    # nuclei call whose -tags includes `cve` combined with a known non-
    # scannable tech, and short-circuit with a clear ERROR — the LLM sees
    # the reason and moves on without spending nuclei time.
    _NUCLEI_NON_SCANNABLE_TAGS = {
        # CDNs / edge
        "cloudflare", "akamai", "fastly", "cloudfront",
        # trackers / analytics
        "google-tag-manager", "google-analytics", "facebook-pixel",
        "hotjar", "segment", "mixpanel", "amplitude",
        # frontend CSS/font libs
        "font-awesome", "bootstrap", "materialize",
        # frontend JS libs with no server surface
        "jquery-migrate", "fitvids.js", "fitvids", "easy-pie-chart",
        # transport / protocol markers
        "hsts", "http/3", "http-2", "http-3",
    }

    def maybe_reject_nuclei_scan(self, command: str) -> str:
        """Return an ERROR reason string if this command is a `nuclei -tags
        cve,<blocked>` scan, else empty string. Called from `_shell` before
        execution. Fires under two conditions:

        (a) `cve` is combined with at least one non-scannable tech (CDN /
            tracker / frontend lib — see `_NUCLEI_NON_SCANNABLE_TAGS`).
        (b) PN9 refuerzo iter 8 (2026-09-04): `cve` is combined with MORE
            THAN 3 tech tags. Iter 7 saw the LLM emit
              `-tags cve,joomla,drupal,magento,adminer,nginx,apache,iis,
                    tomcat,jboss,weblogic,spring,symfony,laravel,django,
                    rails,express,nodejs,portainer,traefik,minio,elasti…`
            (26+ frameworks) against a WordPress+PHP target — pure
            scan-everything panic that burnt ~5 min for 0 findings. If
            the LLM combines `cve` with more than 3 techs, it's ruse-fire,
            not targeted enumeration → reject with a hint to narrow down.

        Plain `-tags <tech>` without `cve` is always allowed (some tech-
        detect templates are legitimately broad)."""
        low = command.lower().strip()
        if not low.startswith("nuclei"):
            return ""
        # PN15 iter 9 (2026-09-04): detect `-tags "Apache HTTP Server"` /
        # `-tags cve,apache http server` — the LLM sometimes copies a
        # display name (from fingerprint) into `-tags` without kebab-case
        # normalizing it. Nuclei then either (a) sees multiple positional
        # args instead of one tag list, or (b) matches nothing because
        # the actual template tag is `apache-http-server`. Either way,
        # scan budget burnt for 0 hits. Detect by shlex-parsing and
        # counting non-flag tokens right after `-tags` — 2+ = space bug.
        import shlex as _shlex
        try:
            toks = _shlex.split(command)
        except ValueError:
            toks = []
        i = 0
        while i < len(toks):
            t = toks[i]
            if t in ("-tags", "--tags") and i + 1 < len(toks):
                extras: list[str] = []
                j = i + 1
                while j < len(toks) and not toks[j].startswith("-"):
                    extras.append(toks[j])
                    j += 1
                if len(extras) > 1:
                    joined = " ".join(extras)
                    return (f"ERROR: nuclei -tags received multiple "
                            f"space-separated tokens ({joined!r}). Nuclei "
                            f"expects one kebab-case slug or a comma-"
                            f"joined list — NO spaces. Convert display "
                            f"names to slugs: 'Apache HTTP Server' → "
                            f"'apache-http-server', 'Google Tag Manager' → "
                            f"'google-tag-manager', 'jQuery Migrate' → "
                            f"'jquery-migrate'. Also strip any `:version` "
                            f"suffix (`php:8.4.24` → `php`). Retry with "
                            f"the normalised tag(s).")
                i = j
                continue
            if t.startswith(("-tags=", "--tags=")) and " " in t:
                bad = t.split("=", 1)[1]
                return (f"ERROR: nuclei -tags= value {bad!r} contains a "
                        f"space. Nuclei tag names are kebab-case slugs — "
                        f"no spaces. Convert 'Apache HTTP Server' → "
                        f"'apache-http-server'. Retry with the "
                        f"normalised tag.")
            i += 1
        # Extract the value of -tags <val> or --tags <val>
        import re as _re
        m = _re.search(r"(?:-tags|--tags)[= ]+([\w,\-.]+)", low)
        if not m:
            return ""
        tags = set(t.strip() for t in m.group(1).split(","))
        if "cve" not in tags:
            return ""
        # (a) blocked-list gate
        blocked = tags & self._NUCLEI_NON_SCANNABLE_TAGS
        if blocked:
            blocked_str = ", ".join(sorted(blocked))
            return (f"ERROR: nuclei -tags cve,{blocked_str} rejected — "
                    f"{blocked_str} has no server-side CVE templates in "
                    f"nuclei-templates (CDN/tracker/frontend lib). Waste of "
                    f"scan budget. Move to a different tech or drop the `cve` "
                    f"tag if you only want tech-detect templates.")
        # (b) broad-combination gate — PN9 refuerzo iter 8 (2026-09-04).
        # "cve" itself doesn't count as a tech tag; only the non-cve tags
        # are counted for the threshold.
        tech_tags = tags - {"cve"}
        if len(tech_tags) > 3:
            preview = ", ".join(sorted(tech_tags)[:6])
            more = (f" (+{len(tech_tags) - 6} more)"
                    if len(tech_tags) > 6 else "")
            return (f"ERROR: nuclei -tags cve combined with {len(tech_tags)} "
                    f"tech tags ({preview}{more}) rejected — combining `cve` "
                    f"with more than 3 tech tags is a scan-everything panic, "
                    f"not targeted enumeration. Nuclei loads a template set "
                    f"per tag; combining 26 frameworks against one target "
                    f"burns budget for near-zero hit rate. Narrow to the "
                    f"1-3 techs that actually fingerprint on this target "
                    f"(see 'Techs detected' in the user message).")
        return ""

    def maybe_inject_headers(self, command: str) -> tuple[str, str]:
        """Return (new_command, note). If custom_headers apply to any
        stage of `command` and the header is not already present, insert
        the flag with the tool's specific syntax and return the modified
        command + a one-line note describing what was added. Otherwise
        return the input untouched with an empty note.

        Exposed as a public method so `BaseAgent._record_tool_activity`
        can log the FINAL command bash actually ran, not the LLM's
        original (N10 visibility fix, 2026-09-04). The injection itself
        was already implemented in `_shell` in the previous iteration —
        this method centralises it and returns a machine-readable diff."""
        if not self.custom_headers:
            return command, ""
        new_cmd = _inject_headers_into_command(command, self.custom_headers)
        if new_cmd == command:
            return command, ""
        # Diff: everything appended (naive — the injector always appends
        # at the end of each modified stage). Keep it short for the log.
        note = ("[harness-inject] added header(s): "
                + ", ".join(f'{n}: {v}' for n, v in
                            self.custom_headers.items()))
        return new_cmd, note

    def maybe_inject_nuclei_safe_flags(
        self, command: str
    ) -> tuple[str, str, str | None]:
        """GUARDRAIL A (2026-09-08) — public method paired with
        `maybe_inject_headers`. Returns (new_command, log_note,
        hard_error). If `hard_error` is non-None, the invocation was
        rejected outright (blocked template ID) and the caller should
        surface the error to the LLM without executing the command.

        Wraps `_inject_nuclei_safe_flags` (module-level) plus a state
        counter update so `report.py` can render the meta-check
        `(o) unauthorized_write_verb_detected` when a nuclei stage
        actually needed injection.
        """
        new_cmd, note, err = _inject_nuclei_safe_flags(command)
        if err and self.state is not None:
            try:
                prev = int(self.state.get(
                    "nuclei_blocked_template_hits", 0) or 0)
                self.state.set("nuclei_blocked_template_hits", prev + 1)
            except Exception:
                pass
        if note and self.state is not None:
            try:
                prev = int(self.state.get(
                    "nuclei_safe_injection_count", 0) or 0)
                self.state.set("nuclei_safe_injection_count", prev + 1)
            except Exception:
                pass
        # Human-readable log line prefix matches `maybe_inject_headers`
        # so grepping tool-activity output stays consistent.
        readable = (f"[harness-inject-guardrail-A] {note}"
                    if note else "")
        return new_cmd, readable, err

    def _shell(self, command: str) -> str:
        if not command or not command.strip():
            return "ERROR: empty command"

        # PN9 reinforce (2026-09-04): reject `nuclei -tags cve,<blocked>`
        # scans before spending nuclei runtime on them. Returns the
        # rejection reason so the LLM sees WHY and adapts on next turn.
        _rej = self.maybe_reject_nuclei_scan(command)
        if _rej:
            return _rej

        # GUARDRAIL A (2026-09-08) — auto-inject -exclude-tags on every
        # nuclei stage lacking the write-verb exclusions, and refuse any
        # nuclei -id request for a template on the write-verb blocklist.
        # See NUCLEI_SAFE_TAG_EXCLUDES / NUCLEI_BLOCKED_TEMPLATE_IDS above
        # and the incident narrative that motivated them. The mutation
        # is safety-net only: BaseAgent already calls
        # `maybe_inject_nuclei_safe_flags` BEFORE dispatch so the tool
        # activity log records the FINAL command. This block catches any
        # caller that reaches `_shell` directly without going through
        # the agent loop.
        command, _nuc_note, _nuc_err = _inject_nuclei_safe_flags(command)
        if _nuc_err:
            # Record for meta-check + return so LLM adapts.
            if self.state is not None:
                try:
                    self.state.set("nuclei_blocked_template_hit", True)
                except Exception:
                    pass
            return _nuc_err
        if _nuc_note and self.state is not None:
            try:
                # Count so report.py meta-check can surface it.
                prev = int(self.state.get("nuclei_safe_injection_count", 0)
                           or 0)
                self.state.set("nuclei_safe_injection_count", prev + 1)
            except Exception:
                pass

        # Header injection is now performed BEFORE dispatch (see
        # `maybe_inject_headers` and BaseAgent._process_tool_call).
        # Kept as safety net for callers that reach `_shell` directly
        # without going through the agent loop (rare).
        if self.custom_headers:
            command = _inject_headers_into_command(command,
                                                    self.custom_headers)

        # Hard denylist first — always wins.
        lower_cmd = " " + command.lower() + " "
        for bad in SHELL_HARD_DENY:
            if bad.lower() in lower_cmd:
                return (f"ERROR: forbidden token '{bad.strip()}' in command "
                        "(hard denylist — no bypass)")
        # Word-boundary flag denylist (2026-09-03): protects against false
        # positives when a forbidden flag substring appears inside a legit
        # path or a longer flag. Uses lookaround so `-sU` matches only when
        # bounded by whitespace/end, NOT inside `-subfinder`.
        import re as _re_deny
        for flag in SHELL_HARD_DENY_FLAGS:
            escaped = _re_deny.escape(flag)
            pattern = rf"(?<![\w\-]){escaped}(?![\w\-])"
            if _re_deny.search(pattern, command, _re_deny.IGNORECASE):
                return (f"ERROR: forbidden flag '{flag}' in command "
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
                # C1 fix (2026-09-08) — surface a more actionable hint
                # when the LLM tries the common `while read x; do …;
                # done` idiom. `while` is blocked (bash loops can run
                # forever); the intended replacement is `xargs -I{}`
                # which is already allowlisted and doesn't loop.
                if first in ("while", "until", "for"):
                    return (f"ERROR: '{first}' loops are not in the "
                            f"shell allowlist (they can run forever if "
                            f"the loop body hangs). Use `xargs -I{{}}` "
                            f"instead — it iterates over stdin lines "
                            f"with a hard per-line command timeout "
                            f"managed by the harness. Example:\n"
                            f"  cat /tmp/hosts.txt | xargs -I{{}} "
                            f"dig +short {{}} A\n"
                            f"is the drop-in replacement for:\n"
                            f"  cat /tmp/hosts.txt | while read h; do "
                            f"dig +short $h A; done\n"
                            f"xargs stops on the shell_timeout_sec cap "
                            f"and reports rows individually.")
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

    # ── Shodan ─────────────────────────────────────────────────
    def _shodan_internetdb(self, ip: str) -> str:
        """Query Shodan InternetDB — free, no key, no throttle.

        Endpoint: https://internetdb.shodan.io/<ip>
        Returns JSON {ip, ports, cpes, hostnames, tags, vulns} for
        indexed IPs, or 404 for uncovered ones (~9M IPs in Shodan).
        """
        if not self.shodan_internetdb_enabled:
            return ("ERROR: shodan_internetdb disabled in config "
                    "(shodan.internetdb_enabled=false).")
        if not ip or not ip.strip():
            return "ERROR: empty IP"
        ip = ip.strip()
        import ipaddress as _ip
        try:
            _ip.ip_address(ip)
        except ValueError:
            return (f"ERROR: '{ip}' is not a valid IP. This tool takes "
                    "an IP; resolve a hostname first (dig +short A <host>).")
        self.limiter.wait()
        try:
            r = requests.get(f"https://internetdb.shodan.io/{ip}",
                              timeout=self.http_timeout)
        except requests.RequestException as e:
            return f"ERROR: InternetDB request failed: {type(e).__name__}: {e}"
        if r.status_code == 404:
            return (f"InternetDB: no data for {ip} "
                    "(IP not indexed by Shodan — internal, dark, or new).")
        if r.status_code != 200:
            return f"InternetDB: HTTP {r.status_code} for {ip}"
        return f"InternetDB {ip}:\n{r.text[:4096]}"

    def _shodan_search(self, query: str, limit=5) -> str:
        """Query Shodan Pro search API — quota-protected + exhaustion-sticky.

        Enforces max_pro_calls_per_run so the LLM can't blast the paid
        quota. Requires shodan.api_key (or env $SHODAN_API_KEY).

        2026-09-03: adds session-sticky exhaustion detection. When the API
        returns 402 (no credits) or an error mentioning quota, subsequent
        calls this session short-circuit to ERROR without spending another
        attempt — the LLM sees the situation clearly and falls back to
        InternetDB (free).
        """
        if not query or not str(query).strip():
            return "ERROR: empty Shodan query"
        if not self.shodan_api_key:
            return ("ERROR: Shodan Pro API key not configured. Set "
                    "shodan.api_key in config.yaml (or export "
                    "$SHODAN_API_KEY) to enable Pro search. Meanwhile "
                    "shodan_internetdb (free) is still available.")
        if self.shodan_pro_exhausted:
            return ("ERROR: Shodan Pro credits exhausted (detected on an "
                    "earlier call this session — quota locked until it "
                    "resets or you top up at https://account.shodan.io). "
                    "Use shodan_internetdb (free, no quota) as fallback.")
        if self.shodan_pro_calls_made >= self.shodan_max_pro_calls:
            return (f"ERROR: Shodan Pro throttle exhausted for this run "
                    f"({self.shodan_pro_calls_made}/"
                    f"{self.shodan_max_pro_calls} calls used). Raise "
                    "shodan.max_pro_calls_per_run in config.yaml if this "
                    "run truly needs more Pro calls.")
        try:
            lim = int(limit) if limit else 5
        except (TypeError, ValueError):
            lim = 5
        lim = max(1, min(20, lim))
        self.limiter.wait()
        try:
            r = requests.get("https://api.shodan.io/shodan/host/search",
                              params={"key": self.shodan_api_key,
                                      "query": str(query), "limit": lim},
                              timeout=self.http_timeout)
        except requests.RequestException as e:
            return f"ERROR: Shodan Pro request failed: {type(e).__name__}: {e}"
        self.shodan_pro_calls_made += 1
        if r.status_code == 401:
            return ("ERROR: Shodan API 401 — key rejected. "
                    "Verify config.shodan.api_key.")
        if r.status_code == 402:
            # No credits — mark exhausted for the rest of the session
            self.shodan_pro_exhausted = True
            if self.state:
                try:
                    self.state.set("shodan_pro_exhausted", True)
                except Exception:
                    pass
            return ("ERROR: Shodan API 402 — Pro credits exhausted "
                    "(monthly query quota reached). Subsequent Pro calls "
                    "this session are short-circuited. Use "
                    "shodan_internetdb (free) or top up at "
                    "https://account.shodan.io.")
        if r.status_code == 429:
            return ("ERROR: Shodan API 429 — rate-limited by the "
                    "provider itself (not our throttle).")
        if r.status_code != 200:
            # Some Shodan errors return 200 or 400 with JSON body mentioning
            # quota. Detect the quota marker in the response body too.
            body_low = r.text[:400].lower()
            if any(m in body_low for m in
                   ("no query credits", "query credits available",
                    "insufficient credits", "credits available",
                    "monthly query limit", "quota exceeded")):
                self.shodan_pro_exhausted = True
                if self.state:
                    try:
                        self.state.set("shodan_pro_exhausted", True)
                    except Exception:
                        pass
                return ("ERROR: Shodan API reports credits exhausted "
                        f"(HTTP {r.status_code}). Session-locked. "
                        "Fallback to shodan_internetdb.")
            return f"ERROR: Shodan API HTTP {r.status_code}: {r.text[:400]}"
        # HTTP 200 — even on 200 the response body can carry an error field
        # in some deprecated endpoints. Check for quota marker in body:
        body_low = r.text[:400].lower()
        if any(m in body_low for m in
               ("no query credits", "query credits available",
                "insufficient credits", "monthly query limit")):
            self.shodan_pro_exhausted = True
            if self.state:
                try:
                    self.state.set("shodan_pro_exhausted", True)
                except Exception:
                    pass
            return ("ERROR: Shodan API returned quota-exhausted marker "
                    "in 200 body. Session-locked. Fallback to "
                    "shodan_internetdb.")
        try:
            data = r.json()
            matches = data.get("matches", []) or []
            total = data.get("total", len(matches))
            slim = [{
                "ip_str": m.get("ip_str"),
                "port": m.get("port"),
                "hostnames": m.get("hostnames", []) or [],
                "org": m.get("org"),
                "product": m.get("product"),
                "os": m.get("os"),
                "country": (m.get("location") or {}).get("country_name"),
                "asn": m.get("asn"),
                "http_title": (m.get("http") or {}).get("title"),
                "cpes": m.get("cpe", []) or [],
                "vulns": list((m.get("vulns") or {}).keys()) if isinstance(
                    m.get("vulns"), dict) else (m.get("vulns") or []),
            } for m in matches[:lim]]
            import json as _j
            return (f"Shodan search {query!r} — total={total}, "
                    f"showing {len(slim)}. "
                    f"Pro quota used {self.shodan_pro_calls_made}/"
                    f"{self.shodan_max_pro_calls}:\n"
                    f"{_j.dumps(slim, indent=2)[:6000]}")
        except Exception as e:
            return f"ERROR: parse failed: {type(e).__name__}: {e}"

    def _oob_token(self, vector: str, label: str) -> str:
        if not self.oob_host:
            return ("ERROR: oob_host not configured in config.yaml. "
                    "Set oob_host to your self-hosted OOB catcher domain.")
        token = f"{self.oob_token_prefix}-{vector}-{label}"[:64]
        url = f"https://{self.oob_host}/oob/{token}"
        return (f"OOB token URL: {url}\n"
                "Use this in blind payloads (SSRF/XXE/XSS). Check the panel "
                "for hits.")
