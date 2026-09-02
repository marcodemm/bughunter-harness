"""Extension framework — drop-in agents, tools and techniques.

Extensions live under `extensions/` (a sibling of harness.py). Three types:

  extensions/agents/<name>.py      → any subclass of BaseAgent is
                                     auto-registered in the pipeline
                                     (ordered via `ENTRY_AFTER` class attr).

  extensions/tools/<name>.yaml     → adds a binary to the shell allowlist,
                                     with an install_hint and a prompt_hint
                                     that gets injected into agent system
                                     prompts so the model knows to call it.

  extensions/techniques/<name>.md  → knowledge base with YAML frontmatter.
                                     Loaded into an agent's system prompt
                                     ONLY when the current context matches
                                     the frontmatter's `applies_when` rules.

Extensions are pure additions: they never modify or shadow core behavior.
A malformed extension is logged and skipped — never crashes the pipeline.

────────────────────────────────────────────────────────────────────────
Adding a new AGENT — minimum viable:
    # extensions/agents/my_takeover.py
    from agents.base import BaseAgent
    class TakeoverAgent(BaseAgent):
        NAME = "takeover"
        DESCRIPTION = "Subdomain takeover check"
        ENTRY_AFTER = "recon"         # insert right after `recon`
        TOOL_NAMES = ["run_shell", "finish"]
        SYSTEM_PROMPT = "..."
        def entry_condition(self, state):
            return bool(state.get("subdomains"))

Adding a new TOOL — minimum viable:
    # extensions/tools/subjack.yaml
    binary: subjack
    install_hint: "go install github.com/haccer/subjack@latest"
    prompt_hint: |
      For subdomain takeover, use:
        subjack -w subs.txt -t 20 -timeout 30 -ssl -v -c fingerprints.json

Adding a new TECHNIQUE — minimum viable:
    # extensions/techniques/prototype-pollution.md
    ---
    name: prototype-pollution
    loaded_by_agents: [web_vuln, api_fuzzer]
    applies_when:
      detected_techs: [nodejs, express, lodash]
    ---
    # Prototype Pollution
    Payload: `?__proto__[polluted]=yes` then check `/api/status`...
"""
from __future__ import annotations

import fnmatch
import importlib.util
import inspect
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None


# ── discovery ──────────────────────────────────────────────────────

def discover_agents(extensions_dir: Path) -> list[type]:
    """Import every extensions/agents/*.py and return the BaseAgent subclasses
    it defines, in filesystem order."""
    agents_dir = extensions_dir / "agents"
    if not agents_dir.is_dir():
        return []
    try:
        from agents.base import BaseAgent
    except Exception:
        return []
    discovered: list[type] = []
    for py in sorted(agents_dir.glob("*.py")):
        if py.name.startswith("_"):
            continue
        try:
            mod_name = f"extensions_agents_{py.stem}"
            spec = importlib.util.spec_from_file_location(mod_name, py)
            if not spec or not spec.loader:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, BaseAgent) and obj is not BaseAgent:
                    if obj.__module__ == mod_name:  # defined here, not imported
                        discovered.append(obj)
        except Exception as e:
            _warn(f"extension agent {py.name} skipped: "
                  f"{type(e).__name__}: {e}")
    return discovered


def discover_tools(extensions_dir: Path) -> list[dict]:
    """Parse extensions/tools/*.yaml → list of tool spec dicts. Each dict has:
      binary       (str, required)  — the executable name
      install_hint (str)            — how to install it
      prompt_hint  (str)            — how the model should use it
      require_installed (bool)      — if True, skip the agent step when
                                       binary is not on PATH
      _source      (str)            — origin filename (auto)"""
    tools_dir = extensions_dir / "tools"
    if not tools_dir.is_dir():
        return []
    if yaml is None:
        _warn("PyYAML not installed — extensions/tools/*.yaml ignored")
        return []
    specs: list[dict] = []
    for y in sorted(tools_dir.glob("*.yaml")) + sorted(tools_dir.glob("*.yml")):
        try:
            data = yaml.safe_load(y.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict) or not data.get("binary"):
                _warn(f"extension tool {y.name} missing 'binary:' key — skipped")
                continue
            data["_source"] = y.name
            specs.append(data)
        except Exception as e:
            _warn(f"extension tool {y.name} skipped: {type(e).__name__}: {e}")
    return specs


def discover_techniques(extensions_dir: Path) -> list[dict]:
    """Parse extensions/techniques/*.md with YAML frontmatter. Each dict has:
      name              (str)          — technique slug
      loaded_by_agents  (list[str])    — agents allowed to load it, ["*"]=all
      applies_when      (dict)         — matching rules:
        detected_techs  (list[str])    — at least one must be in state.detected_techs
        endpoints_match (list[str])    — fnmatch globs (any-match)
      severity_hint     (str)          — informational only
      _body             (str)          — the markdown content after frontmatter
      _source           (str)          — origin filename"""
    tech_dir = extensions_dir / "techniques"
    if not tech_dir.is_dir():
        return []
    techniques: list[dict] = []
    for md in sorted(tech_dir.glob("*.md")):
        try:
            text = md.read_text(encoding="utf-8")
            frontmatter, body = _split_frontmatter(text)
            frontmatter["_body"] = body
            frontmatter["_source"] = md.name
            frontmatter.setdefault("name", md.stem)
            techniques.append(frontmatter)
        except Exception as e:
            _warn(f"extension technique {md.name} skipped: "
                  f"{type(e).__name__}: {e}")
    return techniques


# ── selection / rendering ──────────────────────────────────────────

def techniques_applicable_for(techniques: list[dict], agent_name: str,
                                detected_techs: list[str],
                                endpoints: list[str] | None = None
                                ) -> list[dict]:
    """Filter techniques whose frontmatter matches the current context."""
    detected_low = [str(t).lower() for t in (detected_techs or [])]
    endpoints = endpoints or []
    matched: list[dict] = []
    for tech in techniques:
        # (a) agent gate — if `loaded_by_agents` set, agent_name must be in it
        loaded_by = tech.get("loaded_by_agents")
        if loaded_by:
            allowed = [str(a) for a in loaded_by]
            if agent_name not in allowed and "*" not in allowed:
                continue
        aw = tech.get("applies_when") or {}
        # (b) detected_techs gate — at least one required tech must be seen
        required_techs = [str(t).lower() for t in (aw.get("detected_techs") or [])]
        if required_techs and not any(rt in detected_low for rt in required_techs):
            continue
        # (c) endpoints gate — at least one endpoint must match a pattern
        required_endpoints = aw.get("endpoints_match") or []
        if required_endpoints:
            hit = any(fnmatch.fnmatch(ep, pat)
                      for ep in endpoints for pat in required_endpoints)
            if not hit:
                continue
        matched.append(tech)
    return matched


def render_techniques_for_prompt(techniques: list[dict],
                                   max_chars_per_tech: int = 2000,
                                   max_total_chars: int = 8000) -> str:
    """Render matched techniques as a formatted block for the system prompt."""
    if not techniques:
        return ""
    lines = [
        "",
        "",
        "APPLICABLE TECHNIQUES (extensions/techniques/ — loaded because "
        "the current target context matches their `applies_when` rules)",
        "Use these as playbooks. Each one is distilled from real reports.",
        "",
    ]
    total = sum(len(l) for l in lines)
    for t in techniques:
        name = t.get("name", "unnamed")
        source = t.get("_source", "")
        body = (t.get("_body", "") or "")[:max_chars_per_tech]
        block = (f"── Technique: {name}  (from {source})\n"
                 f"{body}\n")
        if total + len(block) > max_total_chars:
            lines.append(f"[…{len(techniques)-len(lines)} more techniques "
                          f"omitted due to prompt budget]")
            break
        lines.append(block)
        total += len(block)
    return "\n".join(lines)


def render_tools_hint_for_prompt(tools: list[dict]) -> str:
    """Combine all extension tools' prompt_hint into one system-prompt block."""
    if not tools:
        return ""
    lines = ["",
             "",
             "EXTENSION TOOLS (extensions/tools/ — additional binaries "
             "available in run_shell allowlist):",
             ""]
    for spec in tools:
        binary = spec.get("binary", "?")
        hint = spec.get("prompt_hint", "").strip()
        if hint:
            lines.append(f"── {binary}")
            lines.append(hint)
            lines.append("")
    return "\n".join(lines)


# ── helpers ────────────────────────────────────────────────────────

def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Extract YAML frontmatter between --- lines. Returns ({}, body) if none."""
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    fm_raw = parts[1]
    body = parts[2].lstrip("\n")
    try:
        fm = (yaml.safe_load(fm_raw) if yaml else {}) or {}
        if not isinstance(fm, dict):
            fm = {}
    except Exception:
        fm = {}
    return fm, body


def _warn(msg: str) -> None:
    try:
        print(f"[extension_loader] {msg}")
    except Exception:
        pass
