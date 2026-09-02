# Extending Bughunter Harness

Bughunter Harness ships with a three-slot **extension framework** — drop a
file into `extensions/`, restart the harness, and it is live. No core
changes, no plugin registration, no rebuild.

There are three types of extension. They are additive: dropping one never
alters the behaviour of the built-ins, and a malformed extension is logged
and skipped, never crashes the pipeline.

```
extensions/
├── agents/          # (1) new agents in the pipeline
├── tools/           # (2) new binaries in the shell allowlist
└── techniques/      # (3) knowledge base loaded into agents by context
```

Toggle the entire framework with `config.yaml → extensions.enabled` (default
`true`). Add lookup directories with `extensions.extra_dirs: ["/opt/x"]`.

---

## (1) Agents — `extensions/agents/*.py`

Any subclass of `BaseAgent` in a file under `extensions/agents/` is
auto-discovered and spliced into the pipeline. Position is controlled by
the class attribute `ENTRY_AFTER = "recon"` (or any other built-in agent
NAME). Agents without `ENTRY_AFTER` run right before `report`.

**Minimum viable example** — see [`extensions/agents/example_takeover.py`](extensions/agents/example_takeover.py):

```python
from agents.base import BaseAgent

class TakeoverAgent(BaseAgent):
    NAME = "takeover"
    DESCRIPTION = "Subdomain takeover check"
    ENTRY_AFTER = "recon"                    # position in pipeline
    TOOL_NAMES = ["run_shell", "finish"]     # which tools this agent may call
    SYSTEM_PROMPT = "..."                    # the model's instructions

    def entry_condition(self, state) -> bool:
        return bool(state.get("subdomains"))

    def build_objective(self, state) -> str:
        return "..."                          # the first user turn

    def after_run(self, state, transcript):
        pass                                  # parse tool outputs → findings
```

The example takeover agent parses `subjack` output into structured findings
with recommendation text. Copy it, rename the class + NAME, edit the
`SYSTEM_PROMPT` and `after_run` for your own tool, and you have a new
pipeline stage in under 30 lines.

**Gotchas**

- The `NAME` must be unique across the pipeline. Colliding with a built-in
  agent name silently overrides nothing — both run.
- If the agent's `entry_condition(state)` returns `False`, it is skipped
  quietly (marked "skipped" in the run log). Use this to keep your agent
  from firing on irrelevant targets.
- Errors inside your agent are caught by the orchestrator and reported —
  they do not abort the run.

---

## (2) Tools — `extensions/tools/*.yaml`

A YAML file registers a new binary with the shell allowlist and gives the
agents a **prompt hint** so the model knows when and how to use it via
`run_shell`.

**Minimum viable example** — see [`extensions/tools/example_subjack.yaml`](extensions/tools/example_subjack.yaml):

```yaml
binary: subjack
install_hint: "go install github.com/haccer/subjack@latest"
require_installed: false             # if true, agent step skipped when missing
prompt_hint: |
  For subdomain takeover, use:
    subjack -w subs.txt -t 20 -timeout 30 -ssl -v -c fingerprints.json
  Output: "[Vulnerable] sub.example.com -> unclaimed.s3.amazonaws.com"
output_parser: 'regex:\[Vulnerable\]\s+(?P<sub>\S+)\s+->\s+(?P<target>\S+)'
finding_template:
  severity: critical
  title: "Subdomain takeover: {sub} → {target}"
  recommendation: "Remove the dangling CNAME OR reclaim the resource."
```

Only `binary` is required; everything else is optional context that
propagates into the agents' system prompts.

**Where it lands at runtime**

- `SHELL_ALLOWLIST` gains the `binary` name — the harness's shell gate
  will now let agents call it.
- Every agent's system prompt receives an **EXTENSION TOOLS** block with
  each `prompt_hint` concatenated, so the model knows the tool exists and
  how to shape the command line.
- The `output_parser` + `finding_template` are advisory — you still write
  custom `after_run` parsing in your agent for anything non-trivial.

---

## (3) Techniques — `extensions/techniques/*.md`

Markdown files with YAML frontmatter. Loaded into an agent's prompt **only
when the current target context matches** the `applies_when` rules.

**Minimum viable example** — see [`extensions/techniques/example_prototype_pollution.md`](extensions/techniques/example_prototype_pollution.md):

```markdown
---
name: prototype-pollution
description: "Detection + PoC for Node/Express/Lodash prototype pollution."
severity_hint: high
loaded_by_agents: [web_vuln, api_fuzzer]   # or ["*"] for every agent
applies_when:
  detected_techs: [nodejs, express, lodash]
  endpoints_match: ["**/api/**", "**/graphql*"]
---

# Prototype Pollution — how to test
## Sources
...
## Payload
...
## PoC scaffolding
...
## Impact classification
...
```

**Matching rules**

A technique loads into the current agent's prompt if **ALL** of the below
hold — any missing key is not enforced:

- `loaded_by_agents` — the current agent's `NAME` must be in the list, OR
  the list contains `"*"`.
- `applies_when.detected_techs` — at least ONE listed tech must appear in
  `state.detected_techs` (case-insensitive substring match).
- `applies_when.endpoints_match` — at least ONE listed fnmatch glob must
  match at least one discovered endpoint URL.

The frontmatter is optional. A technique file with no frontmatter is
loaded for every agent, every context — use sparingly.

**The body** is markdown you write yourself. The exact same format as a
bug-bounty technique write-up you would keep in your own notes:
sources → sinks → payload → PoC → impact → fix. The model will follow
the playbook when the context lights it up.

---

## Loading order + errors

At startup the harness:

1. Reads `config.yaml → extensions.enabled` (default `true`).
2. Discovers `extensions/agents/*.py`, `extensions/tools/*.yaml`,
   `extensions/techniques/*.md` in the harness root AND every
   `extensions.extra_dirs` entry.
3. Splices agents into `AGENT_ORDER` per each class's `ENTRY_AFTER`.
4. Extends `SHELL_ALLOWLIST` with each tool's `binary`.
5. Caches techniques for per-agent injection at prompt-build time.

Errors during discovery are printed as `[extension_loader] skipped X: ...`
and the offending extension is ignored — the pipeline continues.

---

## Testing your extension without a full pipeline run

**Agents** — write a small script that pre-seeds a `SharedState` with
`subdomains`, `live_hosts`, `endpoints_found` and instantiates the agent
directly. See `agents/login_probe.py` and the smoke test used during its
development for a template — no LLM required if you override `run()`.

**Tools** — inspect the compiled prompt hint block:

```python
from tools import ToolRegistry
from scope import ScopeChecker
from throttle import RateLimiter
r = ToolRegistry(ScopeChecker(patterns=["localhost"]),
                 RateLimiter(min_interval_sec=0.5),
                 {"scope_enforcement": "off"})
print(r.extension_tools_prompt_hint())
```

**Techniques** — check which techniques match a synthetic context:

```python
import extension_loader
from pathlib import Path
techs = extension_loader.discover_techniques(Path("extensions"))
applicable = extension_loader.techniques_applicable_for(
    techs, agent_name="web_vuln",
    detected_techs=["nodejs", "express"],
    endpoints=["https://api.example.com/v1/users"])
print([t["name"] for t in applicable])
```

---

## Sharing extensions

Extensions are pure files with no coupling to your local setup. To share
one:

- Zip `extensions/agents/your_thing.py` (and its tool/technique
  companions).
- The recipient drops the files under their own `extensions/` and the next
  run picks them up.

For heavier reuse across teams, point `extensions.extra_dirs` at a shared
directory (e.g. `/opt/team-extensions/`) that lives in a git repo or a
network share.
