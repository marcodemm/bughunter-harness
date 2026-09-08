"""LLM backend detection and resolution.

Supports seven OpenAI-compatible servers:

  LOCAL (auto-probed in order, no API key needed):
    lmstudio   http://127.0.0.1:1234/v1
    ollama     http://127.0.0.1:11434/v1
    llamacpp   http://127.0.0.1:8080/v1

  CLOUD (never auto-probed; requires --servertype + api_key + $$$):
    openai     https://api.openai.com/v1                              (OPENAI_API_KEY)
    anthropic  https://api.anthropic.com/v1                           (ANTHROPIC_API_KEY)
    nvidia     https://integrate.api.nvidia.com/v1                    (NVIDIA_API_KEY)
    gemini     https://generativelanguage.googleapis.com/v1beta/openai (GEMINI_API_KEY)

Resolution order (highest precedence first):
  1. CLI/REPL flags: --base-url, --servertype, --model
  2. config.yaml -> llm.*  (base_url / servertype / model / api_key / api_key_env)
  3. config.yaml -> top-level base_url / model / api_key  (legacy compat)
  4. Auto-probe: try each LOCAL backend port in order until one responds
     (cloud backends NEVER auto-select; you must set --servertype explicitly)

Auto-model detection:
  - LM Studio: GET /v1/models -> first entry (only one loaded typically)
  - Ollama:    GET /api/ps -> currently loaded model; fallback GET /api/tags
  - Llama.cpp: GET /v1/models -> the single served model
  - openai/nvidia/gemini: GET /v1/models -> first entry (may be huge list)
  - anthropic: no public /models endpoint; --model must be set explicitly

API key sourcing (per cloud backend):
  1. cfg.llm.api_key   (direct value)   ← wins
  2. env var named by cfg.llm.api_key_env
  3. env var default for that backend (OPENAI_API_KEY, ANTHROPIC_API_KEY,
     NVIDIA_API_KEY, GEMINI_API_KEY)
  If none of the above set on a cloud servertype, resolve() raises so you
  don't accidentally hit an unauthenticated endpoint and 401 silently.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

import requests

BACKENDS: dict[str, dict] = {
    # ── LOCAL (auto-probed) ─────────────────────────────────────────
    "lmstudio": {
        "kind": "local",
        "base_url": "http://127.0.0.1:1234/v1",
        "api_key":  "lm-studio-placeholder",
        "models_endpoint": "http://127.0.0.1:1234/v1/models",
    },
    "ollama": {
        "kind": "local",
        "base_url": "http://127.0.0.1:11434/v1",
        "api_key":  "ollama-placeholder",
        "models_endpoint": "http://127.0.0.1:11434/api/ps",
        "models_endpoint_fallback": "http://127.0.0.1:11434/api/tags",
    },
    "llamacpp": {
        "kind": "local",
        "base_url": "http://127.0.0.1:8080/v1",
        "api_key":  "llamacpp-placeholder",
        "models_endpoint": "http://127.0.0.1:8080/v1/models",
    },
    # ── CLOUD (require API key; never auto-selected) ────────────────
    "openai": {
        "kind": "cloud",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "models_endpoint": "https://api.openai.com/v1/models",
        "notes": "Paid. Tool calling native OpenAI format.",
    },
    "anthropic": {
        "kind": "cloud",
        "base_url": "https://api.anthropic.com/v1",
        "api_key_env": "ANTHROPIC_API_KEY",
        "models_endpoint": None,  # no public /models list
        "notes": ("Paid. OpenAI-compat endpoint since 2025. Set --model "
                  "explicitly, e.g. claude-sonnet-4-6 / claude-opus-4-8."),
    },
    "nvidia": {
        "kind": "cloud",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "api_key_env": "NVIDIA_API_KEY",
        "models_endpoint": "https://integrate.api.nvidia.com/v1/models",
        "notes": ("Paid (or NIM credits). Models often prefixed with vendor: "
                  "meta/llama-3.1-405b-instruct, qwen/qwen2.5-coder-32b-instruct."),
    },
    "gemini": {
        "kind": "cloud",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "api_key_env": "GEMINI_API_KEY",
        "models_endpoint":
            "https://generativelanguage.googleapis.com/v1beta/openai/models",
        "notes": ("Paid / free tier limited. Tool calling supported in "
                  "OpenAI-compat mode. Try gemini-2.5-flash, gemini-3-pro."),
    },
}

# Only local backends are auto-probed. Cloud requires explicit servertype.
PROBE_ORDER = ["lmstudio", "ollama", "llamacpp"]

# Cloud backends that require an API key at resolve time
_CLOUD = [name for name, spec in BACKENDS.items()
          if spec.get("kind") == "cloud"]


@dataclass
class BackendResolved:
    servertype: str          # 'lmstudio' | 'ollama' | 'llamacpp' | 'custom'
    base_url: str
    api_key: str
    model: str

    def as_dict(self) -> dict:
        return {
            "servertype": self.servertype,
            "base_url": self.base_url,
            "api_key": self.api_key,
            "model": self.model,
        }


class BackendConfigError(Exception):
    """Raised when a cloud backend is requested without an API key."""


def _http_get_json(url: str, timeout: float = 2.5,
                   headers: dict | None = None):
    r = requests.get(url, timeout=timeout, headers=headers or {})
    r.raise_for_status()
    return r.json()


def _resolve_api_key(servertype: str, cfg: dict,
                     api_key_cli: str | None = None) -> str:
    """Resolve api_key for `servertype`. Precedence: CLI > llm.api_key (direct)
    > env var named by llm.api_key_env > backend default env var.
    Returns '' if nothing found."""
    if api_key_cli:
        return api_key_cli.strip()
    llm_cfg = cfg.get("llm") or {}
    # Direct value in YAML wins
    direct = str(llm_cfg.get("api_key") or cfg.get("api_key") or "").strip()
    if direct and direct not in ("placeholder", "lm-studio-placeholder",
                                 "ollama-placeholder", "llamacpp-placeholder"):
        return direct
    # Env var configured in YAML
    env_name = (llm_cfg.get("api_key_env") or "").strip()
    if env_name:
        val = os.environ.get(env_name, "").strip()
        if val:
            return val
    # Fallback to the backend's default env var
    spec = BACKENDS.get(servertype) or {}
    default_env = spec.get("api_key_env", "")
    if default_env:
        return os.environ.get(default_env, "").strip()
    return ""


def _probe(servertype: str) -> bool:
    """True if the server on that port responds to its models endpoint."""
    spec = BACKENDS.get(servertype)
    if not spec:
        return False
    try:
        _http_get_json(spec["models_endpoint"], timeout=1.5)
        return True
    except Exception:
        # Some Ollama versions don't expose /api/ps if nothing loaded
        fb = spec.get("models_endpoint_fallback")
        if fb:
            try:
                _http_get_json(fb, timeout=1.5)
                return True
            except Exception:
                return False
        return False


def list_loaded_models(servertype: str, api_key: str = "") -> list[str]:
    """List the model IDs available on that server.

    For cloud backends, `api_key` must be supplied — otherwise the models
    endpoint 401s and we return []."""
    spec = BACKENDS.get(servertype)
    if not spec:
        return []
    if not spec.get("models_endpoint"):
        return []  # e.g. anthropic — no public /models
    urls = [spec["models_endpoint"]]
    fb = spec.get("models_endpoint_fallback")
    if fb:
        urls.append(fb)
    headers = {}
    if spec.get("kind") == "cloud" and api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    for url in urls:
        try:
            data = _http_get_json(url, timeout=5 if spec.get("kind") == "cloud" else 2,
                                  headers=headers)
        except Exception:
            continue
        # OpenAI-compat shape (openai/nvidia/gemini/lmstudio/llamacpp)
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            return [str(m.get("id")) for m in data["data"] if m.get("id")]
        # Ollama /api/ps → {"models":[{"name":"llama3:8b","model":"..."}]}
        if isinstance(data, dict) and isinstance(data.get("models"), list):
            names = []
            for m in data["models"]:
                n = m.get("name") or m.get("model")
                if n:
                    names.append(str(n))
            return names
    return []


def resolve(cfg: dict,
            servertype_cli: Optional[str] = None,
            model_cli: Optional[str] = None,
            base_url_cli: Optional[str] = None) -> BackendResolved:
    """Resolve the final backend + model to use for this run.

    Precedence (highest first):
      CLI (--servertype/--model/--base-url) > cfg.llm.* > cfg legacy top-level
      > auto-probe (LOCAL only).

    Raises BackendConfigError if a cloud servertype is chosen without an
    API key, so we never silently 401 against paid endpoints.
    """
    llm_cfg = cfg.get("llm") or {}

    base_url = (base_url_cli
                or llm_cfg.get("base_url")
                or cfg.get("base_url")
                or "").strip()
    servertype = (servertype_cli
                  or llm_cfg.get("servertype")
                  or "auto").strip().lower()
    model = (model_cli
             or llm_cfg.get("model")
             or cfg.get("model")
             or "").strip()
    api_key = ""  # resolved below per backend

    # Explicit servertype named
    if servertype in BACKENDS:
        spec = BACKENDS[servertype]
        if not base_url:
            base_url = spec["base_url"]
        if spec.get("kind") == "cloud":
            api_key = _resolve_api_key(servertype, cfg)
            if not api_key:
                default_env = spec.get("api_key_env", "?")
                raise BackendConfigError(
                    f"Cloud backend '{servertype}' selected but no API key "
                    f"found. Either fill llm.api_key in config.yaml, "
                    f"set llm.api_key_env, or export ${default_env}."
                )
        else:  # local
            api_key = _resolve_api_key(servertype, cfg) or spec.get("api_key", "placeholder")
    elif servertype == "auto":
        # Only probe LOCAL backends — cloud requires explicit opt-in.
        picked = None
        for name in PROBE_ORDER:
            if _probe(name):
                picked = name
                break
        if picked:
            servertype = picked
            spec = BACKENDS[picked]
            if not base_url:
                base_url = spec["base_url"]
            api_key = _resolve_api_key(servertype, cfg) or spec.get("api_key", "placeholder")
        else:
            # Nothing live — default to lmstudio so we fail with a clear
            # error at chat.completions time.
            servertype = "lmstudio"
            spec = BACKENDS["lmstudio"]
            base_url = base_url or spec["base_url"]
            api_key = spec.get("api_key", "placeholder")
    else:
        # Unknown servertype but base_url given -> treat as custom
        servertype = "custom"
        api_key = _resolve_api_key(servertype, cfg) or "custom-placeholder"

    # Auto-detect model if not set (works for backends with /models endpoint)
    if not model and servertype in BACKENDS:
        loaded = list_loaded_models(servertype, api_key=api_key)
        if loaded:
            model = loaded[0]

    return BackendResolved(
        servertype=servertype,
        base_url=base_url,
        api_key=api_key or "placeholder",
        model=model or "",
    )


def print_backend_banner(resolved: BackendResolved) -> None:
    """Small one-liner printed at the top of every run so the operator sees
    which backend + model is actually in use. Cloud backends are flagged."""
    spec = BACKENDS.get(resolved.servertype) or {}
    kind = spec.get("kind", "custom")
    model_txt = resolved.model or "(no model — set --model or load one)"
    tag = "☁️ CLOUD (paid)" if kind == "cloud" else \
          "🏠 LOCAL" if kind == "local" else "custom"
    print(f"[+] LLM backend: {resolved.servertype}  {tag}  @ "
          f"{resolved.base_url}  · model: {model_txt}")
    if kind == "cloud":
        print(f"    ⚠️  {spec.get('notes', '')}")
