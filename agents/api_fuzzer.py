"""API Fuzzer Agent — dispatched if any /api/, /graphql, /v1/ endpoint found.
"""
from __future__ import annotations

import re

from agents.base import BaseAgent


class ApiFuzzerAgent(BaseAgent):
    NAME = "api_fuzzer"
    DESCRIPTION = "API/GraphQL endpoint fuzzing (ffuf + param discovery)"
    MAX_ITERATIONS = 10
    TOOL_NAMES = ["run_shell", "http_get", "http_post", "finish"]

    SYSTEM_PROMPT = """/no_think

You are the API FUZZER AGENT. Only dispatched when API endpoints were
discovered. Enumerate more endpoints, discover parameters, check for
BOLA/BFLA/mass-assignment surface.

Workflow (one tool_call per turn):
  1. curl -s <base>/openapi.json  and /swagger.json  and /api-docs
  2. curl -s <base>/graphql -H "Content-Type: application/json" \
       -d '{"query":"{ __schema { types { name } } }"}'
     (GraphQL introspection — if enabled = huge win)
  3. ffuf -u <base>/api/FUZZ -w <api-wordlist> -mc all -rate 10
  4. For each interesting endpoint: http_get / http_post to observe response
     shape. Report 200s that leak PII, 401 vs 403 gaps, verb tampering.
  5. finish() with findings

Rules:
  - One tool_call per turn.
  - NEVER attempt actual data exfiltration. Confirm the vector and stop.
  - Report auth-related gaps (missing headers, verb tampering) with evidence.
"""

    def entry_condition(self, state) -> bool:
        return state.has_endpoint_matching(
            ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "swagger",
             "openapi"])

    def build_objective(self, state) -> str:
        host = _primary_url(state)
        api_hits = [e for e in state.get("endpoints_found", [])
                    if any(s in str(e.get("url", "")).lower()
                           for s in ("/api/", "/v1/", "/v2/", "/graphql"))]
        return (
            f"Primary host: {host}\n"
            f"API endpoints seen so far ({len(api_hits)}): "
            f"{[e.get('url') for e in api_hits[:10]]}\n\n"
            "Enumerate API surface + auth checks. Finish with findings."
        )

    def after_run(self, state, transcript):
        for entry in transcript:
            args = entry.get("args", {}) or {}
            result = str(entry.get("result", ""))
            # Track 200 responses on API endpoints — potential leaks
            if entry.get("tool") in ("http_get", "http_post"):
                url = args.get("url", "")
                if "HTTP 200" in result and "/api/" in url.lower():
                    body_preview = result[:400]
                    state.add_finding(
                        agent=self.NAME, severity="info",
                        title=f"API endpoint responded 200: {url}",
                        evidence=body_preview,
                        recommendation="Verify authorization required")
            # ffuf status hits (unauth-accessible)
            for m in re.finditer(
                r"(\S+)\s*\[Status:\s*(\d+),\s*Size:\s*(\d+)",
                    result):
                path, status, size = m.group(1), m.group(2), m.group(3)
                if status in ("200", "301", "302", "403"):
                    state.append("endpoints_found",
                                 {"url": path, "via": "api_fuzzer",
                                  "status": int(status), "size": int(size)})


def _primary_url(state):
    hosts = state.get("live_hosts", [])
    if hosts:
        h = hosts[0]
        return f"{h.get('scheme','https')}://{h.get('host')}"
    return state.get("target")
