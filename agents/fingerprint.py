"""Fingerprint Agent — deep tech detection per live host.

Objective: identify the exact stack per host (WordPress, Dokploy, Grafana,
Rails, Next.js, JBoss, WebLogic, etc.). Runs after Recon.
Populates shared_state.detected_techs and endpoints_found.
"""
from __future__ import annotations

import re

from agents.base import BaseAgent


# Techs we explicitly try to match against nuclei tech-detect / http headers
TECH_KEYWORDS = [
    "wordpress", "joomla", "drupal", "magento", "prestashop", "shopify",
    "dokploy", "coolify", "portainer", "traefik", "kong", "consul",
    "vault", "nomad", "minio", "rabbitmq", "elasticsearch", "kibana",
    "airflow", "metabase", "grafana", "prometheus",
    "jenkins", "gitlab", "gitea", "jira", "confluence", "bitbucket",
    "keycloak", "auth0", "okta",
    "next.js", "nuxt", "rails", "django", "flask", "express", "fastapi",
    "spring", "laravel", "symfony",
    "phpmyadmin", "adminer", "directus", "strapi", "payload",
    "jboss", "weblogic", "tomcat", "wildfly",
    "n8n", "zapier", "make",
]


class FingerprintAgent(BaseAgent):
    NAME = "fingerprint"
    DESCRIPTION = "Deep tech stack detection per live host"
    MAX_ITERATIONS = 8
    TOOL_NAMES = ["run_shell", "http_get", "finish"]

    SYSTEM_PROMPT = """/no_think

You are the FINGERPRINT AGENT. For each live host discovered by recon,
identify the exact software stack (product, framework, CMS, version).

Workflow (per host):
  1. curl -s -I -L <url>            (grab Server / X-Powered-By / cookies)
  2. curl -s <url> | head -80       (peek HTML for meta / bundle names)
  3. nuclei -u <url> -tags tech -silent -rl 10 -c 10
     (built-in tech-detection templates; one tag call, do NOT chain 20 tags)
  4. For each detected product name, add it to your final findings list.

Rules:
  - One tool_call per turn. NEVER concatenate 20 tags in a single nuclei call.
  - Focus on identification. Do NOT test vulnerabilities here.
  - After 6-7 tool_calls, call finish() with:
      summary: "Detected: <tech1>, <tech2>, ..."
      findings: ["<host> — <tech> <version>", ...]
"""

    def entry_condition(self, state) -> bool:
        return state.has_live_http() or bool(state.get("target"))

    def build_objective(self, state) -> str:
        live = state.get("live_hosts", [])
        hosts_line = ", ".join(
            f"{h.get('scheme','https')}://{h.get('host')}"
            for h in live[:5]
        ) or state.get("target")
        return (
            f"Live hosts to fingerprint (first few): {hosts_line}\n"
            f"Target: {state.get('target')}\n\n"
            "Identify tech stack per host. Finish with a summary."
        )

    def after_run(self, state, transcript):
        detected: set[str] = set()
        endpoints: list[dict] = []
        for entry in transcript:
            result = str(entry.get("result", "")).lower()
            for tech in TECH_KEYWORDS:
                if tech in result:
                    detected.add(tech)
            # Extract URLs seen in http_get results (probably endpoint hits)
            args = entry.get("args", {}) or {}
            if entry.get("tool") == "http_get" and args.get("url"):
                endpoints.append({
                    "url": args["url"],
                    "via": "fingerprint",
                })
        # Also inspect the model's finish() findings for tech hints
        if detected:
            state.extend("detected_techs", sorted(detected))
        if endpoints:
            state.extend("endpoints_found", endpoints)
