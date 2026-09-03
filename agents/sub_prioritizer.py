"""Sub Prioritizer — deterministic ranker for live_hosts.

Runs right after `recon` (which populates `state.live_hosts` via subfinder →
httpx → optionally naabu). This agent scores every live host on five signals
and reorders `state.live_hosts` so `[0]` is the juiciest sub. It also stores
a `state.prioritized_hosts` list with the per-host score breakdown for the
REPORT.md's "Subdomain Prioritization" section.

The score exists so the downstream single-host pipeline scans the RIGHT sub
by default, and so the multi-host loop (orchestrator._run_multi_host) can
pick the top-N subs without a second LLM pass.

Scoring signals (weighted, additive with per-signal caps):

  1. Naming  — admin/dev/api/jenkins/keycloak/... → high, www/blog/cdn/... → low
  2. Status  — 401/403 auth-protected, 500 server-broken, 429 defended → boost
  3. Tech    — jenkins/gitlab/grafana/adminer/portainer → CRITICAL products
  4. Title   — "index of", "admin panel", "coming soon", "for sale" → +/-
  5. Ports   — 3306/5432/9200/2375/8080/... on unusual ports → boost

Penalties:
  - Random-looking hex/UUID labels → -15 (e.g. `a7f3c9d.example.com`)

Tiers (final score → tier):
  ≥ 60  CRITICAL   (auth-protected admin panel with juicy tech)
  ≥ 40  HIGH       (dev/api/staging on known product)
  ≥ 20  MEDIUM     (something interesting but not obvious)
  < 20  LOW        (www / blog / cdn / static)

The agent is deterministic (no LLM turns). Skips itself if fewer than 2
live hosts exist (nothing to rank).
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from agents.base import BaseAgent


# ── Signal 1: naming ────────────────────────────────────────────────
# Tokens compared case-insensitive against the subdomain labels split on
# both `.` and `-`. The MAX score across all matched tokens is used
# (avoids double-counting `admin-dev` at 40+35).
_NAME_SCORES: dict[str, int] = {
    # CRITICAL — admin surfaces
    "admin": 40, "administrator": 40, "wp-admin": 40, "wpadmin": 40,
    "manage": 40, "manager": 40, "panel": 40, "console": 40,
    "dashboard": 40, "backoffice": 40, "backend": 40, "cpanel": 40,
    "whm": 40, "plesk": 40, "webmin": 40,

    # HIGH — dev / staging / non-prod (often exposed by accident)
    "dev": 35, "develop": 35, "development": 35, "staging": 35,
    "stage": 35, "qa": 35, "uat": 35, "test": 35, "testing": 35,
    "preprod": 35, "pre-prod": 30, "beta": 30, "sandbox": 35,
    "demo": 25, "alpha": 30,

    # HIGH — API surfaces (great for BOLA/BFLA/GraphQL introspection)
    "api": 30, "graphql": 30, "gql": 30, "rest": 25, "ws": 25,
    "websocket": 25, "mobile": 25, "mapi": 30, "gapi": 30, "apis": 25,

    # HIGH — well-known infrastructure products (usually admin panels)
    "jenkins": 40, "gitlab": 40, "gitea": 30, "gogs": 30, "forgejo": 25,
    "jira": 35, "confluence": 35, "wiki": 20, "wiki-js": 20, "wikijs": 20,
    "grafana": 40, "kibana": 40, "prometheus": 35, "nagios": 35,
    "zabbix": 35, "cacti": 30, "opsview": 30,
    "kubernetes": 40, "k8s": 40, "rancher": 40, "portainer": 40,
    "dokploy": 40, "coolify": 40, "traefik": 30, "consul": 35,
    "vault": 40, "keycloak": 35, "airflow": 35, "metabase": 35,
    "adminer": 40, "phpmyadmin": 40, "myadmin": 30,
    "minio": 35, "elasticsearch": 40, "kbn": 30,
    "sonarqube": 30, "sonar": 30, "artifactory": 30, "nexus": 30,
    "harbor": 30, "quay": 30, "registry": 30,

    # HIGH — self-hosted internal tools with strong CVE history
    # (workflow automation / low-code / dev-tools — heavy RCE-hunt targets)
    "n8n": 40, "hasura": 35, "superset": 35, "guacamole": 35,
    "rundeck": 35, "awx": 35, "argocd": 35, "argo": 25,
    "code-server": 35, "coder": 30, "gitpod": 30, "theia": 25,
    "appsmith": 30, "retool": 25, "budibase": 25, "tooljet": 25,
    "openldap": 30, "phpldapadmin": 40, "ldapadmin": 30,
    "jupyterhub": 30, "jupyter": 25,
    "cloudpanel": 35, "caprover": 30, "hestiacp": 30, "vestacp": 30,
    "webmin": 40, "ispmanager": 30, "virtualmin": 35,

    # MEDIUM-HIGH — headless CMS / ERP / project mgmt
    "strapi": 30, "directus": 30, "payload": 25,
    "odoo": 30, "erpnext": 25, "frappe": 25,
    "redmine": 25, "openproject": 20, "taiga": 20,
    "kanboard": 20, "wekan": 15, "focalboard": 15, "plane": 20,
    "mautic": 25, "sendportal": 20, "listmonk": 20,

    # MEDIUM-HIGH — chat / community (XSS/IDOR historical)
    "chat": 15, "chattickets": 15, "chatai": 15,
    "chatwoot": 30, "rocketchat": 30, "mattermost": 30,
    "discourse": 25, "zulip": 20, "element": 15, "synapse": 20,

    # MEDIUM — self-hosted file / photo / media
    "nextcloud": 25, "owncloud": 25, "seafile": 25,
    "immich": 25, "paperless": 20, "paperless-ngx": 20,
    "outline": 20, "bookstack": 20,
    "filebrowser": 25, "filerun": 25, "filecloud": 20,
    "jellyfin": 20, "plex": 20, "emby": 20,

    # MEDIUM — analytics / observability / BI (SSRF/leak historical)
    "umami": 25, "plausible": 20, "matomo": 25, "piwik": 25,
    "posthog": 25, "sentry": 20, "glitchtip": 15,
    "redash": 25, "prefect": 25, "temporal": 25,

    # MEDIUM — status pages / uptime monitoring
    "uptime-kuma": 15, "uptimekuma": 15, "healthchecks": 15,
    "cachet": 15, "statping": 15, "gatus": 15,

    # LOW-MEDIUM — dev tools / stats
    "wakapi": 15, "changedetection": 15, "grimoirelab": 20,

    # HIGH — asset / snipe (typical IDOR + auth-bypass surface)
    "snipe-it": 25, "snipeit": 25,

    # HIGH — VoIP / PBX corporativo (unauth RCE + default creds patterns —
    # see refs/tecnicas/voip-pbx-patterns.md · CVE-2026-9586 Switchvox etc.)
    "switchvox": 40, "sangoma": 40, "asterisk": 30, "freepbx": 35,
    "3cx": 30, "elastix": 25, "grandstream": 25, "ucm": 15,
    "pbx": 30, "voip": 25, "sip": 20, "voice": 15,
    "phones": 20, "phone": 15, "pabx": 25,

    # MEDIUM — auth / identity
    "auth": 25, "sso": 25, "oauth": 25, "login": 25, "signin": 25,
    "id": 20, "identity": 25, "account": 20, "accounts": 20,
    "adfs": 30, "okta": 30, "azuread": 30,

    # MEDIUM — CI/CD
    "git": 25, "ci": 25, "cd": 25, "deploy": 25, "deployment": 25,
    "build": 20, "drone": 30, "teamcity": 30, "bamboo": 30,
    "circleci": 20, "travis": 20, "buildkite": 20,

    # MEDIUM — "internal" markers (interesting because not-meant-to-be-public)
    "internal": 30, "intranet": 30, "corp": 25, "corporate": 25,
    "priv": 25, "private": 25, "secure": 20, "secret": 25,
    "hidden": 20, "restricted": 25,

    # MEDIUM — remote access panels
    "vpn": 30, "remote": 25, "rdp": 30, "ssh": 25, "telnet": 30,
    "ftp": 20, "sftp": 20, "mgmt": 30, "ops": 25,

    # MEDIUM — mail (typically not vulnerable but sometimes)
    "mail": 15, "smtp": 15, "imap": 15, "pop": 15, "mx": 15,
    "webmail": 20, "exchange": 20, "owa": 25, "roundcube": 20,
    "squirrelmail": 20, "postfix": 15,

    # MEDIUM — data services (rarely exposed but very juicy when they are)
    "db": 30, "sql": 30, "mysql": 30, "postgres": 30, "postgresql": 30,
    "mongo": 30, "mongodb": 30, "redis": 30, "memcached": 25,
    "elastic": 30, "hadoop": 30, "spark": 30, "kafka": 25,
    "rabbitmq": 25, "activemq": 25,
    "storage": 20, "s3": 20, "oss": 20, "swift": 20, "ceph": 25,

    # MEDIUM — monitoring / logging (leaks info + admin panels)
    "status": 15, "health": 10, "monitor": 20, "metrics": 20,
    "stats": 15, "analytics": 15, "log": 20, "logs": 20,
    "logging": 20, "splunk": 30, "elk": 30, "syslog": 20,

    # MEDIUM — API docs (endpoint discovery goldmine)
    "api-docs": 25, "apidocs": 25, "docs": 12, "swagger": 25,
    "redoc": 25, "api-explorer": 25, "openapi": 25,

    # MEDIUM — commerce (payment flows = high impact)
    "billing": 25, "invoice": 20, "payment": 25, "pay": 25,
    "checkout": 20, "cart": 15, "orders": 15, "order": 15,
    "store": 10, "shop": 10, "ecommerce": 10, "tienda": 10,

    # LOW — community/support (limited attack surface)
    "forum": 10, "community": 10, "discuss": 8, "help": 5,
    "support": 8, "kb": 8, "faq": 5,

    # LOW — static assets (rarely direct impact)
    "images": 3, "img": 3, "cdn": 3, "static": 3, "assets": 3,
    "media": 3, "files": 5, "download": 5, "downloads": 5,
    "upload": 10, "uploads": 10,   # uploads sometimes exploitable

    # LOW — plain web
    "www": 5, "web": 5, "site": 5, "home": 5,
    "blog": 8, "news": 5, "press": 5, "tv": 5, "video": 5,

    # NEGATIVE — third-party managed services that almost never yield bounty
    # (they're operated by the vendor, not the target org — mostly out of scope)
    "clerk": -10,          # clerk.dev (auth-as-a-service) frontend-api
    "auth0-app": -5,       # auth0 hosted login (also out-of-scope typically)
    "cognito": -5,         # AWS Cognito hosted UI
    "supertokens": -5,     # supertokens managed
    "firebaseapp": -10,    # firebase-hosted
    "netlify": -5,         # netlify-hosted static
    "vercel": -5,          # vercel-hosted static/edge
    "herokuapp": -5,       # heroku-hosted
    "onrender": -5,        # render.com-hosted
    "githubusercontent": -10,  # github pages / raw
}

# ── Signal 2: HTTP status ───────────────────────────────────────────
def _score_status(status) -> tuple[int, list[str]]:
    if status is None:
        return 0, []
    try:
        s = int(status)
    except (TypeError, ValueError):
        return 0, []
    if s in (401, 403):
        return 15, [f"HTTP {s} = auth-protected (+15)"]
    if 500 <= s < 600:
        return 12, [f"HTTP {s} = server error, often exploitable (+12)"]
    if s == 429:
        return 8, [f"HTTP {s} = rate-limited, defended (+8)"]
    if 200 <= s < 300:
        return 8, [f"HTTP {s} = accessible (+8)"]
    if 300 <= s < 400:
        return 5, [f"HTTP {s} = redirect (+5)"]
    if s == 404:
        return -5, [f"HTTP {s} = not found on root (-5)"]
    return 0, []


# ── Signal 3: tech ──────────────────────────────────────────────────
_TECH_SCORES: dict[str, int] = {
    # CRITICAL products (default creds + known CVEs)
    "jenkins": 30, "gitlab": 30, "jira": 25, "confluence": 25,
    "grafana": 30, "kibana": 30, "kubernetes-dashboard": 35, "rancher": 30,
    "portainer": 30, "dokploy": 30, "coolify": 30, "adminer": 35,
    "phpmyadmin": 35, "tomcat": 25, "weblogic": 30, "jboss": 30,
    "keycloak": 25, "vault": 30, "consul": 25, "airflow": 25,
    "metabase": 25, "elasticsearch": 30, "minio": 25,
    "sharepoint": 25, "exchange": 25, "owncloud": 25, "nextcloud": 25,
    "sonarqube": 25, "artifactory": 25, "nexus": 20, "harbor": 25,
    # HIGH — common CMS
    "wordpress": 20, "drupal": 20, "joomla": 20, "magento": 25,
    "typo3": 20, "prestashop": 20, "opencart": 20,
    # MEDIUM — frameworks
    "express": 10, "django": 10, "rails": 10, "spring": 10,
    "laravel": 10, "symfony": 10, "flask": 10, "fastapi": 10,
    "nextjs": 10, "nuxt": 10, "react": 5, "vue": 5, "angular": 5,
    # LOW — generic servers (relevant only via CVEs)
    "nginx": 3, "apache": 3, "iis": 3, "php": 3, "nodejs": 5,
    "openresty": 3, "lighttpd": 3, "caddy": 3,
}

def _score_tech(techs) -> tuple[int, list[str]]:
    if not techs:
        return 0, []
    max_score = 0
    reasons: list[str] = []
    matched: set[str] = set()
    for t in techs:
        low = str(t).lower()
        for key, val in _TECH_SCORES.items():
            if key in low and key not in matched:
                if val > max_score:
                    max_score = val
                reasons.append(f"tech '{t}' matches '{key}' (+{val})")
                matched.add(key)
                break
    return max_score, reasons


# ── Signal 4: title sniffing ────────────────────────────────────────
_TITLE_POSITIVE: list[tuple[str, int]] = [
    ("index of /", 15),           # directory listing = huge
    ("index of ", 15),
    ("phpmyadmin", 15), ("adminer", 15),
    ("grafana", 12), ("jenkins", 12), ("gitlab", 12),
    ("kubernetes", 12), ("portainer", 12), ("rancher", 12),
    ("admin panel", 12), ("administrator", 12),
    ("dashboard", 10), ("control panel", 10), ("console", 10),
    ("login", 8), ("sign in", 8), ("signin", 8), ("iniciar sesión", 8),
    ("git clone", 12),             # .git exposed?
    ("debug", 10), ("trace", 10), ("error", 5),
    ("swagger", 10), ("openapi", 10),
]
_TITLE_NEGATIVE: list[tuple[str, int]] = [
    ("coming soon", -10), ("under construction", -10),
    ("parked", -15), ("for sale", -15), ("this domain", -10),
    ("domain not configured", -20), ("website expired", -20),
    ("suspended", -15), ("account suspended", -20),
    ("we're hiring", -8), ("hiring", -3),
    ("welcome to nginx", -5), ("welcome to apache", -5),
    ("apache http server test page", -5),
    ("cloudflare", -3),
    ("página en construcción", -10), ("próximamente", -10),
]

def _score_title(title) -> tuple[int, list[str]]:
    if not title:
        return 0, []
    low = str(title).lower()
    score = 0
    reasons: list[str] = []
    for text, val in _TITLE_POSITIVE + _TITLE_NEGATIVE:
        if text in low:
            score += val
            reasons.append(f"title contains {text!r} ({'+' if val >= 0 else ''}{val})")
    return max(-20, min(20, score)), reasons


# ── Signal 5: ports ─────────────────────────────────────────────────
_PORT_SCORES: dict[int, int] = {
    # Docker daemon exposed → almost always RCE
    2375: 20, 2376: 20,
    # Databases directly reachable → big deal
    3306: 15, 5432: 15, 27017: 15, 6379: 15, 5984: 12, 11211: 10,
    # Search engines exposed → big deal
    9200: 12, 9300: 12,
    # Kibana
    5601: 12,
    # Web on unusual ports = something interesting
    8080: 8, 8443: 8, 8000: 8, 8888: 6, 8081: 6, 8181: 6,
    3000: 6, 4000: 6, 5000: 6, 7000: 6, 7001: 6, 9000: 8, 9090: 8,
    # DevOps
    9418: 10,   # git://
    # Remote access
    22: 3, 23: 5, 3389: 5, 5900: 5,   # ssh / telnet / rdp / vnc
    # Mail (rarely useful)
    25: 2, 465: 2, 587: 2, 143: 2, 993: 2, 110: 2, 995: 2,
    # Registry / package
    5000: 6, 5001: 6,  # docker registry
}

def _score_ports(ports) -> tuple[int, list[str]]:
    if not ports:
        return 0, []
    score = 0
    reasons: list[str] = []
    for p in ports:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            continue
        if pi in _PORT_SCORES:
            v = _PORT_SCORES[pi]
            score += v
            reasons.append(f"port {pi} open (+{v})")
    return min(25, score), reasons


# ── Signal 6 (penalty): random-looking labels ───────────────────────
_HEX_LABEL = re.compile(r"^[a-f0-9]{16,}$")
_UUID_PREFIX = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}")

def _penalty_random(hostname: str) -> tuple[int, list[str]]:
    label = hostname.split(":", 1)[0].lower()
    parts = label.split(".")
    if len(parts) < 3:
        return 0, []
    first = parts[0]
    if _HEX_LABEL.match(first):
        return -15, [f"random-looking hex label {first!r} (-15)"]
    if _UUID_PREFIX.match(first):
        return -15, [f"UUID-like label {first!r} (-15)"]
    return 0, []


# ── Name score (max across matched tokens) ──────────────────────────
def _score_name(hostname: str) -> tuple[int, list[str]]:
    """Return the max score across all matched tokens.

    IMPORTANT: this is the MAX not the SUM, and NEGATIVE values are
    respected — a sub `clerk.example.com` with only `clerk: -10` in the
    table returns -10 (initialised at None, not 0). Before this fix,
    negative values were silently swallowed by `max_score = 0`.
    """
    label = hostname.split(":", 1)[0].lower()
    parts = label.split(".")
    # If only apex (a.b), no sub component to score
    if len(parts) <= 2:
        return 0, []
    sub_labels = parts[:-2]  # everything before <apex>.<tld>
    tokens: set[str] = set()
    for lbl in sub_labels:
        # Split on - and _; also add the whole label itself
        tokens.add(lbl)
        for tok in re.split(r"[-_]", lbl):
            if tok:
                tokens.add(tok)
    max_score: int | None = None
    reasons: list[str] = []
    for tok in tokens:
        if tok in _NAME_SCORES:
            v = _NAME_SCORES[tok]
            if max_score is None or v > max_score:
                max_score = v
            sign = "+" if v >= 0 else ""
            reasons.append(f"name token {tok!r} ({sign}{v})")
    return (max_score if max_score is not None else 0), reasons


# Hard-killers in the title — irrespective of a juicy-looking name,
# these markers mean the sub is a parking page / expired / for sale, and
# there is NOTHING to attack. When any of these hits, the final score is
# CAPPED to LOW tier (max 15) regardless of other signals.
_TITLE_HARD_KILLERS = [
    "for sale", "parked", "domain not configured", "website expired",
    "account suspended", "this domain is", "buy this domain",
    "acquire this domain", "premium domain",
]


def _title_kills_score(title: str) -> bool:
    if not title:
        return False
    low = str(title).lower()
    return any(k in low for k in _TITLE_HARD_KILLERS)


# Cloudflare (or similar) anti-bot challenge markers. When we hit one of
# these, the HTTP response is the CHALLENGE PAGE, not the real app — no
# non-browser tool (curl / nuclei / ffuf) can pass without a JA3-impersonating
# client (curl-impersonate, headless Chrome). Penalize hard so multi-host
# doesn't burn 30-60 min per sub scanning challenge pages.
_CF_CHALLENGE_TITLES = [
    "just a moment",                       # Cloudflare classic challenge
    "attention required",                  # Cloudflare block page
    "one moment please",                   # Cloudflare variant
    "checking your browser",               # Cloudflare / DataDome
    "please wait...",                      # Sucuri / generic anti-bot
    "please wait while we check",          # Cloudflare
    "verify you are human",                # Turnstile / Cloudflare
    "sorry, you have been blocked",        # Cloudflare block
    "access denied",                       # Akamai / generic
    "pardon our interruption",             # PerimeterX
]


def _is_bot_challenge_page(host_record: dict) -> bool:
    """True if the recorded HTTP response looks like an anti-bot challenge
    page (Cloudflare Bot Management, DataDome, PerimeterX, Sucuri, …) —
    i.e. the tools can't reach the real app without a browser-fingerprint
    bypass. Signals: status 403 or 503 + telltale title + WAF tech marker."""
    status = host_record.get("status")
    title_low = str(host_record.get("title") or "").lower()
    techs_low = [str(t).lower() for t in (host_record.get("tech") or [])]
    title_hit = any(m in title_low for m in _CF_CHALLENGE_TITLES)
    tech_hit = any(("cloudflare" in t and ("bot" in t or "challenge" in t))
                    or "turnstile" in t or "datadome" in t
                    or "perimeterx" in t or "sucuri" in t
                    for t in techs_low)
    denied_status = status in (403, 503)
    # Any TWO of the three signals is enough (title alone can false-positive
    # on legit pages named "please wait"; status alone false-positives too).
    return sum([title_hit, tech_hit, denied_status]) >= 2


# ── Combine ─────────────────────────────────────────────────────────
def score_host(host_record: dict) -> dict:
    hostname = str(host_record.get("host", ""))
    status = host_record.get("status")
    techs = host_record.get("tech") or host_record.get("technologies") or []
    title = host_record.get("title", "")
    # Ports: recon may store as .ports or the record may be from naabu with .port
    ports = host_record.get("ports") or (
        [host_record["port"]] if host_record.get("port") else [])

    n_s, n_r = _score_name(hostname)
    st_s, st_r = _score_status(status)
    te_s, te_r = _score_tech(techs)
    ti_s, ti_r = _score_title(title)
    po_s, po_r = _score_ports(ports)
    pen_s, pen_r = _penalty_random(hostname)

    total = n_s + st_s + te_s + ti_s + po_s + pen_s
    reasons = n_r + st_r + te_r + ti_r + po_r + pen_r

    # Hard cap: parking pages / for-sale / expired titles → LOW tier no matter
    # what a juicy-looking name suggests. This handles `test.example.com` with
    # title "This domain is for sale" — name "test" would normally be +35.
    if _title_kills_score(title):
        capped = min(total, 15)
        reasons.append(f"HARD CAP: title marks this as parking/for-sale/"
                        f"expired → capped from {total} to {capped}")
        total = capped

    # Anti-bot challenge page penalty. Even if the sub name is juicy
    # (`accounts.foo.com`), if the HTTP response is a CF/DataDome/etc.
    # challenge, no non-browser tool can scan it. Push it to LOW tier so
    # multi-host burns time on subs it can actually attack.
    cf_challenge = _is_bot_challenge_page(host_record)
    if cf_challenge:
        penalty = 30
        total -= penalty
        reasons.append(
            f"⚠️ ANTI-BOT CHALLENGE detected (status={host_record.get('status')} "
            f"title={host_record.get('title','')!r:.60}) — non-browser tools "
            f"cannot pass; penalty -{penalty}. Bypass with curl-impersonate "
            f"or headless Chrome to scan for real.")

    return {
        "host": hostname,
        "score": total,
        "tier": _tier(total),
        "components": {
            "name": n_s, "status": st_s, "tech": te_s,
            "title": ti_s, "ports": po_s, "penalty": pen_s,
            "cf_challenge": -30 if cf_challenge else 0,
        },
        "reasons": reasons,
        "bot_challenge": cf_challenge,
    }


def _tier(score: int) -> str:
    if score >= 60:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


# ── The agent ───────────────────────────────────────────────────────
class SubPrioritizerAgent(BaseAgent):
    NAME = "sub_prioritizer"
    DESCRIPTION = "Score + rank live hosts by attack-surface priority"
    MAX_ITERATIONS = 0
    TOOL_NAMES = ["finish"]     # unused; short-circuits run()

    def entry_condition(self, state) -> bool:
        # Only useful when we have more than one live host to rank
        return len(state.get("live_hosts") or []) > 1

    def run(self, state) -> str:
        started = time.time()
        self._emit("start", description=self.DESCRIPTION, max_iterations=1)
        try:
            live = state.get("live_hosts") or []
            scored = [score_host(h) for h in live]
            scored.sort(key=lambda x: x["score"], reverse=True)

            # Re-merge with original records so downstream sees priority_*
            # fields but everything else (status/title/tech) is preserved.
            new_live: list[dict] = []
            for s in scored:
                orig = next((h for h in live
                             if str(h.get("host", "")) == s["host"]),
                            {"host": s["host"]})
                merged = dict(orig)
                merged["priority_score"] = s["score"]
                merged["priority_tier"] = s["tier"]
                new_live.append(merged)
            state.set("live_hosts", new_live)
            state.set("prioritized_hosts", scored)

            # Narrative summary for REPORT
            tiers: dict[str, int] = {}
            for s in scored:
                tiers[s["tier"]] = tiers.get(s["tier"], 0) + 1
            top3 = ", ".join(f"{s['host']}={s['score']}({s['tier']})"
                              for s in scored[:3])
            tier_line = ", ".join(f"{k}={v}"
                                    for k, v in sorted(tiers.items(),
                                                        key=lambda kv: -kv[1]))
            state.append("agent_summaries", {
                "agent": self.NAME,
                "summary": (
                    f"Ranked {len(scored)} live hosts. "
                    f"Distribution: {tier_line}. "
                    f"Top-3: {top3}"),
            })

            elapsed = time.time() - started
            self._emit("progress", turn=1, max_turns=1)
            self._emit("done", elapsed=elapsed, tool_calls=0, turns=1)
            state.mark_agent_run(self.NAME, "done", elapsed, 1, 0)
            return "done"
        except Exception as e:
            state.error(self.NAME, str(e))
            self._emit("error", err=str(e))
            state.mark_agent_run(self.NAME, "error",
                                  time.time() - started, 0, 0)
            return "error"
