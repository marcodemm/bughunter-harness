"""Fingerprint Agent — deep tech detection per live host.

Objective: identify the exact software stack (product, framework, CMS,
plugin, version) on every live host. Runs after Recon and Sub-Prioritizer.

Populates:
  state.detected_techs   — deduped lowercase list of ALL techs seen
                            (used by web_vuln to pick nuclei -tags, and
                            by extension techniques' `applies_when` gate)
  state.endpoints_found  — asset URLs seen in HTML
  state.findings         — one rich `info` finding per (tech, version)
                            with the raw line as evidence + the exact
                            next-step command as recommendation.

Deterministic parsing lives in `after_run`; the LLM turn only drives the
tool_calls. We do NOT rely on the model to format findings — the raw
`curl -sI` / `curl -s HTML` / `nuclei -tags tech` outputs in the transcript
are parsed here.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from agents.base import BaseAgent


# Techs the LLM turn should try to identify. Also used by after_run as a
# fallback keyword scan when structured parsing misses one.
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
    "elementor", "yoast", "woocommerce", "contact-form-7", "wpforms",
    "all-in-one-wp-migration", "duplicate-page", "health-check",
    "wps-hide-login",
    "font-awesome", "google-fonts", "google-site-kit",
    "twentytwentyone", "twentytwentytwo", "twentytwentythree",
    "twentytwentyfour",
]


# Latest known MAJOR version per tech, at the time this table was
# maintained. Used only to flag "impossibly-new" version claims by the
# model (e.g. "WordPress 7.1" when WP peaked at 6.x). A detected MAJOR >
# latest_known + 1 is considered SUSPECT and gets tagged for manual
# verification. This is NOT a CVE database — do not rely on it for
# vulnerability assessment.
LATEST_KNOWN_MAJOR: dict[str, int] = {
    "wordpress": 6,        # 6.x line
    "php": 8,              # 8.3 / 8.4
    "python": 3,
    "ruby": 3,
    "node": 22, "nodejs": 22,
    "nginx": 1,            # 1.x line
    "apache": 2,           # 2.x line
    "openssl": 3,
    "mysql": 8,
    "mariadb": 11,
    "postgres": 17, "postgresql": 17,
    "elementor": 4,        # 3.x still active; 4.x plausible
    "elementor-pro": 3,
    "yoast": 23,           # 21-23 recent
    "yoast-seo": 23,
    "woocommerce": 9,
    "contact-form-7": 5,
    "google-site-kit": 1,
    "all-in-one-wp-migration": 7,
    "duplicate-page": 4,
    "health-check": 1,
    "wps-hide-login": 1,
    "drupal": 10,
    "joomla": 5,
    "magento": 2,
    "jenkins": 2,
    "gitlab": 17,
    "grafana": 11,
    "wpforms": 1,          # 1.x free line
    "twentytwentythree": 1,
    "twentytwentyfour": 1,
    "twentytwentyfive": 1,
}


# ── Recommendation generator ────────────────────────────────────────
def _recommendation_for(tech: str, version: str, url: str) -> str:
    """Build the exact next-step command(s) the operator can run to move
    from 'detected' to 'confirmed vulnerable or not'."""
    tech_low = tech.lower()

    if tech_low == "wordpress":
        return (
            f"1) Enumerate plugins/themes/users:\n"
            f"     wpscan --url {url} --enumerate vp,vt,u,cb,dbe "
            f"--random-user-agent\n"
            f"2) Run WP-specific vuln templates:\n"
            f"     nuclei -u {url} -tags wordpress "
            f"-severity medium,high,critical -silent\n"
            f"3) Check core CVEs for {version}:\n"
            f"     https://wpscan.com/wordpresses/{version.replace('.', '')}"
        )
    if tech_low == "php":
        return (
            f"1) Check PHP CVEs for this version:\n"
            f"     nuclei -u {url} -tags php,cve -severity medium,high,critical "
            f"-silent\n"
            f"2) CVE-2024-4577 (PHP-CGI argument injection, ANY 8.x < 8.3.8):\n"
            f"     nuclei -u {url} -id php-cgi-argument-injection\n"
            f"3) Verify version by direct probe:\n"
            f"     curl -sI {url} | grep -i x-powered-by"
        )
    if tech_low in ("nginx", "apache", "openssl"):
        return (
            f"1) Look up CVEs for {tech} {version}: "
            f"https://nvd.nist.gov/vuln/search?query={tech}+{version}\n"
            f"2) Nuclei generic scan:\n"
            f"     nuclei -u {url} -tags {tech_low},cve "
            f"-severity medium,high,critical -silent"
        )
    if tech_low.startswith("elementor"):
        return (
            f"1) Elementor CVE-2022-1329 (unauth RCE ≤3.6.2), CVE-2023-48777 "
            f"(Pro), CVE-2024-32112 (Pro):\n"
            f"     nuclei -u {url} -tags elementor -silent\n"
            f"2) wpscan plugin lookup:\n"
            f"     https://wpscan.com/plugin/elementor"
        )
    if tech_low in ("yoast", "yoast-seo"):
        return (
            f"1) Yoast SEO plugin vulns: https://wpscan.com/plugin/wordpress-seo\n"
            f"2) nuclei -u {url} -tags yoast -silent"
        )
    if tech_low == "google-site-kit":
        return (
            f"1) Google Site Kit CVE-2023-6316 (v1.117.0-1.121.0 auth "
            f"bypass admin takeover). Check version {version} against advisory.\n"
            f"2) https://wpscan.com/plugin/google-site-kit"
        )
    if tech_low == "all-in-one-wp-migration":
        return (
            f"1) All-in-One WP Migration — multiple CVEs (arbitrary file "
            f"upload / SSRF). Check version {version}:\n"
            f"     https://wpscan.com/plugin/all-in-one-wp-migration"
        )
    if tech_low == "wps-hide-login":
        return (
            f"1) WPS Hide Login — historical bypasses via HEAD / non-standard "
            f"headers. Try:\n"
            f"     curl -X HEAD {url}wp-admin/ -I\n"
            f"     curl {url}wp-login.php -H 'X-Original-URL: /wp-admin/'"
        )
    if tech_low in ("woocommerce",):
        return (
            f"1) WooCommerce vulns: https://wpscan.com/plugin/woocommerce\n"
            f"2) nuclei -u {url} -tags woocommerce -silent"
        )
    if tech_low in ("wordpress-plugin", "wordpress-theme"):
        return (
            f"1) WPScan plugin/theme lookup: search {tech_low} at https://wpscan.com/\n"
            f"2) nuclei -u {url} -tags {tech_low} -silent"
        )
    if tech_low in ("jenkins", "gitlab", "grafana", "kibana", "portainer",
                    "adminer", "phpmyadmin", "keycloak", "vault", "consul",
                    "airflow", "metabase"):
        return (
            f"1) Product-specific templates:\n"
            f"     nuclei -u {url} -tags {tech_low} "
            f"-severity medium,high,critical -silent\n"
            f"2) Try default credentials on the login form (LAB ONLY):\n"
            f"     nuclei -u {url} -tags default-login -silent"
        )
    if tech_low in ("drupal", "joomla", "magento", "prestashop", "shopify",
                    "django", "rails", "spring", "laravel", "symfony"):
        return (
            f"1) Framework-specific templates:\n"
            f"     nuclei -u {url} -tags {tech_low} "
            f"-severity medium,high,critical -silent"
        )
    # Generic fallback
    return (
        f"1) Generic CVE lookup:\n"
        f"     nuclei -u {url} -tags {tech_low} "
        f"-severity medium,high,critical -silent 2>/dev/null\n"
        f"2) NVD search: https://nvd.nist.gov/vuln/search?query={tech}+{version}"
    )


# ── Suspect version check ───────────────────────────────────────────
def _suspect_version(tech: str, version: str) -> str:
    """Return a warning string if `version` looks impossibly-newer than
    what LATEST_KNOWN_MAJOR knows, else ''.

    Threshold: major > known (strict — catches WordPress 7.x when known is 6).
    Keep LATEST_KNOWN_MAJOR up-to-date; when a legit new major is released,
    bump the table so real versions stop showing as suspect.
    """
    if not version:
        return ""
    tech_low = tech.lower()
    if tech_low not in LATEST_KNOWN_MAJOR:
        return ""
    m = re.match(r"^(\d+)", version)
    if not m:
        return ""
    try:
        major = int(m.group(1))
    except ValueError:
        return ""
    known = LATEST_KNOWN_MAJOR[tech_low]
    if major > known:
        return (
            f"⚠️ SUSPECT VERSION — detected major {major} is > known latest "
            f"({known} at parser build time). This is likely a mis-parse of "
            f"a plugin/theme version, or the model conflated two tech "
            f"identifiers. Verify with:\n"
            f"     curl -s <url> | grep -iE 'generator|{tech_low}'\n"
            f"If {tech_low} really shipped a newer major, update "
            f"LATEST_KNOWN_MAJOR in agents/fingerprint.py."
        )
    return ""


# ── Parsers ─────────────────────────────────────────────────────────
# Set-Cookie names that give away the framework/CMS
_COOKIE_TECH_HINTS: dict[str, str] = {
    "wordpress_logged_in": "wordpress",
    "wp-settings": "wordpress",
    "wordpress_test_cookie": "wordpress",
    "phpsessid": "php",
    "laravel_session": "laravel",
    "xsrf-token": "framework-hint",
    "django_session": "django",
    "sessionid": "django",
    "csrftoken": "django",
    "_rails_session": "rails",
    "asp.net_sessionid": "iis-aspnet",
    "aspxauth": "iis-aspnet",
    "jsessionid": "java",
    "ci_session": "codeigniter",
    "yiissess": "yii",
    "connect.sid": "express",
    "next-auth.session-token": "nextjs",
    "grafana_session": "grafana",
    "gitlab_session": "gitlab",
    "jenkins-timestamper-offset": "jenkins",
    "jira.rememberme.cookie": "jira",
    "adminer_key": "adminer",
    "pma_lang": "phpmyadmin",
}


def _parse_curl_headers(raw: str, host_url: str) -> list[dict]:
    """Extract tech+version findings from `curl -sI` output. Returns
    dicts with keys: tech, version, evidence, source."""
    out: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Server: nginx/1.18.0 (Ubuntu)  |  Server: Apache/2.4.25 (Debian)
        m = re.match(r"Server:\s*([A-Za-z_-]+)(?:/(\S+))?", line, re.I)
        if m:
            tech = m.group(1).lower()
            version = m.group(2) or ""
            out.append({"tech": tech, "version": version,
                         "evidence": line, "source": "Server header"})
        # X-Powered-By: PHP/8.2.33  |  X-Powered-By: Express
        m = re.match(r"X-Powered-By:\s*([A-Za-z_.-]+)(?:/(\S+))?",
                     line, re.I)
        if m:
            tech = m.group(1).lower()
            version = m.group(2) or ""
            out.append({"tech": tech, "version": version,
                         "evidence": line, "source": "X-Powered-By header"})
        # X-Generator: Drupal 10 (https://...)
        m = re.match(r"X-Generator:\s*([A-Za-z_-]+)\s*(\S+)?",
                     line, re.I)
        if m:
            tech = m.group(1).lower()
            version = (m.group(2) or "").strip("()")
            out.append({"tech": tech, "version": version,
                         "evidence": line, "source": "X-Generator header"})
        # Set-Cookie: WORDPRESS_TEST_COOKIE=xxx; …
        m = re.match(r"Set-Cookie:\s*([A-Za-z0-9_.-]+)=", line, re.I)
        if m:
            cookie_name = m.group(1).lower()
            for hint_prefix, tech in _COOKIE_TECH_HINTS.items():
                if cookie_name.startswith(hint_prefix):
                    out.append({
                        "tech": tech, "version": "",
                        "evidence": line[:150],
                        "source": f"Set-Cookie {cookie_name!r}"})
                    break
    return out


def _parse_html(raw: str) -> list[dict]:
    """Extract tech+version from HTML: <meta generator>, comments,
    /wp-content/plugins/<name>/... ?ver=<version>, /wp-content/themes/<name>/,
    Elementor-specific comments, etc."""
    out: list[dict] = []

    # <meta name="generator" content="WordPress 6.4.5" />
    for m in re.finditer(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            raw, re.I):
        content = m.group(1).strip()
        # Typical: "WordPress 6.4.5", "Drupal 10 (https://...)", "Joomla! 4.4"
        mm = re.match(r"([A-Za-z][A-Za-z0-9!._-]*)\s+([\d.]+)", content)
        if mm:
            out.append({"tech": mm.group(1).lower().rstrip("!"),
                         "version": mm.group(2),
                         "evidence": m.group(0)[:200],
                         "source": "meta generator"})
        else:
            out.append({"tech": content.lower(), "version": "",
                         "evidence": m.group(0)[:200],
                         "source": "meta generator"})

    # /wp-content/plugins/<slug>/...?ver=<version>
    seen_plugin_ver: set[str] = set()
    for m in re.finditer(
        r"/wp-content/plugins/([A-Za-z0-9._-]+)/[^\"'?>\s]+"
        r"(?:\?ver=([\d.]+))?", raw):
        slug = m.group(1).lower()
        ver = m.group(2) or ""
        key = f"{slug}|{ver}"
        if key in seen_plugin_ver:
            continue
        seen_plugin_ver.add(key)
        out.append({"tech": slug, "version": ver,
                     "evidence": m.group(0)[:200],
                     "source": "wp-content/plugins/ asset URL"})

    # /wp-content/themes/<slug>/style.css?ver=<version>
    seen_theme_ver: set[str] = set()
    for m in re.finditer(
        r"/wp-content/themes/([A-Za-z0-9._-]+)/[^\"'?>\s]+"
        r"(?:\?ver=([\d.]+))?", raw):
        slug = m.group(1).lower()
        ver = m.group(2) or ""
        key = f"{slug}|{ver}"
        if key in seen_theme_ver:
            continue
        seen_theme_ver.add(key)
        out.append({"tech": slug, "version": ver,
                     "evidence": m.group(0)[:200],
                     "source": "wp-content/themes/ asset URL"})

    # HTML comments giving away tech: <!-- Elementor 3.16.0 -->,
    # <!-- Powered by Django 4.2 -->, <!-- Generated by Nuxt.js -->
    for m in re.finditer(
        r"<!--\s*(?:Powered by\s+|Generated by\s+)?"
        r"([A-Za-z][A-Za-z0-9!._-]{1,30})\s+([\d.]+)?[^>]*-->",
            raw, re.I):
        name = m.group(1).lower().rstrip("!")
        ver = m.group(2) or ""
        # filter noise words that show up in comments a lot
        if name in {"the", "this", "page", "generated", "powered",
                    "html", "utf", "note", "test", "todo", "fix",
                    "google", "font"}:
            continue
        out.append({"tech": name, "version": ver,
                     "evidence": m.group(0)[:200],
                     "source": "HTML comment"})

    return out


# Strip ANSI escape sequences (nuclei -silent still emits colors by default)
_ANSI_RE = re.compile(r"\x1b\[[\d;]+m")


def _parse_nuclei_tech(raw: str) -> list[dict]:
    """Parse `nuclei -tags tech` output lines. Nuclei emits two shapes:

      [tech-detect:php] [http] [info] http://x/
      [wordpress-detect] [http] [info] http://x/ [WordPress 6.4.5]

    with ANSI colors even under -silent. This parser:
      1. Strips ANSI colors
      2. Regex both shapes: [template](:extractor)? [proto] [severity] URL ([extra])?
      3. tech = extractor when present (e.g. 'dvwa', 'php', 'apachegeneric')
         else the cleaned template id
      4. Filters out non-tech templates (exposed-*, misconfig, cves, etc.)
    """
    out: list[dict] = []
    clean = _ANSI_RE.sub("", raw)
    # Match per line so the optional `[extra]` group cannot swallow the NEXT
    # nuclei line's [template:extractor] as if it were extra of this line.
    line_re = re.compile(
        r"^\[([\w\-]+)(?::([\w\-]+))?\]\s+\[\w+\]\s+\[info\]\s+(\S+)"
        r"(?:[ \t]+\[(.+?)\])?\s*$",
        re.MULTILINE,
    )
    for m in line_re.finditer(clean):
        template = m.group(1)
        extractor = (m.group(2) or "").strip()
        url = m.group(3)
        extra = (m.group(4) or "").strip()

        # Keep only tech-related templates. Everything else (exposed-*,
        # misconfig, http-*, cve-*, default-login, etc.) is not tech ID.
        is_tech_template = (
            template.endswith("-detect")
            or template.endswith("-fingerprints")
            or template in ("tech-detect", "waf-detect",
                             "fingerprinthub-web-fingerprints")
        )
        if not is_tech_template:
            continue

        # Prefer the extractor when present — it names the actual product
        # (e.g. `tech-detect:php` → tech="php"; `fingerprinthub-web-
        # fingerprints:dvwa` → tech="dvwa"). Otherwise clean the template id.
        if extractor:
            tech = extractor.lower()
        else:
            tech = template.replace("-detect", "").replace("-fingerprints", "")\
                            .replace("-", "").lower() or "unknown"

        # Some extractors are noisy generic labels — normalize a few
        if tech in ("apachegeneric",):
            tech = "apache"

        # Version: from [extra] block or embedded in extractor
        version = ""
        for src in (extra, extractor):
            mv = re.search(r"([\d]+\.[\d.]+)", src)
            if mv:
                version = mv.group(1)
                break

        out.append({"tech": tech, "version": version,
                     "evidence": m.group(0),
                     "source": f"nuclei {template}"
                                + (f":{extractor}" if extractor else "")})
    return out


def _looks_like_tech_name(name: str) -> bool:
    """Sanity filter — is `name` plausibly a tech/product/plugin name?

    Reject when it looks like a sentence the model dumped by mistake:
      - contains sentence punctuation (`.`, `;`, `,`, `!`)
      - contains too many hyphens (`no-xss-or-sqli-detected` = 5)
      - is longer than 40 chars
      - is a common English word / prose leftover
    """
    if not name:
        return False
    if len(name) > 40:
        return False
    # Sentence punctuation → clearly prose the model dumped
    if any(c in name for c in ".,;!?"):
        return False
    # Too many hyphens → phrase-like
    if name.count("-") > 4:
        return False
    # Too many spaces → sentence-like ("a very long sentence with lots of words")
    if name.count(" ") > 2:
        return False
    # Common prose leftovers
    bad_words = {"no", "yes", "unknown", "none", "n/a", "na",
                  "detected", "not-detected", "found", "not-found",
                  "vulnerable", "not-vulnerable", "clean", "empty",
                  "the", "this", "that", "and", "or", "but"}
    if name.lower() in bad_words:
        return False
    return True


def _parse_finish_findings(items: list[str]) -> list[dict]:
    """Fall-back extractor from the strings the model returned in
    finish(findings=[...]). These are typically:
      "https://x/ — WordPress 6.4.5"
      "https://x/ — Elementor 4.1.0 (WordPress page builder)"
      "https://x/ — TwentyTwentyThree theme"

    Passes each candidate through _looks_like_tech_name() so long prose
    strings the model sometimes dumps ("no-xss-or-sqli-detected; sqlmap
    reported all-parameters-non-injectable") do NOT become fake "tech
    detected" findings.
    """
    out: list[dict] = []
    for item in items or []:
        s = str(item)
        # Split on em-dash / hyphen / colon
        parts = re.split(r"\s+[—\-–:|]\s+", s, maxsplit=1)
        if len(parts) != 2:
            continue
        rhs = parts[1].strip()
        # WordPress 6.4.5  |  Elementor 4.1.0 (page builder)  |  Yoast SEO 27.6
        mm = re.match(
            r"([A-Za-z][A-Za-z0-9._\s-]+?)\s+([\d]+\.[\d.]+)"
            r"(?:\s+\((.*)\))?\s*$", rhs)
        if mm:
            tech = mm.group(1).strip().lower().replace(" ", "-")
            if not _looks_like_tech_name(tech):
                continue
            ver = mm.group(2)
            extra = mm.group(3) or ""
            out.append({"tech": tech, "version": ver,
                         "evidence": s[:200],
                         "source": f"model finish() {extra}"
                                    if extra else "model finish()"})
        else:
            # No version — take "<name> theme" / "<name> plugin"
            mm2 = re.match(
                r"([A-Za-z][A-Za-z0-9._\s-]+?)\s+(theme|plugin)\s*$", rhs, re.I)
            if mm2:
                tech = mm2.group(1).strip().lower().replace(" ", "-")
                if not _looks_like_tech_name(tech):
                    continue
                out.append({"tech": tech, "version": "",
                             "evidence": s[:200],
                             "source": f"model finish() ({mm2.group(2)})"})
            else:
                tech = rhs.strip().lower().replace(" ", "-")
                if not _looks_like_tech_name(tech):
                    continue
                out.append({"tech": tech, "version": "",
                             "evidence": s[:200],
                             "source": "model finish()"})
    return out


# ── The agent ───────────────────────────────────────────────────────
class FingerprintAgent(BaseAgent):
    NAME = "fingerprint"
    DESCRIPTION = "Deep tech stack detection per live host"
    MAX_ITERATIONS = 8
    TOOL_NAMES = ["run_shell", "http_get", "finish"]
    # after_run() builds its own rich findings — do not duplicate them
    # from the raw strings the model passes to finish(findings=[...]).
    SKIP_AUTO_FINDINGS_FROM_FINISH = True

    SYSTEM_PROMPT = """/no_think

You are the FINGERPRINT AGENT. For each live host discovered by recon,
identify the exact software stack (product, framework, CMS, plugin, version).

Workflow (per host):
  1. curl -s -I -L <url>              (grab Server / X-Powered-By / cookies)
  2. curl -s <url> | head -200        (peek HTML for meta / asset URLs /
                                       comments — enough to see all plugins)
  3. nuclei -u <url> -tags tech -silent -rl 10 -c 10
     (built-in tech-detection templates; one tag call, do NOT chain 20 tags)
  4. finish() with a one-line SUMMARY listing every detected tech name +
     version (or just name if no version). The harness will build rich
     findings automatically from the RAW OUTPUTS of steps 1-3.

Rules:
  - One tool_call per turn. NEVER concatenate 20 tags in a single nuclei call.
  - Focus on IDENTIFICATION. Do NOT test vulnerabilities here.
  - Do NOT try to guess versions from tea leaves — if the version is not
    visible in headers/meta/asset URLs, leave it blank. The harness parses
    the RAW outputs of your curl/nuclei calls to build findings; the LLM
    summary is only for the report narrative.
"""

    def entry_condition(self, state) -> bool:
        return state.has_live_http() or bool(state.get("target"))

    def build_objective(self, state) -> str:
        live = state.get("live_hosts", [])
        hosts_line = ", ".join(
            f"{h.get('scheme', 'https')}://{h.get('host')}"
            for h in live[:5]
        ) or state.get("target")
        return (
            f"Live hosts to fingerprint (first few): {hosts_line}\n"
            f"Target: {state.get('target')}\n\n"
            "Identify tech stack per host. Finish with a summary."
        )

    def after_run(self, state, transcript):
        """Deterministic parse of every raw curl / nuclei output in the
        transcript. Generates one `info` finding per (tech, version) with:
          - title       : <Tech> <version> detected on <host>  [SUSPECT?]
          - evidence    : the raw line + source (Server / meta / asset URL / …)
          - recommendation : the exact command(s) to move from detected →
                              confirmed vulnerable or not.

        Also populates state.detected_techs with ALL techs (lowercase,
        deduped) so downstream agents (web_vuln, api_fuzzer, extension
        techniques' applies_when) see the full stack, not just the ones
        matching TECH_KEYWORDS.
        """
        primary_url = _first_live_url(state)
        aggregated: list[dict] = []

        for entry in transcript:
            result = str(entry.get("result", ""))
            args = entry.get("args", {}) or {}
            if entry.get("tool") == "run_shell":
                cmd = str(args.get("command", "")).lower()
                if "curl" in cmd and (" -i " in cmd or "-si" in cmd
                                        or "--head" in cmd):
                    aggregated.extend(_parse_curl_headers(result, primary_url))
                if "curl" in cmd and " -i " not in cmd and "-si" not in cmd:
                    # curl -s <url> → HTML body
                    aggregated.extend(_parse_html(result))
                if "nuclei" in cmd:
                    aggregated.extend(_parse_nuclei_tech(result))
            elif entry.get("tool") == "http_get":
                # http_get result starts with "HTTP <code>\nHeaders: {...}\n
                # Body (...): <body>". Feed the whole thing to both parsers.
                aggregated.extend(_parse_curl_headers(result, primary_url))
                aggregated.extend(_parse_html(result))

        # Fold in techs the model itself mentioned in its finish() summary
        # (or findings=[]) — captures plugins/themes our raw parsers missed.
        finish_findings_extras = _parse_finish_findings(
            getattr(self, "finish_findings", []) or [])
        aggregated.extend(finish_findings_extras)

        # Fallback keyword scan across everything (never enough on its own,
        # but catches products spoken about in HTML text)
        joined_text = "\n".join(
            str(e.get("result", "")) for e in transcript).lower()
        for kw in TECH_KEYWORDS:
            if kw in joined_text and not any(
                    d["tech"] == kw for d in aggregated):
                aggregated.append({"tech": kw, "version": "",
                                    "evidence": f"keyword '{kw}' present in "
                                                 f"transcript",
                                    "source": "keyword scan"})

        # Deduplicate by (tech, version), preserving the FIRST occurrence
        # (usually the most authoritative — Server / meta before HTML noise)
        seen: set[tuple[str, str]] = set()
        deduped: list[dict] = []
        for d in aggregated:
            key = (d["tech"], d["version"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(d)

        # Populate state.detected_techs with ALL techs seen (name only,
        # lowercase, deduped, ignoring version)
        state.extend("detected_techs",
                      sorted({d["tech"] for d in deduped
                              if d["tech"] and len(d["tech"]) < 40}))

        # Emit one info finding per (tech, version)
        for d in deduped:
            tech = d["tech"]
            version = d["version"]
            source = d["source"]
            ev = d["evidence"]
            title_ver = f" {version}" if version else ""
            suspect = _suspect_version(tech, version)
            suspect_tag = "  [SUSPECT VERSION]" if suspect else ""
            title = f"{tech}{title_ver} detected on {primary_url}{suspect_tag}"
            rec = _recommendation_for(tech, version, primary_url)
            if suspect:
                rec = f"{suspect}\n\n{rec}"
            state.add_finding(
                agent=self.NAME,
                severity="info",
                title=title[:200],
                evidence=f"({source}) {ev}"[:2000],
                recommendation=rec,
            )


def _first_live_url(state) -> str:
    live = state.get("live_hosts", [])
    if live:
        h = live[0]
        return f"{h.get('scheme', 'https')}://{h.get('host')}"
    return state.get("target") or ""
