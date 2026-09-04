"""Tech alias resolver — PN17 iter 10 (2026-09-04).

nuclei-templates uses several detector template names that are NOT the
tech's canonical name — they're the detection strategy. Downstream code
(sanity checks, entry_conditions, dedup) expects the canonical name,
so an alias table maps the detector form → the tech it detects.

Example fallout when this doesn't run:
  fingerprint emits `version_by_css:7.0.4` (nuclei's WordPress detector
  that reads `?ver=…` from CSS asset URLs). state.detected_techs then
  carries `version_by_css:7.0.4` — not `wordpress:7.0.4`. The wordpress
  agent's `entry_condition` calls `state.has_tech("wordpress")` which
  literal-substring-matches → False → WordPress agent SKIPPED even
  though `/wp-admin/install.php` is in endpoints and the fingerprint
  narrative says literally "running WordPress 7.0.4".

The resolver is called from:
  - shared_state.has_tech()          → alias-resolves before matching
  - report._dedup_techs_for_display  → alias-resolves before deduping
  - report meta-check version sanity → alias-resolves before range check
"""
from __future__ import annotations

# Static exact-match aliases (detector template → canonical tech).
# Keys are lowercased; values are the canonical product slug the tech
# actually is.
_STATIC_ALIASES: dict[str, str] = {
    # WordPress detection templates
    "version_by_css": "wordpress",
    "wordpress-detect:version_by_css": "wordpress",
    "wordpress-detect:generator": "wordpress",
    "wordpress-detect:wp-json": "wordpress",
    "wordpress-detect:readme": "wordpress",
    "wp_generator": "wordpress",
    "wp-generator": "wordpress",
    # Generic anti-patterns
    "httpd": "apache-http-server",
    # Common WAF/CDN detectors emitting a family name
    "waf-detect:modsecurityowasp": "modsecurity",
    "waf-detect:modsecurity": "modsecurity",
    "waf-detect:cloudflare": "cloudflare",
}

# Prefix aliases: template name is `<prefix>:<product>` and we want the
# product portion. Handles `favicon-detect:plesk` → `plesk`,
# `waf-detect:cloudflare` → `cloudflare`, etc. Order matters — first
# match wins.
_PREFIX_ALIASES: tuple[str, ...] = (
    "favicon-detect:",
    "waf-detect:",
    "wordpress-plugin-detect:",
    "wordpress-theme-detect:",
    "tech-detect:",
)


def resolve_tech_alias(name: str) -> str:
    """Return the canonical tech name for `name`, or the lowercased
    input unchanged when no alias applies. Preserves any `:version`
    suffix.

    Always returns lowercase — the resolver's contract is that its
    output is the canonical representation, so downstream key-based
    comparisons (dedup, sanity range check, has_tech match) don't
    need to re-lowercase.

    Examples:
      'version_by_css:7.0.4'                    → 'wordpress:7.0.4'
      'wordpress-detect:version_by_css'         → 'wordpress'
      'favicon-detect:plesk'                    → 'plesk'
      'wordpress-plugin-detect:elementor-pro'   → 'elementor-pro'
      'tech-detect:google-tag-manager'          → 'google-tag-manager'
      'httpd'                                   → 'apache-http-server'
      'WordPress:7.0.4'                         → 'wordpress:7.0.4'
      'nginx:1.24.0'                            → 'nginx:1.24.0'  (unchanged)
    """
    if not name:
        return name
    lo = str(name).strip().lower()
    if not lo:
        return lo

    # Split :version suffix (kept)
    base, sep, version = lo.partition(":")

    # First try the FULL string (some aliases include the colon segment)
    if lo in _STATIC_ALIASES:
        return _STATIC_ALIASES[lo]
    # Then try just the base (before the version suffix)
    if base in _STATIC_ALIASES:
        resolved = _STATIC_ALIASES[base]
        return f"{resolved}:{version}" if version and sep else resolved

    # Prefix aliases: `<known-prefix>:<product>[:version]`
    for prefix in _PREFIX_ALIASES:
        if lo.startswith(prefix):
            rest = lo[len(prefix):]
            if not rest:
                return lo
            # rest may be `product` or `product:version`
            rb, rsep, rver = rest.partition(":")
            if rver and rsep:
                return f"{rb}:{rver}"
            return rb

    # No alias — return the lowercased input for consistency
    return lo


def resolve_tech_aliases(names) -> list[str]:
    """Vectorised form of resolve_tech_alias — returns a new list, same
    order, with each name alias-resolved. Duplicates that emerge post-
    resolution are NOT collapsed here (that's `_dedup_techs_for_display`
    or the caller's job); this function's contract is 1-to-1 mapping."""
    return [resolve_tech_alias(n) for n in (names or [])]
