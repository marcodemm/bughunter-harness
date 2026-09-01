"""Redact secrets from tool output before it goes back to the LLM or to logs.

Never trust the model with raw tokens. Redact aggressively; the model can still
reason about "there is a JWT here" without seeing the token itself.
"""
from __future__ import annotations

import re

# (pattern, replacement) — order matters: longer/more specific first.
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # AWS
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA<REDACTED-16>"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "ASIA<REDACTED-16>"),
    # Google API
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "AIza<REDACTED-35>"),
    # Stripe
    (re.compile(r"sk_live_[0-9a-zA-Z]{20,}"), "sk_live_<REDACTED>"),
    (re.compile(r"sk_test_[0-9a-zA-Z]{20,}"), "sk_test_<REDACTED>"),
    # GitHub
    (re.compile(r"ghp_[0-9A-Za-z]{30,}"), "ghp_<REDACTED>"),
    (re.compile(r"github_pat_[0-9A-Za-z_]{50,}"), "github_pat_<REDACTED>"),
    # Slack
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{20,}"), "xox<REDACTED>"),
    # JWT (three base64url segments)
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}"
                r"\.[A-Za-z0-9_\-]{10,}"),
     "eyJ<REDACTED-JWT>"),
    # PEM keys
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?"
                r"-----END [A-Z ]+PRIVATE KEY-----"),
     "-----BEGIN PRIVATE KEY-----<REDACTED>-----END PRIVATE KEY-----"),
    # Set-Cookie session values (keep name, drop value)
    (re.compile(r"(Set-Cookie:\s*[A-Za-z0-9_\-]+=)[^;\s]{8,}"),
     r"\1<REDACTED>"),
    # Authorization header values
    (re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9_\-\.]{16,}"),
     r"\1<REDACTED>"),
    # Basic auth
    (re.compile(r"(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]{8,}"),
     r"\1<REDACTED>"),
    # SSNs, credit cards (rough)
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<REDACTED-SSN>"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "<REDACTED-CARD>"),
    # Email addresses (leave first char + domain)
    (re.compile(r"([A-Za-z0-9])[A-Za-z0-9._%+\-]+(@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"),
     r"\1<REDACTED>\2"),
]


def redact(text: str) -> str:
    if not text:
        return ""
    out = text
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    return out
