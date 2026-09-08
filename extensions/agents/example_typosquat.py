"""Typosquat / phishing-lookalike extension agent (iter 14, 2026-09-04).

Runs `dnstwist --registered --format json` against the target's apex
domain to enumerate permutations (bit-flips, character-omissions,
typo-additions, homoglyphs, TLD-swaps) that are ACTUALLY registered
and resolve today. Two uses in bug bounty:

  1. Phishing intel — a registered `d0main.com` / `domaln.com` /
     `domain-com.net` for a target whose real apex is `domain.com`
     is a phishing candidate. Some programs (fintech, healthcare)
     accept these as Low/Medium reports.
  2. Takeover pivots — an EXPIRED-then-parked lookalike whose CNAME
     still points to an unclaimed third-party service is a classic
     subdomain-takeover primitive on a sibling domain.

Position: right after `recon` (needs the target's apex, doesn't
need live_hosts). Runs in parallel-friendly order.

Deterministic (no LLM turns).

Skips itself cleanly when:
  - dnstwist not installed (state.missing_tools).
  - Target is a bare IP / localhost / private range (no apex to
    permute).
  - state.target_unreachable is set (nothing to base it on).

Publishes to state on success:
  - typosquat_candidates  (list of {domain, dns_a, ns, mx, whois_created})

Config knobs (config.yaml → typosquat.*):
  typosquat:
    enabled: true            # opt-out
    timeout_sec: 300         # dnstwist over the wire is slow
    max_permutations: 200    # cap to avoid runaway
    include_unregistered: false
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from urllib.parse import urlparse

from agents.base import BaseAgent


class TyposquatAgent(BaseAgent):
    NAME = "typosquat"
    DESCRIPTION = "OSINT — dnstwist for phishing-lookalike domains"
    ENTRY_AFTER = "recon"
    MAX_ITERATIONS = 0
    TOOL_NAMES = ["finish"]  # unused — deterministic

    def entry_condition(self, state) -> bool:
        cfg = (self.cfg.get("typosquat") or {}) if hasattr(self, "cfg") else {}
        if not cfg.get("enabled", True):
            return False
        missing = state.get("missing_tools") or []
        if "dnstwist" in missing:
            return False
        if state.get("target_unreachable"):
            return False
        apex = _extract_apex(state.get("target") or "")
        if not apex:
            return False
        # Skip localhost / IP-only targets (no apex to twist)
        if _is_ip_or_local(apex):
            return False
        return True

    def run(self, state) -> str:
        started = time.time()
        self._emit("start", description=self.DESCRIPTION, max_iterations=1)
        try:
            cfg = (self.cfg.get("typosquat") or {}) if hasattr(self, "cfg") else {}
            timeout = int(cfg.get("timeout_sec", 300))
            max_perm = int(cfg.get("max_permutations", 200))
            include_unregistered = bool(cfg.get("include_unregistered", False))

            if shutil.which("dnstwist") is None:
                state.log(self.NAME, "info",
                          "dnstwist not on PATH — skipping "
                          "(install: `pipx install dnstwist`).")
                self._emit("done", elapsed=time.time() - started,
                           tool_calls=0, turns=0)
                state.mark_agent_run(self.NAME, "skipped",
                                     time.time() - started, 0, 0,
                                     reason="dnstwist not installed")
                return "skipped"

            apex = _extract_apex(state.get("target") or "")
            cmd = ["dnstwist", "--format", "json"]
            if not include_unregistered:
                cmd.append("--registered")
            cmd.append(apex)
            state.log(self.NAME, "info",
                      f"dnstwist enumerating permutations of `{apex}` "
                      f"(--registered={not include_unregistered}, "
                      f"timeout {timeout}s)")

            try:
                proc = subprocess.run(cmd, capture_output=True,
                                       text=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                state.log(self.NAME, "warn",
                          f"dnstwist timed out after {timeout}s — "
                          f"no partial output usable.")
                self._emit("done", elapsed=time.time() - started,
                           tool_calls=1, turns=1)
                state.mark_agent_run(self.NAME, "error",
                                     time.time() - started, 1, 1,
                                     reason="dnstwist timeout")
                return "error"

            candidates: list[dict] = []
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    parsed = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    # dnstwist occasionally prefixes output with progress
                    # lines; strip everything before the first `[`.
                    idx = proc.stdout.find("[")
                    parsed = (json.loads(proc.stdout[idx:])
                              if idx >= 0 else [])
                dropped_subdomain_fp = 0
                for row in (parsed or [])[:max_perm]:
                    dom = row.get("domain") or row.get("domain-name")
                    if not dom or dom == apex:
                        continue
                    fuzzer = row.get("fuzzer") or row.get("fuzzer-type") or ""
                    # PN21 iter 14 (2026-09-05): dnstwist's `subdomain`
                    # fuzzer splits the original domain arbitrarily and
                    # checks whether "<left>.<right>" resolves as a
                    # subdomain of a REAL "<right>" domain. When the
                    # split's right half is itself a valid registered
                    # 2LD (e.g. some real country-code 2LDs happen to
                    # be word-shaped and appear inside longer english
                    # words), the finding is `<fragment>.<other-real-
                    # domain>` — an unrelated subdomain of an unrelated
                    # domain, NOT a typosquat of the original. Drop
                    # these by requiring the 2LD of the candidate to
                    # match the 2LD of the original apex.
                    if fuzzer == "subdomain":
                        if _2ld(dom) != _2ld(apex):
                            dropped_subdomain_fp += 1
                            continue
                    dns_a = row.get("dns_a") or row.get("dns-a") or []
                    ns = row.get("dns_ns") or row.get("dns-ns") or []
                    mx = row.get("dns_mx") or row.get("dns-mx") or []
                    who = (row.get("whois_created")
                           or row.get("whois-created") or "")
                    candidates.append({
                        "domain": dom,
                        "fuzzer": fuzzer,
                        "dns_a": dns_a if isinstance(dns_a, list)
                                 else [dns_a],
                        "ns": ns if isinstance(ns, list) else [ns],
                        "mx": mx if isinstance(mx, list) else [mx],
                        "whois_created": who,
                    })
                if dropped_subdomain_fp:
                    state.log(self.NAME, "info",
                               f"dropped {dropped_subdomain_fp} `subdomain`-"
                               f"fuzzer FP(s) whose 2LD doesn't match `{apex}` "
                               f"(these are subs of unrelated real domains, "
                               f"not typosquats of the target).")

            state.set("typosquat_candidates", candidates)
            state.log(self.NAME, "info",
                      f"dnstwist: {len(candidates)} registered "
                      f"permutation(s) of `{apex}` found.")

            elapsed = time.time() - started
            self._emit("progress", turn=1, max_turns=1)
            self._emit("done", elapsed=elapsed, tool_calls=1, turns=1)
            state.mark_agent_run(self.NAME, "done", elapsed, 1, 1)
            return "done"
        except Exception as e:
            state.error(self.NAME, str(e))
            self._emit("error", err=str(e))
            state.mark_agent_run(self.NAME, "error",
                                 time.time() - started, 0, 0)
            return "error"


def _extract_apex(target: str) -> str:
    """Return the registrable apex (e.g. `example.com` from
    `https://www.sub.example.com/path`). Best-effort: doesn't parse
    the Public Suffix List — assumes the last 2 labels are the apex,
    which is right for `.com`/`.org`/`.net`/etc. but wrong for
    `.co.uk`. Good enough for a first pass; refine if needed."""
    if not target:
        return ""
    parsed = urlparse(target if "://" in target else "http://" + target)
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) < 2:
        return ""
    return ".".join(parts[-2:])


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# Common multi-part TLDs where the "2LD" concept needs 3 labels
# (e.g. `example.co.uk`, `example.com.br`). Best-effort — not a full
# PSL parse. Add more as we run into false positives.
_MULTIPART_TLDS = {
    "co.uk", "co.jp", "co.kr", "co.nz", "co.za",
    "com.br", "com.mx", "com.ar", "com.au", "com.pe",
    "com.co", "com.tr", "com.tw", "com.hk",
    "org.uk", "gov.uk", "ac.uk", "net.au",
}


def _2ld(host: str) -> str:
    """Return the second-level registrable part of `host` — a poor-
    man's PSL. `www.example.com` → `example.com`, `sub.example.co.uk`
    → `example.co.uk`. When the last two labels match a known
    multi-part TLD, keep the third label; else keep the last two."""
    if not host:
        return ""
    parts = host.lower().strip(".").split(".")
    if len(parts) < 2:
        return host.lower()
    last2 = ".".join(parts[-2:])
    if last2 in _MULTIPART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def _is_ip_or_local(host: str) -> bool:
    if not host:
        return True
    if _IP_RE.match(host):
        return True
    return host.lower() in ("localhost", "127.0.0.1", "::1")
