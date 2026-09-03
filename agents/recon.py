"""Recon Agent — passive + active reconnaissance.

Objective: enumerate subdomains, live hosts, DNS records and open ports.
Populates shared_state with:
  subdomains, live_hosts (with tech hints)
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from agents.base import BaseAgent


class ReconAgent(BaseAgent):
    NAME = "recon"
    DESCRIPTION = "Subdomain + host + port enumeration"
    MAX_ITERATIONS = 10
    TOOL_NAMES = ["run_shell", "http_get", "finish"]

    SYSTEM_PROMPT = """/no_think

You are the RECONNAISSANCE AGENT of a bug-bounty pipeline. Your ONLY job is
to enumerate the attack surface — subdomains, live hosts, open ports.
DO NOT test vulnerabilities. That is another agent's job.

Workflow (execute these tool_calls in order, then finish):
  1. subfinder -d <apex-domain> -silent
  2. dnsx -l <subs-file> -a -aaaa -silent            (if dnsx available)
  3. httpx -l <subs-file> -silent -status-code -title -tech-detect -json
     ↑ IMPORTANT: run WITHOUT -o <file>. The harness parses httpx's stdout
       — using -o silences stdout and the harness sees nothing.
     ↑ IMPORTANT: DO NOT filter the output by status_code (no `jq
       'select(.status_code >= 200 and .status_code < 400)'`). Hosts that
       answer 401 or 403 are AUTH-PROTECTED — MORE interesting than a
       plain 200 (they hide something). Keep them all.
  4. naabu -host <apex> -top-ports 100 -silent       (if naabu available)
  5. finish() with a short summary listing subs/live hosts count

Rules:
  - One tool_call per turn. NEVER duplicate tool_calls.
  - Use scope-only targets. In-scope hosts are already known to you via the
    initial user message.
  - Save intermediate output to /tmp/harness-recon-<random>.txt if you need
    to pipe between tools.
  - After 6-8 tool_calls, call finish() with the count of live hosts found.
"""

    def build_objective(self, state) -> str:
        target = state.get("target")
        in_scope = state.get("in_scope_hosts", [])
        apex = _extract_apex(target)
        # If the target is localhost / IP / private range, subfinder makes
        # no sense. Instruct the model to skip it and go straight to
        # httpx / probe of the given URL.
        local_target = _is_local_or_ip(target)
        if local_target:
            return (
                f"Target: {target}\n"
                f"NOTE: Target is a LOCAL / IP-BASED host — do NOT run "
                f"subfinder / dnsx / naabu against it (no subdomains apply). "
                f"Instead:\n"
                f"  1. curl -sI {target}          (headers, quick check)\n"
                f"  2. httpx -u {target} -silent -status -title -tech-detect "
                f"-json    (fingerprint)\n"
                f"  3. finish() with the target as the single live host.\n"
                f"Do NOT loop trying subfinder variants — it will never work "
                f"on localhost/IP."
            )
        return (
            f"Target: {target}\n"
            f"Apex domain: {apex}\n"
            f"In-scope hostnames/patterns: {in_scope}\n\n"
            "Enumerate subdomains + live HTTP hosts + open ports. "
            "Finish when you have a live-hosts list."
        )

    def after_run(self, state, transcript):
        subs: set[str] = set()
        live: list[dict] = []
        # Track file paths the model may have redirected httpx output to
        # with `-o /tmp/…json`. If we see one, we'll read it after the loop
        # to recover records the model may have filtered out with jq.
        httpx_out_files: set[str] = set()
        import json as _j

        for entry in transcript:
            if entry.get("tool") != "run_shell":
                continue
            result = str(entry.get("result", ""))
            cmd = str(entry.get("args", {}).get("command", ""))
            # subfinder / dnsx / naabu → any bare host per line
            if "subfinder" in cmd or "dnsx" in cmd:
                for m in re.finditer(r"^([a-z0-9._-]+\.[a-z]{2,})\s*$",
                                     result, re.MULTILINE | re.IGNORECASE):
                    subs.add(m.group(1).lower())
            # httpx json output — parse EVERY JSON line in the raw result,
            # regardless of status_code. 401/403 are auth-protected =
            # interesting; 200 is public; keep both.
            if "httpx" in cmd and "-json" in cmd:
                # Capture any file the model wrote httpx output to, so the
                # fallback can read it even when the model then filtered
                # with `jq 'select(.status < 400)'` (which drops the
                # juicy 401/403 hosts). Match both httpx `-o file` AND
                # shell redirects `> file` / `>> file`.
                for m in re.finditer(r"(?:-o|>>?)\s+(\S+)", cmd):
                    httpx_out_files.add(m.group(1))
                for line in result.splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        rec = _j.loads(line)
                    except Exception:
                        continue
                    _append_httpx_record(live, rec)
            # naabu → host:port
            if "naabu" in cmd:
                for m in re.finditer(r"^([a-z0-9._-]+):(\d+)\s*$",
                                     result, re.MULTILINE | re.IGNORECASE):
                    live.append({
                        "host": m.group(1).lower(),
                        "port": int(m.group(2)),
                        "scheme": "tcp",
                    })

        # Fallback: recover records from httpx `-o <file>` when the model
        # silenced stdout. Also protects against `jq 'select(.status < 400)'`
        # filtering — reading the raw file gets us EVERY record httpx wrote.
        for path in httpx_out_files:
            try:
                from pathlib import Path as _P
                p = _P(path)
                if not p.is_file() or p.stat().st_size > 20 * 1024 * 1024:
                    continue  # 20 MB safety cap
                for line in p.read_text(encoding="utf-8",
                                          errors="ignore").splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        rec = _j.loads(line)
                    except Exception:
                        continue
                    _append_httpx_record(live, rec)
            except Exception:
                pass  # never let a file read break the pipeline

        # Deduplicate live hosts by (host, port|scheme) — the fallback file
        # read may re-add records the stdout parser already saw.
        seen: set[tuple] = set()
        deduped: list[dict] = []
        for h in live:
            key = (str(h.get("host", "")).lower(),
                   h.get("port"), h.get("scheme"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(h)
        live = deduped

        if subs:
            state.extend("subdomains", sorted(subs))
        if live:
            state.extend("live_hosts", live)
            # Propagate tech hints from httpx directly
            techs: set[str] = set()
            for h in live:
                for t in h.get("tech", []) or []:
                    techs.add(str(t).lower())
            if techs:
                state.extend("detected_techs", sorted(techs))

        # Shodan InternetDB enrichment (2026-09-03): populate each
        # live_host with passive intel (ports/CVEs/tags/vulns/hostnames)
        # from Shodan's free InternetDB. Zero cost (no key, no throttle),
        # so we do it unconditionally unless disabled in config.
        # sub_prioritizer picks these up as a new signal.
        self._enrich_with_shodan_internetdb(state)

        # B2 fallback (2026-09-03): si tras parsear TODO no hay live_hosts
        # pero el target original es http/https, meterlo como live host de
        # oficio. Sin esto, sub_prioritizer skipea y toda la pipeline
        # downstream (fingerprint/content_discovery/web_vuln) opera con
        # live_hosts=[] aunque el target claramente respondia — visto en
        # run 20260903T094840Z: httpx tool call devolvia (no exit) por bug
        # B3, transcript vacio, y el target respondia HEAD 200 a ojos del
        # operador. Este fallback rompe el fallo silencioso.
        if not state.get("live_hosts") and state.get("target"):
            try:
                p = urlparse(state.get("target"))
                if p.scheme in ("http", "https") and p.hostname:
                    host_str = p.hostname + (f":{p.port}" if p.port else "")
                    state.extend("live_hosts", [{
                        "host": host_str,
                        "scheme": p.scheme,
                        "status": None,
                        "title": "",
                        "tech": [],
                        "source": "recon-fallback",
                    }])
                    state.log(self.NAME, "info",
                              f"live_hosts empty after httpx parse; added "
                              f"target '{host_str}' as fallback live host "
                              f"so downstream agents don't skip on gate")
            except Exception:
                pass


    def _enrich_with_shodan_internetdb(self, state) -> None:
        """For each live_host, resolve to an IP and hit Shodan InternetDB
        (free, no API key). Populate host_record['shodan'] with:
            {ip, ports, cpes, vulns, tags, hostnames}
        so sub_prioritizer can bump scores on hosts with known CVEs or
        juicy tags. On any failure the field is simply not set — never
        breaks the pipeline.
        """
        if not (self.cfg.get("shodan") or {}).get(
                "internetdb_enabled", True):
            return
        import ipaddress as _ip
        import socket as _sock
        try:
            import requests as _rq
        except Exception:
            return
        for h in state.get("live_hosts") or []:
            host = str(h.get("host", "")).split(":", 1)[0]
            if not host:
                continue
            # Already enriched (e.g. from a previous pass in multi-host)?
            if h.get("shodan"):
                continue
            # Resolve to IP if hostname
            try:
                _ip.ip_address(host)
                ip = host
            except ValueError:
                try:
                    ip = _sock.gethostbyname(host)
                except (_sock.gaierror, _sock.herror, OSError):
                    continue
            try:
                r = _rq.get(f"https://internetdb.shodan.io/{ip}",
                             timeout=8)
                if r.status_code == 200:
                    data = r.json()
                    h["shodan"] = {
                        "ip": ip,
                        "ports": data.get("ports") or [],
                        "cpes": data.get("cpes") or [],
                        "vulns": data.get("vulns") or [],
                        "tags": data.get("tags") or [],
                        "hostnames": data.get("hostnames") or [],
                    }
                elif r.status_code == 404:
                    h["shodan"] = {"ip": ip, "not_indexed": True}
            except _rq.RequestException:
                continue
            except Exception:
                continue
        # Aggregate a summary log for the report / audit
        enriched = sum(1 for h in (state.get("live_hosts") or [])
                       if h.get("shodan") and not
                       h["shodan"].get("not_indexed"))
        if enriched:
            state.log(self.NAME, "shodan",
                       f"InternetDB enriched {enriched} live_host(s) with "
                       f"passive intel (ports/CVEs/tags)")


def _append_httpx_record(live: list, rec: dict) -> None:
    """Extract a single httpx JSON record into a live_hosts dict entry.
    Does NOT filter by status_code — 401/403 auth-protected hosts are
    kept because they are MORE interesting than a public 200 (they hide
    something)."""
    host = rec.get("host") or rec.get("input") or ""
    if not host:
        return
    live.append({
        "host": host,
        "scheme": rec.get("scheme", "https"),
        "status": rec.get("status_code") or rec.get("status-code"),
        "title": rec.get("title", ""),
        "tech": rec.get("tech") or rec.get("technologies") or [],
    })


def _extract_apex(target: str) -> str:
    try:
        host = urlparse(target).hostname or target
    except Exception:
        host = target
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _is_local_or_ip(target: str) -> bool:
    """True if target is localhost, an IP address, or a private/reserved
    range where subfinder-style DNS enumeration makes no sense."""
    import ipaddress as _ip
    try:
        host = urlparse(target).hostname or target
    except Exception:
        host = target
    host = (host or "").lower().strip()
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return True
    if host.endswith(".local"):
        return True
    # IP literal?
    try:
        addr = _ip.ip_address(host)
        return addr.is_loopback or addr.is_private or addr.is_reserved
    except ValueError:
        pass
    return False
