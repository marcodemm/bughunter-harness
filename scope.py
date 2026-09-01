"""Scope allowlist. One host or wildcard per line in scope.txt.

Supported entries:
  - exact host: example.com  (matches only "example.com")
  - wildcard subdomain: *.example.com  (matches any sub of example.com, NOT the apex)
  - exact IP: 10.0.0.1
  - CIDR: 10.0.0.0/24
  - explicit apex + wildcard: both lines needed if you want both
Lines starting with # are ignored.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path


class ScopeChecker:
    def __init__(self, scope_file: str | None = None,
                 patterns: list[str] | None = None):
        """Init from either a scope_file path OR an inline list of patterns.
        If both are given, `patterns` takes precedence (CLI --scope override)."""
        self.hosts: set[str] = set()
        self.wildcards: list[str] = []
        self.networks: list[ipaddress._BaseNetwork] = []
        self.path: Path | None = None

        if patterns:
            self._ingest_lines(patterns)
        elif scope_file:
            self.path = Path(scope_file)
            if not self.path.is_absolute():
                self.path = (Path(__file__).resolve().parent / scope_file).resolve()
            self._load_file()

    def _load_file(self) -> None:
        if not self.path.exists():
            # No scope file: load empty. The harness's scope_enforcement
            # decides whether that is fatal (strict) or just relaxes the gate.
            return
        self._ingest_lines(self.path.read_text(encoding="utf-8").splitlines())

    def _ingest_lines(self, lines: list[str]) -> None:
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("*."):
                self.wildcards.append(line[2:].lower())
                continue
            # CIDR?
            if "/" in line:
                try:
                    self.networks.append(ipaddress.ip_network(line, strict=False))
                    continue
                except ValueError:
                    pass
            self.hosts.add(line.lower())

    def is_in_scope(self, host: str) -> bool:
        if not host:
            return False
        host = host.strip().lower().rstrip(".")
        # Direct hit
        if host in self.hosts:
            return True
        # Wildcard subdomain match
        for w in self.wildcards:
            if host.endswith("." + w) or host == w:
                # "*.example.com" matches "a.example.com" but ALSO
                # allow the apex if the user listed both entries.
                return True
        # CIDR
        try:
            ip = ipaddress.ip_address(host)
            for net in self.networks:
                if ip in net:
                    return True
        except ValueError:
            pass
        return False
