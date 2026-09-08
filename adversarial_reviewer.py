"""Adversarial finding reviewer — post-pipeline gate.

For each finding in state.findings with severity >= min_severity, this
module sends the finding to an LLM with an adversarial-verification prompt.
Only findings the LLM confirms with `VERDICT: PASS` survive the gate;
`VERDICT: REJECT` findings are moved to state.rejected_findings (still
visible in REPORT.md but not surfaced to notification channels).

By default the reviewer uses the SAME LLM as the main pipeline (works fine
on single-slot LM Studio). Override adversarial_review.model / servertype /
base_url in config.yaml to use a different backend (e.g. cloud Sonnet to
review local Qwen findings).

Cost budget guardrails (config.yaml → adversarial_review.*):
  - enabled              → hard toggle
  - min_severity         → only findings ≥ this severity go through review
  - max_findings         → cap so a runaway run doesn't cost 200 LLM calls
  - reject_action        → "hide" (move to rejected list) | "flag" (keep + mark)
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from openai import OpenAI

import llm_backend


DEFAULT_PROMPT = """/no_think

You are an ADVERSARIAL REVIEWER of a bug-bounty finding produced by an
automated pentest pipeline. Your job is to REJECT weak / speculative /
non-actionable findings BEFORE they reach the researcher's inbox.

APPLY THIS 7-QUESTION GATE. The finding must pass ALL 7 or you REJECT it.

  1. Is there a SPECIFIC endpoint, parameter, or asset named — not "the app
     could be vulnerable to X"?
  2. Is the impact concrete and demonstrable — not "an attacker might"?
  3. Is the claimed severity matched by the evidence? (No "critical missing
     header", no "high self-XSS".)
  4. Would a triager reproduce this with the evidence alone, without asking
     for more info?
  5. Is it in-scope for a real bug-bounty program — not an informative-only
     issue class (SPF/DMARC missing, HTTPS not redirected, EXIF metadata,
     verbose stack trace on 404, missing security headers alone…)?
  6. Would the program actually pay for it? (No clickjacking on non-sensitive
     pages, no self-XSS, no info disclosure of framework version alone.)
  7. Is it NOT a known duplicate class heavily covered by every scanner
     (missing X-Frame-Options / referrer-policy alone, server banner
     disclosure alone…)?

FORMAT YOUR RESPONSE EXACTLY:
  VERDICT: PASS | REJECT
  REASON: <one sentence>

Nothing else. No preamble. No markdown. No bullet points.
"""


SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class AdversarialReviewer:
    """Runs one LLM call per eligible finding and updates SharedState in place."""

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}
        rev_cfg = self.cfg.get("adversarial_review") or {}
        self.enabled = bool(rev_cfg.get("enabled", True))
        self.min_severity = str(rev_cfg.get("min_severity", "medium")).lower()
        self.max_findings = int(rev_cfg.get("max_findings", 20))
        self.reject_action = str(rev_cfg.get("reject_action", "hide")).lower()
        if self.reject_action not in ("hide", "flag"):
            self.reject_action = "hide"

        # Resolve the reviewer's LLM backend. If any of servertype/base_url/
        # api_key/api_key_env/model is set in adversarial_review.*, we build
        # a synthetic config for llm_backend.resolve() with those overrides.
        # Otherwise we reuse the exact same backend as the main pipeline —
        # this is the default and works fine on a single-slot LM Studio.
        rev_overrides: dict = {}
        for k in ("servertype", "base_url", "api_key", "api_key_env", "model"):
            v = rev_cfg.get(k)
            if v:
                rev_overrides[k] = v

        if rev_overrides:
            synthetic = dict(self.cfg)
            merged_llm = dict(self.cfg.get("llm") or {})
            merged_llm.update(rev_overrides)
            synthetic["llm"] = merged_llm
            self.backend = llm_backend.resolve(synthetic)
        else:
            self.backend = llm_backend.resolve(self.cfg)

        self.client = OpenAI(
            base_url=self.backend.base_url,
            api_key=self.backend.api_key or "placeholder",
        )
        self.model = self.backend.model or self.cfg.get("model", "")

        # Prompt template: "default" or path to a .md
        template = rev_cfg.get("prompt_template", "default")
        if template and template != "default":
            try:
                self.prompt = Path(template).read_text(encoding="utf-8")
            except Exception:
                self.prompt = DEFAULT_PROMPT
        else:
            self.prompt = DEFAULT_PROMPT

    # ── main entry ──────────────────────────────────────────────────
    def review(self, state) -> dict:
        """Reviews eligible findings in state.findings. Returns a summary dict:
            {reviewed: N, passed: N, rejected: N, skipped_reason: "..."}"""
        summary = {"enabled": self.enabled, "reviewed": 0,
                    "passed": 0, "rejected": 0}
        if not self.enabled:
            summary["skipped_reason"] = "adversarial_review.enabled=false"
            return summary

        findings = list(state.get("findings") or [])
        if not findings:
            summary["skipped_reason"] = "no findings to review"
            return summary

        min_rank = SEV_RANK.get(self.min_severity, 2)
        eligible = [(i, f) for i, f in enumerate(findings)
                    if SEV_RANK.get(str(f.get("severity", "info")).lower(),
                                      0) >= min_rank]
        if not eligible:
            summary["skipped_reason"] = (
                f"no findings ≥ {self.min_severity} to review")
            return summary

        # Cap runaway
        if len(eligible) > self.max_findings:
            state.log("adversarial_review", "info",
                      f"capping review at {self.max_findings} of "
                      f"{len(eligible)} eligible findings")
            eligible = eligible[:self.max_findings]

        verdicts: list[dict] = []
        rejected_indices: list[int] = []
        for i, f in eligible:
            verdict, reason = self._review_one(f, state)
            verdicts.append({
                "index": i,
                "severity": f.get("severity", ""),
                "title": str(f.get("title", ""))[:120],
                "verdict": verdict,
                "reason": reason[:200],
            })
            summary["reviewed"] += 1
            if verdict == "REJECT":
                summary["rejected"] += 1
                rejected_indices.append(i)
            else:
                summary["passed"] += 1

        # Apply reject_action
        if rejected_indices and self.reject_action == "hide":
            kept: list[dict] = []
            rejected: list[dict] = []
            for i, f in enumerate(findings):
                if i in rejected_indices:
                    f = dict(f)
                    f["_adversarial_reason"] = next(
                        (v["reason"] for v in verdicts if v["index"] == i), "")
                    rejected.append(f)
                else:
                    kept.append(f)
            state.set("findings", kept)
            state.set("rejected_findings", rejected)
        elif rejected_indices and self.reject_action == "flag":
            # Keep findings but stamp them
            all_findings = list(state.get("findings") or [])
            for i in rejected_indices:
                reason = next((v["reason"] for v in verdicts
                                if v["index"] == i), "")
                all_findings[i] = dict(all_findings[i])
                all_findings[i]["_adversarial_verdict"] = "REJECT"
                all_findings[i]["_adversarial_reason"] = reason
            state.set("findings", all_findings)

        # Always save the verdicts for the REPORT
        state.set("adversarial_verdicts", verdicts)
        return summary

    # ── one-finding review ──────────────────────────────────────────
    def _review_one(self, finding: dict, state) -> tuple[str, str]:
        target = state.get("target", "")
        context = (
            f"Target: {target}\n"
            f"Agent that produced this: {finding.get('agent', '')}\n"
            f"Claimed severity: {finding.get('severity', '')}\n"
            f"Title: {finding.get('title', '')}\n"
            f"Evidence:\n{str(finding.get('evidence', ''))[:800]}\n"
            f"Recommendation:\n{str(finding.get('recommendation', ''))[:500]}"
        )
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.prompt},
                    {"role": "user", "content": context},
                ],
                temperature=0.1,
                max_tokens=200,
            )
            raw = (resp.choices[0].message.content or "").strip()
        except Exception as e:
            # Fail-open: on reviewer error, PASS the finding (don't hide bugs
            # because the reviewer LLM is down).
            return "PASS", f"reviewer error: {type(e).__name__}: {str(e)[:80]}"

        verdict = "PASS"
        reason = ""
        for line in raw.splitlines():
            low = line.strip().lower()
            if low.startswith("verdict:"):
                v = line.split(":", 1)[1].strip().upper()
                if v.startswith("REJECT"):
                    verdict = "REJECT"
            elif low.startswith("reason:"):
                reason = line.split(":", 1)[1].strip()

        if not reason:
            reason = raw[:200] or "(no reason given)"
        return verdict, reason
