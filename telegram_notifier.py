"""Send the pipeline REPORT.md via Telegram Bot API.

Two payloads per notification:
  1. A short executive-summary text (sendMessage)
  2. The full REPORT.md as an attachment (sendDocument)

Bot token NEVER lives in config.yaml — read from an env var whose name
comes from telegram.bot_token_env (default: TELEGRAM_BOT_TOKEN). Chat_id
can live in config.yaml (not secret) or in an env var if the operator
prefers.

Setup (one-time):
  1. In Telegram: talk to @BotFather → /newbot → get the bot token
  2. Start a chat with your new bot (send it any message)
  3. curl https://api.telegram.org/bot<TOKEN>/getUpdates
     → find "chat":{"id":<CHAT_ID>,...}
  4. Put the token in an env var:   export TELEGRAM_BOT_TOKEN='123:ABC...'
  5. Put the chat_id in config.yaml → telegram.chat_id
"""
from __future__ import annotations

import os
from pathlib import Path

import requests

API_BASE = "https://api.telegram.org"
TEXT_LIMIT = 4000  # actual limit is 4096; keep a safety margin


class TelegramError(Exception):
    pass


def send_report(cfg: dict, report_path: Path,
                summary_text: str, chat_id_override: str | None = None) -> None:
    """Send the executive summary + REPORT.md file. Raises TelegramError on
    misconfiguration; returns quietly on transient API errors after logging.
    """
    tcfg = cfg.get("telegram") or {}
    if not tcfg.get("enabled", False):
        raise TelegramError("telegram.enabled = false in config.yaml")

    # Bot token: prefer `bot_token` (direct value) → fall back to env var
    # named by `bot_token_env`. Direct value wins because the operator
    # explicitly opted in to storing it in the YAML.
    token = str(tcfg.get("bot_token") or "").strip()
    if not token:
        token_env = tcfg.get("bot_token_env", "TELEGRAM_BOT_TOKEN")
        token = os.environ.get(token_env, "").strip()
    if not token:
        env_name = tcfg.get("bot_token_env", "TELEGRAM_BOT_TOKEN")
        raise TelegramError(
            f"Telegram bot token not set. Either fill telegram.bot_token in "
            f"config.yaml, or export ${env_name} "
            "(get one from @BotFather in Telegram)."
        )

    # Chat id — CLI/REPL override > config > env fallback
    chat_id = (chat_id_override
               or tcfg.get("chat_id")
               or os.environ.get(tcfg.get("chat_id_env", "TELEGRAM_CHAT_ID"),
                                 "")).strip() if any([
                    chat_id_override,
                    tcfg.get("chat_id"),
                    os.environ.get(tcfg.get("chat_id_env",
                                            "TELEGRAM_CHAT_ID"))]) else ""
    if not chat_id:
        raise TelegramError(
            "Telegram chat_id not set. Fill telegram.chat_id in config.yaml "
            "or export $TELEGRAM_CHAT_ID."
        )

    # Send the text summary (split into chunks if very long)
    if tcfg.get("send_summary_text", True) and summary_text:
        for chunk in _split(summary_text, TEXT_LIMIT):
            _send_message(token, chat_id, chunk)

    # Send REPORT.md as a document (up to 50 MB per Bot API limits)
    if tcfg.get("send_report_file", True) and report_path and Path(report_path).is_file():
        _send_document(token, chat_id, Path(report_path))


def _send_message(token: str, chat_id: str, text: str) -> None:
    url = f"{API_BASE}/bot{token}/sendMessage"
    r = requests.post(url, timeout=30, data={
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": "true",
    })
    if not r.ok:
        raise TelegramError(f"sendMessage failed: HTTP {r.status_code} "
                            f"— {r.text[:200]}")


def _send_document(token: str, chat_id: str, path: Path) -> None:
    url = f"{API_BASE}/bot{token}/sendDocument"
    with path.open("rb") as fh:
        r = requests.post(url, timeout=120,
                          data={"chat_id": chat_id,
                                "caption": f"REPORT.md — {path.parent.name}"},
                          files={"document": (path.name, fh, "text/markdown")})
    if not r.ok:
        raise TelegramError(f"sendDocument failed: HTTP {r.status_code} "
                            f"— {r.text[:200]}")


def _split(text: str, limit: int) -> list[str]:
    """Split by newlines so no chunk breaks mid-line."""
    if len(text) <= limit:
        return [text]
    out: list[str] = []
    buf = ""
    for line in text.splitlines(keepends=True):
        if len(buf) + len(line) > limit:
            if buf:
                out.append(buf)
            buf = line if len(line) <= limit else line[:limit]
        else:
            buf += line
    if buf:
        out.append(buf)
    return out
