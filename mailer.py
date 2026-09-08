"""SMTP mailer for end-of-session reports.

Two modes, auto-selected based on config.yaml -> smtp.*:

  1) AUTHENTICATED SMTP (Gmail / Outlook / any provider)
     Triggered when smtp.host AND smtp.username are set in config.yaml.
     Password is read from the env var named by smtp.password_env
     (default SMTP_PASSWORD) — NEVER stored in the YAML.

  2) LOCAL RELAY, NO AUTH  (fallback)
     Triggered when smtp.host / smtp.username are empty or missing.
     Connects to localhost:25 (or smtp.host:smtp.port if partially set)
     with no STARTTLS, no auth. Requires a local MTA listening —
     postfix / exim / sendmail / Mailhog / Mailpit / etc.

     macOS note: by default there is NO MTA on port 25. Options:
       - `brew install mailpit && mailpit`  (dev inbox on localhost:1025/8025)
       - `brew install postfix` and enable it
       - Docker: `docker run -p 1025:1025 -p 8025:8025 axllent/mailpit`
     Then set smtp.host=127.0.0.1, smtp.port=1025, leave username empty.
"""
from __future__ import annotations

import mimetypes
import os
import smtplib
import socket
from email.message import EmailMessage
from pathlib import Path


class MailerError(Exception):
    pass


def _default_from(cfg_from: str | None) -> str:
    if cfg_from:
        return cfg_from
    # Reasonable default so the mail is not rejected outright by local relays
    host = socket.gethostname() or "localhost"
    return f"harness@{host}"


def _is_auth_mode(smtp_cfg: dict) -> bool:
    """True if we should use authenticated SMTP; False → local relay fallback."""
    return bool(smtp_cfg and smtp_cfg.get("host") and smtp_cfg.get("username"))


def send_report(smtp_cfg: dict, to_addr: str, subject: str, body: str,
                attachments: list[Path] | None = None) -> None:
    """Send `body` as plain text to `to_addr`. Selects auth or local mode.

    Optional `attachments` is a list of Path objects — each attached with its
    MIME type inferred from the extension (fallback application/octet-stream).
    """
    smtp_cfg = smtp_cfg or {}
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = _default_from(smtp_cfg.get("from"))
    msg["To"] = to_addr
    msg.set_content(body)

    # Attach each file (REPORT.md, state.json, etc.)
    for path in attachments or []:
        path = Path(path)
        if not path.is_file():
            continue
        ctype, encoding = mimetypes.guess_type(path.name)
        if ctype is None or encoding is not None:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        try:
            data = path.read_bytes()
        except Exception:
            continue
        msg.add_attachment(data, maintype=maintype, subtype=subtype,
                           filename=path.name)

    if _is_auth_mode(smtp_cfg):
        _send_authenticated(smtp_cfg, msg)
    else:
        _send_local(smtp_cfg, msg)


def _send_authenticated(smtp_cfg: dict, msg: EmailMessage) -> None:
    # Password: prefer `password` (direct value) → fall back to env var
    # named by `password_env`. Direct value wins because the operator
    # explicitly opted in to storing it in the YAML.
    password = str(smtp_cfg.get("password") or "").strip()
    if not password:
        env_name = smtp_cfg.get("password_env", "SMTP_PASSWORD")
        password = os.environ.get(env_name) or ""
    if not password:
        env_name = smtp_cfg.get("password_env", "SMTP_PASSWORD")
        raise MailerError(
            f"SMTP password not set. Either fill smtp.password in config.yaml, "
            f"or export ${env_name} before launching the harness "
            f"(e.g. `export {env_name}='app-password'`)."
        )
    host = smtp_cfg["host"]
    port = int(smtp_cfg.get("port", 587))
    use_ssl = bool(smtp_cfg.get("use_ssl", port == 465))

    if use_ssl:
        with smtplib.SMTP_SSL(host, port, timeout=30) as s:
            s.login(smtp_cfg["username"], password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=30) as s:
            s.starttls()
            s.login(smtp_cfg["username"], password)
            s.send_message(msg)


def _send_local(smtp_cfg: dict, msg: EmailMessage) -> None:
    """Send via local MTA — no auth, no TLS. Defaults to 127.0.0.1:25."""
    host = (smtp_cfg or {}).get("host") or "127.0.0.1"
    port = int((smtp_cfg or {}).get("port") or 25)
    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.send_message(msg)
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        raise MailerError(
            f"Local SMTP relay not reachable at {host}:{port} ({e}). "
            "Either fill smtp.* in config.yaml with a remote provider "
            "(Gmail / Outlook / …), or start a local MTA "
            "(mailpit, postfix, sendmail) listening on that host:port."
        )
