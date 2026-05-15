#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clean administrator-facing email sender for the network-thesis project.

Purpose:
- send only the most relevant output files;
- keep the email body understandable for an IT systems administrator;
- do not list technical document/file names in the email body;
- avoid sending the large internal/debug package.
"""

from __future__ import annotations

import mimetypes
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable


SUBJECT = "Automatinio vidinio tinklo saugumo vertinimo rezultatai"

EMAIL_BODY = """Sveiki,

Prisegama automatinio vidinio tinklo saugumo vertinimo ataskaita.

Ataskaitoje pateikiama bendra tinklo būklės santrauka, svarbiausi radiniai, rekomenduojami administravimo veiksmai ir jų prioritetai. Ji skirta padėti nuspręsti, kokius darbus reikėtų atlikti pirmiausia.

Jeigu prisegti papildomi duomenys, jie skirti tik detalesnei peržiūrai arba pakartotinei analizei su DI įrankiu. Kasdieniam rezultatų įvertinimui pakanka peržiūrėti pagrindinę ataskaitą.

Prieš taikant pakeitimus produkcinėje aplinkoje, rekomenduojama radinius patikrinti pagal organizacijos administravimo tvarką.

Pagarbiai
Automatinė vidinio tinklo saugumo vertinimo sistema
"""


class ConfigError(RuntimeError):
    pass


def project_root() -> Path:
    """Resolve the project root from this file, cwd, or PROJECT_DIR."""
    env_root = os.environ.get("PROJECT_DIR", "").strip()
    if env_root:
        return Path(env_root).expanduser().resolve()

    here = Path(__file__).resolve()
    if here.parent.name == "src":
        return here.parent.parent

    cwd = Path.cwd().resolve()
    if (cwd / "src").is_dir() and (cwd / "latest").exists():
        return cwd
    if cwd.name == "src":
        return cwd.parent
    return cwd


def latest_run_dir(root: Path) -> Path | None:
    runs = root / "runs"
    if not runs.exists():
        return None
    candidates = [p for p in runs.glob("*/*") if p.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def first_existing(paths: Iterable[Path]) -> Path | None:
    for path in paths:
        if path and path.exists() and path.is_file() and path.stat().st_size > 0:
            return path
    return None


def newest_matching(paths: Iterable[Path]) -> Path | None:
    found: list[Path] = []
    for base in paths:
        if not base or not base.exists():
            continue
        if base.is_file():
            found.append(base)
        elif base.is_dir():
            found.extend([p for p in base.rglob("*") if p.is_file() and p.stat().st_size > 0])
    if not found:
        return None
    return max(found, key=lambda p: p.stat().st_mtime)


def select_attachments(root: Path) -> list[Path]:
    """
    Select only administrator-relevant attachments.

    Priority:
    1) main human-readable report: PDF if available, otherwise Markdown;
    2) compact technical evidence for optional additional analysis;
    3) ready-to-use prompt for optional additional analysis.
    """
    latest = root / "latest"
    run_dir = latest_run_dir(root)
    search_roots = [p for p in [latest, run_dir] if p and p.exists()]

    attachments: list[Path] = []

    # Main report: prefer PDF, fallback to Markdown.
    report = first_existing([
        latest / "recommendations_latest.pdf",
        latest / "final_recommendations_latest.pdf",
    ])
    if report is None:
        report = newest_matching([
            latest / "recommendations_latest.md",
            latest / "final_recommendations_latest.md",
            latest / "llm_recommendations_latest.md",
        ])
    if report is None and run_dir:
        report = newest_matching([
            run_dir / "reports",
            run_dir / "ai",
        ])
        if report and report.suffix.lower() not in {".pdf", ".md"}:
            report = None
    if report:
        attachments.append(report)

    # Compact evidence only. Avoid the full internal ai_evidence JSON unless no compact file exists.
    compact_candidates: list[Path] = []
    for base in search_roots:
        compact_candidates.extend(base.rglob("ai_evidence_compact_for_chatgpt.json"))
        compact_candidates.extend(base.rglob("*compact*chatgpt*.json"))
    compact = newest_matching(compact_candidates)
    if compact:
        attachments.append(compact)

    # Optional prompt for additional DI analysis.
    prompt_candidates: list[Path] = []
    for base in search_roots:
        prompt_candidates.extend(base.rglob("CHATGPT_UZKLAUSA_REKOMENDACIJOMS.txt"))
        prompt_candidates.extend(base.rglob("*UZKLAUSA*REKOMENDACIJOMS*.txt"))
    prompt = newest_matching(prompt_candidates)
    if prompt:
        attachments.append(prompt)

    # Remove duplicates while preserving order.
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in attachments:
        resolved = path.resolve()
        if resolved not in seen:
            unique.append(path)
            seen.add(resolved)

    return unique


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"Nenurodytas {name}")
    return value


def build_email(attachments: list[Path]) -> EmailMessage:
    if os.environ.get("EMAIL_ENABLED", "0").strip() != "1":
        raise ConfigError("EMAIL_ENABLED nėra 1, todėl laiškas nesiunčiamas")

    smtp_user = require_env("SMTP_USER")
    mail_to = require_env("SMTP_TO")
    mail_from = os.environ.get("EMAIL_FROM", "").strip() or smtp_user

    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg["Subject"] = os.environ.get("EMAIL_SUBJECT", SUBJECT).strip() or SUBJECT
    msg.set_content(EMAIL_BODY)

    for path in attachments:
        content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        maintype, subtype = content_type.split("/", 1)
        msg.add_attachment(path.read_bytes(), maintype=maintype, subtype=subtype, filename=path.name)

    return msg


def send_message(msg: EmailMessage) -> None:
    host = require_env("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587").strip() or "587")
    user = require_env("SMTP_USER")
    password = require_env("SMTP_PASSWORD").replace(" ", "")

    if port == 465:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=context, timeout=60) as smtp:
            smtp.login(user, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=60) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            smtp.login(user, password)
            smtp.send_message(msg)


def main() -> int:
    root = project_root()
    attachments = select_attachments(root)

    if not attachments:
        print("[KLAIDA] Nerasta siunčiamų rezultatų failų. Pirma paleisk full_assessment.py.", file=sys.stderr)
        return 2

    try:
        msg = build_email(attachments)
        send_message(msg)
    except ConfigError as exc:
        print(f"[KLAIDA] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[KLAIDA] Laiško išsiųsti nepavyko: {exc}", file=sys.stderr)
        return 1

    print(f"[GERAI] Laiškas išsiųstas. Prisegta failų: {len(attachments)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

