#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chatgpt_manual_email_package.py

Paskirtis:
- Po full_assessment.py paleidimo suranda naujausią vertinimo katalogą.
- Paruošia paketą rankiniam įkėlimui į ChatGPT projektą / web sąsają.
- Prie paketo prideda pilną techninių įrodymų dokumentą ir vidinių LLM rezultatus.
- Jei sukonfigūruotas SMTP, išsiunčia el. laišką su priedais.

Naudojimas atskirai:
    cd ~/network-thesis-GIT/src
    python3 chatgpt_manual_email_package.py

Naudojimas iš full_assessment.py:
    from chatgpt_manual_email_package import prepare_chatgpt_manual_package
    prepare_chatgpt_manual_package(run_dir=None, send_email=True)

SMTP nustatymai per aplinkos kintamuosius:
    export EMAIL_ENABLED=1
    export SMTP_HOST="smtp.gmail.com"
    export SMTP_PORT="587"
    export SMTP_USER="tavo_pastas@gmail.com"
    export SMTP_PASSWORD="programos_slaptazodis"
    export SMTP_FROM="tavo_pastas@gmail.com"
    export SMTP_TO="kur_siusti@gmail.com"
    export SMTP_STARTTLS=1

Jeigu EMAIL_ENABLED nėra 1, laiškas nebus siunčiamas, bet paketas bus sukurtas.
"""

from __future__ import annotations

import json
import mimetypes
import os
import smtplib
import sys
import textwrap
from dataclasses import dataclass, asdict
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Iterable, Optional

DEFAULT_RUNS_ROOT = Path(os.environ.get("NETWORK_THESIS_RUNS_ROOT", "/home/kali/network-thesis-GIT/runs"))
DEFAULT_MAX_ATTACHMENT_MB = float(os.environ.get("MAX_ATTACHMENT_MB", "22"))
PACKAGE_DIR_NAME = "chatgpt_manual_package"


@dataclass
class PackageStatus:
    status: str
    run_dir: str
    package_dir: str
    created_at: str
    evidence_file: Optional[str]
    prompt_file: str
    compact_file: Optional[str]
    attached_files: list[str]
    skipped_files: list[dict[str, Any]]
    email_enabled: bool
    email_sent: bool
    email_error: Optional[str]
    notes: list[str]


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _safe_read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def _safe_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _safe_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def find_latest_run_dir(runs_root: Path = DEFAULT_RUNS_ROOT) -> Path:
    """Suranda naujausią run katalogą pagal failų sistemos modifikavimo laiką."""
    if not runs_root.exists():
        raise FileNotFoundError(f"Nerastas runs katalogas: {runs_root}")

    candidates: list[Path] = []
    for date_dir in runs_root.iterdir():
        if not date_dir.is_dir():
            continue
        for run_dir in date_dir.iterdir():
            if run_dir.is_dir():
                candidates.append(run_dir)

    if not candidates:
        raise FileNotFoundError(f"Nerasta paleidimų katalogų po: {runs_root}")

    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def find_evidence_file(run_dir: Path) -> Optional[Path]:
    """Suranda pagrindinį ai_evidence JSON dokumentą."""
    patterns = [
        "ai/ai_evidence*.json",
        "ai/*evidence*.json",
        "*ai_evidence*.json",
        "**/ai_evidence*.json",
        "**/*evidence*.json",
    ]

    found: list[Path] = []
    for pattern in patterns:
        found.extend([p for p in run_dir.glob(pattern) if p.is_file()])

    # Pirmenybė failams, kuriuose tikrai yra document_type=ai_evidence
    unique = sorted(set(found), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in unique:
        try:
            data = _safe_read_json(path)
            if isinstance(data, dict) and data.get("document_type") == "ai_evidence":
                return path
        except Exception:
            continue

    return unique[0] if unique else None


def find_internal_llm_outputs(run_dir: Path, package_dir: Path, limit: int = 8) -> list[Path]:
    """
    Suranda tikėtinus vidinių LLM rezultatų failus.
    Ribojama iki kelių aktualiausių, kad laiškas netaptų per didelis.
    """
    ai_dir = run_dir / "ai"
    search_roots = [ai_dir] if ai_dir.exists() else [run_dir]

    keywords = [
        "recommend", "recommendation", "recommendations",
        "rekomend", "rekomendacijos",
        "llm", "ollama", "qwen", "llama", "mistral", "gemma",
        "model", "ai_result", "ai_rezult",
    ]
    allowed_suffixes = {".txt", ".md", ".json", ".html", ".pdf"}

    candidates: list[Path] = []
    for root in search_roots:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if package_dir in path.parents:
                continue
            if path.suffix.lower() not in allowed_suffixes:
                continue
            name = path.name.lower()
            if any(k in name for k in keywords):
                # Neimame paties evidence kaip LLM rezultato
                if "ai_evidence" in name or "evidence" in name:
                    continue
                candidates.append(path)

    # Pirmenybė naujausiems ir ai katalogo failams
    candidates = sorted(set(candidates), key=lambda p: (p.parent == ai_dir, p.stat().st_mtime), reverse=True)
    return candidates[:limit]


def _top_hosts_from_evidence(data: dict[str, Any], max_hosts: int = 8) -> list[dict[str, Any]]:
    top = data.get("risk_summary", {}).get("top_10", [])
    if isinstance(top, list) and top:
        return top[:max_hosts]
    hosts = data.get("hosts_for_ai", [])
    if isinstance(hosts, list):
        sorted_hosts = sorted(
            hosts,
            key=lambda h: float(h.get("official_risk_score") or 0),
            reverse=True,
        )
        return [
            {
                "ip": h.get("ip"),
                "device_class": h.get("device_class"),
                "risk_score": h.get("official_risk_score"),
                "risk_level": h.get("official_risk_level"),
                "top_reasons": h.get("risk_explanation", [])[:6],
            }
            for h in sorted_hosts[:max_hosts]
        ]
    return []


def build_compact_evidence(evidence_file: Path, out_file: Path) -> Optional[Path]:
    """Sukuria sutrumpintą JSON, kurį lengviau įkelti į ChatGPT, bet pilnas dokumentas lieka priede."""
    try:
        data = _safe_read_json(evidence_file)
        if not isinstance(data, dict):
            return None

        compact = {
            "document_type": "ai_evidence_compact_for_chatgpt",
            "source_file": str(evidence_file),
            "generated_at": data.get("generated_at"),
            "run_id": data.get("run_id"),
            "network": data.get("network"),
            "instruction_for_llm": data.get("instruction_for_llm"),
            "executive_summary": data.get("executive_summary"),
            "risk_model": data.get("risk_model"),
            "risk_summary": data.get("risk_summary"),
            "top_hosts": _top_hosts_from_evidence(data, max_hosts=10),
            "correlated_summary": data.get("technical_findings", {}).get("correlated_summary"),
            "correlated_findings": data.get("technical_findings", {}).get("correlated_findings"),
            "cve_epss_kev": data.get("cve_epss_kev"),
            "endpoint_context_summary": data.get("endpoint_context", {}).get("summary"),
            "remediation_tracking_summary": data.get("remediation_tracking", {}).get("summary"),
            "remediation_finding_status": data.get("remediation_tracking", {}).get("finding_status"),
            "validation_context": data.get("validation_context"),
        }
        _safe_write_json(out_file, compact)
        return out_file
    except Exception:
        return None


def build_chatgpt_prompt(run_dir: Path, evidence_file: Optional[Path], internal_outputs: list[Path]) -> str:
    evidence_name = evidence_file.name if evidence_file else "NERASTAS ai_evidence JSON failas"
    internal_names = "\n".join(f"- {p.name}" for p in internal_outputs) if internal_outputs else "- Vidinių LLM rezultatų failų nerasta arba jie dar nesugeneruoti."

    return textwrap.dedent(f"""
    UŽDUOTIS CHATGPT PROJEKTUI
    ==========================

    Pridedu autonominės vidinio tinklo saugumo vertinimo sistemos techninių įrodymų dokumentą ir, jei sugeneruota, du / kelis vidinio LLM rekomendacijų variantus.

    Pagrindinis techninių įrodymų failas:
    - {evidence_name}

    Vidinio LLM rezultatų failai:
    {internal_names}

    Prašau remtis tik pateiktais techniniais įrodymais ir sugeneruoti pilną prioritetizuotų saugumo rekomendacijų dokumentą lietuvių kalba.

    Dokumento struktūra turi būti tokia:
    1. Santrauka vadovui.
    2. Vertinimo apimtis ir šaltiniai.
    3. Bendras rizikos vaizdas.
    4. Prioritetizuotos rekomendacijos pagal radinius.
    5. Rekomendacijos pagal įrenginius / IP adresus.
    6. Ką tvarkyti pirmiausia.
    7. Kaip patikrinti, ar pataisymai įgyvendinti.
    8. Apribojimai ir radinių patikimumas.
    9. Išvada.

    Kiekvienai rekomendacijai nurodyk:
    - kas aptikta;
    - kodėl tai svarbu;
    - ką tiksliai atlikti;
    - kaip patikrinti pataisymą;
    - prioritetą;
    - susijusius IP adresus arba paslaugas;
    - ar radinys patvirtintas, ar tik potencialus pagal banner/CPE informaciją.

    Svarbios taisyklės:
    - Nesiremti gamintojo pavadinimu kaip pagrindiniu sprendimo argumentu.
    - Aiškiai atskirti patvirtintus konfigūracinius radinius nuo potencialių CVE pagal banner/CPE.
    - Nepateikti išnaudojimo instrukcijų ar puolimo veiksmų.
    - Rekomendacijas formuluoti kaip gynybines administravimo priemones.
    - Jeigu vidinių LLM rezultatai prieštarauja techniniam įrodymų dokumentui, pirmenybę teikti techniniam įrodymų dokumentui.

    Šis failas paruoštas automatiškai iš katalogo:
    {run_dir}
    """).strip() + "\n"


def _file_size_mb(path: Path) -> float:
    return path.stat().st_size / (1024 * 1024)


def _filter_attachments(paths: Iterable[Path], max_each_mb: float) -> tuple[list[Path], list[dict[str, Any]]]:
    accepted: list[Path] = []
    skipped: list[dict[str, Any]] = []
    seen: set[Path] = set()

    for path in paths:
        path = path.resolve()
        if path in seen or not path.exists() or not path.is_file():
            continue
        seen.add(path)
        size_mb = _file_size_mb(path)
        if size_mb > max_each_mb:
            skipped.append({
                "file": str(path),
                "reason": f"Failas didesnis nei MAX_ATTACHMENT_MB={max_each_mb}",
                "size_mb": round(size_mb, 2),
            })
        else:
            accepted.append(path)
    return accepted, skipped


def send_email_with_attachments(subject: str, body: str, attachments: list[Path]) -> None:
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    mail_from = os.environ.get("SMTP_FROM", username).strip()
    mail_to = os.environ.get("SMTP_TO", "").strip()
    use_ssl = os.environ.get("SMTP_SSL", "0") == "1"
    use_starttls = os.environ.get("SMTP_STARTTLS", "1") == "1"

    if not host:
        raise ValueError("Nenurodytas SMTP_HOST")
    if not mail_to:
        raise ValueError("Nenurodytas SMTP_TO")
    if not mail_from:
        raise ValueError("Nenurodytas SMTP_FROM arba SMTP_USER")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg.set_content(body)

    for path in attachments:
        ctype, encoding = mimetypes.guess_type(str(path))
        if ctype is None or encoding is not None:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        data = path.read_bytes()
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=path.name)

    if use_ssl:
        with smtplib.SMTP_SSL(host, port, timeout=60) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=60) as smtp:
            smtp.ehlo()
            if use_starttls:
                smtp.starttls()
                smtp.ehlo()
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)


def prepare_chatgpt_manual_package(
    run_dir: Optional[str | Path] = None,
    send_email: bool = True,
    runs_root: Path = DEFAULT_RUNS_ROOT,
) -> PackageStatus:
    """Pagrindinė funkcija, kurią kviečia full_assessment.py."""
    notes: list[str] = []

    if run_dir is None:
        run_dir_path = find_latest_run_dir(runs_root)
        notes.append("run_dir neperduotas, pasirinktas naujausias runs katalogas.")
    else:
        run_dir_path = Path(run_dir).expanduser().resolve()

    if not run_dir_path.exists():
        raise FileNotFoundError(f"Nerastas run_dir: {run_dir_path}")

    package_dir = run_dir_path / "ai" / PACKAGE_DIR_NAME
    package_dir.mkdir(parents=True, exist_ok=True)

    evidence_file = find_evidence_file(run_dir_path)
    if evidence_file is None:
        notes.append("Nepavyko rasti ai_evidence JSON failo. Paketas sukurtas be pagrindinio įrodymų dokumento.")

    internal_outputs = find_internal_llm_outputs(run_dir_path, package_dir)
    if not internal_outputs:
        notes.append("Vidinių LLM rezultatų failų nerasta. Gal jie generuojami kitu pavadinimu arba dar nesukurti.")

    prompt_file = package_dir / "CHATGPT_UZKLAUSA_REKOMENDACIJOMS.txt"
    prompt_text = build_chatgpt_prompt(run_dir_path, evidence_file, internal_outputs)
    _safe_write_text(prompt_file, prompt_text)

    compact_file: Optional[Path] = None
    if evidence_file is not None:
        compact_candidate = package_dir / "ai_evidence_compact_for_chatgpt.json"
        compact_file = build_compact_evidence(evidence_file, compact_candidate)
        if compact_file is None:
            notes.append("Nepavyko sukurti sutrumpinto įrodymų dokumento.")

    attachments_ordered: list[Path] = [prompt_file]
    if evidence_file is not None:
        attachments_ordered.append(evidence_file)
    if compact_file is not None:
        attachments_ordered.append(compact_file)
    attachments_ordered.extend(internal_outputs)

    accepted_attachments, skipped_files = _filter_attachments(attachments_ordered, DEFAULT_MAX_ATTACHMENT_MB)
    if skipped_files:
        notes.append("Kai kurie priedai neprisegti dėl dydžio limito. Jie lieka run kataloge.")

    package_email_requested = os.environ.get("CHATGPT_PACKAGE_EMAIL_ENABLED", "0") == "1"
    email_enabled = package_email_requested and os.environ.get("EMAIL_ENABLED", "0") == "1" and send_email
    email_sent = False
    email_error: Optional[str] = None

    if email_enabled:
        try:
            subject = f"ChatGPT rekomendacijų generavimo paketas - {run_dir_path.name}"
            body = textwrap.dedent(f"""
            Sveiki,

            Prisegtas autonominės vidinio tinklo saugumo vertinimo sistemos paketas rankiniam įkėlimui į ChatGPT.

            Ką daryti:
            1. Atsidaryti ChatGPT projektą arba pokalbį.
            2. Įkelti prisegtą pilną ai_evidence JSON failą.
            3. Įkelti vidinių LLM rezultatų failus, jei jie prisegti.
            4. Nukopijuoti tekstą iš CHATGPT_UZKLAUSA_REKOMENDACIJOMS.txt ir pateikti kaip užklausą.
            5. Sugeneruotą atsakymą išsaugoti kaip trečią, rankiniu būdu gautą ChatGPT rekomendacijų variantą.

            Run katalogas Raspberry Pi sistemoje:
            {run_dir_path}

            Pastabos:
            {chr(10).join('- ' + n for n in notes) if notes else '- Pastabų nėra.'}
            """).strip()
            send_email_with_attachments(subject, body, accepted_attachments)
            email_sent = True
        except Exception as exc:
            email_error = str(exc)
            notes.append(f"El. laiško išsiųsti nepavyko: {email_error}")
    else:
        if not send_email:
            notes.append("send_email=False, todėl laiškas nesiųstas.")
        elif not package_email_requested:
            notes.append("CHATGPT_PACKAGE_EMAIL_ENABLED nėra 1, todėl rankinio įkėlimo paketo laiškas nesiųstas. Paketas tik paruoštas kataloge.")
        elif os.environ.get("EMAIL_ENABLED", "0") != "1":
            notes.append("EMAIL_ENABLED nėra 1, todėl laiškas nesiųstas. Paketas tik paruoštas kataloge.")
        elif os.environ.get("CHATGPT_PACKAGE_EMAIL_ENABLED", "0") != "1":
            notes.append("CHATGPT_PACKAGE_EMAIL_ENABLED nėra 1, todėl rankinio įkėlimo paketo laiškas nesiųstas.")
        elif os.environ.get("CHATGPT_PACKAGE_EMAIL_ENABLED", "0") != "1":
            notes.append("CHATGPT_PACKAGE_EMAIL_ENABLED nėra 1, todėl rankinio įkėlimo paketo laiškas nesiųstas.")

    status = PackageStatus(
        status="ok",
        run_dir=str(run_dir_path),
        package_dir=str(package_dir),
        created_at=_now_iso(),
        evidence_file=str(evidence_file) if evidence_file else None,
        prompt_file=str(prompt_file),
        compact_file=str(compact_file) if compact_file else None,
        attached_files=[str(p) for p in accepted_attachments],
        skipped_files=skipped_files,
        email_enabled=email_enabled,
        email_sent=email_sent,
        email_error=email_error,
        notes=notes,
    )

    status_file = package_dir / "chatgpt_manual_package_status.json"
    _safe_write_json(status_file, asdict(status))
    return status


def main(argv: list[str]) -> int:
    run_dir_arg = argv[1] if len(argv) > 1 else None
    try:
        status = prepare_chatgpt_manual_package(run_dir=run_dir_arg, send_email=True)
        print(json.dumps(asdict(status), ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
