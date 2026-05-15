#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from common import get_run_paths, save_json, timestamp_now
except Exception:
    def timestamp_now() -> str:
        return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    def get_run_paths() -> dict:
        base = Path("/home/kali/network-thesis-GIT")
        run_id = os.getenv("ASSESSMENT_RUN_ID") or timestamp_now()
        run_date = run_id[:10]
        run_dir = base / "runs" / run_date / run_id
        paths = {
            "run_id": run_id,
            "run_date": run_date,
            "run_dir": run_dir,
            "reports_dir": run_dir / "reports",
            "ai_dir": run_dir / "ai",
        }
        for d in (paths["run_dir"], paths["reports_dir"], paths["ai_dir"]):
            d.mkdir(parents=True, exist_ok=True)
        return paths
    def save_json(path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=4), encoding="utf-8")

BASE_DIR = Path(os.getenv("NETWORK_THESIS_BASE", "/home/kali/network-thesis-GIT"))
ENDPOINT_EVENT_DIR = Path(os.getenv("ENDPOINT_EVENT_LOG_DIR", str(BASE_DIR / "endpoint_event_log")))
ESET_CSV_DIR = Path(os.getenv("ESET_CSV_LOG_DIR", str(BASE_DIR / "eset_csv_log")))
LOOKBACK_HOURS = int(os.getenv("ENDPOINT_EVENT_LOOKBACK_HOURS", "24"))
MAX_EVENTS_SAMPLE = int(os.getenv("ENDPOINT_EVENT_SAMPLE", "200"))
MAX_ESET_ROWS_SAMPLE = int(os.getenv("ESET_CSV_ROWS_SAMPLE", "200"))

SECURITY_EVENT_NAMES = {
    4624: ("successful_logon", "authentication", "success", "žema"),
    4625: ("failed_logon", "authentication", "failure", "vidutinė"),
    4634: ("logoff", "authentication", "success", "žema"),
    4648: ("explicit_credentials_logon", "authentication", "success", "vidutinė"),
    4672: ("special_privileges_assigned", "privilege", "success", "vidutinė"),
    4688: ("process_created", "process", "success", "žema"),
    4697: ("service_installed", "persistence", "success", "aukšta"),
    4720: ("user_account_created", "account_management", "success", "aukšta"),
    4722: ("user_account_enabled", "account_management", "success", "vidutinė"),
    4726: ("user_account_deleted", "account_management", "success", "vidutinė"),
    4732: ("member_added_to_group", "account_management", "success", "aukšta"),
    4738: ("user_account_changed", "account_management", "success", "vidutinė"),
    4740: ("account_locked_out", "authentication", "failure", "vidutinė"),
    4776: ("ntlm_credential_validation", "authentication", "unknown", "žema"),
    1102: ("audit_log_cleared", "audit", "success", "kritinė"),
}
HIGH_VALUE_EVENT_IDS = {4625, 4648, 4672, 4697, 4720, 4732, 4740, 1102}
WINDOWS_SOURCE_TYPES = {"windows_event", "eset_windows_event"}
ESET_ROW_SOURCE_TYPES = {"eset_csv_row"}
ESET_FILE_SUMMARY_TYPES = {"eset_csv_file_summary", "eset_csv_file"}
PAYLOAD_SUMMARY_TYPES = {"endpoint_payload_summary"}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    if not s:
        return None
    # PowerShell often sends 2026-04-28T10:20:30.1234567Z; Python accepts max 6 microseconds.
    s = re.sub(r"(\.\d{6})\d+(Z|[+-]\d\d:?\d\d)?$", r"\1\2", s)
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y.%m.%d %H:%M:%S",
        "%d.%m.%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d",
        "%d.%m.%Y",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def event_dt(raw: dict) -> datetime | None:
    for key in ("time_created", "parsed_time", "collector_received_at", "file_last_write_time", "last_write_time", "generated_at"):
        dt = parse_time(raw.get(key))
        if dt:
            return dt
    return None


def dedupe_key(raw: dict) -> str:
    st = raw.get("source_type") or "unknown"
    if st in WINDOWS_SOURCE_TYPES:
        base = "|".join(str(raw.get(k) or "") for k in (
            "source_type", "computer", "log_name", "provider", "record_id", "event_id", "time_created"
        ))
    elif st == "eset_csv_row":
        base = "|".join(str(raw.get(k) or "") for k in (
            "source_type", "computer", "filename", "row_hash", "row_number", "parsed_time", "raw_line"
        ))
    elif st == "eset_csv_file_summary":
        base = "|".join(str(raw.get(k) or "") for k in (
            "source_type", "computer", "filename", "last_write_time", "size_bytes", "rows_included"
        ))
    else:
        base = json.dumps(raw, ensure_ascii=False, sort_keys=True)
    return sha256_text(base)


def normalize_event(raw: dict) -> dict:
    event_id = raw.get("event_id")
    try:
        event_id_int = int(event_id) if event_id is not None else None
    except Exception:
        event_id_int = None

    name, category, outcome, severity = SECURITY_EVENT_NAMES.get(
        event_id_int,
        ("windows_event", "system", "unknown", "žema"),
    )

    log_name = raw.get("log_name") or "unknown"
    if log_name not in {"Security", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"}:
        if event_id_int in HIGH_VALUE_EVENT_IDS:
            severity = "vidutinė" if severity == "žema" else severity

    event_data = raw.get("event_data") if isinstance(raw.get("event_data"), dict) else {}
    actor_user = event_data.get("SubjectUserName") or event_data.get("AccountName") or raw.get("user_id")
    target_user = event_data.get("TargetUserName") or event_data.get("MemberName") or event_data.get("AccountName")
    src_ip = event_data.get("IpAddress") or event_data.get("SourceNetworkAddress") or event_data.get("ClientAddress")
    process_name = event_data.get("ProcessName") or event_data.get("NewProcessName") or event_data.get("Application")

    return {
        "schema_version": "1.0",
        "source_type": raw.get("source_type") or "windows_event",
        "source": {
            "computer": raw.get("computer") or raw.get("machine_name"),
            "collector_seen_ip": raw.get("collector_seen_ip"),
        },
        "event": {
            "id": event_id_int,
            "name": name,
            "category": category,
            "action": name,
            "outcome": outcome,
            "severity": severity,
            "time": raw.get("time_created"),
            "record_id": raw.get("record_id"),
            "channel": log_name,
            "provider": raw.get("provider"),
            "level": raw.get("level"),
        },
        "actor": {"user": actor_user, "domain": event_data.get("SubjectDomainName")},
        "target": {"user": target_user, "process_name": process_name},
        "network": {"src_ip": src_ip, "src_port": event_data.get("IpPort")},
        "auth": {"logon_type": event_data.get("LogonType"), "auth_package": event_data.get("AuthenticationPackageName")},
        "message": raw.get("message"),
        "dedupe_key": dedupe_key(raw),
    }


def eset_severity_from_text(text: str) -> tuple[str, str]:
    low = text.lower()
    if any(x in low for x in ["trojan", "malware", "virus", "threat", "aptikta", "grėsm", "kenk", "quarantine", "karantin"]):
        return "aukšta", "threat_or_malware_indicator"
    if any(x in low for x in ["blocked", "denied", "forbidden", "užbloku", "blokuota", "blocked website"]):
        return "vidutinė", "blocked_activity"
    if any(x in low for x in ["allowed", "leista", "cleaned", "clean"]):
        return "žema", "allowed_or_cleaned_activity"
    return "žema", "eset_log_row"


def normalize_eset_row(raw: dict) -> dict:
    fields = raw.get("fields") if isinstance(raw.get("fields"), dict) else {}
    raw_line = raw.get("raw_line") or ""
    merged_text = " ".join([raw_line] + [str(v) for v in fields.values() if v is not None])
    severity, event_name = eset_severity_from_text(merged_text)

    # Try to identify common URL/user/app columns without depending on one ESET language.
    def first_field(names: list[str]) -> Any:
        lower_map = {str(k).lower(): v for k, v in fields.items()}
        for name in names:
            for k, v in lower_map.items():
                if name in k:
                    return v
        return None

    url = first_field(["url", "svetain", "website", "address", "adresas"])
    user = first_field(["user", "naudoto", "vartoto"])
    app = first_field(["application", "program", "app", "proces"])
    action = first_field(["action", "veiks", "result", "rezultat"])

    return {
        "schema_version": "1.0",
        "source_type": "eset_csv_row",
        "source": {
            "computer": raw.get("computer"),
            "collector_seen_ip": raw.get("collector_seen_ip"),
            "filename": raw.get("filename"),
            "source_path": raw.get("source_path"),
        },
        "event": {
            "vendor": "ESET",
            "name": event_name,
            "category": "endpoint_security",
            "severity": severity,
            "time": raw.get("parsed_time") or raw.get("collector_received_at") or raw.get("file_last_write_time"),
            "row_number": raw.get("row_number"),
            "time_parse_status": raw.get("time_parse_status"),
        },
        "security": {
            "url": url,
            "user": user,
            "application": app,
            "action": action,
            "fields": fields,
            "raw_line": raw_line,
        },
        "dedupe_key": dedupe_key(raw),
    }


def load_endpoint_records(cutoff: datetime) -> tuple[list[dict], list[dict], list[dict], list[dict], dict]:
    windows_events: list[dict] = []
    eset_rows: list[dict] = []
    eset_file_summaries: list[dict] = []
    payload_summaries: list[dict] = []
    stats = {
        "raw_files_read": 0,
        "parsed_lines": 0,
        "skipped_old_or_invalid": 0,
        "skipped_duplicates_in_context": 0,
        "raw_windows_events": 0,
        "raw_eset_csv_rows": 0,
        "raw_eset_file_summaries": 0,
        "raw_payload_summaries": 0,
    }
    seen = set()

    for file in sorted(ENDPOINT_EVENT_DIR.glob("**/*.jsonl")):
        try:
            if datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc) < cutoff - timedelta(hours=2):
                continue
        except Exception:
            pass
        stats["raw_files_read"] += 1
        with file.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except Exception:
                    continue
                if not isinstance(raw, dict):
                    continue
                stats["parsed_lines"] += 1
                st = raw.get("source_type") or "windows_event"
                dt = event_dt(raw)
                if dt is None or dt < cutoff:
                    stats["skipped_old_or_invalid"] += 1
                    continue
                key = dedupe_key(raw)
                if key in seen:
                    stats["skipped_duplicates_in_context"] += 1
                    continue
                seen.add(key)

                if st in WINDOWS_SOURCE_TYPES:
                    windows_events.append(normalize_event(raw))
                    stats["raw_windows_events"] += 1
                elif st in ESET_ROW_SOURCE_TYPES:
                    eset_rows.append(normalize_eset_row(raw))
                    stats["raw_eset_csv_rows"] += 1
                elif st in ESET_FILE_SUMMARY_TYPES:
                    eset_file_summaries.append(raw)
                    stats["raw_eset_file_summaries"] += 1
                elif st in PAYLOAD_SUMMARY_TYPES:
                    payload_summaries.append(raw)
                    stats["raw_payload_summaries"] += 1
                else:
                    # Unknown records are kept as payload summaries to avoid losing provenance.
                    payload_summaries.append(raw)

    stats["windows_events_in_context"] = len(windows_events)
    stats["eset_csv_rows_in_context"] = len(eset_rows)
    stats["eset_file_summaries_in_context"] = len(eset_file_summaries)
    stats["payload_summaries_in_context"] = len(payload_summaries)
    stats["events_in_context"] = len(windows_events) + len(eset_rows)
    return windows_events, eset_rows, eset_file_summaries, payload_summaries, stats


def read_text_guess(path: Path) -> str:
    data = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16", "cp1257", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", errors="replace")


def parse_csv_sample(path: Path) -> dict:
    text = read_text_guess(path)
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return {"rows": 0, "columns": [], "sample_rows": []}
    sample_text = "\n".join(lines[:20])
    try:
        dialect = csv.Sniffer().sniff(sample_text, delimiters=",;\t|")
    except Exception:
        dialect = csv.excel
    reader = csv.DictReader(lines, dialect=dialect)
    rows = []
    total = 0
    for row in reader:
        total += 1
        if len(rows) < MAX_ESET_ROWS_SAMPLE:
            rows.append(dict(row))
    return {"rows": total, "columns": reader.fieldnames or [], "sample_rows": rows}


def load_eset_file_manifest() -> dict[str, dict]:
    """Read receiver-created manifests so legacy uploaded CSV files keep host/IP provenance."""
    index: dict[str, dict] = {}
    for manifest in sorted(ESET_CSV_DIR.glob("**/*_eset_file_manifest.jsonl")):
        try:
            with manifest.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(item, dict):
                        continue
                    saved_path = item.get("saved_path") or item.get("file")
                    if saved_path:
                        index[str(Path(saved_path))] = item
        except Exception:
            continue
    return index


def infer_ip_from_filename(name: str) -> str | None:
    """Best-effort fallback for files saved as 192_168_1_10_YYYY-MM-DD_name.csv."""
    m = re.match(r"^(\d{1,3})_(\d{1,3})_(\d{1,3})_(\d{1,3})_", name)
    if not m:
        return None
    parts = [int(x) for x in m.groups()]
    if all(0 <= x <= 255 for x in parts):
        return ".".join(str(x) for x in parts)
    return None


def first_row_time(fields: dict) -> Any:
    lower_map = {str(k).lower(): v for k, v in fields.items()}
    preferred = ["time", "date", "laikas", "data", "timestamp", "event time", "detected"]
    for token in preferred:
        for key, value in lower_map.items():
            if token in key and value:
                return value
    return None


def build_legacy_eset_rows(file: Path, summary: dict, parsed: dict, manifest_meta: dict) -> list[dict]:
    rows: list[dict] = []
    sample_rows = parsed.get("sample_rows") if isinstance(parsed.get("sample_rows"), list) else []
    collector_ip = manifest_meta.get("collector_seen_ip") or summary.get("collector_seen_ip") or infer_ip_from_filename(file.name)
    computer = manifest_meta.get("computer") or summary.get("computer")
    file_mtime = summary.get("mtime") or summary.get("last_write_time")
    for idx, fields in enumerate(sample_rows, start=1):
        if not isinstance(fields, dict):
            continue
        raw_line = json.dumps(fields, ensure_ascii=False, sort_keys=True)
        parsed_time = first_row_time(fields) or file_mtime
        rows.append({
            "source_type": "eset_csv_row",
            "collector_received_at": manifest_meta.get("received_at") or file_mtime,
            "collector_seen_ip": collector_ip,
            "computer": computer,
            "filename": summary.get("filename") or file.name,
            "source_path": manifest_meta.get("source_path") or str(file),
            "file_last_write_time": manifest_meta.get("last_write_time") or file_mtime,
            "parsed_time": parsed_time,
            "time_parse_status": "from_csv_or_file_mtime",
            "row_number": idx,
            "row_hash": sha256_text(raw_line),
            "raw_line": raw_line,
            "fields": fields,
        })
    return rows


def load_legacy_eset_files_and_rows(cutoff: datetime) -> tuple[list[dict], list[dict]]:
    summaries: list[dict] = []
    normalized_rows: list[dict] = []
    manifest_index = load_eset_file_manifest()
    seen_row_keys: set[str] = set()
    for file in sorted(ESET_CSV_DIR.glob("**/*")):
        if not file.is_file() or file.name.endswith("_eset_file_manifest.jsonl"):
            continue
        try:
            mtime_dt = datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc)
            if mtime_dt < cutoff:
                continue
        except Exception:
            mtime_dt = datetime.now(timezone.utc)
        manifest_meta = manifest_index.get(str(file), {})
        parsed = parse_csv_sample(file) if file.suffix.lower() in {".csv", ".txt", ".log"} else {"rows": None, "columns": [], "sample_rows": []}
        summary = {
            "source_type": "eset_csv_file",
            "file": str(file),
            "filename": file.name,
            "collector_seen_ip": manifest_meta.get("collector_seen_ip") or infer_ip_from_filename(file.name),
            "computer": manifest_meta.get("computer"),
            "source_path": manifest_meta.get("source_path"),
            "size_bytes": file.stat().st_size,
            "mtime": mtime_dt.isoformat(timespec="seconds"),
            "last_write_time": manifest_meta.get("last_write_time"),
            "sha256": manifest_meta.get("sha256"),
            "parsed": parsed,
        }
        summaries.append(summary)
        for raw_row in build_legacy_eset_rows(file, summary, parsed, manifest_meta):
            key = dedupe_key(raw_row)
            if key in seen_row_keys:
                continue
            seen_row_keys.add(key)
            normalized_rows.append(normalize_eset_row(raw_row))
    return summaries, normalized_rows


def load_legacy_eset_files(cutoff: datetime) -> list[dict]:
    summaries, _rows = load_legacy_eset_files_and_rows(cutoff)
    return summaries

def build_summary(windows_events: list[dict], eset_rows: list[dict], eset_files: list[dict], payload_summaries: list[dict]) -> dict:
    by_log = Counter(e["event"].get("channel") for e in windows_events)
    by_id = Counter(str(e["event"].get("id")) for e in windows_events)
    by_severity = Counter(e["event"].get("severity") for e in windows_events)
    eset_by_file = Counter((e.get("source") or {}).get("filename") for e in eset_rows)
    eset_by_severity = Counter(e["event"].get("severity") for e in eset_rows)

    high_windows = [e for e in windows_events if e["event"].get("id") in HIGH_VALUE_EVENT_IDS or e["event"].get("severity") in {"aukšta", "kritinė"}]
    high_eset = [e for e in eset_rows if e["event"].get("severity") in {"aukšta", "kritinė"}]

    failed_by_host = defaultdict(int)
    for e in windows_events:
        if e["event"].get("id") == 4625:
            failed_by_host[e["source"].get("computer") or "unknown"] += 1

    findings = []
    for host, count in failed_by_host.items():
        if count >= 10:
            findings.append({
                "type": "many_failed_logons",
                "severity": "aukšta" if count >= 30 else "vidutinė",
                "host": host,
                "count": count,
                "recommendation": "Patikrinti prisijungimo šaltinius, riboti RDP/SMB prieigą, įjungti paskyrų blokavimo ir MFA politiką, jei taikoma.",
            })

    if any(e["event"].get("id") == 1102 for e in windows_events):
        findings.append({
            "type": "audit_log_cleared",
            "severity": "kritinė",
            "recommendation": "Patikrinti, kas išvalė audito žurnalą, ir įvertinti galimą incidentą.",
        })

    if len(high_eset) > 0:
        findings.append({
            "type": "eset_high_value_rows_present",
            "severity": "aukšta" if any(e["event"].get("severity") == "aukšta" for e in high_eset) else "vidutinė",
            "count": len(high_eset),
            "recommendation": "Peržiūrėti ESET žurnalų eilutes: grėsmės, blokavimai arba filtravimo įvykiai gali būti susiję su naudotojų naršymu, kenkėjiškais URL arba lokaliomis grėsmėmis.",
        })

    return {
        "total_events": len(windows_events) + len(eset_rows),
        "windows_events_count": len(windows_events),
        "eset_csv_rows_count": len(eset_rows),
        "by_log": dict(by_log),
        "by_event_id": dict(by_id),
        "by_windows_severity": dict(by_severity),
        "by_eset_file": dict(eset_by_file),
        "by_eset_severity": dict(eset_by_severity),
        "high_value_windows_events_sample": high_windows[:50],
        "high_value_eset_rows_sample": high_eset[:50],
        "aggregated_findings": findings,
        "eset_files_count": len(eset_files),
        "payload_summaries_count": len(payload_summaries),
    }


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)

    windows_events, eset_rows, eset_file_summaries, payload_summaries, stats = load_endpoint_records(cutoff)
    legacy_eset_files, legacy_eset_rows = load_legacy_eset_files_and_rows(cutoff)
    # Older collectors may upload ESET CSV/log files instead of already parsed `eset_csv_rows`.
    # Convert those file samples into the same normalized row format so correlation/risk/AI can use them.
    eset_rows.extend(legacy_eset_rows)
    stats["legacy_eset_csv_rows_in_context"] = len(legacy_eset_rows)
    stats["eset_csv_rows_in_context"] = len(eset_rows)
    stats["events_in_context"] = len(windows_events) + len(eset_rows)
    all_eset_files = eset_file_summaries + legacy_eset_files
    summary = build_summary(windows_events, eset_rows, all_eset_files, payload_summaries)

    payload = {
        "payload_type": "endpoint_events",
        "timestamp": timestamp,
        "lookback_hours": LOOKBACK_HOURS,
        "source_dirs": {
            "endpoint_event_log": str(ENDPOINT_EVENT_DIR),
            "legacy_eset_csv_log": str(ESET_CSV_DIR),
        },
        "stats": stats,
        "summary": summary,
        "normalized_events_sample": windows_events[:MAX_EVENTS_SAMPLE],
        "eset_csv_rows_sample": eset_rows[:MAX_ESET_ROWS_SAMPLE],
        "eset_files": all_eset_files[:200],
        "payload_summaries": payload_summaries[-20:],
    }

    report_file = paths["reports_dir"] / f"endpoint_events_{timestamp}.json"
    ai_file = paths["ai_dir"] / f"endpoint_events_ai_payload_{timestamp}.json"
    save_json(report_file, payload)
    save_json(ai_file, {
        "instruction": "Naudok Windows endpoint įvykius ir ESET CSV žurnalų eilutes kartu su tinklo skenavimo rezultatais. Įvertink autentifikacijos anomalijas, PowerShell/RDP/WMI/Task Scheduler įvykius, ESET filtravimo ir grėsmių įrašus bei pateik praktines rekomendacijas.",
        **payload,
    })

    print(f"Endpoint events report: {report_file}")
    print(f"Endpoint AI payload: {ai_file}")
    print(f"Windows events in context: {len(windows_events)}")
    print(f"ESET CSV rows in context: {len(eset_rows)}")
    print(f"ESET file summaries: {len(all_eset_files)}")


if __name__ == "__main__":
    main()
