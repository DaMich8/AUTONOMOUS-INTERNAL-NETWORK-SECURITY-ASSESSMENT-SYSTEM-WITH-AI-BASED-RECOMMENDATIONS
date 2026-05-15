from __future__ import annotations

import hashlib
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from common import BASE_DIR, get_run_paths, save_json, timestamp_now

WINDOWS_SECURITY_LOG_DIR = Path(os.getenv("WINDOWS_SECURITY_LOG_DIR", "/home/kali/network-thesis-GIT/windows_security_log"))
COLLECTOR_DIR = BASE_DIR / "windows_events"
INBOX_DIR = COLLECTOR_DIR / "inbox"  # legacy path compatibility
STATE_DIR = BASE_DIR / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = STATE_DIR / "windows_security_event_dedupe.json"

LOOKBACK_DAYS = int(os.getenv("WINDOWS_EVENT_LOOKBACK_DAYS", "1"))
STATE_RETENTION_DAYS = int(os.getenv("WINDOWS_EVENT_STATE_RETENTION_DAYS", "14"))
MAX_EVENTS_IN_AI_PAYLOAD = int(os.getenv("WINDOWS_EVENT_AI_MAX_EVENTS", "500"))
# context: kiekvieno full_assessment metu į AI kontekstą įtraukiami visi unikalūs paskutinio laikotarpio įvykiai.
# new_only: į ataskaitą įtraukiami tik anksčiau nematyti įvykiai.
WINDOWS_EVENT_NORMALIZER_MODE = os.getenv("WINDOWS_EVENT_NORMALIZER_MODE", "context").lower().strip()

EVENT_MAP = {
    4624: {"name": "successful_logon", "category": "authentication", "action": "logon", "outcome": "success", "severity": "informacinė"},
    4625: {"name": "failed_logon", "category": "authentication", "action": "logon", "outcome": "failure", "severity": "vidutinė"},
    4634: {"name": "logoff", "category": "authentication", "action": "logoff", "outcome": "success", "severity": "informacinė"},
    4648: {"name": "explicit_credentials_used", "category": "authentication", "action": "explicit_credentials", "outcome": "success", "severity": "vidutinė"},
    4672: {"name": "special_privileges_assigned", "category": "privilege", "action": "admin_privileges", "outcome": "success", "severity": "vidutinė"},
    4688: {"name": "process_created", "category": "process", "action": "process_create", "outcome": "success", "severity": "informacinė"},
    4697: {"name": "service_installed", "category": "persistence", "action": "service_install", "outcome": "success", "severity": "aukšta"},
    4720: {"name": "user_account_created", "category": "account_management", "action": "user_create", "outcome": "success", "severity": "aukšta"},
    4722: {"name": "user_account_enabled", "category": "account_management", "action": "user_enable", "outcome": "success", "severity": "vidutinė"},
    4726: {"name": "user_account_deleted", "category": "account_management", "action": "user_delete", "outcome": "success", "severity": "vidutinė"},
    4732: {"name": "member_added_to_local_group", "category": "account_management", "action": "group_member_add", "outcome": "success", "severity": "aukšta"},
    4738: {"name": "user_account_changed", "category": "account_management", "action": "user_change", "outcome": "success", "severity": "vidutinė"},
    4740: {"name": "user_account_locked", "category": "authentication", "action": "account_lockout", "outcome": "failure", "severity": "vidutinė"},
    4776: {"name": "ntlm_credential_validation", "category": "authentication", "action": "credential_validation", "outcome": "unknown", "severity": "informacinė"},
    1102: {"name": "audit_log_cleared", "category": "defense_evasion", "action": "audit_log_clear", "outcome": "success", "severity": "kritinė"},
}

SEVERITY_RANK = {"informacinė": 0, "žema": 1, "vidutinė": 2, "aukšta": 3, "kritinė": 4}


def parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    # PowerShell dažnai siunčia ISO su Z arba su lokalia zona. Normalizuojame paprastai.
    text = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except Exception:
            continue
    return None


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {"seen": {}}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("seen"), dict):
            return data
    except Exception:
        pass
    return {"seen": {}}


def save_state(state: dict) -> None:
    save_json(STATE_FILE, state)


def prune_state(state: dict) -> None:
    cutoff = datetime.now() - timedelta(days=STATE_RETENTION_DAYS)
    seen = state.get("seen", {})
    kept = {}
    for key, meta in seen.items():
        ts = parse_dt(meta.get("first_seen_at") if isinstance(meta, dict) else None)
        if ts is None or ts >= cutoff:
            kept[key] = meta
    state["seen"] = kept


def iter_raw_files() -> list[Path]:
    """Skaito naują vartotojo nurodytą katalogą ir seną inbox kelią dėl suderinamumo."""
    cutoff = datetime.now() - timedelta(days=max(LOOKBACK_DAYS + 1, 2))
    roots = [WINDOWS_SECURITY_LOG_DIR, INBOX_DIR]
    files = []
    seen_paths = set()

    for root in roots:
        if not root.exists():
            continue
        for file in root.glob("**/*.jsonl"):
            if "_receiver_logs" in file.parts:
                continue
            try:
                resolved = file.resolve()
                if resolved in seen_paths:
                    continue
                if datetime.fromtimestamp(file.stat().st_mtime) >= cutoff:
                    files.append(file)
                    seen_paths.add(resolved)
            except Exception:
                continue
    return sorted(files)


def event_data(raw_event: dict) -> dict:
    for key in ("event_data", "EventData", "eventData", "data"):
        value = raw_event.get(key)
        if isinstance(value, dict):
            return value
    return {}


def pick(raw_event: dict, data: dict, *names: str) -> Any:
    for name in names:
        if name in raw_event and raw_event.get(name) not in (None, ""):
            return raw_event.get(name)
        if name in data and data.get(name) not in (None, ""):
            return data.get(name)
    return None


def build_dedupe_key(raw_event: dict, data: dict, collector_file: str) -> str:
    parts = [
        str(pick(raw_event, data, "computer", "Computer", "machine_name", "MachineName") or ""),
        str(pick(raw_event, data, "log_name", "LogName", "channel", "Channel") or "Security"),
        str(pick(raw_event, data, "record_id", "RecordId", "recordId") or ""),
        str(pick(raw_event, data, "id", "Id", "event_id", "EventID") or ""),
        str(pick(raw_event, data, "time_created", "TimeCreated", "event_time", "EventTime") or ""),
    ]
    # Jei RecordId nėra, vis tiek turime stabilų hash iš pagrindinių laukų.
    if not parts[2]:
        parts.append(json.dumps(data, sort_keys=True, ensure_ascii=False)[:2000])
        parts.append(collector_file)
    base = "|".join(parts)
    return hashlib.sha256(base.encode("utf-8", errors="ignore")).hexdigest()


def event_mapping(event_id: int, data: dict) -> dict:
    mapping = dict(EVENT_MAP.get(event_id, {
        "name": "windows_security_event",
        "category": "security",
        "action": "observed",
        "outcome": "unknown",
        "severity": "žema",
    }))

    # 4732 į Administrators grupę yra svarbiau nei į paprastą grupę.
    if event_id == 4732:
        group_name = str(data.get("TargetUserName") or data.get("GroupName") or "").lower()
        if "admin" in group_name or "administrators" in group_name:
            mapping["severity"] = "kritinė"
            mapping["name"] = "member_added_to_admin_group"

    # 4625 su daug kartojimų agreguojamas vėliau, bet pats įvykis lieka vidutinis.
    return mapping


def normalize_event(wrapped: dict, source_file: Path) -> dict | None:
    raw_event = wrapped.get("event") if isinstance(wrapped.get("event"), dict) else wrapped
    if not isinstance(raw_event, dict):
        return None

    data = event_data(raw_event)
    try:
        event_id = int(pick(raw_event, data, "id", "Id", "event_id", "EventID") or 0)
    except Exception:
        event_id = 0

    event_time_value = pick(raw_event, data, "time_created", "TimeCreated", "event_time", "EventTime")
    event_time = parse_dt(event_time_value)
    if event_time is None:
        event_time = parse_dt((wrapped.get("ingest_meta") or {}).get("ingested_at")) or datetime.now()

    if event_time < datetime.now() - timedelta(days=LOOKBACK_DAYS):
        return None

    mapping = event_mapping(event_id, data)
    dedupe_key = build_dedupe_key(raw_event, data, str(source_file))
    ingest_meta = wrapped.get("ingest_meta") if isinstance(wrapped.get("ingest_meta"), dict) else {}

    computer = pick(raw_event, data, "computer", "Computer", "machine_name", "MachineName")
    record_id = pick(raw_event, data, "record_id", "RecordId", "recordId")
    provider = pick(raw_event, data, "provider_name", "ProviderName", "Provider")
    channel = pick(raw_event, data, "log_name", "LogName", "channel", "Channel") or "Security"

    src_ip = pick(raw_event, data, "IpAddress", "SourceNetworkAddress", "ClientAddress")
    src_port = pick(raw_event, data, "IpPort", "SourcePort")
    logon_type = pick(raw_event, data, "LogonType")

    actor_user = pick(raw_event, data, "SubjectUserName", "AccountName", "TargetUserName")
    actor_domain = pick(raw_event, data, "SubjectDomainName", "AccountDomain", "TargetDomainName")
    target_user = pick(raw_event, data, "TargetUserName", "NewTargetUserName", "MemberName")
    target_domain = pick(raw_event, data, "TargetDomainName")
    process_name = pick(raw_event, data, "ProcessName", "NewProcessName", "ParentProcessName")

    message = raw_event.get("message") or raw_event.get("Message")
    if isinstance(message, str) and len(message) > 1500:
        message = message[:1500] + "..."

    return {
        "schema_version": "1.0",
        "source_type": "windows_security_event",
        "collector": {
            "ingested_at": ingest_meta.get("ingested_at"),
            "remote_addr": ingest_meta.get("collector_remote_addr"),
            "source_file": source_file.name,
        },
        "source": {
            "computer": computer,
            "collector_seen_ip": ingest_meta.get("collector_remote_addr"),
        },
        "event": {
            "id": event_id,
            "name": mapping["name"],
            "category": mapping["category"],
            "action": mapping["action"],
            "outcome": mapping["outcome"],
            "severity": mapping["severity"],
            "time": event_time.isoformat(timespec="seconds"),
            "record_id": record_id,
            "provider": provider,
            "channel": channel,
        },
        "actor": {
            "user": actor_user,
            "domain": actor_domain,
            "sid": pick(raw_event, data, "SubjectUserSid", "TargetSid"),
        },
        "target": {
            "user": target_user,
            "domain": target_domain,
            "object_name": pick(raw_event, data, "ObjectName", "ShareName"),
            "process_name": process_name,
            "group_name": pick(raw_event, data, "GroupName", "TargetUserName"),
        },
        "network": {
            "src_ip": src_ip,
            "src_port": src_port,
            "workstation": pick(raw_event, data, "WorkstationName", "Workstation"),
        },
        "auth": {
            "logon_type": logon_type,
            "logon_process": pick(raw_event, data, "LogonProcessName"),
            "auth_package": pick(raw_event, data, "AuthenticationPackageName"),
        },
        "dedupe_key": dedupe_key,
        "message": message,
    }


def load_normalized_events() -> tuple[list[dict], dict]:
    """Normalize Windows Security events.

    Default mode is "context": the report contains all unique events from the
    lookback window, even if they were already seen in an earlier run. This is
    the right mode for full_assessment.py because AI needs the current 24h
    security context, not only events that are new since the previous timer run.

    Set WINDOWS_EVENT_NORMALIZER_MODE=new_only only if you intentionally want a
    delta-only export.
    """
    mode = WINDOWS_EVENT_NORMALIZER_MODE if WINDOWS_EVENT_NORMALIZER_MODE in {"context", "new_only"} else "context"
    state = load_state()
    prune_state(state)
    seen = state.setdefault("seen", {})

    raw_files = iter_raw_files()
    normalized = []
    in_current_report = set()

    parsed_lines = 0
    skipped_old = 0
    skipped_duplicate_lines = 0
    already_seen_before = 0
    new_events = 0

    for raw_file in raw_files:
        with open(raw_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    wrapped = json.loads(line)
                    parsed_lines += 1
                except Exception:
                    continue

                event = normalize_event(wrapped, raw_file)
                if event is None:
                    skipped_old += 1
                    continue

                key = event["dedupe_key"]
                if key in in_current_report:
                    skipped_duplicate_lines += 1
                    continue
                in_current_report.add(key)

                was_seen = key in seen
                if was_seen:
                    already_seen_before += 1
                else:
                    new_events += 1
                    seen[key] = {
                        "first_seen_at": datetime.now().isoformat(timespec="seconds"),
                        "event_time": event["event"]["time"],
                        "computer": event["source"].get("computer"),
                        "event_id": event["event"].get("id"),
                    }

                event["dedupe"] = {
                    "mode": mode,
                    "already_seen_before": was_seen,
                    "included_in_current_context": True,
                }

                if mode == "new_only" and was_seen:
                    continue

                normalized.append(event)

    save_state(state)
    stats = {
        "mode": mode,
        "raw_files_read": len(raw_files),
        "parsed_lines": parsed_lines,
        "events_in_context": len(normalized),
        "new_events": new_events,
        "already_seen_before": already_seen_before,
        "skipped_duplicates_in_current_report": skipped_duplicate_lines,
        "skipped_duplicates": skipped_duplicate_lines,
        "skipped_old_or_invalid": skipped_old,
        "state_seen_total": len(state.get("seen", {})),
    }
    return normalized, stats

def build_summary(events: list[dict]) -> dict:
    by_host = defaultdict(Counter)
    by_event_id = Counter()
    by_severity = Counter()
    high_value = []

    for event in events:
        host = event.get("source", {}).get("computer") or event.get("collector", {}).get("remote_addr") or "unknown"
        event_id = event.get("event", {}).get("id")
        severity = event.get("event", {}).get("severity") or "žema"
        name = event.get("event", {}).get("name") or "event"
        by_host[host][str(event_id)] += 1
        by_event_id[str(event_id)] += 1
        by_severity[severity] += 1
        if SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["aukšta"]:
            high_value.append({
                "time": event.get("event", {}).get("time"),
                "host": host,
                "event_id": event_id,
                "name": name,
                "severity": severity,
                "actor": event.get("actor", {}),
                "target": event.get("target", {}),
                "network": event.get("network", {}),
            })

    failed_logons_by_host = []
    for host, counts in by_host.items():
        failed = counts.get("4625", 0)
        if failed >= 5:
            failed_logons_by_host.append({
                "host": host,
                "failed_logons_4625": failed,
                "severity": "aukšta" if failed >= 20 else "vidutinė",
                "recommendation": "Patikrinti pasikartojančius nesėkmingus prisijungimus, šaltinio IP ir paskyras; prireikus taikyti blokavimą ar paskyros apsaugą.",
            })

    return {
        "total_events_in_context": len(events),
        "total_new_events": sum(1 for e in events if not e.get("dedupe", {}).get("already_seen_before")),
        "by_event_id": dict(by_event_id.most_common()),
        "by_severity": dict(by_severity),
        "by_host_event_id": {host: dict(counter) for host, counter in by_host.items()},
        "high_value_events": high_value[:100],
        "aggregated_findings": failed_logons_by_host,
    }


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    events, stats = load_normalized_events()
    summary = build_summary(events)

    report = {
        "scan_type": "windows_security_events",
        "timestamp": timestamp,
        "lookback_days": LOOKBACK_DAYS,
        "dedupe_state_file": str(STATE_FILE),
        "raw_log_dirs": [str(WINDOWS_SECURITY_LOG_DIR), str(INBOX_DIR)],
        "stats": stats,
        "summary": summary,
        "normalized_events": events,
    }

    report_file = paths["reports_dir"] / f"windows_security_events_{timestamp}.json"
    save_json(report_file, report)

    ai_payload = {
        "instruction": (
            "Naudok normalizuotus Windows Security žurnalo įvykius kartu su tinklo skenavimo rezultatais. "
            "Įvertink autentifikacijos anomalijas, privilegijų suteikimą, paskyrų pakeitimus, naujų paslaugų diegimą, "
            "audito žurnalo išvalymą ir pakartotinius nesėkmingus prisijungimus. Pateik praktines rekomendacijas, "
            "kurias būtų galima susieti su ugniasienės, paskyrų apsaugos, segmentavimo ir monitoringo veiksmais."
        ),
        "payload_type": "windows_security_events",
        "timestamp": timestamp,
        "lookback_days": LOOKBACK_DAYS,
        "stats": stats,
        "summary": summary,
        "normalized_events_sample": events[:MAX_EVENTS_IN_AI_PAYLOAD],
    }

    ai_file = paths["ai_dir"] / f"windows_security_ai_payload_{timestamp}.json"
    save_json(ai_file, ai_payload)

    print(f"Windows Security normalizuota ataskaita: {report_file}")
    print(f"Windows Security AI payload: {ai_file}")
    print(f"Windows Security konteksto įvykiai: {len(events)}")
    print(f"Nauji įvykiai pagal dedupe būseną: {stats['new_events']}")
    print(f"Pasikartojančios eilutės tame pačiame kontekste: {stats['skipped_duplicates_in_current_report']}")


if __name__ == "__main__":
    main()
