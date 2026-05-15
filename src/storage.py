from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from common import BASE_DIR, RUNS_DIR, get_run_paths, load_json, save_json, timestamp_now

DATA_DIR = BASE_DIR / "data"
DEFAULT_DB = DATA_DIR / "network_thesis.db"


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def scalar(value: Any) -> Any:
    """SQLite įrašams palieka tik paprastus tipus; sudėtinius saugo kaip JSON tekstą."""
    if value is None or isinstance(value, (str, int, float, bytes)):
        return value
    if isinstance(value, bool):
        return int(value)
    try:
        return json_dumps(value)
    except Exception:
        return str(value)


def safe_int(value: Any) -> int | None:
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(float(str(value)))
    except Exception:
        return None


def sha256_file(path: Path) -> str | None:
    if not path or not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def ip_sort_key(ip: str):
    try:
        return tuple(int(part) for part in str(ip).split("."))
    except Exception:
        return (999, 999, 999, 999)


def latest_file(directory: Path, pattern: str) -> Path | None:
    files = sorted(directory.glob(pattern)) if directory.exists() else []
    return files[-1] if files else None


def latest_global(pattern: str) -> Path | None:
    files = sorted(RUNS_DIR.glob(f"**/{pattern}"))
    return files[-1] if files else None


def infer_run_dir_from_file(path: Path) -> Path:
    if path.parent.name in {"reports", "ai", "services", "discovery", "logs", "power", "meta"}:
        return path.parent.parent
    return path.parent


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def apply_schema_migrations(conn: sqlite3.Connection) -> None:
    """Papildo senas SQLite lenteles naujais laukais, neištrinant istorijos.

    CREATE TABLE IF NOT EXISTS nekeičia jau egzistuojančios lentelės struktūros,
    todėl po naujų laukų įvedimo sena DB gali neturėti, pvz., asset_id.
    Ši migracija sąmoningai naudoja tik ADD COLUMN, kad būtų saugi Raspberry Pi
    aplinkoje ir neištrintų ankstesnių skenavimo rezultatų.
    """
    migrations: dict[str, dict[str, str]] = {
        "scan_runs": {
            "run_id": "TEXT",
            "timestamp": "TEXT",
            "run_date": "TEXT",
            "network": "TEXT",
            "interface": "TEXT",
            "source_ip": "TEXT",
            "run_dir": "TEXT",
            "assessment_file": "TEXT",
            "risk_scores_file": "TEXT",
            "endpoint_events_file": "TEXT",
            "created_at": "TEXT",
            "updated_at": "TEXT",
            "summary_json": "TEXT",
        },
        "assets": {
            "asset_id": "TEXT",
            "mac": "TEXT",
            "vendor": "TEXT",
            "hostname": "TEXT",
            "state": "TEXT",
            "device_class": "TEXT",
            "priority_score": "REAL",
            "priority_level": "TEXT",
            "risk_score": "REAL",
            "risk_level": "TEXT",
            "open_ports_count": "INTEGER",
            "tcp_ports_json": "TEXT",
            "udp_ports_json": "TEXT",
            "service_names_json": "TEXT",
            "change_summary_json": "TEXT",
            "raw_json": "TEXT",
        },
        "services": {
            "state": "TEXT",
            "service_name": "TEXT",
            "product": "TEXT",
            "version": "TEXT",
            "extra_info": "TEXT",
            "tunnel": "TEXT",
            "cpes_json": "TEXT",
            "scripts_json": "TEXT",
            "raw_json": "TEXT",
        },
        "vulnerabilities": {
            "cvss": "REAL",
            "epss": "REAL",
            "kev": "INTEGER DEFAULT 0",
            "source_port": "TEXT DEFAULT ''",
            "raw_json": "TEXT",
        },
        "risk_scores": {
            "asset_id": "TEXT",
            "risk_score": "REAL",
            "risk_level": "TEXT",
            "previous_risk_score": "REAL",
            "previous_risk_level": "TEXT",
            "risk_delta": "REAL",
            "device_class": "TEXT",
            "components_json": "TEXT",
            "weighted_parts_json": "TEXT",
            "weights_json": "TEXT",
            "explanation_json": "TEXT",
            "raw_json": "TEXT",
        },
        "endpoint_events": {
            "first_seen_scan_id": "TEXT",
            "last_seen_scan_id": "TEXT",
            "seen_count": "INTEGER DEFAULT 1",
            "computer": "TEXT",
            "source_type": "TEXT",
            "log_name": "TEXT",
            "provider": "TEXT",
            "event_id": "TEXT",
            "event_time": "TEXT",
            "severity": "TEXT",
            "event_name": "TEXT",
            "category": "TEXT",
            "action": "TEXT",
            "outcome": "TEXT",
            "src_ip": "TEXT",
            "target_user": "TEXT",
            "raw_json": "TEXT",
        },
        "findings": {
            "scan_id": "TEXT",
            "ip": "TEXT",
            "asset_id": "TEXT",
            "source": "TEXT",
            "severity": "TEXT",
            "title": "TEXT",
            "details": "TEXT",
            "recommendation": "TEXT",
            "status": "TEXT",
            "risk_score": "REAL",
            "raw_json": "TEXT",
        },
        "recommendations": {
            "scan_id": "TEXT",
            "ip": "TEXT",
            "finding": "TEXT",
            "risk_level": "TEXT",
            "priority": "TEXT",
            "recommendation_json": "TEXT",
            "verification_json": "TEXT",
            "status": "TEXT DEFAULT 'open'",
            "raw_json": "TEXT",
        },
        "raw_sources": {
            "sha256": "TEXT",
            "size_bytes": "INTEGER",
            "modified_at": "TEXT",
        },
    }
    for table, columns in migrations.items():
        existing = table_columns(conn, table)
        for column, definition in columns.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                existing.add(column)


def init_db(conn: sqlite3.Connection) -> None:
    # Tik lentelių sukūrimas. Indeksai kuriami po migracijų, nes senoje DB
    # lentelė gali egzistuoti be naujų stulpelių, pvz. assets.asset_id.
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            scan_id TEXT PRIMARY KEY,
            run_id TEXT,
            timestamp TEXT,
            run_date TEXT,
            network TEXT,
            interface TEXT,
            source_ip TEXT,
            run_dir TEXT,
            assessment_file TEXT,
            risk_scores_file TEXT,
            endpoint_events_file TEXT,
            created_at TEXT,
            updated_at TEXT,
            summary_json TEXT
        );

        CREATE TABLE IF NOT EXISTS assets (
            scan_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            asset_id TEXT,
            mac TEXT,
            vendor TEXT,
            hostname TEXT,
            state TEXT,
            device_class TEXT,
            priority_score REAL,
            priority_level TEXT,
            risk_score REAL,
            risk_level TEXT,
            open_ports_count INTEGER,
            tcp_ports_json TEXT,
            udp_ports_json TEXT,
            service_names_json TEXT,
            change_summary_json TEXT,
            raw_json TEXT,
            PRIMARY KEY (scan_id, ip),
            FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS services (
            scan_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT,
            service_name TEXT,
            product TEXT,
            version TEXT,
            extra_info TEXT,
            tunnel TEXT,
            cpes_json TEXT,
            scripts_json TEXT,
            raw_json TEXT,
            PRIMARY KEY (scan_id, ip, port, protocol),
            FOREIGN KEY (scan_id, ip) REFERENCES assets(scan_id, ip) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            scan_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            cve TEXT NOT NULL,
            cvss REAL,
            epss REAL,
            kev INTEGER DEFAULT 0,
            source_port TEXT DEFAULT '',
            raw_json TEXT,
            PRIMARY KEY (scan_id, ip, cve, source_port),
            FOREIGN KEY (scan_id, ip) REFERENCES assets(scan_id, ip) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS risk_scores (
            scan_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            asset_id TEXT,
            risk_score REAL,
            risk_level TEXT,
            previous_risk_score REAL,
            previous_risk_level TEXT,
            risk_delta REAL,
            device_class TEXT,
            components_json TEXT,
            weighted_parts_json TEXT,
            weights_json TEXT,
            explanation_json TEXT,
            raw_json TEXT,
            PRIMARY KEY (scan_id, ip),
            FOREIGN KEY (scan_id, ip) REFERENCES assets(scan_id, ip) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS endpoint_events (
            event_key TEXT PRIMARY KEY,
            first_seen_scan_id TEXT,
            last_seen_scan_id TEXT,
            seen_count INTEGER DEFAULT 1,
            computer TEXT,
            source_type TEXT,
            log_name TEXT,
            provider TEXT,
            event_id TEXT,
            event_time TEXT,
            severity TEXT,
            event_name TEXT,
            category TEXT,
            action TEXT,
            outcome TEXT,
            src_ip TEXT,
            target_user TEXT,
            raw_json TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_endpoint_events (
            scan_id TEXT NOT NULL,
            event_key TEXT NOT NULL,
            PRIMARY KEY (scan_id, event_key),
            FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
            FOREIGN KEY (event_key) REFERENCES endpoint_events(event_key) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            finding_key TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            ip TEXT,
            asset_id TEXT,
            source TEXT,
            severity TEXT,
            title TEXT,
            details TEXT,
            recommendation TEXT,
            status TEXT,
            risk_score REAL,
            raw_json TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS recommendations (
            recommendation_key TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            ip TEXT,
            finding TEXT,
            risk_level TEXT,
            priority TEXT,
            recommendation_json TEXT,
            verification_json TEXT,
            status TEXT DEFAULT 'open',
            raw_json TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS raw_sources (
            scan_id TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            sha256 TEXT,
            size_bytes INTEGER,
            modified_at TEXT,
            PRIMARY KEY (scan_id, file_type, file_path),
            FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id) ON DELETE CASCADE
        );
        """
    )

    apply_schema_migrations(conn)

    # View perkurti saugu, nes tai nėra istoriniai duomenys. Taip išvengiama
    # neatitikimų, jei view buvo sukurtas pagal senesnę schemą.
    conn.executescript(
        """
        DROP VIEW IF EXISTS latest_asset_state;
        CREATE VIEW latest_asset_state AS
        SELECT a.*
        FROM assets a
        JOIN (
            SELECT ip, MAX(scan_id) AS latest_scan_id
            FROM assets
            GROUP BY ip
        ) x ON x.ip = a.ip AND x.latest_scan_id = a.scan_id;

        CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
        CREATE INDEX IF NOT EXISTS idx_assets_asset_id ON assets(asset_id);
        CREATE INDEX IF NOT EXISTS idx_services_ip_port ON services(ip, port, protocol);
        CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve);
        CREATE INDEX IF NOT EXISTS idx_risk_score ON risk_scores(risk_score DESC);
        CREATE INDEX IF NOT EXISTS idx_endpoint_computer_time ON endpoint_events(computer, event_time);
        CREATE INDEX IF NOT EXISTS idx_findings_scan_ip ON findings(scan_id, ip);
        CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
        """
    )
    conn.commit()

def get_scan_id(assessment: dict, assessment_file: Path) -> str:
    ts = assessment.get("timestamp") or assessment_file.stem.replace("assessment_", "")
    network = str(assessment.get("network") or "unknown").replace("/", "_").replace(".", "_")
    return f"{ts}_{network}"


def insert_scan_run(conn: sqlite3.Connection, scan_id: str, assessment: dict, assessment_file: Path, risk_file: Path | None, endpoint_file: Path | None) -> None:
    run_dir = infer_run_dir_from_file(assessment_file)
    run_id = run_dir.name
    run_date = run_dir.parent.name if run_dir.parent else None
    now = datetime.now().isoformat(timespec="seconds")
    summary = assessment.get("summary") or {}
    conn.execute(
        """
        INSERT INTO scan_runs (
            scan_id, run_id, timestamp, run_date, network, interface, source_ip,
            run_dir, assessment_file, risk_scores_file, endpoint_events_file,
            created_at, updated_at, summary_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scan_id) DO UPDATE SET
            updated_at=excluded.updated_at,
            assessment_file=excluded.assessment_file,
            risk_scores_file=excluded.risk_scores_file,
            endpoint_events_file=excluded.endpoint_events_file,
            summary_json=excluded.summary_json
        """,
        (scan_id, run_id, assessment.get("timestamp"), run_date, assessment.get("network"), assessment.get("interface"), assessment.get("source_ip"), str(run_dir), str(assessment_file), str(risk_file) if risk_file else None, str(endpoint_file) if endpoint_file else None, now, now, json_dumps(summary)),
    )


def risk_index(risk_data: dict | None) -> dict[str, dict]:
    if not risk_data:
        return {}
    return {str(h.get("ip")): h for h in as_list(risk_data.get("hosts")) if h.get("ip")}


def insert_assets_and_services(conn: sqlite3.Connection, scan_id: str, assessment: dict, risk_by_ip: dict[str, dict]) -> dict:
    counts = {"assets": 0, "services": 0, "vulnerabilities": 0}
    for host in sorted(as_list(assessment.get("hosts")), key=lambda h: ip_sort_key(h.get("ip", "0.0.0.0"))):
        ip = host.get("ip")
        if not ip:
            continue
        profile = as_dict(host.get("normalized_security_profile"))
        risk = risk_by_ip.get(ip, {})
        conn.execute(
            """
            INSERT OR REPLACE INTO assets (
                scan_id, ip, asset_id, mac, vendor, hostname, state, device_class,
                priority_score, priority_level, risk_score, risk_level,
                open_ports_count, tcp_ports_json, udp_ports_json, service_names_json,
                change_summary_json, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, ip, host.get("asset_id"), host.get("mac"), host.get("vendor"), host.get("hostname"), host.get("state"), profile.get("device_class"), host.get("legacy_priority_score", host.get("priority_score")), host.get("legacy_priority_level", host.get("priority_level")), risk.get("risk_score", host.get("risk_score")), risk.get("risk_level", host.get("risk_level")), host.get("open_ports_count"), json_dumps(profile.get("tcp_open_ports", [])), json_dumps(profile.get("udp_open_ports", [])), json_dumps(profile.get("service_names", [])), json_dumps(host.get("change_summary") or {}), json_dumps(host)),
        )
        counts["assets"] += 1

        for port in as_list(host.get("ports")) + as_list(host.get("udp_ports")):
            port_num = safe_int(port.get("port"))
            if port_num is None:
                continue
            protocol = port.get("protocol") or "tcp"
            scripts = []
            for key in ("scripts", "enrichment_scripts", "vuln_scripts"):
                scripts.extend(as_list(port.get(key)))
            conn.execute(
                """
                INSERT OR REPLACE INTO services (
                    scan_id, ip, port, protocol, state, service_name, product, version,
                    extra_info, tunnel, cpes_json, scripts_json, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, ip, port_num, protocol, scalar(port.get("state")), scalar(port.get("service_name")), scalar(port.get("product")), scalar(port.get("version")), scalar(port.get("extra_info")), scalar(port.get("tunnel")), json_dumps(port.get("cpes") or []), json_dumps(scripts), json_dumps(port)),
            )
            counts["services"] += 1

        vulns = as_dict(profile.get("vulnerabilities"))
        for item in as_list(vulns.get("all_cves")):
            if isinstance(item, dict):
                cve = item.get("cve")
                cvss = item.get("cvss")
                raw = item
            else:
                cve = str(item) if item else None
                cvss = None
                raw = {"cve": cve}
            if not cve:
                continue
            conn.execute(
                """
                INSERT OR REPLACE INTO vulnerabilities (scan_id, ip, cve, cvss, epss, kev, source_port, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, ip, cve, cvss, raw.get("epss") if isinstance(raw, dict) else None, 1 if isinstance(raw, dict) and raw.get("kev") else 0, str(raw.get("source_port") or "") if isinstance(raw, dict) else "", json_dumps(raw)),
            )
            counts["vulnerabilities"] += 1
    return counts


def insert_risk_scores(conn: sqlite3.Connection, scan_id: str, risk_data: dict | None) -> int:
    if not risk_data:
        return 0
    count = 0
    for item in as_list(risk_data.get("hosts")):
        ip = item.get("ip")
        if not ip:
            continue
        conn.execute(
            """
            INSERT OR REPLACE INTO risk_scores (
                scan_id, ip, asset_id, risk_score, risk_level, previous_risk_score,
                previous_risk_level, risk_delta, device_class, components_json,
                weighted_parts_json, weights_json, explanation_json, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, ip, item.get("asset_id"), item.get("risk_score"), item.get("risk_level"), item.get("previous_risk_score"), item.get("previous_risk_level"), item.get("risk_delta"), item.get("device_class"), json_dumps(item.get("risk_components") or {}), json_dumps(item.get("weighted_parts") or {}), json_dumps(item.get("weights_used") or {}), json_dumps(item.get("explanation") or []), json_dumps(item)),
        )
        count += 1
    return count


def extract_endpoint_events(endpoint_data: dict | None) -> list[dict]:
    if not endpoint_data:
        return []
    for key in ("normalized_events", "events", "endpoint_events", "windows_events"):
        if isinstance(endpoint_data.get(key), list):
            return endpoint_data[key]
    if isinstance(endpoint_data.get("normalized_events_sample"), list):
        return endpoint_data["normalized_events_sample"]
    return []


def nested(data: dict, *paths: str) -> Any:
    for path in paths:
        cur: Any = data
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok:
            return cur
    return None


def event_key(event: dict) -> str:
    for key in ("dedupe_key", "event_key", "row_hash", "hash"):
        if event.get(key):
            return str(event.get(key))
    return sha256_text(json_dumps(event))


def insert_endpoint_events(conn: sqlite3.Connection, scan_id: str, endpoint_data: dict | None) -> int:
    count = 0
    for event in extract_endpoint_events(endpoint_data):
        if not isinstance(event, dict):
            continue
        key = event_key(event)
        computer = nested(event, "source.computer", "computer")
        event_id = nested(event, "event.id", "event_id", "id")
        event_time = nested(event, "event.time", "time_created", "TimeCreated", "timestamp")
        log_name = nested(event, "event.channel", "log_name", "LogName")
        provider = nested(event, "event.provider", "provider", "ProviderName")
        severity = nested(event, "event.severity", "severity", "level")
        event_name = nested(event, "event.name", "event_name")
        category = nested(event, "event.category", "category")
        action = nested(event, "event.action", "action")
        outcome = nested(event, "event.outcome", "outcome")
        src_ip = nested(event, "network.src_ip", "src_ip", "source_ip")
        target_user = nested(event, "target.user", "target_user", "TargetUserName")
        source_type = event.get("source_type") or "endpoint_event"
        existing = conn.execute("SELECT seen_count FROM endpoint_events WHERE event_key=?", (key,)).fetchone()
        if existing:
            conn.execute("UPDATE endpoint_events SET last_seen_scan_id=?, seen_count=seen_count+1, raw_json=? WHERE event_key=?", (scan_id, json_dumps(event), key))
        else:
            conn.execute(
                """
                INSERT INTO endpoint_events (
                    event_key, first_seen_scan_id, last_seen_scan_id, seen_count,
                    computer, source_type, log_name, provider, event_id, event_time,
                    severity, event_name, category, action, outcome, src_ip,
                    target_user, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (key, scan_id, scan_id, 1, scalar(computer), scalar(source_type), scalar(log_name), scalar(provider), scalar(event_id), scalar(event_time), scalar(severity), scalar(event_name), scalar(category), scalar(action), scalar(outcome), scalar(src_ip), scalar(target_user), json_dumps(event)),
            )
        conn.execute("INSERT OR IGNORE INTO scan_endpoint_events (scan_id, event_key) VALUES (?, ?)", (scan_id, key))
        count += 1
    return count


def insert_findings(conn: sqlite3.Connection, scan_id: str, risk_report: dict | None) -> int:
    if not risk_report:
        return 0
    count = 0
    for item in as_list(risk_report.get("findings")):
        if not isinstance(item, dict):
            continue
        basis = json_dumps({"scan_id": scan_id, "finding": item})
        key = item.get("finding_id") or sha256_text(basis)
        conn.execute(
            """
            INSERT OR REPLACE INTO findings (finding_key, scan_id, ip, asset_id, source, severity, title, details, recommendation, status, risk_score, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(key),
                scan_id,
                scalar(item.get("ip")),
                scalar(item.get("asset_id")),
                scalar(item.get("source") or item.get("source_module") or risk_report.get("report_type") or "risk_report"),
                scalar(item.get("severity")),
                scalar(item.get("title")),
                scalar(item.get("details") or item.get("impact") or "; ".join(str(x) for x in as_list(item.get("evidence"))[:5])),
                scalar(item.get("recommendation") or item.get("recommended_fix")),
                scalar(item.get("status") or "open"),
                scalar(item.get("risk_score") or item.get("risk_increase")),
                json_dumps(item),
            ),
        )
        count += 1
    return count


def insert_raw_source(conn: sqlite3.Connection, scan_id: str, file_type: str, path: Path | None) -> bool:
    if not path or not path.exists():
        return False
    stat = path.stat()
    conn.execute(
        """
        INSERT OR REPLACE INTO raw_sources (scan_id, file_type, file_name, file_path, sha256, size_bytes, modified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (scan_id, file_type, path.name, str(path), sha256_file(path), stat.st_size, datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")),
    )
    return True


def table_count(conn: sqlite3.Connection, table: str, scan_id: str | None = None) -> int:
    if scan_id and table not in {"endpoint_events"}:
        row = conn.execute(f"SELECT COUNT(*) AS c FROM {table} WHERE scan_id=?", (scan_id,)).fetchone()
    else:
        row = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()
    return int(row["c"])


def build_storage_summary(conn: sqlite3.Connection, scan_id: str, db_path: Path, counts: dict, source_files: dict) -> dict:
    top_risk = [dict(row) for row in conn.execute("SELECT ip, risk_score, risk_level, device_class FROM risk_scores WHERE scan_id=? ORDER BY risk_score DESC LIMIT 10", (scan_id,)).fetchall()]
    return {
        "report_type": "storage_summary",
        "timestamp": timestamp_now(),
        "scan_id": scan_id,
        "database": str(db_path),
        "source_files": source_files,
        "inserted_or_updated": counts,
        "tables_for_scan": {
            "assets": table_count(conn, "assets", scan_id),
            "services": table_count(conn, "services", scan_id),
            "vulnerabilities": table_count(conn, "vulnerabilities", scan_id),
            "risk_scores": table_count(conn, "risk_scores", scan_id),
            "findings": table_count(conn, "findings", scan_id),
            "raw_sources": table_count(conn, "raw_sources", scan_id),
        },
        "global_tables": {
            "scan_runs": table_count(conn, "scan_runs"),
            "endpoint_events_unique": table_count(conn, "endpoint_events"),
        },
        "top_risk_hosts": top_risk,
    }


def update_ai_payload(run_dir: Path, summary_file: Path, summary: dict) -> Path | None:
    payload = latest_file(run_dir / "ai", "ai_recommendation_payload_*.json")
    if not payload:
        return None
    try:
        data = load_json(payload)
    except Exception:
        return None
    data["storage_context"] = {
        "source_file": summary_file.name,
        "database": summary.get("database"),
        "scan_id": summary.get("scan_id"),
        "tables_for_scan": summary.get("tables_for_scan"),
        "global_tables": summary.get("global_tables"),
    }
    save_json(payload, data)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Persist Network Thesis run outputs into SQLite history database.")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite DB path")
    parser.add_argument("--assessment", default=None, help="Specific assessment_*.json file")
    args = parser.parse_args()
    paths = get_run_paths()
    assessment_file = Path(args.assessment).expanduser() if args.assessment else latest_file(paths["reports_dir"], "assessment_*.json")
    if assessment_file is None:
        assessment_file = latest_global("assessment_*.json")
    if assessment_file is None:
        raise FileNotFoundError("Nerastas assessment_*.json failas. Pirmiausia paleisk merge_assessment.py")
    run_dir = infer_run_dir_from_file(assessment_file)
    risk_file = latest_file(run_dir / "reports", "risk_scores_*.json") or latest_global("risk_scores_*.json")
    endpoint_file = latest_file(run_dir / "reports", "endpoint_events_*.json") or latest_global("endpoint_events_*.json")
    risk_report_file = latest_file(run_dir / "reports", "risk_report_*.json") or latest_global("risk_report_*.json")
    assessment = load_json(assessment_file)
    risk_data = load_json(risk_file) if risk_file and risk_file.exists() else None
    endpoint_data = load_json(endpoint_file) if endpoint_file and endpoint_file.exists() else None
    risk_report = load_json(risk_report_file) if risk_report_file and risk_report_file.exists() else None
    scan_id = get_scan_id(assessment, assessment_file)
    db_path = Path(args.db).expanduser()
    conn = connect(db_path)
    init_db(conn)
    with conn:
        insert_scan_run(conn, scan_id, assessment, assessment_file, risk_file, endpoint_file)
        rindex = risk_index(risk_data)
        counts = insert_assets_and_services(conn, scan_id, assessment, rindex)
        counts["risk_scores"] = insert_risk_scores(conn, scan_id, risk_data)
        counts["endpoint_events_seen_in_scan"] = insert_endpoint_events(conn, scan_id, endpoint_data)
        counts["findings"] = insert_findings(conn, scan_id, risk_report)
        raw_count = 0
        for ftype, fpath in {"assessment": assessment_file, "risk_scores": risk_file, "endpoint_events": endpoint_file, "risk_report": risk_report_file}.items():
            raw_count += 1 if insert_raw_source(conn, scan_id, ftype, fpath) else 0
        counts["raw_sources"] = raw_count
    source_files = {"assessment": str(assessment_file) if assessment_file else None, "risk_scores": str(risk_file) if risk_file else None, "endpoint_events": str(endpoint_file) if endpoint_file else None, "risk_report": str(risk_report_file) if risk_report_file else None}
    summary = build_storage_summary(conn, scan_id, db_path, counts, source_files)
    output_dir = run_dir / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / f"storage_summary_{timestamp_now()}.json"
    save_json(out_file, summary)
    ai_updated = update_ai_payload(run_dir, out_file, summary)
    print(f"SQLite duomenų bazė: {db_path}")
    print(f"Storage santrauka: {out_file}")
    print(f"Scan ID: {scan_id}")
    print(f"Assets: {summary['tables_for_scan']['assets']}")
    print(f"Services: {summary['tables_for_scan']['services']}")
    print(f"Vulnerabilities: {summary['tables_for_scan']['vulnerabilities']}")
    print(f"Risk scores: {summary['tables_for_scan']['risk_scores']}")
    print(f"Endpoint unique events total: {summary['global_tables']['endpoint_events_unique']}")
    if ai_updated:
        print(f"AI payload papildytas storage_context: {ai_updated}")


if __name__ == "__main__":
    main()
