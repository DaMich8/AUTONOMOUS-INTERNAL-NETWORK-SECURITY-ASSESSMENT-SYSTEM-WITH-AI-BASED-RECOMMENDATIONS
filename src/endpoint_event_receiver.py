#!/usr/bin/env python3
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
from receiver_security import body_hash, rate_limit_ok, verify_hmac
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(os.getenv("NETWORK_THESIS_BASE", "/home/kali/network-thesis-GIT"))
ENDPOINT_EVENT_DIR = Path(os.getenv("ENDPOINT_EVENT_LOG_DIR", str(BASE_DIR / "endpoint_event_log")))
ESET_CSV_DIR = Path(os.getenv("ESET_CSV_LOG_DIR", str(BASE_DIR / "eset_csv_log")))
CONFIG_TOKEN = os.getenv("ENDPOINT_LOG_TOKEN") or os.getenv("WINDOWS_LOG_TOKEN") or ""
PRODUCTION_MODE = str(os.getenv("ENDPOINT_RECEIVER_PRODUCTION", "")).strip().lower() in {"1", "true", "yes", "on"}
AUTH_REQUIRED = PRODUCTION_MODE or str(os.getenv("ENDPOINT_AUTH_REQUIRED", "")).strip().lower() in {"1", "true", "yes", "on"}
HOST = os.getenv("ENDPOINT_EVENT_RECEIVER_HOST", "0.0.0.0")
PORT = int(os.getenv("ENDPOINT_EVENT_RECEIVER_PORT", "8766"))
MAX_BODY_BYTES = int(os.getenv("ENDPOINT_EVENT_MAX_BODY_BYTES", str(100 * 1024 * 1024)))
MAX_DECOMPRESSED_BYTES = int(os.getenv("ENDPOINT_EVENT_MAX_DECOMPRESSED_BYTES", str(300 * 1024 * 1024)))

SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def safe_name(value: str, default: str = "unknown") -> str:
    value = (value or default).strip().replace("\\", "_").replace("/", "_")
    value = SAFE_RE.sub("_", value)
    value = value.strip("._-")
    return value or default


def ip_slug(ip: str) -> str:
    return safe_name((ip or "unknown").replace(":", "_").replace(".", "_"), "unknown")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ensure_dirs() -> None:
    for d in (ENDPOINT_EVENT_DIR, ESET_CSV_DIR):
        d.mkdir(parents=True, exist_ok=True)


def append_jsonl(path: Path, items: list[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("a", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def list_from_payload(payload: dict, key: str) -> list:
    value = payload.get(key)
    return value if isinstance(value, list) else []


def save_eset_files(date_value: str, ip_value: str, files: list[dict]) -> list[dict]:
    """Backward compatibility: accepts older payloads with base64 CSV/log files in `files`."""
    saved = []
    day_dir = ESET_CSV_DIR / date_value
    day_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = day_dir / f"{ip_slug(ip_value)}_{date_value}_eset_file_manifest.jsonl"

    for item in files:
        if not isinstance(item, dict):
            continue
        source_type = item.get("source_type") or item.get("type") or "eset_csv"
        filename = safe_name(item.get("filename") or item.get("name") or "eset_log.csv", "eset_log.csv")
        content_b64 = item.get("content_b64") or item.get("contentBase64")
        if not content_b64:
            continue
        try:
            content = base64.b64decode(content_b64, validate=True)
        except Exception:
            continue

        expected_hash = (item.get("sha256") or "").lower().strip()
        actual_hash = sha256_bytes(content)
        hash_ok = (not expected_hash) or expected_hash == actual_hash

        prefix = f"{ip_slug(ip_value)}_{date_value}"
        out_path = day_dir / f"{prefix}_{filename}"

        if out_path.exists():
            if sha256_bytes(out_path.read_bytes()) == actual_hash:
                status = "already_exists_same_hash"
            else:
                out_path = day_dir / f"{prefix}_{actual_hash[:12]}_{filename}"
                out_path.write_bytes(content)
                status = "saved_renamed_hash_conflict"
        else:
            out_path.write_bytes(content)
            status = "saved"

        meta = {
            "received_at": now_iso(),
            "source_type": source_type,
            "collector_seen_ip": ip_value,
            "computer": item.get("computer"),
            "filename": filename,
            "saved_path": str(out_path),
            "size_bytes": len(content),
            "sha256": actual_hash,
            "hash_ok": hash_ok,
            "status": status,
            "last_write_time": item.get("last_write_time"),
            "source_path": item.get("source_path"),
        }
        saved.append(meta)

    if saved:
        append_jsonl(manifest_path, saved)
    return saved


class Handler(BaseHTTPRequestHandler):
    server_version = "NetworkThesisEndpointReceiver/3.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.client_address[0]} - {fmt % args}", flush=True)

    def send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self.send_json(200, {
                "status": "ok",
                "service": "endpoint_event_receiver",
                "version": "3.0",
                "endpoint": "/ingest/endpoint-events",
                "event_dir": str(ENDPOINT_EVENT_DIR),
                "eset_csv_dir": str(ESET_CSV_DIR),
                "token_required": bool(CONFIG_TOKEN) or AUTH_REQUIRED,
                "production_mode": PRODUCTION_MODE,
                "auth_required": AUTH_REQUIRED,
                "accepted_payloads": ["events", "eset_csv_rows", "eset_csv_files", "files"],
                "accepted_content_encoding": ["identity", "gzip"],
                "hmac_scheme": "X-Signature = HMAC_SHA256(secret, X-Timestamp + . + sha256(raw_http_body))",
                "tls_note": "Production režime paleisti už TLS terminavimo reverse proxy arba naudoti lokalų tunelį su TLS.",
                "max_body_bytes": MAX_BODY_BYTES,
                "max_decompressed_bytes": MAX_DECOMPRESSED_BYTES,
            })
            return
        self.send_json(404, {"status": "error", "reason": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/ingest/endpoint-events":
            self.send_json(404, {"status": "error", "reason": "not_found"})
            return

        hmac_secret = os.getenv("ENDPOINT_HMAC_SECRET", "").strip()
        if AUTH_REQUIRED and not CONFIG_TOKEN and not hmac_secret:
            self.send_json(503, {"status": "error", "reason": "receiver_auth_required_but_not_configured"})
            return

        if CONFIG_TOKEN:
            provided = self.headers.get("X-Collector-Token") or self.headers.get("Authorization", "").replace("Bearer ", "")
            if provided != CONFIG_TOKEN:
                self.send_json(401, {"status": "error", "reason": "unauthorized"})
                return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"status": "error", "reason": "bad_content_length"})
            return
        if length <= 0:
            self.send_json(400, {"status": "error", "reason": "empty_body"})
            return
        if length > MAX_BODY_BYTES:
            self.send_json(413, {"status": "error", "reason": "payload_too_large", "max_body_bytes": MAX_BODY_BYTES})
            return

        raw = self.rfile.read(length)
        raw_payload_hash = body_hash(raw)

        # STRUCTURAL_PATCH_HMAC_START
        ok_rate, rate_reason = rate_limit_ok(self.client_address[0])
        if not ok_rate:
            self.send_json(429, {"status": "error", "reason": rate_reason})
            return
        if hmac_secret:
            # Parašas skaičiuojamas nuo originalaus HTTP body.
            ts_header = self.headers.get("X-Timestamp")
            sig_header = self.headers.get("X-Signature")
            ok_sig, sig_reason = verify_hmac(hmac_secret, ts_header, sig_header, raw)
            if not ok_sig:
                self.send_json(401, {"status": "error", "reason": sig_reason})
                return
        elif AUTH_REQUIRED:
            self.send_json(401, {"status": "error", "reason": "hmac_required"})
            return
        # STRUCTURAL_PATCH_HMAC_END
        compressed = self.headers.get("Content-Encoding", "").lower().strip() == "gzip"
        if compressed:
            try:
                raw = gzip.decompress(raw)
            except Exception as exc:
                self.send_json(400, {"status": "error", "reason": "invalid_gzip", "details": str(exc)})
                return
            if len(raw) > MAX_DECOMPRESSED_BYTES:
                self.send_json(413, {"status": "error", "reason": "decompressed_payload_too_large", "max_decompressed_bytes": MAX_DECOMPRESSED_BYTES})
                return

        try:
            payload = json.loads(raw.decode("utf-8-sig"))
        except Exception as exc:
            self.send_json(400, {"status": "error", "reason": "invalid_json", "details": str(exc)})
            return

        date_value = today_str()
        ip_value = self.client_address[0]
        computer = payload.get("computer") or payload.get("hostname")
        received_at = now_iso()

        windows_events = list_from_payload(payload, "events")
        eset_rows = list_from_payload(payload, "eset_csv_rows")
        eset_file_summaries = list_from_payload(payload, "eset_csv_files")
        legacy_files = list_from_payload(payload, "files")

        records: list[dict] = []

        # Store payload summary as one raw record so later assessment can prove what was received.
        records.append({
            "source_type": "endpoint_payload_summary",
            "collector_received_at": received_at,
            "collector_seen_ip": ip_value,
            "computer": computer,
            "payload_type": payload.get("payload_type"),
            "schema_version": payload.get("schema_version"),
            "generated_at": payload.get("generated_at"),
            "lookback_hours": payload.get("lookback_hours"),
            "since": payload.get("since"),
            "stats": payload.get("stats", {}),
            "payload_hash": "sha256:" + raw_payload_hash,
            "hmac_verified": bool(hmac_secret),
        })

        for ev in windows_events:
            if not isinstance(ev, dict):
                continue
            ev.setdefault("source_type", "windows_event")
            ev.setdefault("collector_received_at", received_at)
            ev.setdefault("collector_seen_ip", ip_value)
            if computer:
                ev.setdefault("computer", computer)
            records.append(ev)

        for row in eset_rows:
            if not isinstance(row, dict):
                continue
            row.setdefault("source_type", "eset_csv_row")
            row.setdefault("collector_received_at", received_at)
            row.setdefault("collector_seen_ip", ip_value)
            if computer:
                row.setdefault("computer", computer)
            records.append(row)

        for summary in eset_file_summaries:
            if not isinstance(summary, dict):
                continue
            summary.setdefault("source_type", "eset_csv_file_summary")
            summary.setdefault("collector_received_at", received_at)
            summary.setdefault("collector_seen_ip", ip_value)
            if computer:
                summary.setdefault("computer", computer)
            records.append(summary)

        event_file = ENDPOINT_EVENT_DIR / date_value / f"{ip_slug(ip_value)}_{date_value}_endpoint_event_log.jsonl"
        accepted_records = append_jsonl(event_file, records) if records else 0
        saved_files = save_eset_files(date_value, ip_value, legacy_files) if legacy_files else []

        self.send_json(200, {
            "status": "ok",
            "content_encoding": "gzip" if compressed else "identity",
            "payload_hash": "sha256:" + raw_payload_hash,
            "hmac_verified": bool(hmac_secret),
            "accepted_records": accepted_records,
            "accepted_windows_events": len(windows_events),
            "accepted_eset_csv_rows": len(eset_rows),
            "accepted_eset_csv_file_summaries": len(eset_file_summaries),
            "accepted_legacy_files": len(saved_files),
            "event_file": str(event_file) if accepted_records else None,
            "saved_files": saved_files,
        })


def main() -> None:
    ensure_dirs()
    print(f"Endpoint Event Receiver klausosi {HOST}:{PORT}", flush=True)
    print(f"Endpoint: http://<collector-ip>:{PORT}/ingest/endpoint-events", flush=True)
    print(f"Endpoint raw katalogas: {ENDPOINT_EVENT_DIR}", flush=True)
    print(f"Legacy ESET CSV katalogas: {ESET_CSV_DIR}", flush=True)
    print(f"Token required: {bool(CONFIG_TOKEN) or AUTH_REQUIRED}", flush=True)
    print(f"Production mode: {PRODUCTION_MODE}", flush=True)
    print(f"HMAC enabled: {bool(os.getenv('ENDPOINT_HMAC_SECRET', '').strip())}", flush=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
