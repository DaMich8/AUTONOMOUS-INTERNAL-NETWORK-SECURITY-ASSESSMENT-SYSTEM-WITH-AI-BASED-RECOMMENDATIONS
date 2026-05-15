from __future__ import annotations

import gzip
import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from common import BASE_DIR, save_json
from receiver_security import body_hash, rate_limit_ok, verify_hmac

# LEGACY ADAPTER:
# Oficialus kelias naujiems endpoint / Windows / ESET įvykiams:
# endpoint_event_receiver.py -> endpoint_event_normalizer.py -> correlation_engine.py -> risk_engine.py / AI.
# Šis failas paliktas suderinamumui su senu Windows Security logų siuntėju.
WINDOWS_SECURITY_LOG_DIR = Path(os.getenv("WINDOWS_SECURITY_LOG_DIR", str(BASE_DIR / "windows_security_log")))
RECEIVER_LOG_DIR = WINDOWS_SECURITY_LOG_DIR / "_receiver_logs"
LEGACY_COLLECTOR_DIR = BASE_DIR / "windows_events"
LEGACY_INBOX_DIR = LEGACY_COLLECTOR_DIR / "inbox"

for d in (WINDOWS_SECURITY_LOG_DIR, RECEIVER_LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)

HOST = os.getenv("WINDOWS_LOG_RECEIVER_HOST", "0.0.0.0")
PORT = int(os.getenv("WINDOWS_LOG_RECEIVER_PORT", "8765"))
TOKEN = os.getenv("WINDOWS_LOG_TOKEN", "").strip()
HMAC_SECRET = os.getenv("WINDOWS_HMAC_SECRET", os.getenv("ENDPOINT_HMAC_SECRET", "")).strip()
PRODUCTION_MODE = str(os.getenv("WINDOWS_RECEIVER_PRODUCTION", os.getenv("ENDPOINT_RECEIVER_PRODUCTION", ""))).strip().lower() in {"1", "true", "yes", "on"}
AUTH_REQUIRED = PRODUCTION_MODE or str(os.getenv("WINDOWS_AUTH_REQUIRED", "")).strip().lower() in {"1", "true", "yes", "on"}
MAX_BODY_BYTES = int(os.getenv("WINDOWS_LOG_MAX_BODY_BYTES", str(25 * 1024 * 1024)))
MAX_DECOMPRESSED_BYTES = int(os.getenv("WINDOWS_LOG_MAX_DECOMPRESSED_BYTES", str(100 * 1024 * 1024)))
MIRROR_LEGACY_INBOX = os.getenv("WINDOWS_LOG_MIRROR_LEGACY_INBOX", "0").strip().lower() in {"1", "true", "yes"}


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def safe_ip_for_filename(ip: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in ip).strip("_") or "unknown_ip"


def normalize_payload(payload: Any) -> list[dict]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        events = payload.get("events")
        if isinstance(events, list):
            return [x for x in events if isinstance(x, dict)]
        return [payload]
    return []


def token_from_headers(headers) -> str:
    direct = headers.get("X-Collector-Token", "").strip()
    if direct:
        return direct
    auth = headers.get("Authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return ""


def build_daily_output_file(remote_ip: str) -> Path:
    day = today_str()
    day_dir = WINDOWS_SECURITY_LOG_DIR / day
    day_dir.mkdir(parents=True, exist_ok=True)
    return day_dir / f"{safe_ip_for_filename(remote_ip)}_{day}_security_log.jsonl"


def append_events(out_file: Path, events: list[dict], ingest_meta: dict) -> None:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "a", encoding="utf-8") as f:
        for event in events:
            wrapped = {"ingest_meta": ingest_meta, "event": event}
            f.write(json.dumps(wrapped, ensure_ascii=False, separators=(",", ":")) + "\n")


class WindowsEventHandler(BaseHTTPRequestHandler):
    server_version = "NetworkThesisWindowsEventReceiver/1.2-legacy"

    def log_message(self, fmt: str, *args) -> None:
        log_file = RECEIVER_LOG_DIR / f"receiver_{today_str()}.log"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{now_iso()} {self.client_address[0]} {fmt % args}\n")

    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/health":
            self._send_json(200, {
                "status": "ok",
                "service": "windows_event_receiver",
                "role": "legacy_adapter",
                "official_endpoint_path": "endpoint_event_receiver.py -> endpoint_event_normalizer.py -> correlation_engine.py",
                "time": now_iso(),
                "windows_security_log_dir": str(WINDOWS_SECURITY_LOG_DIR),
                "token_required": bool(TOKEN) or AUTH_REQUIRED,
                "hmac_enabled": bool(HMAC_SECRET),
                "production_mode": PRODUCTION_MODE,
            })
            return
        self._send_json(404, {"status": "error", "reason": "not_found"})

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/ingest/windows-security":
            self._send_json(404, {"status": "error", "reason": "not_found"})
            return

        ok_rate, rate_reason = rate_limit_ok(self.client_address[0])
        if not ok_rate:
            self._send_json(429, {"status": "error", "reason": rate_reason})
            return

        if AUTH_REQUIRED and not TOKEN and not HMAC_SECRET:
            self._send_json(503, {"status": "error", "reason": "receiver_auth_required_but_not_configured"})
            return

        if TOKEN:
            provided = token_from_headers(self.headers)
            if provided != TOKEN:
                self._send_json(401, {"status": "error", "reason": "unauthorized"})
                return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"status": "error", "reason": "bad_content_length"})
            return

        if length <= 0:
            self._send_json(400, {"status": "error", "reason": "empty_body"})
            return
        if length > MAX_BODY_BYTES:
            self._send_json(413, {"status": "error", "reason": "payload_too_large", "max_bytes": MAX_BODY_BYTES})
            return

        raw_body = self.rfile.read(length)
        raw_payload_hash = "sha256:" + body_hash(raw_body)

        if HMAC_SECRET:
            ok_sig, sig_reason = verify_hmac(HMAC_SECRET, self.headers.get("X-Timestamp"), self.headers.get("X-Signature"), raw_body)
            if not ok_sig:
                self._send_json(401, {"status": "error", "reason": sig_reason})
                return
        elif AUTH_REQUIRED:
            self._send_json(401, {"status": "error", "reason": "hmac_required"})
            return

        compressed = self.headers.get("Content-Encoding", "").lower().strip() == "gzip"
        body = raw_body
        if compressed:
            try:
                body = gzip.decompress(raw_body)
            except Exception as exc:
                self._send_json(400, {"status": "error", "reason": "invalid_gzip", "details": str(exc)})
                return
            if len(body) > MAX_DECOMPRESSED_BYTES:
                self._send_json(413, {"status": "error", "reason": "decompressed_payload_too_large", "max_bytes": MAX_DECOMPRESSED_BYTES})
                return

        try:
            payload = json.loads(body.decode("utf-8-sig"))
        except Exception as exc:
            self._send_json(400, {"status": "error", "reason": "invalid_json", "details": str(exc)})
            return

        events = normalize_payload(payload)
        if not events:
            self._send_json(200, {"status": "ok", "accepted": 0, "reason": "no_events", "payload_hash": raw_payload_hash})
            return

        remote_ip = self.client_address[0]
        out_file = build_daily_output_file(remote_ip)
        ingest_meta = {
            "ingested_at": now_iso(),
            "collector_remote_addr": remote_ip,
            "user_agent": self.headers.get("User-Agent"),
            "storage_path": str(out_file),
            "payload_hash": raw_payload_hash,
            "hmac_verified": bool(HMAC_SECRET),
            "content_encoding": "gzip" if compressed else "identity",
            "receiver_role": "legacy_adapter",
        }

        append_events(out_file, events, ingest_meta)

        legacy_file = None
        if MIRROR_LEGACY_INBOX:
            legacy_day_dir = LEGACY_INBOX_DIR / today_str()
            legacy_day_dir.mkdir(parents=True, exist_ok=True)
            legacy_file = legacy_day_dir / out_file.name
            append_events(legacy_file, events, ingest_meta)

        self._send_json(200, {
            "status": "ok",
            "accepted": len(events),
            "file": str(out_file),
            "legacy_file": str(legacy_file) if legacy_file else None,
            "payload_hash": raw_payload_hash,
            "hmac_verified": bool(HMAC_SECRET),
        })


def main() -> None:
    status_file = WINDOWS_SECURITY_LOG_DIR / "receiver_status.json"
    save_json(status_file, {
        "service": "windows_event_receiver",
        "role": "legacy_adapter",
        "official_endpoint_path": "endpoint_event_receiver.py -> endpoint_event_normalizer.py -> correlation_engine.py -> risk_engine.py / ai_recommendation_engine.py",
        "host": HOST,
        "port": PORT,
        "token_required": bool(TOKEN) or AUTH_REQUIRED,
        "hmac_enabled": bool(HMAC_SECRET),
        "production_mode": PRODUCTION_MODE,
        "windows_security_log_dir": str(WINDOWS_SECURITY_LOG_DIR),
        "file_pattern": "<ip_adresas>_<YYYY-MM-DD>_security_log.jsonl",
        "started_at": now_iso(),
        "mirror_legacy_inbox": MIRROR_LEGACY_INBOX,
    })

    print(f"Windows Event Receiver klausosi {HOST}:{PORT}", flush=True)
    print("[INFO] Šis imtuvas yra legacy adapteris. Naujam keliui naudok endpoint_event_receiver.py", flush=True)
    print(f"Endpoint: http://<collector-ip>:{PORT}/ingest/windows-security", flush=True)
    print(f"Windows Security log katalogas: {WINDOWS_SECURITY_LOG_DIR}", flush=True)
    print(f"Token required: {bool(TOKEN) or AUTH_REQUIRED}", flush=True)
    print(f"HMAC enabled: {bool(HMAC_SECRET)}", flush=True)

    httpd = ThreadingHTTPServer((HOST, PORT), WindowsEventHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Stabdoma.", flush=True)
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
