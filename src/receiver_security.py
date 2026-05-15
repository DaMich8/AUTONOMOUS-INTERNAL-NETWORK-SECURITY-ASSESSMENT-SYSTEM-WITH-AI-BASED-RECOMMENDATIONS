#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections import defaultdict, deque

REPLAY_WINDOW_SECONDS = int(os.getenv("ENDPOINT_REPLAY_WINDOW_SECONDS", "300"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("ENDPOINT_RATE_LIMIT_PER_MINUTE", "60"))
_seen_signatures: dict[str, float] = {}
_rate: dict[str, deque[float]] = defaultdict(deque)


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def build_signature(secret: str, timestamp: str, body: bytes) -> str:
    message = f"{timestamp}.{body_hash(body)}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_hmac(secret: str, timestamp: str | None, signature: str | None, body: bytes) -> tuple[bool, str]:
    if not secret:
        return False, "missing_secret"
    if not timestamp or not signature:
        return False, "missing_timestamp_or_signature"
    try:
        ts = float(timestamp)
    except Exception:
        return False, "invalid_timestamp"
    now = time.time()
    if abs(now - ts) > REPLAY_WINDOW_SECONDS:
        return False, "timestamp_outside_allowed_window"
    expected = build_signature(secret, timestamp, body)
    if not hmac.compare_digest(expected, signature):
        return False, "invalid_signature"
    key = f"{timestamp}:{signature}"
    # Periodinis senų raktų išvalymas.
    for k, v in list(_seen_signatures.items()):
        if now - v > REPLAY_WINDOW_SECONDS:
            _seen_signatures.pop(k, None)
    if key in _seen_signatures:
        return False, "replay_detected"
    _seen_signatures[key] = now
    return True, "ok"


def rate_limit_ok(client_ip: str) -> tuple[bool, str]:
    now = time.time()
    q = _rate[client_ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_MINUTE:
        return False, "rate_limit_exceeded"
    q.append(now)
    return True, "ok"
