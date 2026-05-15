#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any

MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    text = str(mac).strip().upper().replace("-", ":")
    return text if MAC_RE.match(text) else None


def normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def build_asset_id(ip: str | None = None, mac: str | None = None, hostname: str | None = None, vendor: str | None = None) -> str:
    """Return a stable asset identifier.

    Priority is MAC + hostname + vendor as recommended for DHCP environments.
    If those fields are absent, IP is used only as a last-resort fallback so legacy
    lab scans still produce a deterministic identifier.
    """
    mac_norm = normalize_mac(mac)
    hostname_norm = normalize_text(hostname)
    vendor_norm = normalize_text(vendor)
    ip_fallback = normalize_text(ip) if not (mac_norm or hostname_norm or vendor_norm) else ""
    raw = "|".join([mac_norm or "", hostname_norm, vendor_norm, ip_fallback])
    return "sha256:" + hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def build_asset_record(
    *,
    ip: str | None = None,
    mac: str | None = None,
    hostname: str | None = None,
    vendor: str | None = None,
    first_seen: str | None = None,
    last_seen: str | None = None,
) -> dict:
    ts = now_iso()
    mac_norm = normalize_mac(mac)
    return {
        "asset_id": build_asset_id(ip=ip, mac=mac_norm or mac, hostname=hostname, vendor=vendor),
        "ip": ip,
        "mac": mac_norm or mac,
        "hostname": hostname,
        "vendor": vendor,
        "first_seen": first_seen or ts,
        "last_seen": last_seen or ts,
    }


def enrich_host_asset_id(host: dict) -> dict:
    if not isinstance(host, dict):
        return host
    host["asset_id"] = host.get("asset_id") or build_asset_id(
        ip=host.get("ip"),
        mac=host.get("mac"),
        hostname=host.get("hostname"),
        vendor=host.get("vendor"),
    )
    asset = host.get("asset_identity") if isinstance(host.get("asset_identity"), dict) else {}
    first_seen = asset.get("first_seen") or host.get("first_seen")
    last_seen = asset.get("last_seen") or host.get("last_seen")
    host["asset_identity"] = build_asset_record(
        ip=host.get("ip"),
        mac=host.get("mac"),
        hostname=host.get("hostname"),
        vendor=host.get("vendor"),
        first_seen=first_seen,
        last_seen=last_seen,
    )
    # Keep the top-level id as the canonical value even if a pre-existing nested
    # record was stale or generated with a weaker fallback.
    host["asset_identity"]["asset_id"] = host["asset_id"]
    return host
