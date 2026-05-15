from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path

from common import BASE_DIR, get_run_paths, save_json, timestamp_now

REQUIRED_SCRIPTS = [
    "common.py",
    "full_assessment.py",
    "scan_network.py",
    "parse_discovery.py",
    "service_scan.py",
    "parse_services.py",
    "merge_assessment.py",
]
OPTIONAL_SCRIPTS = [
    "experimental_validation.py",
    "epss_kev_enrichment.py",
    "endpoint_event_normalizer.py",
    "risk_engine.py",
    "storage.py",
    "correlation_engine.py",
    "ai_recommendation_engine.py",
    "remediation_tracker.py",
    "report_generator.py",
]
TOOLS = {
    "nmap": "būtinas discovery ir servisų skenavimui",
    "arp-scan": "naudojamas L2 inventorizacijai",
    "sslscan": "naudojamas TLS auditui",
    "whatweb": "naudojamas web fingerprint analizei",
    "enum4linux-ng": "naudojamas SMB praturtinimui",
    "onesixtyone": "naudojamas SNMP community tikrinimui",
    "jq": "nebūtinas, bet patogus JSON tikrinimui terminale",
}


def cmd_available(name: str) -> bool:
    return shutil.which(name) is not None


def check_endpoint_receiver(host: str = "127.0.0.1", port: int = 8766, timeout: float = 1.5) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"host": host, "port": port, "reachable": True, "status": "ok"}
    except Exception as exc:
        return {"host": host, "port": port, "reachable": False, "status": "warning", "error": str(exc)}


def disk_usage(path: Path) -> dict:
    total, used, free = shutil.disk_usage(path)
    return {
        "path": str(path),
        "total_gb": round(total / 1024**3, 2),
        "used_gb": round(used / 1024**3, 2),
        "free_gb": round(free / 1024**3, 2),
        "free_percent": round((free / total) * 100, 2) if total else None,
    }


def throttling_status() -> dict:
    if not cmd_available("vcgencmd"):
        return {"available": False, "status": "not_available"}
    try:
        out = subprocess.check_output(["vcgencmd", "get_throttled"], text=True, timeout=3).strip()
        return {"available": True, "raw": out, "throttled": out.split("=", 1)[-1] if "=" in out else out}
    except Exception as exc:
        return {"available": True, "status": "error", "error": str(exc)}


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    src_dir = BASE_DIR / "src"

    required = []
    for script in REQUIRED_SCRIPTS:
        exists = (src_dir / script).exists()
        required.append({"script": script, "exists": exists, "severity": "critical" if not exists else "ok"})

    optional = []
    for script in OPTIONAL_SCRIPTS:
        exists = (src_dir / script).exists()
        optional.append({"script": script, "exists": exists, "severity": "warning" if not exists else "ok"})

    tools = []
    for tool, reason in TOOLS.items():
        tools.append({"tool": tool, "available": cmd_available(tool), "purpose": reason})

    endpoint = check_endpoint_receiver()
    disk = disk_usage(BASE_DIR)
    throttle = throttling_status()

    critical_failures = [x for x in required if not x["exists"]]
    warnings = [x for x in optional if not x["exists"]] + [x for x in tools if not x["available"]]
    if not endpoint["reachable"]:
        warnings.append({"component": "endpoint_receiver", "warning": "8766 portas nepasiekiamas lokaliai"})
    if disk.get("free_percent") is not None and disk["free_percent"] < 10:
        warnings.append({"component": "disk", "warning": "laisvos vietos diske mažiau nei 10 %"})

    report = {
        "report_type": "preflight_check",
        "timestamp": timestamp,
        "status": "critical" if critical_failures else "ok_with_warnings" if warnings else "ok",
        "required_scripts": required,
        "optional_scripts": optional,
        "tools": tools,
        "endpoint_receiver": endpoint,
        "disk": disk,
        "raspberry_throttling": throttle,
        "critical_failures_count": len(critical_failures),
        "warnings_count": len(warnings),
        "warnings": warnings[:50],
        "note": "Preflight modulis informacinis ir nestabdo full_assessment grandinės, kad nebūtų sugadintas esamas funkcionalumas.",
    }

    out_json = paths["reports_dir"] / f"preflight_check_{timestamp}.json"
    out_txt = paths["reports_dir"] / f"preflight_check_{timestamp}.txt"
    save_json(out_json, report)

    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(f"Preflight check: {report['status']}\n")
        f.write(f"Critical failures: {len(critical_failures)}\n")
        f.write(f"Warnings: {len(warnings)}\n\n")
        for item in critical_failures:
            f.write(f"[CRITICAL] missing script: {item['script']}\n")
        for item in warnings[:50]:
            f.write(f"[WARN] {item}\n")

    print(f"Preflight check: {report['status']}")
    print(f"Ataskaita: {out_json}")


if __name__ == "__main__":
    main()
