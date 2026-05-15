from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(os.getenv("NETWORK_THESIS_BASE", str(Path.home() / "network-thesis-GIT"))).expanduser()
SRC_DIR = Path(os.getenv("NETWORK_THESIS_SRC", str(BASE_DIR / "src"))).expanduser()
RUNS_DIR = BASE_DIR / "runs"
BASELINE_DIR = BASE_DIR / "baseline"
ARCHIVE_DIR = BASE_DIR / "archive"

for d in (BASE_DIR, SRC_DIR, RUNS_DIR, BASELINE_DIR, ARCHIVE_DIR):
    d.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def timestamp_now() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def date_now() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def network_slug(network: str) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "_", network)


def get_run_id() -> str:
    return os.getenv("ASSESSMENT_RUN_ID") or timestamp_now()


def get_run_paths(run_id: str | None = None) -> dict:
    run_id = run_id or get_run_id()
    run_date = run_id[:10] if len(run_id) >= 10 else date_now()

    date_dir = RUNS_DIR / run_date
    run_dir = date_dir / run_id

    discovery_dir = run_dir / "discovery"
    services_dir = run_dir / "services"
    reports_dir = run_dir / "reports"
    power_dir = run_dir / "power"
    logs_dir = run_dir / "logs"
    meta_dir = run_dir / "meta"
    ai_dir = run_dir / "ai"

    for d in (date_dir, run_dir, discovery_dir, services_dir, reports_dir, power_dir, logs_dir, meta_dir, ai_dir):
        d.mkdir(parents=True, exist_ok=True)

    return {
        "run_id": run_id,
        "run_date": run_date,
        "date_dir": date_dir,
        "run_dir": run_dir,
        "discovery_dir": discovery_dir,
        "services_dir": services_dir,
        "reports_dir": reports_dir,
        "power_dir": power_dir,
        "logs_dir": logs_dir,
        "meta_dir": meta_dir,
        "ai_dir": ai_dir,
    }


def write_run_context(extra: dict | None = None) -> Path:
    paths = get_run_paths()
    context = {
        "run_id": paths["run_id"],
        "run_date": paths["run_date"],
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "run_dir": str(paths["run_dir"]),
        "ai_dir": str(paths["ai_dir"]),
    }
    if extra:
        context.update(extra)

    output = paths["meta_dir"] / "run_context.json"
    save_json(output, context)
    return output


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def detect_default_interface() -> str:
    routes = json.loads(run_cmd(["ip", "-j", "route", "show", "default"]))
    for route in routes:
        dev = route.get("dev")
        if dev:
            return dev
    raise RuntimeError("Nepavyko nustatyti default tinklo sąsajos.")


def detect_runtime_network() -> tuple[str, str, str | None]:
    override = os.getenv("TARGET_NETWORK")
    iface = detect_default_interface()

    if override:
        return override, iface, None

    addr_info = json.loads(run_cmd(["ip", "-j", "addr", "show", "dev", iface]))
    if not addr_info:
        raise RuntimeError(f"Nepavyko gauti informacijos apie sąsają {iface}.")

    for item in addr_info[0].get("addr_info", []):
        if item.get("family") == "inet":
            local_ip = item["local"]
            prefixlen = item["prefixlen"]
            network = str(ipaddress.ip_network(f"{local_ip}/{prefixlen}", strict=False))
            return network, iface, local_ip

    raise RuntimeError(f"Nepavyko nustatyti IPv4 tinklo sąsajai {iface}.")


def latest_current_file(section_name: str, pattern: str):
    paths = get_run_paths()
    files = sorted(paths[section_name].glob(pattern))
    return files[-1] if files else None


def latest_json_by_prefix(prefix: str, network: str | None = None) -> Path | None:
    files = sorted(RUNS_DIR.glob(f"**/{prefix}_*.json"))
    if not files:
        return None

    if network is None:
        return files[-1]

    matched = []
    for file in files:
        try:
            data = load_json(file)
            if data.get("network") == network:
                matched.append(file)
        except Exception:
            continue

    return matched[-1] if matched else None


def list_json_by_prefix(prefix: str, network: str | None = None) -> list[Path]:
    files = sorted(RUNS_DIR.glob(f"**/{prefix}_*.json"))
    if network is None:
        return files

    matched = []
    for file in files:
        try:
            data = load_json(file)
            if data.get("network") == network:
                matched.append(file)
        except Exception:
            continue
    return matched


def latest_file_in_dir(directory: Path, pattern: str) -> Path | None:
    files = sorted(directory.glob(pattern))
    return files[-1] if files else None


def sort_hosts_by_ip(hosts: list[dict]) -> list[dict]:
    return sorted(hosts, key=lambda h: ipaddress.ip_address(h.get("ip", "0.0.0.0")))
