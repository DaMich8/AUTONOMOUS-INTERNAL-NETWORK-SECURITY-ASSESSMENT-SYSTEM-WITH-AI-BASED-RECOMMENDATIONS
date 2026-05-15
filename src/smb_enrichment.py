import json
import shutil
import subprocess
from pathlib import Path

from common import (
    detect_runtime_network,
    get_run_paths,
    latest_current_file,
    latest_json_by_prefix,
    load_json,
    save_json,
    timestamp_now,
)

SMB_SERVICE_NAMES = {"microsoft-ds", "netbios-ssn", "smb"}
SMB_PORTS = {139, 445}


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def select_targets(services_data: dict) -> list[dict]:
    targets = []
    for host in services_data.get("hosts", []):
        ip = host.get("ip")
        if not ip:
            continue
        ports = []
        for port in host.get("ports", []):
            if port.get("port") in SMB_PORTS or (port.get("service_name") or "").lower() in SMB_SERVICE_NAMES:
                ports.append(port.get("port"))
        if ports:
            targets.append({"ip": ip, "asset_id": host.get("asset_id"), "ports": sorted(set(ports))})
    return targets


def main() -> None:
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()
    timestamp = timestamp_now()

    services_file = latest_current_file("services_dir", "services_*.json")
    if services_file is None:
        services_file = latest_json_by_prefix("services", network=network)
    if services_file is None:
        raise FileNotFoundError("Nerastas services JSON failas.")

    services_data = load_json(services_file)
    targets = select_targets(services_data)

    output_json = paths["services_dir"] / f"smb_enrichment_{timestamp}.json"
    log_json = paths["logs_dir"] / f"smb_enrichment_run_{timestamp}.json"
    parts_dir = paths["services_dir"] / f"smb_parts_{timestamp}"
    parts_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("enum4linux-ng"):
        save_json(output_json, {
            "scan_type": "smb_enrichment",
            "timestamp": timestamp,
            "network": network,
            "interface": interface,
            "source_ip": source_ip,
            "status": "skipped",
            "reason": "enum4linux-ng tool not found",
            "results": [],
            "hosts": []
        })
        save_json(log_json, {"scan_type": "smb_enrichment", "timestamp": timestamp, "status": "skipped"})
        print(f"SMB enrichment praleistas: enum4linux-ng nerastas. {output_json}")
        return

    results = []
    runs = []

    for idx, target in enumerate(targets, start=1):
        ip = target["ip"]
        asset_id = target.get("asset_id")
        base = parts_dir / f"{ip.replace('.', '_')}_enum4linux"
        expected_json = Path(str(base) + ".json")
        cmd = ["enum4linux-ng", "-A", "-oJ", str(base), ip]
        print(f"[{idx}/{len(targets)}] SMB enrichment hostui {ip}", flush=True)
        rc, out, err = run_cmd(cmd)

        parsed = None
        if expected_json.exists():
            try:
                with open(expected_json, "r", encoding="utf-8") as f:
                    parsed = json.load(f)
            except Exception as exc:
                err = (err + f"\nJSON parse klaida: {exc}").strip()

        results.append({
            "ip": ip,
            "asset_id": asset_id,
            "ports": target["ports"],
            "tool_output": parsed,
            "stdout": out if not parsed else None,
            "returncode": rc,
            "scan_status": "success" if rc == 0 else "partial",
        })
        runs.append({
            "ip": ip,
            "asset_id": asset_id,
            "ports": target["ports"],
            "command": " ".join(cmd),
            "returncode": rc,
            "json_file": str(expected_json),
            "stderr": err,
        })

    payload = {
        "scan_type": "smb_enrichment",
        "timestamp": timestamp,
        "network": network,
        "interface": interface,
        "source_ip": source_ip,
        "source_services_file": services_file.name,
        "targets_count": len(targets),
        "scan_status": "success" if all(r.get("returncode") == 0 for r in results) else "partial",
        "results": results,
        "hosts": results
    }

    save_json(output_json, payload)
    save_json(log_json, {
        "scan_type": "smb_enrichment",
        "timestamp": timestamp,
        "runs": runs,
    })

    print(f"Sukurtas SMB enrichment JSON: {output_json}")
    print(f"Apdoroti hostai: {len(targets)}")


if __name__ == "__main__":
    main()
