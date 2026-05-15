import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from finding_schema import normalize_finding

from common import (
    detect_runtime_network,
    get_run_paths,
    latest_current_file,
    latest_json_by_prefix,
    load_json,
    save_json,
    timestamp_now,
)

SNMP_PORTS = {161}
SNMP_SERVICE_NAMES = {"snmp"}
RESP_RE = re.compile(r'^(\d+\.\d+\.\d+\.\d+)\s+\[(.*?)\]\s+(.*)$')


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def select_targets(services_data: dict) -> list[dict]:
    targets = []
    for host in services_data.get("hosts", []):
        ip = host.get("ip")
        if not ip:
            continue
        ports = host.get("ports", [])
        if (
            not ports
            or any(
                p.get("port") in SNMP_PORTS
                or (p.get("service_name") or "").lower() in SNMP_SERVICE_NAMES
                for p in ports
            )
        ):
            targets.append({"ip": ip, "asset_id": host.get("asset_id")})

    # Dedupe by IP.
    unique = {}
    for item in targets:
        unique[item["ip"]] = item
    return [unique[ip] for ip in sorted(unique.keys())]

def parse_onesixtyone(output: str) -> list[dict]:
    entries = []
    for line in output.splitlines():
        line = line.strip()
        m = RESP_RE.match(line)
        if m:
            entries.append({
                "ip": m.group(1),
                "community": m.group(2),
                "sysdescr": m.group(3),
            })
    return entries


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

    output_json = paths["services_dir"] / f"snmp_enrichment_{timestamp}.json"
    log_json = paths["logs_dir"] / f"snmp_enrichment_run_{timestamp}.json"

    if not shutil.which("onesixtyone"):
        save_json(output_json, {
            "scan_type": "snmp_enrichment",
            "timestamp": timestamp,
            "network": network,
            "interface": interface,
            "source_ip": source_ip,
            "status": "skipped",
            "reason": "onesixtyone tool not found",
            "results": [],
            "responsive_hosts": [],
            "detailed_results": []
        })
        save_json(log_json, {"scan_type": "snmp_enrichment", "timestamp": timestamp, "status": "skipped"})
        print(f"SNMP enrichment praleistas: onesixtyone nerastas. {output_json}")
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        host_file = Path(tmpdir) / "hosts.txt"
        community_file = Path(tmpdir) / "community.txt"

        host_file.write_text("\n".join(t["ip"] for t in targets) + "\n", encoding="utf-8")
        community_file.write_text("public\nprivate\n", encoding="utf-8")

        detect_cmd = ["onesixtyone", "-c", str(community_file), "-i", str(host_file), "-w", "2"]
        rc, out, err = run_cmd(detect_cmd)
        responsive = parse_onesixtyone(out) if rc == 0 else []

    detailed = []
    if shutil.which("snmpcheck"):
        for entry in responsive:
            ip = entry["ip"]
            community = entry["community"]
            cmd = ["snmpcheck", "-t", ip, "-c", community]
            rc2, out2, err2 = run_cmd(cmd)
            detailed.append({
                "ip": ip,
                "community": community,
                "returncode": rc2,
                "stdout": out2,
                "stderr": err2,
            })

    asset_by_ip = {t["ip"]: t.get("asset_id") for t in targets}
    results = []
    all_findings = []
    for entry in responsive:
        ip = entry["ip"]
        detail = next((d for d in detailed if d["ip"] == ip and d["community"] == entry["community"]), None)
        asset_id = asset_by_ip.get(ip)
        findings = []
        if str(entry.get("community", "")).lower() in {"public", "private"}:
            findings.append(normalize_finding({
                "finding_id": f"SNMP_DEFAULT_COMMUNITY_{ip.replace('.', '_')}",
                "rule_id": "snmp_default_community",
                "severity": "aukšta",
                "confidence": "aukštas",
                "title": "SNMP paslauga atsako su numatytąja community reikšme",
                "evidence": [f"community={entry.get('community')}", entry.get("sysdescr")],
                "impact": "Numatytosios SNMP community reikšmės gali leisti rinkti informaciją apie įrenginį arba konfigūraciją.",
                "recommended_fix": "Pakeisti community reikšmes, naudoti SNMPv3 ir riboti SNMP prieigą tik valdymo segmentui.",
                "validation": f"Pakartoti onesixtyone/snmpcheck patikrą hostui {ip}.",
            }, source_module="snmp_enrichment.py", ip=ip, asset_id=asset_id, port=161, protocol="udp", service="snmp"))
        all_findings.extend(findings)
        results.append({
            "ip": ip,
            "asset_id": asset_id,
            "community": entry["community"],
            "sysdescr": entry["sysdescr"],
            "detail": detail,
            "findings": findings,
            "scan_status": "success",
        })

    save_json(output_json, {
        "scan_type": "snmp_enrichment",
        "timestamp": timestamp,
        "network": network,
        "interface": interface,
        "source_ip": source_ip,
        "source_services_file": services_file.name,
        "targets_count": len(targets),
        "results": results,
        "responsive_hosts": responsive,
        "detailed_results": detailed,
        "findings": all_findings,
        "scan_status": "success" if rc == 0 else "partial",
    })

    save_json(log_json, {
        "scan_type": "snmp_enrichment",
        "timestamp": timestamp,
        "detect_command": "onesixtyone -c <communities> -i <hosts> -w 2",
        "detect_returncode": rc,
        "detect_stderr": err,
        "responsive_count": len(responsive),
    })

    print(f"Sukurtas SNMP enrichment JSON: {output_json}")
    print(f"SNMP atsakę hostai: {len(responsive)}")


if __name__ == "__main__":
    main()
