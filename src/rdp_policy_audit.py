import shutil
import subprocess
import xml.etree.ElementTree as ET
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

RDP_PORTS = {3389}
RDP_SERVICE_NAMES = {"ms-wbt-server", "rdp"}


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
            service = (port.get("service_name") or "").lower()
            if port.get("port") in RDP_PORTS or service in RDP_SERVICE_NAMES:
                ports.append(port.get("port") or 3389)
        if ports:
            targets.append({"ip": ip, "asset_id": host.get("asset_id"), "ports": sorted(set(ports))})
    return targets


def parse_scripts(xml_file: Path) -> list[dict]:
    if not xml_file.exists():
        return []
    tree = ET.parse(xml_file)
    root = tree.getroot()
    return [{"id": s.get("id"), "output": s.get("output") or ""} for s in root.findall(".//port/script")]


def build_findings(ip: str, port: int, scripts: list[dict], asset_id: str | None = None) -> list[dict]:
    text = "\n".join(s.get("output") or "" for s in scripts)
    findings = [
        normalize_finding({
            "finding_id": f"RDP_EXPOSED_IN_LAN_{ip.replace('.', '_')}_{port}",
            "rule_id": "rdp_exposed_in_lan",
            "severity": "aukšta",
            "confidence": "aukštas",
            "title": "Atvira RDP administravimo sąsaja",
            "evidence": [f"{port}/tcp atviras"],
            "impact": "RDP yra administravimo sąsaja, todėl ji neturėtų būti plačiai pasiekiama iš bendro LAN segmento.",
            "recommended_fix": "Leisti RDP tik iš administravimo IP, VPN arba atskiro valdymo VLAN; kitiems LAN įrenginiams blokuoti.",
            "validation": f"Pakartoti nmap -Pn -p{port} {ip} patikrą iš bendro LAN ir valdymo segmento.",
        }, source_module="rdp_policy_audit.py", ip=ip, asset_id=asset_id, port=port, protocol="tcp", service="rdp")
    ]

    if "CredSSP (NLA): SUCCESS" not in text:
        findings.append(normalize_finding({
            "finding_id": f"RDP_NLA_NOT_CONFIRMED_{ip.replace('.', '_')}_{port}",
            "rule_id": "rdp_nla_not_confirmed",
            "severity": "aukšta",
            "confidence": "vidutinis",
            "title": "RDP NLA nepatvirtintas",
            "evidence": ["rdp-enum-encryption nerado CredSSP (NLA): SUCCESS"],
            "impact": "Be NLA RDP autentifikacija ir sesijos inicijavimas yra silpnesni.",
            "recommended_fix": "Įjungti Network Level Authentication ir neleisti seno Native RDP režimo, jei jis nereikalingas.",
            "validation": f"Pakartoti rdp-enum-encryption patikrą: nmap -Pn -p{port} --script rdp-enum-encryption {ip}.",
        }, source_module="rdp_policy_audit.py", ip=ip, asset_id=asset_id, port=port, protocol="tcp", service="rdp"))

    if "Native RDP: SUCCESS" in text:
        findings.append(normalize_finding({
            "finding_id": f"RDP_NATIVE_LAYER_ALLOWED_{ip.replace('.', '_')}_{port}",
            "rule_id": "rdp_native_layer_allowed",
            "severity": "vidutinė",
            "confidence": "vidutinis",
            "title": "RDP leidžia Native RDP saugumo sluoksnį",
            "evidence": ["Native RDP: SUCCESS"],
            "impact": "Senas saugumo sluoksnis gali būti nereikalingas ir didina suderinamumo riziką.",
            "recommended_fix": "RDP konfigūracijoje palikti tik NLA/TLS pagrindu veikiančią prieigą, jei suderinamumas leidžia.",
            "validation": f"Pakartoti rdp-enum-encryption patikrą: nmap -Pn -p{port} --script rdp-enum-encryption {ip}.",
        }, source_module="rdp_policy_audit.py", ip=ip, asset_id=asset_id, port=port, protocol="tcp", service="rdp"))

    return findings

def main() -> None:
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()
    timestamp = timestamp_now()

    services_file = latest_current_file("services_dir", "services_*.json")
    if services_file is None:
        services_file = latest_json_by_prefix("services", network=network)

    output_json = paths["services_dir"] / f"rdp_policy_{timestamp}.json"
    log_json = paths["logs_dir"] / f"rdp_policy_run_{timestamp}.json"

    if services_file is None:
        payload = {"scan_type": "rdp_policy_audit", "timestamp": timestamp, "network": network, "status": "skipped", "reason": "services JSON not found", "results": []}
        save_json(output_json, payload)
        save_json(log_json, payload)
        return

    services_data = load_json(services_file)
    targets = select_targets(services_data)
    parts_dir = paths["services_dir"] / f"rdp_policy_parts_{timestamp}"
    parts_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("nmap"):
        payload = {"scan_type": "rdp_policy_audit", "timestamp": timestamp, "network": network, "status": "skipped", "reason": "nmap not found", "results": []}
        save_json(output_json, payload)
        save_json(log_json, payload)
        print(f"RDP policy audit praleistas: nmap nerastas. {output_json}")
        return

    results = []
    runs = []
    for idx, target in enumerate(targets, start=1):
        ip = target["ip"]
        asset_id = target.get("asset_id")
        ports = target["ports"]
        xml_file = parts_dir / f"{ip.replace('.', '_')}_rdp_policy.xml"
        txt_file = parts_dir / f"{ip.replace('.', '_')}_rdp_policy.txt"
        cmd = [
            "nmap", "-Pn", "-n", "-p", ",".join(str(p) for p in ports),
            "--script", "rdp-enum-encryption,rdp-ntlm-info,ssl-cert",
            "--script-timeout", "25s", "-oX", str(xml_file), "-oN", str(txt_file), ip,
        ]
        print(f"[{idx}/{len(targets)}] RDP policy audit {ip}", flush=True)
        rc, out, err = run_cmd(cmd)
        scripts = parse_scripts(xml_file) if xml_file.exists() else []
        results.append({"ip": ip, "asset_id": asset_id, "ports": ports, "scripts": scripts, "findings": [f for p in ports for f in build_findings(ip, p, scripts, asset_id=asset_id)], "returncode": rc, "stdout": out if rc != 0 else None, "scan_status": "success" if rc == 0 else "failed"})
        runs.append({"ip": ip, "command": " ".join(cmd), "returncode": rc, "stderr": err, "xml_file": str(xml_file), "txt_file": str(txt_file)})

    all_findings = []
    for item in results:
        all_findings.extend(item.get("findings", []))
    save_json(output_json, {"scan_type": "rdp_policy_audit", "timestamp": timestamp, "network": network, "interface": interface, "source_ip": source_ip, "source_services_file": services_file.name, "targets_count": len(targets), "results": results, "findings": all_findings, "scan_status": "success" if all(r.get("returncode") == 0 for r in results) else "partial"})
    save_json(log_json, {"scan_type": "rdp_policy_audit", "timestamp": timestamp, "runs": runs})
    print(f"Sukurtas RDP policy audit JSON: {output_json}")
    print(f"RDP target'ai: {len(targets)}")


if __name__ == "__main__":
    main()
