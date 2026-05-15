import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from asset_identity import build_asset_id
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

RPC_NFS_PORTS = {111, 2049, 20048, 32765, 32766, 32767, 32768, 32769, 4045}
RPC_NFS_SERVICES = {"rpcbind", "nfs", "mountd", "nlockmgr", "status", "rpc", "rquotad"}
R_SERVICES = {512: "rexec", 513: "rlogin/rwho", 514: "rsh/shell"}


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
        risky_r_ports = []
        for port in host.get("ports", []):
            service = (port.get("service_name") or "").lower()
            p = port.get("port")
            if p in RPC_NFS_PORTS or service in RPC_NFS_SERVICES:
                ports.append(p)
            if p in R_SERVICES:
                risky_r_ports.append(p)
                ports.append(p)
        if ports:
            targets.append({"ip": ip, "asset_id": host.get("asset_id") or build_asset_id(ip=ip, mac=host.get("mac"), hostname=host.get("hostname"), vendor=host.get("vendor")), "ports": sorted(set(ports)), "r_services": sorted(set(risky_r_ports))})
    return targets


def parse_scripts(xml_file: Path) -> list[dict]:
    if not xml_file.exists():
        return []
    tree = ET.parse(xml_file)
    root = tree.getroot()
    scripts = []
    for script in root.findall(".//port/script") + root.findall(".//hostscript/script"):
        scripts.append({"id": script.get("id"), "output": script.get("output") or ""})
    return scripts


def build_findings(target: dict, scripts: list[dict]) -> list[dict]:
    ports = set(target.get("ports", []))
    text = "\n".join(s.get("output") or "" for s in scripts)
    findings = []

    if 111 in ports:
        findings.append({
            "finding_id": "RPCBIND_EXPOSED",
            "severity": "vidutinė",
            "title": "Atviras RPCbind prievadas",
            "evidence": ["111/tcp atviras"],
            "impact": "RPCbind gali atskleisti papildomas RPC/NFS tarnybas ir didinti atakos paviršių.",
            "recommended_fix": "Riboti 111/tcp pasiekiamumą tik reikalingiems hostams arba išjungti rpcbind, jei jis nereikalingas.",
            "validation": "Pakartoti nmap -p111 ir rpcinfo patikrą.",
            "confidence": "aukštas",
        })

    if 2049 in ports or "nfs" in text.lower() or "nfs-showmount" in text.lower():
        findings.append({
            "finding_id": "NFS_EXPOSED",
            "severity": "aukšta",
            "title": "Aptikta NFS/RPC failų dalijimosi paslauga",
            "evidence": ["2049/tcp arba NFS NSE rezultatai"],
            "impact": "NFS neturėtų būti plačiai pasiekiamas iš bendro LAN, nes gali atskleisti katalogus arba leisti netinkamą prieigą.",
            "recommended_fix": "NFS eksportus apriboti konkrečiais IP/subnetais, peržiūrėti /etc/exports ir ugniasiene blokuoti 2049/tcp iš nereikalingų segmentų.",
            "validation": "Pakartoti nfs-showmount ir patikrinti, ar eksportai nebematomi iš neleistino segmento.",
            "confidence": "vidutinis",
        })

    if any(marker in text.lower() for marker in ("export list", "showmount", " /", "everyone", "no_root_squash")):
        findings.append({
            "finding_id": "NFS_EXPORTS_VISIBLE",
            "severity": "aukšta",
            "title": "NFS eksportai matomi tinkle",
            "evidence": ["nfs-showmount grąžino eksportų informaciją"],
            "impact": "Matomi NFS eksportai gali atskleisti katalogų struktūrą ir klaidingą prieigos kontrolę.",
            "recommended_fix": "Apriboti eksportus tik reikalingiems klientams, naudoti root_squash ir pašalinti nereikalingus eksportus.",
            "validation": "Pakartoti showmount -e arba nmap nfs-showmount iš neleistino segmento.",
            "confidence": "vidutinis",
        })

    for p in target.get("r_services", []):
        findings.append({
            "finding_id": "LEGACY_R_SERVICE_EXPOSED",
            "severity": "aukšta",
            "title": f"Aptikta sena r-services tipo paslauga ({p}/tcp)",
            "evidence": [f"{p}/tcp {R_SERVICES.get(p)}"],
            "impact": "rlogin/rsh/rexec tipo servisai istoriškai laikomi nesaugiais ir neturėtų būti naudojami.",
            "recommended_fix": "Išjungti r-services tipo servisus ir naudoti SSH arba kitą saugų administravimo mechanizmą.",
            "validation": f"Pakartoti nmap -p{p} patikrą.",
            "confidence": "aukštas",
        })

    return findings



def normalize_target_findings(target: dict, findings: list[dict], scan_status: str = "success") -> list[dict]:
    normalized = []
    ports = target.get("ports") or []
    default_port = ports[0] if ports else None
    service = "rpc_nfs"
    if 2049 in ports:
        service = "nfs"
    elif 111 in ports:
        service = "rpcbind"
    for finding in findings:
        raw = dict(finding)
        raw.setdefault("rule_id", str(raw.get("finding_id") or "rpc_nfs_finding").lower())
        normalized.append(normalize_finding(
            raw,
            source_module="rpc_nfs_audit.py",
            ip=target.get("ip"),
            asset_id=target.get("asset_id"),
            port=raw.get("port") or default_port,
            protocol=raw.get("protocol") or "tcp",
            service=raw.get("service") or service,
            scan_status=raw.get("scan_status") or scan_status,
        ))
    return normalized


def main() -> None:
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()
    timestamp = timestamp_now()

    services_file = latest_current_file("services_dir", "services_*.json")
    if services_file is None:
        services_file = latest_json_by_prefix("services", network=network)

    output_json = paths["services_dir"] / f"rpc_nfs_{timestamp}.json"
    log_json = paths["logs_dir"] / f"rpc_nfs_run_{timestamp}.json"

    if services_file is None:
        payload = {"scan_type": "rpc_nfs_audit", "timestamp": timestamp, "network": network, "status": "skipped", "reason": "services JSON not found", "results": []}
        save_json(output_json, payload)
        save_json(log_json, payload)
        return

    services_data = load_json(services_file)
    targets = select_targets(services_data)
    parts_dir = paths["services_dir"] / f"rpc_nfs_parts_{timestamp}"
    parts_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("nmap"):
        payload = {"scan_type": "rpc_nfs_audit", "timestamp": timestamp, "network": network, "status": "skipped", "reason": "nmap not found", "results": []}
        save_json(output_json, payload)
        save_json(log_json, payload)
        print(f"RPC/NFS audit praleistas: nmap nerastas. {output_json}")
        return

    results = []
    runs = []
    for idx, target in enumerate(targets, start=1):
        ip = target["ip"]
        ports = target["ports"]
        xml_file = parts_dir / f"{ip.replace('.', '_')}_rpc_nfs.xml"
        txt_file = parts_dir / f"{ip.replace('.', '_')}_rpc_nfs.txt"
        cmd = [
            "nmap", "-Pn", "-n", "-sV", "-p", ",".join(str(p) for p in ports),
            "--script", "rpcinfo,nfs-showmount,nfs-statfs",
            "--script-timeout", "30s", "-oX", str(xml_file), "-oN", str(txt_file), ip,
        ]
        print(f"[{idx}/{len(targets)}] RPC/NFS audit {ip}", flush=True)
        rc, out, err = run_cmd(cmd)
        scripts = parse_scripts(xml_file) if xml_file.exists() else []
        scan_status = "success" if rc == 0 else "partial"
        raw_findings = build_findings(target, scripts)
        findings = normalize_target_findings(target, raw_findings, scan_status=scan_status)
        results.append({"ip": ip, "asset_id": target.get("asset_id"), "ports": ports, "scripts": scripts, "findings": findings, "scan_status": scan_status, "returncode": rc, "stdout": out if rc != 0 else None})
        runs.append({"ip": ip, "command": " ".join(cmd), "returncode": rc, "stderr": err, "xml_file": str(xml_file), "txt_file": str(txt_file)})

    all_findings = [finding for result in results for finding in result.get("findings", [])]
    save_json(output_json, {"scan_type": "rpc_nfs_audit", "timestamp": timestamp, "network": network, "interface": interface, "source_ip": source_ip, "source_services_file": services_file.name, "targets_count": len(targets), "results": results, "findings": all_findings, "scan_status": "success" if results else "skipped"})
    save_json(log_json, {"scan_type": "rpc_nfs_audit", "timestamp": timestamp, "runs": runs})
    print(f"Sukurtas RPC/NFS audit JSON: {output_json}")
    print(f"RPC/NFS target'ai: {len(targets)}")


if __name__ == "__main__":
    main()
