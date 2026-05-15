import os
import re
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

TCP_CHECK_PORTS = {53, 80, 443, 8080, 8443}
TCP_SCRIPTS = "dns-recursion,dns-nsid,http-title,http-server-header,http-methods,http-headers"
UDP_AUDIT_ENABLED = os.getenv("DNS_ROUTER_UDP_AUDIT", "0") == "1"
UDP_CHECK_PORTS = "53,67,68,123,161,1900,5353"
UDP_SCRIPTS = "dns-recursion,dns-nsid,upnp-info,snmp-info,mdns-discovery"


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
            p = port.get("port")
            if p in TCP_CHECK_PORTS or service in {"domain", "dns", "http", "https", "ssl/http"}:
                ports.append(p)
        # Include common gateway addresses even if only a subset of ports was detected.
        if ip.endswith(".1") or ip.endswith(".254"):
            ports.extend([80, 443, 53])
        if ports:
            targets.append({"ip": ip, "asset_id": host.get("asset_id") or build_asset_id(ip=ip, mac=host.get("mac"), hostname=host.get("hostname"), vendor=host.get("vendor")), "tcp_ports": sorted(set(p for p in ports if p))})
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
    text = "\n".join(s.get("output") or "" for s in scripts)
    lowered = text.lower()
    ports = set(target.get("tcp_ports", []))
    findings = []

    if 53 in ports and any(x in lowered for x in ("recursive queries supported", "recursion enabled", "recursion appears to be enabled")):
        findings.append({
            "finding_id": "DNS_RECURSION_ENABLED",
            "severity": "vidutinė",
            "title": "DNS rekursija gali būti įjungta",
            "evidence": ["dns-recursion NSE rezultatas"],
            "impact": "Atvira rekursija netinkamuose segmentuose gali būti panaudota informacijos rinkimui arba DNS amplification scenarijams.",
            "recommended_fix": "Leisti DNS rekursiją tik vidiniams klientams arba tik DNS serverio aptarnaujamam segmentui.",
            "validation": "Pakartoti dns-recursion patikrą iš neleistino segmento.",
            "confidence": "vidutinis",
        })

    if any(p in ports for p in (80, 443, 8080, 8443)):
        title_or_server = [s.get("output") or "" for s in scripts if s.get("id") in {"http-title", "http-server-header", "http-headers"}]
        evidence = [x.strip() for x in title_or_server if x.strip()][:3]
        findings.append({
            "finding_id": "NETWORK_DEVICE_WEB_INTERFACE",
            "severity": "vidutinė",
            "title": "Tinklo įrenginyje aptikta web administravimo sąsaja",
            "evidence": evidence or ["HTTP/HTTPS prievadas atviras"],
            "impact": "Maršrutizatoriaus arba tinklo įrenginio web sąsaja neturėtų būti pasiekiama iš viso bendro LAN.",
            "recommended_fix": "Administravimo web sąsają leisti tik valdymo IP/VLAN, pakeisti numatytuosius slaptažodžius ir išjungti nuotolinį administravimą, jei nereikalingas.",
            "validation": "Pakartoti nmap/http-title patikrą iš bendro LAN ir valdymo segmento.",
            "confidence": "vidutinis",
        })

    methods = re.findall(r"Supported Methods:\s*(.+)", text)
    for method_line in methods:
        risky = sorted(set(method_line.split()) & {"PUT", "DELETE", "TRACE", "CONNECT"})
        if risky:
            findings.append({
                "finding_id": "HTTP_RISKY_METHODS",
                "severity": "vidutinė",
                "title": "Web sąsaja leidžia rizikingus HTTP metodus",
                "evidence": risky,
                "impact": "Rizikingi HTTP metodai gali sudaryti sąlygas netinkamam turinio keitimui arba diagnostinės informacijos atskleidimui.",
                "recommended_fix": "Web serveryje išjungti nereikalingus HTTP metodus ir palikti tik GET/HEAD/POST, jei kiti nereikalingi.",
                "validation": "Pakartoti http-methods patikrą.",
                "confidence": "vidutinis",
            })

    if "upnp" in lowered or "ssdp" in lowered:
        findings.append({
            "finding_id": "UPNP_DETECTED",
            "severity": "vidutinė",
            "title": "Aptiktas UPnP/SSDP požymis",
            "evidence": ["upnp-info arba SSDP tekstas"],
            "impact": "UPnP namų ar mažų biurų tinkluose gali automatiškai keisti prievadų nukreipimus.",
            "recommended_fix": "Išjungti UPnP maršrutizatoriuje, jei jo nereikia, arba riboti jį tik patikimiems įrenginiams.",
            "validation": "Pakartoti UDP 1900/upnp-info patikrą.",
            "confidence": "vidutinis",
        })

    return findings



def normalize_target_findings(target: dict, findings: list[dict], scan_status: str = "success") -> list[dict]:
    normalized = []
    ports = target.get("tcp_ports") or []
    default_port = ports[0] if ports else None
    service = "dns_router"
    if 53 in ports:
        service = "dns"
    elif any(p in ports for p in (80, 443, 8080, 8443)):
        service = "http"
    for finding in findings:
        raw = dict(finding)
        raw.setdefault("rule_id", str(raw.get("finding_id") or "dns_router_finding").lower())
        normalized.append(normalize_finding(
            raw,
            source_module="dns_router_audit.py",
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

    output_json = paths["services_dir"] / f"dns_router_{timestamp}.json"
    log_json = paths["logs_dir"] / f"dns_router_run_{timestamp}.json"

    if services_file is None:
        payload = {"scan_type": "dns_router_audit", "timestamp": timestamp, "network": network, "status": "skipped", "reason": "services JSON not found", "results": []}
        save_json(output_json, payload)
        save_json(log_json, payload)
        return

    services_data = load_json(services_file)
    targets = select_targets(services_data)
    parts_dir = paths["services_dir"] / f"dns_router_parts_{timestamp}"
    parts_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("nmap"):
        payload = {"scan_type": "dns_router_audit", "timestamp": timestamp, "network": network, "status": "skipped", "reason": "nmap not found", "results": []}
        save_json(output_json, payload)
        save_json(log_json, payload)
        print(f"DNS/router audit praleistas: nmap nerastas. {output_json}")
        return

    results = []
    runs = []
    for idx, target in enumerate(targets, start=1):
        ip = target["ip"]
        tcp_ports = target["tcp_ports"]
        scripts = []
        rc_values = []

        if tcp_ports:
            xml_file = parts_dir / f"{ip.replace('.', '_')}_dns_router_tcp.xml"
            txt_file = parts_dir / f"{ip.replace('.', '_')}_dns_router_tcp.txt"
            cmd = ["nmap", "-Pn", "-n", "-p", ",".join(str(p) for p in tcp_ports), "--script", TCP_SCRIPTS, "--script-timeout", "25s", "-oX", str(xml_file), "-oN", str(txt_file), ip]
            print(f"[{idx}/{len(targets)}] DNS/router TCP audit {ip}", flush=True)
            rc, out, err = run_cmd(cmd)
            rc_values.append(rc)
            scripts.extend(parse_scripts(xml_file) if xml_file.exists() else [])
            runs.append({"ip": ip, "mode": "tcp", "command": " ".join(cmd), "returncode": rc, "stderr": err, "xml_file": str(xml_file), "txt_file": str(txt_file)})

        if UDP_AUDIT_ENABLED:
            xml_file = parts_dir / f"{ip.replace('.', '_')}_dns_router_udp.xml"
            txt_file = parts_dir / f"{ip.replace('.', '_')}_dns_router_udp.txt"
            cmd = ["nmap", "-Pn", "-n", "-sU", "-p", UDP_CHECK_PORTS, "--max-retries", "1", "--host-timeout", "90s", "--script", UDP_SCRIPTS, "--script-timeout", "25s", "-oX", str(xml_file), "-oN", str(txt_file), ip]
            print(f"[{idx}/{len(targets)}] DNS/router UDP audit {ip}", flush=True)
            rc, out, err = run_cmd(cmd)
            rc_values.append(rc)
            scripts.extend(parse_scripts(xml_file) if xml_file.exists() else [])
            runs.append({"ip": ip, "mode": "udp", "command": " ".join(cmd), "returncode": rc, "stderr": err, "xml_file": str(xml_file), "txt_file": str(txt_file)})

        scan_status = "success" if rc_values and all(rc == 0 for rc in rc_values) else "partial"
        raw_findings = build_findings(target, scripts)
        findings = normalize_target_findings(target, raw_findings, scan_status=scan_status)
        results.append({"ip": ip, "asset_id": target.get("asset_id"), "ports": tcp_ports, "scripts": scripts, "findings": findings, "scan_status": scan_status, "returncode": 0 if all(rc == 0 for rc in rc_values) else 2})

    all_findings = [finding for result in results for finding in result.get("findings", [])]
    save_json(output_json, {"scan_type": "dns_router_audit", "timestamp": timestamp, "network": network, "interface": interface, "source_ip": source_ip, "source_services_file": services_file.name, "udp_audit_enabled": UDP_AUDIT_ENABLED, "targets_count": len(targets), "results": results, "findings": all_findings, "scan_status": "success" if results else "skipped"})
    save_json(log_json, {"scan_type": "dns_router_audit", "timestamp": timestamp, "runs": runs})
    print(f"Sukurtas DNS/router audit JSON: {output_json}")
    print(f"DNS/router target'ai: {len(targets)}")


if __name__ == "__main__":
    main()
