#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from common import detect_runtime_network, get_run_paths, latest_current_file, latest_json_by_prefix, load_json, save_json, timestamp_now
from finding_schema import normalize_finding

VULN_SERVICE_SET = {"http", "https", "ssl/http", "microsoft-ds", "netbios-ssn", "ms-wbt-server", "ssh", "ftp", "smtp", "pop3", "imap"}
# Covers common vulners output: CVE-2024-1234 7.5, CVE-2024-1234\t7.5, CVE-2024-1234 | 7.5
CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,})(?:[^\n\r0-9]{1,32}([0-9]+(?:\.[0-9]+)?))?", re.IGNORECASE)
NSE_CANDIDATES = [
    Path("/usr/share/nmap/scripts/vulners.nse"),
    Path("/usr/local/share/nmap/scripts/vulners.nse"),
]

ALLOWED_CVE_STATUS = {"confirmed", "potential", "false_positive", "not_verified"}


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def run_nmap(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def vulners_script_available() -> tuple[bool, str | None]:
    for path in NSE_CANDIDATES:
        if path.exists():
            return True, str(path)
    nmap = shutil.which("nmap")
    if not nmap:
        return False, None
    try:
        result = subprocess.run([nmap, "--script-help", "vulners"], capture_output=True, text=True, timeout=10)
        text = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0 and "vulners" in text.lower():
            return True, "nmap_script_help:vulners"
    except Exception:
        pass
    return False, None


def cvss_to_severity(cvss: float | None) -> str:
    if cvss is None:
        return "vidutinė"
    if cvss >= 9:
        return "kritinė"
    if cvss >= 7:
        return "aukšta"
    if cvss >= 4:
        return "vidutinė"
    return "žema"


def infer_cve_status(script_output: str, *, authenticated: bool = False) -> str:
    text = (script_output or "").lower()
    if "false positive" in text or "not vulnerable" in text:
        return "false_positive"
    # Vulners is banner/CPE based. Even if exploit references exist, that does not prove
    # exploitation is possible on this exact host/configuration.
    if authenticated and ("vulnerable" in text or "confirmed" in text):
        return "confirmed"
    if "cve-" in text:
        return "potential"
    return "not_verified"


def parse_cves(text: str, port: int | None = None, protocol: str | None = None, script_id: str | None = None) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    status = infer_cve_status(text)
    for match in CVE_RE.finditer(text or ""):
        cve = match.group(1).upper()
        if cve in seen:
            continue
        seen.add(cve)
        cvss = None
        if match.group(2):
            try:
                cvss = float(match.group(2))
            except Exception:
                cvss = None
        out.append({
            "cve": cve,
            "cvss": cvss,
            "source": "nmap_vulners",
            "source_script": script_id or "vulners",
            "source_port": f"{port}/{protocol}" if port and protocol else None,
            "confidence": "vidutinis",
            "match_type": "banner_or_cpe",
            "status": status if status in ALLOWED_CVE_STATUS else "potential",
        })
    return out


def service_host_index(services_data: dict) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for host in as_list(services_data.get("hosts")):
        if isinstance(host, dict) and host.get("ip"):
            result[str(host["ip"])] = host
    return result


def dedupe_cves(cves: list[dict]) -> list[dict]:
    best: dict[str, dict] = {}
    for item in cves:
        cve = item.get("cve")
        if not cve:
            continue
        current = best.get(cve)
        if current is None or float(item.get("cvss") or 0) > float(current.get("cvss") or 0):
            best[cve] = item
    return sorted(best.values(), key=lambda x: (float(x.get("cvss") or 0), x.get("cve") or ""), reverse=True)


def parse_vuln_xml(xml_file: Path, host_assets: dict[str, dict] | None = None) -> list[dict]:
    host_assets = host_assets or {}
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []
    for host in root.findall("host"):
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
        asset = host_assets.get(str(ip), {})
        host_entry = {
            "ip": ip,
            "asset_id": asset.get("asset_id"),
            "ports": [],
            "host_scripts": [],
            "cves": [],
            "findings": [],
            "scan_status": "success",
        }
        for script in host.findall("hostscript/script"):
            sid = script.get("id")
            output = script.get("output") or ""
            host_entry["host_scripts"].append({"id": sid, "output": output})
            host_entry["cves"].extend(parse_cves(output, script_id=sid))
        ports_tag = host.find("ports")
        if ports_tag is not None:
            for port in ports_tag.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port_num = int(port.get("portid"))
                proto = port.get("protocol") or "tcp"
                entry = {"port": port_num, "protocol": proto, "scripts": [], "cves": []}
                for script in port.findall("script"):
                    sid = script.get("id")
                    output = script.get("output") or ""
                    entry["scripts"].append({"id": sid, "output": output})
                    cves = parse_cves(output, port_num, proto, sid)
                    entry["cves"].extend(cves)
                    host_entry["cves"].extend(cves)
                host_entry["ports"].append(entry)

        host_entry["cves"] = dedupe_cves(host_entry["cves"])
        for cve in host_entry["cves"][:50]:
            cvss = cve.get("cvss")
            sev = cvss_to_severity(cvss)
            source_port = cve.get("source_port")
            port_number = None
            protocol = None
            if source_port and "/" in str(source_port):
                p, protocol = str(source_port).split("/", 1)
                try:
                    port_number = int(p)
                except Exception:
                    port_number = None
            host_entry["findings"].append(normalize_finding({
                "finding_id": f"CVE_{cve['cve'].replace('-', '_')}_{str(ip).replace('.', '_')}_{str(source_port or 'host').replace('/', '_')}",
                "rule_id": "service_cve_detected",
                "severity": sev,
                "confidence": cve.get("confidence", "vidutinis"),
                "title": f"Pagal paslaugos versiją aptiktas galimas pažeidžiamumas: {cve['cve']}",
                "evidence": [
                    f"{cve['cve']} CVSS {cvss if cvss is not None else 'nenustatytas'}",
                    f"source={cve.get('source')}",
                    f"source_script={cve.get('source_script')}",
                    f"match_type={cve.get('match_type')}",
                    f"status={cve.get('status')}",
                    f"port={source_port}",
                ],
                "impact": "CVE aptiktas pagal paslaugos versiją, CPE arba banner informaciją. Tai yra potencialus radinys, kurį reikia patvirtinti pagal tikslią programinės įrangos versiją ir konfigūraciją.",
                "recommended_fix": "Patikrinti paveiktos paslaugos versiją, pritaikyti gamintojo saugumo pataisas arba riboti paslaugos pasiekiamumą, kol pažeidžiamumas patvirtinamas arba paneigiamas.",
                "validation": "Pakartoti nmap --script vulners patikrą ir papildomai patikrinti programinės įrangos versiją gamintojo dokumentacijoje.",
                "false_positive_conditions": [
                    "Banner arba CPE informacija gali būti netiksli",
                    "Paslauga gali turėti backportintas pataisas nepakeitus matomos versijos",
                    "Vulners NSE rezultatas nėra autentifikuotas pažeidžiamumo patvirtinimas",
                ],
                "cve": cve.get("cve"),
                "cvss": cvss,
                "cve_status": cve.get("status"),
                "match_type": cve.get("match_type"),
                "source_script": cve.get("source_script"),
                "scan_status": "success",
            }, source_module="vuln_enrichment.py", ip=ip, asset_id=asset.get("asset_id"), port=port_number, protocol=protocol, service="vulnerability"))
        hosts.append(host_entry)
    return hosts


def target_ports_for_host(host: dict) -> list[str]:
    interesting_ports = []
    for port in as_list(host.get("ports")):
        service = (port.get("service_name") or "").lower()
        cpes = as_list(port.get("cpes"))
        if service in VULN_SERVICE_SET or cpes:
            if port.get("port") is not None:
                interesting_ports.append(str(port["port"]))
    return sorted(set(interesting_ports), key=int)


def main() -> None:
    paths = get_run_paths()
    network, _, _ = detect_runtime_network()
    services_file = latest_current_file("services_dir", "services_*.json") or latest_json_by_prefix("services", network=network)
    if services_file is None:
        raise FileNotFoundError("Nerastas paslaugų JSON failas.")

    services_data = load_json(services_file)
    host_assets = service_host_index(services_data)
    timestamp = timestamp_now()
    output_json = paths["services_dir"] / f"vuln_{timestamp}.json"
    log_json = paths["logs_dir"] / f"vuln_run_{timestamp}.json"
    parts_dir = paths["services_dir"] / f"vuln_parts_{timestamp}"
    parts_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("nmap"):
        payload = {"scan_type": "vuln_enrichment", "timestamp": timestamp, "network": network, "status": "skipped", "scan_status": "skipped", "reason": "nmap tool not found", "hosts": [], "cves": [], "findings": []}
        save_json(output_json, payload)
        save_json(log_json, payload)
        print(f"[PRALEISTA] CVE patikra neatlikta, nes nerastas nmap įrankis: {output_json}")
        return

    script_ok, script_source = vulners_script_available()
    if not script_ok:
        payload = {"scan_type": "vuln_enrichment", "timestamp": timestamp, "network": network, "status": "skipped", "scan_status": "skipped", "reason": "vulners NSE script not found", "hosts": [], "cves": [], "findings": []}
        save_json(output_json, payload)
        save_json(log_json, payload)
        print(f"[PRALEISTA] CVE patikra neatlikta, nes nerastas vulners NSE scriptas: {output_json}")
        return

    targets = []
    for host in as_list(services_data.get("hosts")):
        if not isinstance(host, dict) or not host.get("ip"):
            continue
        ports = target_ports_for_host(host)
        if ports:
            targets.append((host["ip"], ports, host.get("asset_id")))

    host_results = []
    host_logs = []
    all_findings = []
    all_cves = []
    for idx, (ip, ports, asset_id) in enumerate(targets, start=1):
        xml_file = parts_dir / f"{ip.replace('.', '_')}_vuln.xml"
        txt_file = parts_dir / f"{ip.replace('.', '_')}_vuln.txt"
        cmd = ["nmap", "-Pn", "-n", "-sV", "-p", ",".join(ports), "--script", "vulners", "--script-timeout", "30s", "-oX", str(xml_file), "-oN", str(txt_file), ip]
        print(f"[{idx}/{len(targets)}] Tikrinami galimi CVE pagal paslaugų versijas: {ip}", flush=True)
        rc, out, err = run_nmap(cmd)
        scan_status = "success" if rc == 0 else "failed"
        host_logs.append({"ip": ip, "asset_id": asset_id, "ports": ports, "command": " ".join(cmd), "returncode": rc, "xml_file": str(xml_file), "txt_file": str(txt_file), "stderr": err, "scan_status": scan_status, "source_script": script_source})
        if rc == 0 and xml_file.exists():
            parsed = parse_vuln_xml(xml_file, host_assets)
            for h in parsed:
                if not h.get("asset_id"):
                    h["asset_id"] = asset_id
                host_results.append(h)
                all_findings.extend(h.get("findings", []))
                all_cves.extend(h.get("cves", []))
        else:
            failure = normalize_finding({
                "finding_id": f"VULN_SCAN_FAILED_{ip.replace('.', '_')}",
                "rule_id": "vuln_scan_failed",
                "severity": "vidutinė",
                "confidence": "vidutinis",
                "title": "Pažeidžiamumų patikra nebuvo užbaigta",
                "evidence": [f"nmap returncode={rc}", err],
                "impact": "Nepavykus patikrai dalis CVE gali likti neaptikta.",
                "recommended_fix": "Patikrinti nmap/vulners NSE įdiegimą ir pakartoti patikrą.",
                "validation": "Pakartoti vuln_enrichment.py.",
                "scan_status": "failed",
            }, source_module="vuln_enrichment.py", ip=ip, asset_id=asset_id, scan_status="failed")
            all_findings.append(failure)
            host_results.append({"ip": ip, "asset_id": asset_id, "ports": [], "cves": [], "findings": [failure], "scan_status": "failed"})

    all_cves = dedupe_cves(all_cves)
    output = {
        "scan_type": "vuln_enrichment",
        "timestamp": timestamp,
        "network": network,
        "source_services_file": services_file.name,
        "vulners_script": script_source,
        "targets_count": len(targets),
        "hosts": host_results,
        "cves": all_cves,
        "findings": all_findings,
        "summary": {
            "unique_cves": len(all_cves),
            "potential_cves": sum(1 for c in all_cves if c.get("status") == "potential"),
            "confirmed_cves": sum(1 for c in all_cves if c.get("status") == "confirmed"),
            "not_verified_cves": sum(1 for c in all_cves if c.get("status") == "not_verified"),
        },
        "scan_status": "success" if not any(h.get("scan_status") == "failed" for h in host_results) else "partial",
    }
    save_json(output_json, output)
    save_json(log_json, {"scan_type": "vuln_enrichment", "timestamp": timestamp, "network": network, "runs": host_logs})
    print(f"[GERAI] CVE praturtinimo JSON failas sukurtas: {output_json}")
    print(f"[INFO] Patikrinti įrenginiai: {len(targets)}; unikalūs CVE: {len(all_cves)}; radiniai: {len(all_findings)}")


if __name__ == "__main__":
    main()
