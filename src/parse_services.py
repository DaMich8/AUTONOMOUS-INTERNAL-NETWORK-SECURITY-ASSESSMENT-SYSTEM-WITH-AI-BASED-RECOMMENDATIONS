import json
import xml.etree.ElementTree as ET
from pathlib import Path

from asset_identity import enrich_host_asset_id
from common import get_run_paths, save_json, sort_hosts_by_ip


def extract_timestamp(file: Path) -> str:
    return file.stem.replace("services_", "")


def parse_script_nodes(parent):
    scripts = []
    if parent is None:
        return scripts

    for script in parent.findall("script"):
        scripts.append({
            "id": script.get("id"),
            "output": script.get("output")
        })
    return scripts


def parse_os_matches(host):
    os_data = []
    os_tag = host.find("os")
    if os_tag is None:
        return os_data

    for osmatch in os_tag.findall("osmatch"):
        entry = {
            "name": osmatch.get("name"),
            "accuracy": osmatch.get("accuracy"),
            "line": osmatch.get("line"),
            "classes": []
        }

        for osclass in osmatch.findall("osclass"):
            entry["classes"].append({
                "type": osclass.get("type"),
                "vendor": osclass.get("vendor"),
                "osfamily": osclass.get("osfamily"),
                "osgen": osclass.get("osgen"),
                "accuracy": osclass.get("accuracy"),
                "cpe": [c.text for c in osclass.findall("cpe") if c.text]
            })

        os_data.append(entry)

    return os_data


def main() -> None:
    paths = get_run_paths()
    xml_files = sorted(paths["services_dir"].glob("services_*.xml"))
    if not xml_files:
        raise FileNotFoundError("Nerastas nei vienas services XML failas.")

    latest_xml = xml_files[-1]
    timestamp = extract_timestamp(latest_xml)
    json_output = latest_xml.with_suffix(".json")
    log_file = paths["logs_dir"] / f"service_run_{timestamp}.json"

    tree = ET.parse(latest_xml)
    root = tree.getroot()

    network = None
    interface = None
    source_ip = None
    profile = None
    log_data = {}

    if log_file.exists():
        with open(log_file, "r", encoding="utf-8") as f:
            log_data = json.load(f)
        network = log_data.get("network")
        interface = log_data.get("interface")
        source_ip = log_data.get("source_ip")
        profile = log_data.get("profile")

    host_logs_by_ip = {}
    for item in (log_data.get("successful_hosts") or []) + (log_data.get("failed_hosts") or []):
        if isinstance(item, dict) and item.get("ip"):
            host_logs_by_ip[str(item.get("ip"))] = item

    hosts = []
    total_open_ports = 0

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = None
        mac = None
        vendor = None

        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")

        hostname_tag = host.find("hostnames/hostname")
        hostname = hostname_tag.get("name") if hostname_tag is not None else None

        extraports_info = []
        ports_tag = host.find("ports")
        if ports_tag is not None:
            for extraports in ports_tag.findall("extraports"):
                extraports_info.append({
                    "state": extraports.get("state"),
                    "count": extraports.get("count"),
                    "reason": extraports.find("extrareasons").get("reason")
                    if extraports.find("extrareasons") is not None else None
                })

        ports_data = []
        if ports_tag is not None:
            for port in ports_tag.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                service = port.find("service")
                cpes = []
                if service is not None:
                    for cpe in service.findall("cpe"):
                        if cpe.text:
                            cpes.append(cpe.text)

                scripts = parse_script_nodes(port)

                port_entry = {
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "state": state.get("state"),
                    "reason": state.get("reason"),
                    "service_name": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "extra_info": service.get("extrainfo") if service is not None else None,
                    "tunnel": service.get("tunnel") if service is not None else None,
                    "method": service.get("method") if service is not None else None,
                    "conf": service.get("conf") if service is not None else None,
                    "service_fingerprint": service.get("servicefp") if service is not None else None,
                    "cpes": cpes,
                    "scripts": scripts
                }
                ports_data.append(port_entry)

        total_open_ports += len(ports_data)

        host_scripts = parse_script_nodes(host.find("hostscript"))
        os_matches = parse_os_matches(host)

        ports_data = sorted(ports_data, key=lambda p: (p["port"], p["protocol"]))

        host_log = host_logs_by_ip.get(str(ip), {})
        host_entry = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "state": "up",
            "status_reason": status.get("reason"),
            "open_ports_count": len(ports_data),
            "extraports": extraports_info,
            "os_matches": os_matches,
            "host_scripts": host_scripts,
            "ports": ports_data,
            "scan_status": host_log.get("scan_status") or "success",
            "service_scan_status": host_log.get("scan_status") or "success",
            "timeout_reason": host_log.get("timeout_reason"),
            "confidence_penalty": host_log.get("confidence_penalty", 0.0),
            "service_scan_duration_s": host_log.get("duration_s"),
        }
        enrich_host_asset_id(host_entry)
        hosts.append(host_entry)

    hosts = sort_hosts_by_ip(hosts)

    result = {
        "scan_type": "services",
        "timestamp": timestamp,
        "network": network,
        "interface": interface,
        "source_ip": source_ip,
        "profile": profile,
        "source_file": latest_xml.name,
        "hosts_up": len(hosts),
        "total_open_ports": total_open_ports,
        "scan_status": (log_data or {}).get("scan_status", "success"),
        "nmap_version": (log_data or {}).get("nmap_version"),
        "scan_intensity_score": (log_data or {}).get("scan_intensity_score"),
        "host_duration_summary": (log_data or {}).get("host_duration_summary"),
        "failed_hosts": (log_data or {}).get("failed_hosts", []),
        "hosts": hosts
    }

    save_json(json_output, result)

    print(f"Sukurtas services JSON failas: {json_output}")
    print(f"Hostų skaičius: {len(hosts)}")
    print(f"Atvirų portų suma: {total_open_ports}")
    print(f"Tinklas: {network}")
    print(f"Profilis: {profile}")


if __name__ == "__main__":
    main()
