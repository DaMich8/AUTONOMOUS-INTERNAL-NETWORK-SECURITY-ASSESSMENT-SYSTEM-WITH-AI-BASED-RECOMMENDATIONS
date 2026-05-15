import re
import xml.etree.ElementTree as ET
from pathlib import Path

from asset_identity import enrich_host_asset_id
from common import get_run_paths, save_json, sort_hosts_by_ip


def extract_timestamp(file: Path) -> str:
    return file.stem.replace("discovery_", "")


def extract_network_from_args(args: str) -> str | None:
    match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", args)
    return match.group(1) if match else None


def main() -> None:
    paths = get_run_paths()
    xml_files = sorted(paths["discovery_dir"].glob("discovery_*.xml"))
    if not xml_files:
        raise FileNotFoundError("Nerastas nei vienas discovery XML failas.")

    latest_xml = xml_files[-1]
    timestamp = extract_timestamp(latest_xml)
    json_output = latest_xml.with_suffix(".json")
    log_file = paths["logs_dir"] / f"run_{timestamp}.json"

    tree = ET.parse(latest_xml)
    root = tree.getroot()

    network = None
    interface = None
    source_ip = None

    if log_file.exists():
        import json
        with open(log_file, "r", encoding="utf-8") as f:
            log_data = json.load(f)
        network = log_data.get("network")
        interface = log_data.get("interface")
        source_ip = log_data.get("source_ip")

    if network is None:
        network = extract_network_from_args(root.get("args", ""))

    hosts = []

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

        host_entry = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "state": "up",
            "scan_status": "success",
        }
        enrich_host_asset_id(host_entry)
        hosts.append(host_entry)

    hosts = sort_hosts_by_ip(hosts)

    result = {
        "scan_type": "discovery",
        "timestamp": timestamp,
        "network": network,
        "interface": interface,
        "source_ip": source_ip,
        "source_file": latest_xml.name,
        "hosts_up": len(hosts),
        "scan_status": "success",
        "hosts": hosts
    }

    save_json(json_output, result)

    print(f"Sukurtas JSON failas: {json_output}")
    print(f"Aktyvių hostų skaičius: {len(hosts)}")
    print(f"Tinklas: {network}")


if __name__ == "__main__":
    main()
