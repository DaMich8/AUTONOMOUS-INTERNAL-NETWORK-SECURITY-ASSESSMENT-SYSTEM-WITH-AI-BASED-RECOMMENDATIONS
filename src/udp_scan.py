
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from common import get_run_paths, latest_current_file, latest_json_by_prefix, detect_runtime_network, load_json, save_json, timestamp_now

UDP_TOP_PORTS = os.getenv("UDP_TOP_PORTS", "50")


def run_nmap(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def parse_udp_xml(xml_file: Path) -> list[dict]:
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []

    for host in root.findall("host"):
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")

        ports = []
        ports_tag = host.find("ports")
        if ports_tag is not None:
            for port in ports_tag.findall("port"):
                state = port.find("state")
                if state is None:
                    continue
                service = port.find("service")
                ports.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "state": state.get("state"),
                    "reason": state.get("reason"),
                    "service_name": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                })

        hosts.append({"ip": ip, "udp_ports": ports})
    return hosts


def main():
    paths = get_run_paths()
    network, _, _ = detect_runtime_network()

    services_file = latest_current_file("services_dir", "services_*.json")
    if services_file is None:
        services_file = latest_json_by_prefix("services", network=network)
    if services_file is None:
        raise FileNotFoundError("Nerastas services JSON failas.")

    services_data = load_json(services_file)
    timestamp = timestamp_now()
    output_json = paths["services_dir"] / f"udp_{timestamp}.json"
    log_json = paths["logs_dir"] / f"udp_run_{timestamp}.json"
    parts_dir = paths["services_dir"] / f"udp_parts_{timestamp}"
    parts_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        h["ip"] for h in services_data.get("hosts", [])
        if h.get("ip") and h.get("open_ports_count", 0) <= 2
    ]

    host_results = []
    host_logs = []

    for ip in targets:
        xml_file = parts_dir / f"{ip.replace('.', '_')}_udp.xml"
        txt_file = parts_dir / f"{ip.replace('.', '_')}_udp.txt"

        cmd = [
            "nmap",
            "-Pn",
            "-n",
            "-sU",
            "--top-ports", UDP_TOP_PORTS,
            "-sV",
            "--version-light",
            "--script", "snmp-info,mdns-discovery,nbstat,upnp-info",
            "--script-timeout", "20s",
            "-oX", str(xml_file),
            "-oN", str(txt_file),
            ip
        ]

        rc, out, err = run_nmap(cmd)
        host_logs.append({
            "ip": ip,
            "command": " ".join(cmd),
            "returncode": rc,
            "xml_file": str(xml_file),
            "txt_file": str(txt_file),
            "stderr": err,
        })

        if rc == 0 and xml_file.exists():
            host_results.extend(parse_udp_xml(xml_file))

    save_json(output_json, {
        "scan_type": "udp_enrichment",
        "timestamp": timestamp,
        "network": network,
        "source_services_file": services_file.name,
        "hosts": host_results,
    })
    save_json(log_json, {
        "scan_type": "udp_enrichment",
        "timestamp": timestamp,
        "network": network,
        "runs": host_logs,
    })

    print(f"Sukurtas UDP JSON: {output_json}")
    print(f"UDP tikrinti hostai: {len(targets)}")


if __name__ == "__main__":
    main()
