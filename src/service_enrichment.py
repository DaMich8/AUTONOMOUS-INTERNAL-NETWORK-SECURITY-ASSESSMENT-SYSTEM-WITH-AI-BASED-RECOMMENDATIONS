
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

from common import get_run_paths, latest_current_file, latest_json_by_prefix, detect_runtime_network, load_json, save_json, timestamp_now


SERVICE_SCRIPT_MAP = {
    "http": ["http-title", "http-headers", "http-methods", "http-auth-finder"],
    "ssl/http": ["ssl-cert", "ssl-enum-ciphers", "http-title", "http-headers"],
    "https": ["ssl-cert", "ssl-enum-ciphers", "http-title", "http-headers"],
    "ssh": ["ssh-hostkey", "ssh2-enum-algos"],
    "microsoft-ds": ["smb-os-discovery", "smb-protocols", "smb-security-mode", "smb-enum-shares"],
    "netbios-ssn": ["smb-os-discovery", "smb-protocols", "smb-security-mode"],
    "ms-wbt-server": ["rdp-enum-encryption", "rdp-ntlm-info"],
    "mqtt": ["banner"],
    "ssl": ["ssl-cert", "ssl-enum-ciphers"],
}


def run_nmap(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


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


def parse_host_enrichment(xml_file: Path) -> list[dict]:
    tree = ET.parse(xml_file)
    root = tree.getroot()
    result = []

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
                if state is None or state.get("state") != "open":
                    continue
                ports.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "scripts": parse_script_nodes(port),
                })

        result.append({
            "ip": ip,
            "host_scripts": parse_script_nodes(host.find("hostscript")),
            "ports": ports
        })
    return result


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

    output_json = paths["services_dir"] / f"enrichment_{timestamp}.json"
    log_json = paths["logs_dir"] / f"enrichment_run_{timestamp}.json"
    txt_dir = paths["services_dir"] / f"enrichment_parts_{timestamp}"
    txt_dir.mkdir(parents=True, exist_ok=True)

    host_results = []
    host_logs = []

    for host in services_data.get("hosts", []):
        ip = host.get("ip")
        if not ip:
            continue

        selected_scripts = []
        selected_ports = []

        for port in host.get("ports", []):
            service_name = (port.get("service_name") or "").lower()
            if service_name in SERVICE_SCRIPT_MAP:
                selected_ports.append(str(port["port"]))
                selected_scripts.extend(SERVICE_SCRIPT_MAP[service_name])

        selected_scripts = sorted(set(selected_scripts))
        selected_ports = sorted(set(selected_ports), key=int)

        if not selected_scripts or not selected_ports:
            continue

        xml_file = txt_dir / f"{ip.replace('.', '_')}_enrichment.xml"
        txt_file = txt_dir / f"{ip.replace('.', '_')}_enrichment.txt"

        cmd = [
            "nmap",
            "-Pn",
            "-n",
            "-p", ",".join(selected_ports),
            "--script", ",".join(selected_scripts),
            "--script-timeout", "25s",
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
            host_results.extend(parse_host_enrichment(xml_file))

    save_json(output_json, {
        "scan_type": "service_enrichment",
        "timestamp": timestamp,
        "network": network,
        "source_services_file": services_file.name,
        "hosts": host_results,
    })
    save_json(log_json, {
        "scan_type": "service_enrichment",
        "timestamp": timestamp,
        "network": network,
        "runs": host_logs,
    })

    print(f"Sukurtas enrichment JSON: {output_json}")
    print(f"Apdoroti hostai: {len(host_results)}")


if __name__ == "__main__":
    main()
