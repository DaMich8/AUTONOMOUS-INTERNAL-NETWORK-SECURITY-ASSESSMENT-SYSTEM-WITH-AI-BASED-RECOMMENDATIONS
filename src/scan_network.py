import subprocess

from common import detect_runtime_network, get_run_paths, save_json, timestamp_now


def run_scan() -> None:
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()
    timestamp = timestamp_now()

    xml_file = paths["discovery_dir"] / f"discovery_{timestamp}.xml"
    txt_file = paths["discovery_dir"] / f"discovery_{timestamp}.txt"
    log_file = paths["logs_dir"] / f"run_{timestamp}.json"

    command = [
        "nmap",
        "-sn",
        network,
        "-oX", str(xml_file),
        "-oN", str(txt_file)
    ]

    result = subprocess.run(command, capture_output=True, text=True)

    execution_log = {
        "timestamp": timestamp,
        "scan_type": "discovery",
        "network": network,
        "interface": interface,
        "source_ip": source_ip,
        "command": " ".join(command),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "xml_file": str(xml_file),
        "txt_file": str(txt_file)
    }

    save_json(log_file, execution_log)

    if result.returncode != 0:
        print("Discovery nuskaitymas nepavyko.")
        print(result.stderr)
        raise SystemExit(result.returncode)

    print("Discovery nuskaitymas baigtas.")
    print(f"Tinklas: {network}")
    print(f"Sąsaja: {interface}")
    print(f"XML rezultatai: {xml_file}")
    print(f"TXT rezultatai: {txt_file}")
    print(f"Žurnalas: {log_file}")


if __name__ == "__main__":
    run_scan()
