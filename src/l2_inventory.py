import shutil
import subprocess

from asset_identity import enrich_host_asset_id
from common import detect_runtime_network, get_run_paths, save_json, timestamp_now


def run_command(command: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def parse_arp_scan_output(output: str) -> list[dict]:
    hosts = []

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue
        if line.startswith("Interface:"):
            continue
        if line.startswith("Starting arp-scan"):
            continue
        if line.startswith("Ending arp-scan"):
            continue
        if "packets received by filter" in line:
            continue

        parts = line.split("\t")
        if len(parts) >= 2:
            ip = parts[0].strip()
            mac = parts[1].strip()
            vendor = parts[2].strip() if len(parts) >= 3 else None

            if ip.count(".") == 3:
                hosts.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor
                })

    return hosts


def main() -> None:
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()
    timestamp = timestamp_now()

    out_json = paths["discovery_dir"] / f"l2_inventory_{timestamp}.json"
    out_log = paths["logs_dir"] / f"l2_inventory_run_{timestamp}.json"

    if shutil.which("arp-scan") is None:
        result = {
            "scan_type": "l2_inventory",
            "timestamp": timestamp,
            "network": network,
            "interface": interface,
            "source_ip": source_ip,
            "status": "skipped",
            "reason": "arp-scan nerastas sistemoje",
            "hosts": []
        }
        save_json(out_json, result)
        save_json(out_log, result)
        print(f"L2 inventory praleistas: arp-scan nerastas. {out_json}")
        return

    command = [
        "sudo", "-n",
        "arp-scan",
        "--localnet",
        "--interface", interface,
        "--ouifile", "/usr/share/arp-scan/ieee-oui.txt",
        "--macfile", "/usr/share/arp-scan/mac-vendor.txt",
    ]

    returncode, stdout, stderr = run_command(command)
    hosts = parse_arp_scan_output(stdout) if returncode == 0 else []
    for host in hosts:
        enrich_host_asset_id(host)

    result = {
        "scan_type": "l2_inventory",
        "timestamp": timestamp,
        "network": network,
        "interface": interface,
        "source_ip": source_ip,
        "status": "ok" if returncode == 0 else "error",
        "command": " ".join(command),
        "returncode": returncode,
        "stderr": stderr,
        "hosts_count": len(hosts),
        "hosts": hosts
    }

    save_json(out_json, result)
    save_json(out_log, result)

    if returncode != 0:
        print(f"L2 inventory nepavyko: {out_json}")
        print(stderr)
        return

    print(f"Sukurtas L2 inventory JSON: {out_json}")
    print(f"ARP aptikti hostai: {len(hosts)}")


if __name__ == "__main__":
    main()
