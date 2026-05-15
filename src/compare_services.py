import shutil

from common import BASELINE_DIR, detect_runtime_network, get_run_paths, list_json_by_prefix, load_json, network_slug, save_json


def host_port_map(scan_data: dict) -> dict:
    result = {}
    for host in scan_data.get("hosts", []):
        ip = host.get("ip")
        if not ip:
            continue

        ports = {}
        for port in host.get("ports", []):
            key = f"{port['port']}/{port['protocol']}"
            value = {
                "service_name": port.get("service_name"),
                "product": port.get("product"),
                "version": port.get("version"),
                "extra_info": port.get("extra_info")
            }
            ports[key] = value
        result[ip] = ports
    return result


def compare(reference: dict, current: dict) -> dict:
    ref_map = host_port_map(reference)
    cur_map = host_port_map(current)

    ref_hosts = set(ref_map.keys())
    cur_hosts = set(cur_map.keys())

    new_hosts = sorted(cur_hosts - ref_hosts)
    missing_hosts = sorted(ref_hosts - cur_hosts)
    unchanged_hosts = sorted(cur_hosts & ref_hosts)

    new_ports = []
    closed_ports = []
    changed_services = []

    for ip in unchanged_hosts:
        ref_ports = ref_map[ip]
        cur_ports = cur_map[ip]

        ref_keys = set(ref_ports.keys())
        cur_keys = set(cur_ports.keys())

        for port_key in sorted(cur_keys - ref_keys):
            new_ports.append({
                "ip": ip,
                "port": port_key,
                "service": cur_ports[port_key]
            })

        for port_key in sorted(ref_keys - cur_keys):
            closed_ports.append({
                "ip": ip,
                "port": port_key,
                "service": ref_ports[port_key]
            })

        for port_key in sorted(cur_keys & ref_keys):
            if cur_ports[port_key] != ref_ports[port_key]:
                changed_services.append({
                    "ip": ip,
                    "port": port_key,
                    "reference": ref_ports[port_key],
                    "current": cur_ports[port_key]
                })

    return {
        "new_hosts": new_hosts,
        "missing_hosts": missing_hosts,
        "unchanged_hosts": unchanged_hosts,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "changed_services": changed_services
    }


def main() -> None:
    paths = get_run_paths()
    network, _, _ = detect_runtime_network()
    slug = network_slug(network)

    json_files = list_json_by_prefix("services", network=network)
    if not json_files:
        raise FileNotFoundError(f"Nerasta services JSON failų tinklui {network}.")

    current_file = json_files[-1]
    current_data = load_json(current_file)

    baseline_file = BASELINE_DIR / f"baseline_services_{slug}.json"

    if not baseline_file.exists():
        shutil.copy(current_file, baseline_file)
        print(f"Sukurtas services baseline: {baseline_file}")
        print("Services palyginimas bus pilnai prasmingas nuo kito nuskaitymo.")
        return

    baseline_data = load_json(baseline_file)
    baseline_cmp = compare(baseline_data, current_data)

    previous_cmp = None
    if len(json_files) >= 2:
        previous_data = load_json(json_files[-2])
        previous_cmp = compare(previous_data, current_data)

    report = {
        "report_type": "services_compare",
        "network": network,
        "current_file": current_file.name,
        "baseline_file": baseline_file.name,
        "baseline_comparison": baseline_cmp,
        "previous_comparison": previous_cmp
    }

    report_file = paths["reports_dir"] / f"services_compare_{slug}_{current_data['timestamp']}.json"
    save_json(report_file, report)

    print("Palyginimas su services baseline:")
    print(f"Nauji hostai: {len(baseline_cmp['new_hosts'])}")
    print(f"Dingę hostai: {len(baseline_cmp['missing_hosts'])}")
    print(f"Nauji portai: {len(baseline_cmp['new_ports'])}")
    print(f"Uždaryti portai: {len(baseline_cmp['closed_ports'])}")
    print(f"Pasikeitusios paslaugos: {len(baseline_cmp['changed_services'])}")

    if previous_cmp:
        print()
        print("Palyginimas su ankstesniu services nuskaitymu:")
        print(f"Nauji hostai: {len(previous_cmp['new_hosts'])}")
        print(f"Dingę hostai: {len(previous_cmp['missing_hosts'])}")
        print(f"Nauji portai: {len(previous_cmp['new_ports'])}")
        print(f"Uždaryti portai: {len(previous_cmp['closed_ports'])}")
        print(f"Pasikeitusios paslaugos: {len(previous_cmp['changed_services'])}")

    print(f"\nServices palyginimo ataskaita: {report_file}")


if __name__ == "__main__":
    main()
