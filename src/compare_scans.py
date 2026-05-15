import shutil

from common import BASELINE_DIR, detect_runtime_network, get_run_paths, list_json_by_prefix, load_json, network_slug, save_json


def get_ip_set(scan_data: dict) -> set[str]:
    return {host["ip"] for host in scan_data.get("hosts", []) if host.get("ip")}


def compare(reference: dict, current: dict) -> dict:
    ref_ips = get_ip_set(reference)
    cur_ips = get_ip_set(current)

    return {
        "reference_hosts": len(ref_ips),
        "current_hosts": len(cur_ips),
        "new_hosts": sorted(cur_ips - ref_ips),
        "missing_hosts": sorted(ref_ips - cur_ips),
        "unchanged_hosts": sorted(cur_ips & ref_ips)
    }


def main() -> None:
    paths = get_run_paths()
    network, _, _ = detect_runtime_network()
    slug = network_slug(network)

    json_files = list_json_by_prefix("discovery", network=network)
    if not json_files:
        raise FileNotFoundError(f"Nerasta discovery JSON failų tinklui {network}.")

    current_file = json_files[-1]
    current_data = load_json(current_file)

    baseline_file = BASELINE_DIR / f"baseline_discovery_{slug}.json"

    if not baseline_file.exists():
        shutil.copy(current_file, baseline_file)
        print(f"Sukurtas discovery baseline: {baseline_file}")
        print("Discovery palyginimas bus pilnai prasmingas nuo kito nuskaitymo.")
        return

    baseline_data = load_json(baseline_file)
    baseline_cmp = compare(baseline_data, current_data)

    previous_cmp = None
    if len(json_files) >= 2:
        previous_data = load_json(json_files[-2])
        previous_cmp = compare(previous_data, current_data)

    report = {
        "report_type": "discovery_compare",
        "network": network,
        "current_file": current_file.name,
        "baseline_file": baseline_file.name,
        "baseline_comparison": baseline_cmp,
        "previous_comparison": previous_cmp
    }

    report_file = paths["reports_dir"] / f"discovery_compare_{slug}_{current_data['timestamp']}.json"
    save_json(report_file, report)

    print("Palyginimas su discovery baseline:")
    print(f"Nauji hostai: {len(baseline_cmp['new_hosts'])}")
    for ip in baseline_cmp["new_hosts"]:
        print(f"  + {ip}")

    print(f"Dingę hostai: {len(baseline_cmp['missing_hosts'])}")
    for ip in baseline_cmp["missing_hosts"]:
        print(f"  - {ip}")

    print(f"Nepasikeitę hostai: {len(baseline_cmp['unchanged_hosts'])}")

    if previous_cmp:
        print()
        print("Palyginimas su ankstesniu discovery nuskaitymu:")
        print(f"Nauji hostai: {len(previous_cmp['new_hosts'])}")
        for ip in previous_cmp["new_hosts"]:
            print(f"  + {ip}")

        print(f"Dingę hostai: {len(previous_cmp['missing_hosts'])}")
        for ip in previous_cmp["missing_hosts"]:
            print(f"  - {ip}")

        print(f"Nepasikeitę hostai: {len(previous_cmp['unchanged_hosts'])}")

    print(f"\nDiscovery palyginimo ataskaita: {report_file}")


if __name__ == "__main__":
    main()
