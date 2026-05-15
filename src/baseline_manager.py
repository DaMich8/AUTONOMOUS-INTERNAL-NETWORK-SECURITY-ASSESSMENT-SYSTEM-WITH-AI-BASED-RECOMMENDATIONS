#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from common import BASELINE_DIR, detect_runtime_network, latest_json_by_prefix, network_slug, save_json, timestamp_now


def main() -> None:
    parser = argparse.ArgumentParser(description="Pradinio palyginimo taško valdymas.")
    parser.add_argument("--approve-current", action="store_true", help="Patvirtinti naujausius discovery/services failus kaip pradinį palyginimo tašką")
    parser.add_argument("--reason", default="Nenurodyta", help="Patvirtinimo priežastis")
    args = parser.parse_args()

    network, interface, source_ip = detect_runtime_network()
    slug = network_slug(network)
    timestamp = timestamp_now()
    manifest = BASELINE_DIR / f"baseline_manifest_{slug}.json"

    if not args.approve_current:
        print("[INFO] Nurodyk --approve-current, jei nori patvirtinti naujausią būseną kaip baseline.")
        return

    discovery = latest_json_by_prefix("discovery", network=network)
    services = latest_json_by_prefix("services", network=network)
    if not discovery or not services:
        raise FileNotFoundError("Nerasti naujausi discovery arba services JSON failai.")

    target_discovery = BASELINE_DIR / f"baseline_discovery_{slug}.json"
    target_services = BASELINE_DIR / f"baseline_services_{slug}.json"
    shutil.copy(discovery, target_discovery)
    shutil.copy(services, target_services)

    payload = {
        "status": "approved",
        "approved_at": timestamp,
        "reason": args.reason,
        "network": network,
        "interface": interface,
        "source_ip": source_ip,
        "discovery_baseline": target_discovery.name,
        "services_baseline": target_services.name,
        "source_discovery": discovery.name,
        "source_services": services.name,
    }
    save_json(manifest, payload)
    print(f"[GERAI] Pradinis palyginimo taškas patvirtintas: {manifest}")


if __name__ == "__main__":
    main()
