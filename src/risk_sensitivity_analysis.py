#!/usr/bin/env python3
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from common import BASE_DIR, get_run_paths, latest_file_in_dir, load_json, save_json, timestamp_now

MODEL_FILE = BASE_DIR / "config" / "risk_model.json"


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def normalize_weights(weights: dict[str, float]) -> dict[str, float]:
    total = sum(float(v) for v in weights.values()) or 1.0
    return {k: round(float(v) / total, 4) for k, v in weights.items()}


def recompute_score(components: dict, weights: dict) -> float:
    return round(max(0, min(100, sum(float(weights.get(k, 0)) * float(components.get(k, 0) or 0) for k in weights))), 2)


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    risk_file = latest_file_in_dir(paths["reports_dir"], "risk_scores_*.json")
    if not risk_file:
        raise FileNotFoundError("Nerastas risk_scores_*.json failas.")
    risk_data = load_json(risk_file)
    model = load_json(MODEL_FILE) if MODEL_FILE.exists() else {"weights": {"V": .35, "E": .2, "K": .15, "C": .15, "L": .1, "A": .05}}
    base_weights = {k: float(v) for k, v in (model.get("weights") or {}).items()}

    experiments = []
    variants = {
        "base": base_weights,
        "without_epss": {**base_weights, "E": 0},
        "without_kev": {**base_weights, "K": 0},
        "without_endpoint_logs": {**base_weights, "L": 0},
        "cvss_only": {"V": 1, "E": 0, "K": 0, "C": 0, "L": 0, "A": 0},
        "attack_surface_emphasis": {**base_weights, "A": base_weights.get("A", 0) + 0.15, "V": max(0, base_weights.get("V", 0) - 0.15)},
    }

    for name, raw_weights in variants.items():
        weights = normalize_weights(raw_weights)
        rows = []
        for host in as_list(risk_data.get("hosts")):
            comps = host.get("risk_components") or {}
            rows.append({
                "ip": host.get("ip"),
                "device_class": host.get("device_class"),
                "base_risk_score": host.get("risk_score"),
                "variant_risk_score": recompute_score(comps, weights),
            })
        rows = sorted(rows, key=lambda x: x["variant_risk_score"], reverse=True)
        experiments.append({"variant": name, "weights": weights, "top_hosts": rows[:20]})

    output = {"report_type": "risk_sensitivity_analysis", "timestamp": timestamp, "source_risk_scores_file": risk_file.name, "base_weights": base_weights, "experiments": experiments}
    out_file = paths["reports_dir"] / f"risk_sensitivity_analysis_{timestamp}.json"
    save_json(out_file, output)
    print(f"[GERAI] Rizikos modelio jautrumo analizė: {out_file}")


if __name__ == "__main__":
    main()
