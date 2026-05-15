#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from common import BASE_DIR, get_run_paths, latest_file_in_dir, load_json, save_json, timestamp_now

CONFIG_FILE = BASE_DIR / "config" / "validation_scenarios.json"
LOCAL_CONFIG_FILE = Path(__file__).with_name("validation_scenarios.json")


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def safe_div(a: float, b: float) -> float:
    return round(a / b, 4) if b else 0.0


def load_config() -> dict:
    for candidate in (CONFIG_FILE, LOCAL_CONFIG_FILE):
        if candidate.exists():
            return json.loads(candidate.read_text(encoding="utf-8"))
    return {"scenarios": []}


def detected_rule_ids(correlated: dict | None, normalized: dict | None) -> set[str]:
    ids = set()
    for source in (correlated, normalized):
        for item in as_list((source or {}).get("findings")):
            if isinstance(item, dict):
                if item.get("rule_id"):
                    ids.add(str(item["rule_id"]))
                if item.get("finding_id"):
                    ids.add(str(item["finding_id"]))
    return ids


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    scenarios = [s for s in as_list(load_config().get("scenarios")) if isinstance(s, dict) and s.get("enabled")]
    corr_file = latest_file_in_dir(paths["reports_dir"], "correlated_findings_*.json")
    norm_file = latest_file_in_dir(paths["reports_dir"], "normalized_findings_*.json")
    correlated = load_json(corr_file) if corr_file else None
    normalized = load_json(norm_file) if norm_file else None
    detected = detected_rule_ids(correlated, normalized)

    results = []
    total_tp = total_fp = total_fn = 0
    for scenario in scenarios:
        expected = set(str(x) for x in as_list(scenario.get("expected_findings")))
        expected_absent = set(str(x) for x in as_list(scenario.get("expected_absent_findings") or scenario.get("unexpected_findings")))
        expected_detected = sorted(expected & detected)
        missed = sorted(expected - detected)
        false_positives = sorted(expected_absent & detected)

        # Optional strict mode: all detections outside the expected set count as FP.
        # Default remains scenario-scoped to avoid marking unrelated real findings as FP.
        if scenario.get("strict_findings_scope"):
            allowed = expected | expected_absent | set(str(x) for x in as_list(scenario.get("allowed_findings")))
            false_positives = sorted((detected - allowed) | set(false_positives))

        tp = len(expected_detected)
        fn = len(missed)
        fp = len(false_positives)
        total_tp += tp; total_fn += fn; total_fp += fp
        results.append({
            "scenario": scenario.get("id") or scenario.get("name"),
            "description": scenario.get("description"),
            "expected_findings": sorted(expected),
            "expected_absent_findings": sorted(expected_absent),
            "detected_expected_findings": expected_detected,
            "missed_expected_findings": missed,
            "false_positive_findings": false_positives,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "status": "pass" if fn == 0 and fp == 0 else "fail",
        })

    precision = safe_div(total_tp, total_tp + total_fp)
    recall = safe_div(total_tp, total_tp + total_fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    output = {
        "report_type": "validation_metrics",
        "timestamp": timestamp,
        "source_files": {"correlated_findings": corr_file.name if corr_file else None, "normalized_findings": norm_file.name if norm_file else None},
        "summary": {"enabled_scenarios": len(scenarios), "tp": total_tp, "fp": total_fp, "fn": total_fn, "precision": precision, "recall": recall, "f1": f1},
        "scenario_results": results,
    }
    out_file = paths["reports_dir"] / f"validation_metrics_{timestamp}.json"
    save_json(out_file, output)
    print(f"[GERAI] Validacijos metrikų ataskaita: {out_file}")
    print(f"[INFO] Precision={precision}, Recall={recall}, F1={f1}")


if __name__ == "__main__":
    main()
