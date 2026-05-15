#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from common import get_run_paths, save_json, timestamp_now


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def load_pipeline_log(paths: dict) -> list[dict]:
    candidates = sorted(paths["logs_dir"].glob("pipeline_step_*.json"))
    steps = []
    for file in candidates:
        try:
            steps.append(json.loads(file.read_text(encoding="utf-8")))
        except Exception:
            continue
    return steps


def infer_outputs(paths: dict) -> dict[str, list[str]]:
    sections = ["discovery_dir", "services_dir", "reports_dir", "ai_dir", "logs_dir", "power_dir"]
    return {section: sorted(p.name for p in paths[section].glob("*")) for section in sections if section in paths}


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    steps = load_pipeline_log(paths)
    successful = sum(1 for s in steps if s.get("status") == "success" or s.get("returncode") == 0)
    total = len(steps)
    health = round((successful / total) * 100, 2) if total else None
    output = {
        "report_type": "pipeline_audit",
        "timestamp": timestamp,
        "run_id": paths["run_id"],
        "summary": {
            "total_steps": total,
            "successful_steps": successful,
            "failed_or_partial_steps": total - successful,
            "pipeline_health_percent": health,
        },
        "steps": steps,
        "outputs_by_section": infer_outputs(paths),
    }
    out_file = paths["reports_dir"] / f"pipeline_audit_{timestamp}.json"
    save_json(out_file, output)
    print(f"[GERAI] Pipeline audito ataskaita: {out_file}")
    if health is not None:
        print(f"[INFO] Pipeline būklė: {health} %")


if __name__ == "__main__":
    main()
