from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from common import BASE_DIR, get_run_paths, load_json, save_json, timestamp_now

CONFIG_FILE = BASE_DIR / "config" / "retention_policy.json"


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def default_policy() -> dict:
    return {
        "dry_run": True,
        "rules": [
            {"name": "endpoint_event_raw", "path": "endpoint_event_log", "days": 14, "patterns": ["*.jsonl"]},
            {"name": "windows_security_raw", "path": "windows_security_log", "days": 14, "patterns": ["*.jsonl"]},
            {"name": "eset_csv_raw", "path": "eset_csv_log", "days": 14, "patterns": ["*.csv", "*.jsonl"]},
            {"name": "old_nmap_xml", "path": "runs", "days": 30, "patterns": ["**/*.xml"]},
            {"name": "old_txt_outputs", "path": "runs", "days": 30, "patterns": ["**/*.txt"]},
        ],
    }


def load_policy() -> dict:
    policy = default_policy()
    if CONFIG_FILE.exists():
        try:
            custom = load_json(CONFIG_FILE)
            policy.update(custom)
        except Exception:
            pass
    return policy


def iter_candidates(base: Path, patterns: list[str]) -> list[Path]:
    files = []
    for pattern in patterns:
        files.extend(base.glob(pattern))
    return sorted(set(f for f in files if f.is_file()))


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    policy = load_policy()
    dry_run = bool(policy.get("dry_run", True))
    now = time.time()
    actions = []

    for rule in as_list(policy.get("rules")):
        if not isinstance(rule, dict):
            continue
        name = rule.get("name", "unnamed")
        rel_path = rule.get("path")
        days = int(rule.get("days", 30))
        patterns = as_list(rule.get("patterns")) or ["*"]
        if not rel_path:
            continue
        base = BASE_DIR / rel_path
        if not base.exists():
            continue
        cutoff = now - days * 86400
        for file in iter_candidates(base, patterns):
            try:
                mtime = file.stat().st_mtime
                if mtime >= cutoff:
                    continue
                item = {
                    "rule": name,
                    "path": str(file),
                    "age_days": round((now - mtime) / 86400, 2),
                    "size_bytes": file.stat().st_size,
                    "action": "would_delete" if dry_run else "deleted",
                }
                if not dry_run:
                    try:
                        file.unlink()
                    except Exception as exc:
                        item["action"] = "delete_failed"
                        item["error"] = str(exc)
                actions.append(item)
            except Exception as exc:
                actions.append({"rule": name, "path": str(file), "action": "inspect_failed", "error": str(exc)})

    report = {
        "report_type": "retention_cleanup",
        "timestamp": timestamp,
        "dry_run": dry_run,
        "policy_file": str(CONFIG_FILE) if CONFIG_FILE.exists() else None,
        "actions_count": len(actions),
        "actions": actions[:500],
        "note": "Pagal nutylėjimą dry_run=true. Norint realiai trinti, config/retention_policy.json pakeisti dry_run į false.",
    }

    out_file = paths["reports_dir"] / f"retention_cleanup_{timestamp}.json"
    save_json(out_file, report)
    print(f"Retention cleanup ataskaita: {out_file}")
    print(f"Dry run: {dry_run}; veiksmų: {len(actions)}")


if __name__ == "__main__":
    main()
