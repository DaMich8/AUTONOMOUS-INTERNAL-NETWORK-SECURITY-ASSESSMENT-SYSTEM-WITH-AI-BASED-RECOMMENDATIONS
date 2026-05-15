#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import get_run_paths, latest_file_in_dir, save_json, timestamp_now


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def validate_required(data: dict, required: list[str]) -> list[str]:
    return [f"Trūksta privalomo lauko: {key}" for key in required if key not in data]


def validate_assessment(data: dict) -> list[str]:
    errors = validate_required(data, ["hosts"])
    for idx, host in enumerate(as_list(data.get("hosts"))):
        if not isinstance(host, dict):
            errors.append(f"hosts[{idx}] nėra objektas")
            continue
        if not host.get("ip"):
            errors.append(f"hosts[{idx}] neturi ip lauko")
        if not host.get("asset_id"):
            errors.append(f"hosts[{idx}] neturi asset_id lauko")
    return errors


def validate_risk_scores(data: dict) -> list[str]:
    errors = validate_required(data, ["hosts", "summary"])
    for idx, host in enumerate(as_list(data.get("hosts"))):
        score = host.get("risk_score") if isinstance(host, dict) else None
        try:
            s = float(score)
            if not (0 <= s <= 100):
                errors.append(f"hosts[{idx}].risk_score nėra 0–100 skalėje: {score}")
        except Exception:
            errors.append(f"hosts[{idx}].risk_score nėra skaičius")
    return errors


def validate_findings(data: dict) -> list[str]:
    errors = validate_required(data, ["findings"])
    required = {"schema_version", "finding_id", "rule_id", "source_module", "ip", "asset_id", "port", "protocol", "service", "severity", "confidence", "title", "evidence", "impact", "recommended_fix", "validation", "scan_status", "created_at"}
    for idx, finding in enumerate(as_list(data.get("findings"))):
        if not isinstance(finding, dict):
            errors.append(f"findings[{idx}] nėra objektas")
            continue
        missing = sorted(required - set(finding.keys()))
        if missing:
            errors.append(f"findings[{idx}] trūksta laukų: {', '.join(missing)}")
        if finding.get("severity") not in {"žema", "vidutinė", "aukšta", "kritinė"}:
            errors.append(f"findings[{idx}].severity neteisinga reikšmė: {finding.get('severity')}")
        if finding.get("confidence") not in {"žemas", "vidutinis", "aukštas"}:
            errors.append(f"findings[{idx}].confidence neteisinga reikšmė: {finding.get('confidence')}")
        if finding.get("scan_status") not in {"success", "partial", "failed", "skipped", "timeout", "host_down", "not_scanned"}:
            errors.append(f"findings[{idx}].scan_status neteisinga reikšmė: {finding.get('scan_status')}")
    return errors



def validate_ai_recommendations(data: dict) -> list[str]:
    errors = validate_required(data, ["recommendations", "model_used", "prompt_version", "input_hash", "output_hash"])
    required = {"recommendation_id", "finding_id", "host", "risk", "ai_recommendation", "evidence_used", "verification", "model_used", "prompt_version", "input_hash", "output_hash", "confidence"}
    for idx, rec in enumerate(as_list(data.get("recommendations"))):
        if not isinstance(rec, dict):
            errors.append(f"recommendations[{idx}] nėra objektas")
            continue
        missing = sorted(required - set(rec.keys()))
        if missing:
            errors.append(f"recommendations[{idx}] trūksta laukų: {', '.join(missing)}")
    return errors


def validate_endpoint_events(data: dict) -> list[str]:
    errors = []
    events = as_list(data.get("normalized_events") or data.get("events") or data.get("normalized_events_sample"))
    for idx, event in enumerate(events[:1000]):
        if not isinstance(event, dict):
            errors.append(f"events[{idx}] nėra objektas")
            continue
        if not event.get("source_type"):
            errors.append(f"events[{idx}] neturi source_type")
        if not event.get("dedupe_key"):
            errors.append(f"events[{idx}] neturi dedupe_key")
    return errors


def validate_generic(data: dict, kind: str) -> list[str]:
    if kind == "assessment":
        return validate_assessment(data)
    if kind == "risk_scores":
        return validate_risk_scores(data)
    if kind in {"normalized_findings", "correlated_findings"}:
        return validate_findings(data)
    if kind == "ai_recommendations":
        return validate_ai_recommendations(data)
    if kind == "endpoint_events":
        return validate_endpoint_events(data)
    return []


def infer_kind(path: Path, data: dict) -> str:
    rt = str(data.get("report_type") or data.get("scan_type") or "")
    name = path.name
    if name.startswith("assessment_"):
        return "assessment"
    if name.startswith("risk_scores_"):
        return "risk_scores"
    if name.startswith("normalized_findings_"):
        return "normalized_findings"
    if name.startswith("correlated_findings_"):
        return "correlated_findings"
    if name.startswith("ai_recommendations_"):
        return "ai_recommendations"
    if name.startswith("endpoint_events_"):
        return "endpoint_events"
    return rt or "unknown"


def validate_file(path: Path) -> dict:
    data = load_json(path)
    kind = infer_kind(path, data)
    errors = validate_generic(data, kind)
    return {"file": str(path), "kind": kind, "status": "ok" if not errors else "warning", "errors": errors}


def main() -> None:
    parser = argparse.ArgumentParser(description="JSON duomenų kokybės patikra.")
    parser.add_argument("--file", help="Tikrinamas JSON failas")
    parser.add_argument("--all-current", action="store_true", help="Patikrinti pagrindinius einamojo paleidimo JSON failus")
    args = parser.parse_args()

    paths = get_run_paths()
    timestamp = timestamp_now()
    files: list[Path] = []
    if args.file:
        files.append(Path(args.file))
    else:
        patterns = ["assessment_*.json", "risk_scores_*.json", "normalized_findings_*.json", "correlated_findings_*.json", "ai_recommendations_*.json", "remediation_status_*.json", "endpoint_events_*.json"]
        for pattern in patterns:
            file = latest_file_in_dir(paths["reports_dir"], pattern)
            if file:
                files.append(file)

    results = [validate_file(file) for file in files if file.exists()]
    output = {
        "report_type": "schema_validation",
        "timestamp": timestamp,
        "summary": {
            "checked_files": len(results),
            "warnings": sum(1 for r in results if r["status"] != "ok"),
            "status": "ok" if all(r["status"] == "ok" for r in results) else "ok_with_warnings",
        },
        "results": results,
    }
    out_file = paths["reports_dir"] / f"schema_validation_{timestamp}.json"
    save_json(out_file, output)
    print(f"[GERAI] Schemos patikros ataskaita: {out_file}")
    print(f"[INFO] Patikrinti failai: {len(results)}; pastabos: {output['summary']['warnings']}")


if __name__ == "__main__":
    main()
