#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from common import RUNS_DIR, get_run_paths, latest_file_in_dir, load_json, save_json, timestamp_now


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def latest_current(paths: dict, pattern: str) -> Path | None:
    return latest_file_in_dir(paths["reports_dir"], pattern)


def previous_file(current: Path | None, pattern: str) -> Path | None:
    files = sorted(RUNS_DIR.glob(pattern))
    if current:
        files = [f for f in files if f.resolve() != current.resolve()]
    return files[-1] if files else None


def load_optional(path: Path | None) -> dict | None:
    if path and path.exists():
        try:
            return load_json(path)
        except Exception:
            return None
    return None


def finding_key(item: dict) -> str:
    for key in ("finding_id", "recommendation_id"):
        if item.get(key):
            return str(item[key])
    asset = item.get("asset_id") or item.get("ip") or item.get("host") or "global"
    rule = item.get("rule_id") or item.get("finding") or item.get("title") or "unknown"
    port = item.get("port") or ""
    return f"{rule}_{asset}_{port}".replace(" ", "_")


def identity_key(item: dict) -> str | None:
    return item.get("asset_id") or item.get("ip")


def score_map(risk_data: dict | None) -> dict[str, dict]:
    result = {}
    items = as_list((risk_data or {}).get("hosts") or (risk_data or {}).get("host_scores"))
    for item in items:
        if not isinstance(item, dict):
            continue
        key = identity_key(item)
        if key:
            result[key] = item
        if item.get("ip"):
            result.setdefault(item.get("ip"), item)
    return result


def current_host_scan_status(assessment: dict | None) -> dict[str, str]:
    statuses = {}
    for host in as_list((assessment or {}).get("hosts")):
        if not isinstance(host, dict):
            continue
        status = host.get("scan_status") or host.get("service_scan_status")
        if not status:
            state = str(host.get("state") or "up").lower()
            status = "host_down" if state in {"down", "unknown_down"} else "success"
        for key in {host.get("asset_id"), host.get("ip")}:
            if key:
                statuses[str(key)] = str(status)
    return statuses


def not_observed_status(prev: dict, current_statuses: dict[str, str], current_report: dict | None) -> str:
    report_status = str((current_report or {}).get("scan_status") or "success")
    key = identity_key(prev)
    host_status = current_statuses.get(str(key)) if key else None
    ip_status = current_statuses.get(str(prev.get("ip"))) if prev.get("ip") else None
    effective = host_status or ip_status
    if report_status in {"failed", "partial", "timeout"}:
        return "not_observed_scan_failed"
    if effective in {"failed", "partial", "timeout"}:
        return "not_observed_scan_failed"
    if effective in {"host_down", "down", "not_scanned"} or effective is None:
        return "not_observed_host_down"
    if effective == "success":
        return "fixed_verified"
    return "fixed_unverified"


def compare_findings(current: dict | None, previous: dict | None, assessment: dict | None) -> list[dict]:
    cur_items = {finding_key(f): f for f in as_list((current or {}).get("findings")) if isinstance(f, dict)}
    prev_items = {finding_key(f): f for f in as_list((previous or {}).get("findings")) if isinstance(f, dict)}
    all_keys = sorted(set(cur_items) | set(prev_items))
    current_statuses = current_host_scan_status(assessment)
    output = []

    for key in all_keys:
        cur = cur_items.get(key)
        prev = prev_items.get(key)
        if cur and not prev:
            status = "open_new"
        elif cur and prev:
            cur_inc = cur.get("risk_increase", 0) or 0
            prev_inc = prev.get("risk_increase", 0) or 0
            if cur_inc < prev_inc:
                status = "partially_fixed"
            elif cur_inc > prev_inc:
                status = "worsened"
            else:
                status = "still_open"
        elif prev and not cur:
            status = not_observed_status(prev, current_statuses, current)
        else:
            status = "unknown"

        output.append({
            "finding_key": key,
            "status": status,
            "asset_id": (cur or prev or {}).get("asset_id"),
            "ip": (cur or prev or {}).get("ip") or (cur or prev or {}).get("host"),
            "title": (cur or prev or {}).get("title") or (cur or prev or {}).get("finding"),
            "previous_severity": (prev or {}).get("severity") or (prev or {}).get("risk"),
            "current_severity": (cur or {}).get("severity") or (cur or {}).get("risk"),
            "previous_risk_increase": (prev or {}).get("risk_increase"),
            "current_risk_increase": (cur or {}).get("risk_increase"),
            "previous_scan_status": (prev or {}).get("scan_status"),
            "current_scan_status": (cur or {}).get("scan_status"),
            "evidence_before": as_list((prev or {}).get("evidence"))[:5],
            "evidence_after": as_list((cur or {}).get("evidence"))[:5],
        })
    return output


def compare_scores(current: dict | None, previous: dict | None) -> list[dict]:
    cur = score_map(current)
    prev = score_map(previous)
    all_keys = sorted(set(cur) | set(prev))
    output = []
    for key in all_keys:
        cur_item = cur.get(key)
        prev_item = prev.get(key)
        cur_score = float((cur_item or {}).get("risk_score", 0) or 0)
        prev_score = float((prev_item or {}).get("risk_score", 0) or 0)
        delta = round(cur_score - prev_score, 2)
        if cur_item and not prev_item:
            status = "new_asset_or_score"
        elif prev_item and not cur_item:
            status = "missing_asset_or_score"
        elif delta <= -10:
            status = "risk_reduced"
        elif delta >= 10:
            status = "risk_increased"
        else:
            status = "risk_stable"
        output.append({
            "asset_or_ip": key,
            "asset_id": (cur_item or prev_item or {}).get("asset_id"),
            "ip": (cur_item or prev_item or {}).get("ip"),
            "status": status,
            "previous_risk_score": prev_score if prev_item else None,
            "current_risk_score": cur_score if cur_item else None,
            "risk_delta": delta if cur_item and prev_item else None,
            "previous_risk_level": (prev_item or {}).get("risk_level"),
            "current_risk_level": (cur_item or {}).get("risk_level"),
        })
    return output


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()

    cur_corr_file = latest_current(paths, "correlated_findings_*.json")
    cur_risk_file = latest_current(paths, "risk_scores_*.json")
    cur_assessment_file = latest_current(paths, "assessment_*.json")
    prev_corr_file = previous_file(cur_corr_file, "**/reports/correlated_findings_*.json")
    prev_risk_file = previous_file(cur_risk_file, "**/reports/risk_scores_*.json")

    cur_corr = load_optional(cur_corr_file)
    prev_corr = load_optional(prev_corr_file)
    cur_risk = load_optional(cur_risk_file)
    prev_risk = load_optional(prev_risk_file)
    cur_assessment = load_optional(cur_assessment_file)

    finding_status = compare_findings(cur_corr, prev_corr, cur_assessment)
    score_status = compare_scores(cur_risk, prev_risk)

    status_counts = Counter(i["status"] for i in finding_status)
    summary = {
        "finding_status_counts": dict(status_counts),
        "risk_status_counts": dict(Counter(i["status"] for i in score_status)),
        "fixed_verified_count": status_counts.get("fixed_verified", 0),
        "fixed_unverified_count": status_counts.get("fixed_unverified", 0),
        "not_observed_count": status_counts.get("not_observed_scan_failed", 0) + status_counts.get("not_observed_host_down", 0),
        "worsened_count": status_counts.get("worsened", 0) + sum(1 for i in score_status if i["status"] == "risk_increased"),
        "risk_reduced_count": sum(1 for i in score_status if i["status"] == "risk_reduced"),
    }

    output = {
        "report_type": "remediation_tracker",
        "timestamp": timestamp,
        "current_correlated_findings_file": cur_corr_file.name if cur_corr_file else None,
        "previous_correlated_findings_file": prev_corr_file.name if prev_corr_file else None,
        "current_risk_scores_file": cur_risk_file.name if cur_risk_file else None,
        "previous_risk_scores_file": prev_risk_file.name if prev_risk_file else None,
        "current_assessment_file": cur_assessment_file.name if cur_assessment_file else None,
        "summary": summary,
        "finding_status": finding_status,
        "risk_score_status": score_status,
        "status_meaning": {
            "fixed_verified": "radinys išnyko ir dabartinis hosto skenavimas buvo sėkmingas",
            "fixed_unverified": "radinys išnyko, bet nepakanka duomenų patvirtinti pataisymą",
            "not_observed_scan_failed": "radinys nebeaptiktas, tačiau dabartinis skenavimas buvo nepilnas arba nepavyko",
            "not_observed_host_down": "radinys nebeaptiktas, nes hostas nebuvo stebėtas arba buvo nepasiekiamas",
            "still_open": "radinys išliko",
            "open_new": "naujas radinys",
            "worsened": "radinio rizikos įtaka padidėjo",
            "partially_fixed": "radinys dar yra, bet rizikos įtaka sumažėjo",
            "risk_reduced": "hosto rizikos balas sumažėjo bent 10 punktų",
            "risk_increased": "hosto rizikos balas padidėjo bent 10 punktų",
        },
    }

    out_file = paths["reports_dir"] / f"remediation_status_{timestamp}.json"
    save_json(out_file, output)

    ai_files = sorted(paths["ai_dir"].glob("ai_recommendation_payload_*.json"))
    if ai_files:
        try:
            ai_file = ai_files[-1]
            ai = load_json(ai_file)
            ai["remediation_tracking"] = {
                "source_file": out_file.name,
                "summary": summary,
                "fixed_verified_findings": [i for i in finding_status if i["status"] == "fixed_verified"][:20],
                "not_observed_items": [i for i in finding_status if i["status"].startswith("not_observed")] [:20],
                "worsened_items": [i for i in finding_status if i["status"] == "worsened"][:20] + [i for i in score_status if i["status"] == "risk_increased"][:20],
                "risk_reduced_hosts": [i for i in score_status if i["status"] == "risk_reduced"][:20],
            }
            save_json(ai_file, ai)
        except Exception:
            pass

    print(f"Remediation status: {out_file}")
    print(summary)


if __name__ == "__main__":
    main()
