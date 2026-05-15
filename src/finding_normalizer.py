#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Any

from asset_identity import enrich_host_asset_id
from common import get_run_paths, latest_file_in_dir, load_json, save_json, timestamp_now
from finding_schema import normalize_finding, validate_finding


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def infer_scan_status(item: dict) -> str:
    if item.get("scan_status"):
        return str(item.get("scan_status"))
    if item.get("status") in {"skipped", "failed", "partial", "timeout", "host_down"}:
        return str(item.get("status"))
    try:
        return "success" if int(item.get("returncode", 0) or 0) == 0 else "partial"
    except Exception:
        return "success"


def iter_result_items(data: dict) -> list[dict]:
    items: list[dict] = []
    for key in ("results", "hosts", "targets"):
        items.extend([x for x in as_list(data.get(key)) if isinstance(x, dict)])
    return items


def normalize_module_results(data: dict | None, source_module: str) -> list[dict]:
    if not data:
        return []
    findings: list[dict] = []

    # Preserve module-level findings too. This is important for failed/skipped
    # module statuses where no per-host result exists.
    for raw in as_list(data.get("findings")):
        if isinstance(raw, dict):
            findings.append(normalize_finding(raw, source_module=source_module, scan_status=infer_scan_status(raw)))

    for host_item in iter_result_items(data):
        ip = host_item.get("ip")
        asset_id = host_item.get("asset_id")
        scan_status = infer_scan_status(host_item)
        for raw in as_list(host_item.get("findings")):
            findings.append(normalize_finding(raw, source_module=source_module, ip=ip, asset_id=asset_id, scan_status=scan_status))
        # Kai kurie moduliai turi top-level portą arba vieną radinį pačiame host objekte.
        if not host_item.get("findings") and host_item.get("finding_id"):
            findings.append(normalize_finding(host_item, source_module=source_module, ip=ip, asset_id=asset_id, scan_status=scan_status))
    # Stable de-duplication by finding_id while preserving first occurrence.
    deduped: list[dict] = []
    seen = set()
    for item in findings:
        key = item.get("finding_id")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    reports_dir = paths["reports_dir"]
    services_dir = paths["services_dir"]

    assessment_file = latest_file_in_dir(reports_dir, "assessment_*.json")
    assessment = load_json(assessment_file) if assessment_file else None
    if assessment:
        for host in as_list(assessment.get("hosts")):
            enrich_host_asset_id(host)

    module_patterns = {
        "ssh_policy_audit.py": "ssh_policy_*.json",
        "tls_audit.py": "tls_audit_*.json",
        "rdp_policy_audit.py": "rdp_policy_*.json",
        "rpc_nfs_audit.py": "rpc_nfs_*.json",
        "dns_router_audit.py": "dns_router_*.json",
        "web_fingerprint.py": "web_fingerprint_*.json",
        "vuln_enrichment.py": "vuln_*.json",
        "smb_enrichment.py": "smb_enrichment_*.json",
        "snmp_enrichment.py": "snmp_enrichment_*.json",
    }

    all_findings = []
    source_files = {}
    for module, pattern in module_patterns.items():
        file = latest_file_in_dir(services_dir, pattern)
        if not file:
            continue
        source_files[module] = file.name
        try:
            data = load_json(file)
            all_findings.extend(normalize_module_results(data, module))
        except Exception as exc:
            all_findings.append(normalize_finding({
                "finding_id": f"NORMALIZER_ERROR_{module}",
                "rule_id": "normalizer_error",
                "severity": "vidutinė",
                "confidence": "aukštas",
                "title": f"Nepavyko normalizuoti modulio {module} radinių",
                "evidence": [str(exc)],
                "impact": "Dalis modulio radinių gali būti neįtraukta į suvienodintą radinių rinkinį.",
                "recommended_fix": "Patikrinti nurodyto modulio JSON failą ir pakartoti normalizavimą.",
                "validation": "Pakartoti finding_normalizer.py.",
                "scan_status": "partial",
            }, source_module="finding_normalizer.py", scan_status="partial"))

    validation_errors = []
    for item in all_findings:
        errs = validate_finding(item)
        if errs:
            validation_errors.append({"finding_id": item.get("finding_id"), "errors": errs})

    output = {
        "report_type": "normalized_findings",
        "timestamp": timestamp,
        "assessment_file": assessment_file.name if assessment_file else None,
        "source_files": source_files,
        "summary": {
            "normalized_findings_count": len(all_findings),
            "validation_errors_count": len(validation_errors),
        },
        "findings": all_findings,
        "validation_errors": validation_errors,
    }
    out_file = reports_dir / f"normalized_findings_{timestamp}.json"
    save_json(out_file, output)

    if assessment:
        assessment["normalized_findings_file"] = out_file.name
        save_json(assessment_file, assessment)

    print(f"[GERAI] Suvienodintų radinių failas sukurtas: {out_file}")
    print(f"[INFO] Suvienodintų radinių skaičius: {len(all_findings)}")
    if validation_errors:
        print(f"[ĮSPĖJIMAS] Radinių schemos pastabos: {len(validation_errors)}")


if __name__ == "__main__":
    main()
