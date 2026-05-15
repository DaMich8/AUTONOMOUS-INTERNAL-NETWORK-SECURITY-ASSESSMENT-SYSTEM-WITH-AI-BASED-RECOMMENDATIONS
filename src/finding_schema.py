#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

SEVERITY_LEVELS = {"informacinė", "žema", "vidutinė", "aukšta", "kritinė"}
CONFIDENCE_LEVELS = {"žemas", "vidutinis", "aukštas"}
SCAN_STATUS_VALUES = {"success", "partial", "failed", "skipped", "timeout", "host_down", "not_scanned", "unknown"}
REMEDIATION_STATUSES = {
    "open", "in_progress", "still_open", "fixed_verified", "fixed_unverified", "partially_fixed",
    "worsened", "not_observed_host_down", "not_observed_scan_failed",
}
VERIFICATION_STATUSES = {"not_checked", "passed", "failed", "partial", "not_applicable"}
FINDING_SCHEMA_VERSION = "2.1-master-ready"

REQUIRED_FINDING_FIELDS = {
    "schema_version", "finding_id", "rule_id", "source_module", "ip", "asset_id", "port", "protocol",
    "service", "severity", "confidence", "confidence_reason", "finding_status", "incident_confirmed",
    "finding_type", "cve_based", "title", "evidence", "impact", "recommended_fix", "recommended_actions",
    "validation", "verification_steps", "expected_after_fix_state", "mitre_attack", "cis_controls",
    "false_positive_conditions", "scan_status", "remediation_status", "verification_status", "risk_score",
    "risk_level", "risk_components", "created_at",
}


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def stable_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def slug(value: Any) -> str:
    text = str(value or "unknown").strip().upper()
    text = re.sub(r"[^0-9A-Z]+", "_", text)
    return text.strip("_") or "UNKNOWN"


def normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    mapping = {
        "info": "informacinė", "informational": "informacinė", "informacinis": "informacinė",
        "low": "žema", "medium": "vidutinė", "warning": "vidutinė", "warn": "vidutinė",
        "high": "aukšta", "critical": "kritinė", "severe": "aukšta",
    }
    text = mapping.get(text, text)
    return text if text in SEVERITY_LEVELS else "vidutinė"


def normalize_confidence(value: Any) -> str:
    text = str(value or "").strip().lower()
    mapping = {"low": "žemas", "medium": "vidutinis", "high": "aukštas"}
    text = mapping.get(text, text)
    return text if text in CONFIDENCE_LEVELS else "vidutinis"


def normalize_scan_status(value: Any) -> str:
    text = str(value or "success").strip().lower()
    mapping = {"ok": "success", "error": "failed", "up": "success", "down": "host_down"}
    text = mapping.get(text, text)
    return text if text in SCAN_STATUS_VALUES else "unknown"


def normalize_remediation_status(value: Any) -> str:
    text = str(value or "open").strip().lower()
    return text if text in REMEDIATION_STATUSES else "open"


def normalize_verification_status(value: Any) -> str:
    text = str(value or "not_checked").strip().lower()
    return text if text in VERIFICATION_STATUSES else "not_checked"


def build_asset_id(ip: str | None = None, mac: str | None = None, hostname: str | None = None, vendor: str | None = None) -> str:
    try:
        from asset_identity import build_asset_id as _build_asset_id
        return _build_asset_id(ip=ip, mac=mac, hostname=hostname, vendor=vendor)
    except Exception:
        basis = "|".join([(mac or "").lower(), (hostname or "").lower(), (vendor or "").lower(), ip or ""])
        return stable_hash({"asset": basis})


def default_finding_status(rule_id: str | None, *, cve_based: bool = False) -> tuple[str, bool]:
    rule = str(rule_id or "").lower()
    if cve_based:
        return "potential_vulnerability", False
    if any(x in rule for x in ("eset", "endpoint", "powershell", "audit_log", "logon", "account_change", "windows_event")):
        return "requires_human_review", False
    return "confirmed_configuration_issue", True


def default_confidence_reason(confidence: str, source_module: str, finding_status: str) -> str:
    if finding_status == "requires_human_review":
        return "Radinys paremtas įvykiais arba indikaciniais žurnalų įrašais, todėl prieš laikant incidentu būtina žmogaus peržiūra."
    if confidence == "aukštas":
        return f"Radinys patvirtintas modulio {source_module} techniniais rezultatais."
    if confidence == "žemas":
        return "Radinys pagrįstas ribotais arba netiesioginiais įrodymais."
    return "Radinys pagrįstas techniniais įrodymais, tačiau galimos aplinkos ar administracinės išimtys."


def infer_finding_type(raw: dict, rule_id: str | None) -> tuple[str, bool]:
    if raw.get("cve_based") is not None:
        return ("vulnerability" if bool(raw.get("cve_based")) else raw.get("finding_type") or "configuration", bool(raw.get("cve_based")))
    if raw.get("cve") or raw.get("cves") or str(rule_id or "").lower().startswith("cve"):
        return "vulnerability", True
    return raw.get("finding_type") or "configuration", False


def normalize_finding(
    raw: dict,
    *,
    source_module: str,
    ip: str | None = None,
    asset_id: str | None = None,
    port: int | str | None = None,
    protocol: str | None = None,
    service: str | None = None,
    scan_status: str = "success",
) -> dict:
    if not isinstance(raw, dict):
        raw = {"title": str(raw)}

    ip_value = clean_text(raw.get("ip") or raw.get("host") or ip)
    port_value = raw.get("port", port)
    try:
        port_value = int(port_value) if port_value not in (None, "") else None
    except Exception:
        port_value = None

    rule_id = clean_text(raw.get("rule_id") or raw.get("type") or raw.get("finding") or raw.get("title") or raw.get("finding_id") or "generic_finding")
    rule_slug = slug(rule_id)
    finding_id = clean_text(raw.get("finding_id")) or "_".join(x for x in [rule_slug, str(ip_value or "GLOBAL").replace('.', '_'), str(port_value or '')] if x)

    finding_type, cve_based = infer_finding_type(raw, rule_id)
    status_default, incident_default = default_finding_status(rule_id, cve_based=cve_based)
    finding_status = clean_text(raw.get("finding_status")) or status_default
    incident_confirmed = bool(raw.get("incident_confirmed")) if raw.get("incident_confirmed") is not None else incident_default
    confidence = normalize_confidence(raw.get("confidence"))

    evidence = [str(x) for x in as_list(raw.get("evidence") or raw.get("details") or raw.get("reasoning")) if x not in (None, "")]
    recommended_actions = [str(x) for x in as_list(raw.get("recommended_actions") or raw.get("actions")) if x not in (None, "")]
    recommended_fix = clean_text(raw.get("recommended_fix") or raw.get("recommendation") or raw.get("fix"))
    if not recommended_actions and recommended_fix:
        recommended_actions = [recommended_fix]
    if not recommended_fix and recommended_actions:
        recommended_fix = recommended_actions[0]

    verification_steps = [str(x) for x in as_list(raw.get("verification_steps") or raw.get("verification") or raw.get("validation")) if x not in (None, "")]
    validation = clean_text(raw.get("validation") or raw.get("verification"))
    if not validation and verification_steps:
        validation = verification_steps[0]

    expected = [str(x) for x in as_list(raw.get("expected_after_fix_state")) if x not in (None, "")]

    normalized = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "finding_id": finding_id,
        "rule_id": rule_id,
        "source_module": clean_text(raw.get("source_module") or source_module) or source_module,
        "ip": ip_value,
        "asset_id": clean_text(raw.get("asset_id") or asset_id) or (build_asset_id(ip=ip_value) if ip_value else "unknown"),
        "port": port_value,
        "protocol": clean_text(raw.get("protocol") or protocol),
        "service": clean_text(raw.get("service") or raw.get("service_name") or service),
        "severity": normalize_severity(raw.get("severity") or raw.get("risk") or raw.get("risk_level")),
        "confidence": confidence,
        "confidence_reason": clean_text(raw.get("confidence_reason")) or default_confidence_reason(confidence, source_module, finding_status),
        "finding_status": finding_status,
        "incident_confirmed": incident_confirmed,
        "finding_type": finding_type,
        "cve_based": cve_based,
        "title": clean_text(raw.get("title") or raw.get("finding") or "Saugumo radinys"),
        "evidence": evidence,
        "impact": clean_text(raw.get("impact") or raw.get("details") or "Radinys gali didinti įrenginio atakos paviršių arba apsunkinti saugumo kontrolę."),
        "recommended_fix": recommended_fix or "Peržiūrėti radinio įrodymus ir suplanuoti tinkamus pataisymo veiksmus.",
        "recommended_actions": recommended_actions or ["Peržiūrėti radinio įrodymus ir suplanuoti tinkamus pataisymo veiksmus."],
        "validation": validation or "Pakartoti vertinimą ir patikrinti, ar radinys nebeaptinkamas.",
        "verification_steps": verification_steps or ["Pakartoti vertinimą ir patikrinti, ar radinys nebeaptinkamas."],
        "expected_after_fix_state": expected,
        "mitre_attack": [str(x) for x in as_list(raw.get("mitre_attack")) if x not in (None, "")],
        "cis_controls": [str(x) for x in as_list(raw.get("cis_controls")) if x not in (None, "")],
        "false_positive_conditions": [str(x) for x in as_list(raw.get("false_positive_conditions")) if x not in (None, "")],
        "scan_status": normalize_scan_status(raw.get("scan_status") or scan_status),
        "remediation_status": normalize_remediation_status(raw.get("remediation_status")),
        "verification_status": normalize_verification_status(raw.get("verification_status")),
        "risk_score": raw.get("risk_score"),
        "risk_level": clean_text(raw.get("risk_level")) or normalize_severity(raw.get("severity") or raw.get("risk")),
        "risk_delta": raw.get("risk_delta"),
        "risk_components": raw.get("risk_components") if isinstance(raw.get("risk_components"), dict) else {},
        "created_at": clean_text(raw.get("created_at")) or now_iso(),
        "raw_finding_hash": stable_hash(raw),
    }
    if raw.get("asset_identity"):
        normalized["asset_identity"] = raw.get("asset_identity")
    if raw.get("cves"):
        normalized["cves"] = raw.get("cves")
    return normalized


def make_finding(**kwargs: Any) -> dict:
    source_module = kwargs.pop("source_module", "unknown")
    ip = kwargs.pop("ip", None)
    asset_id = kwargs.pop("asset_id", None)
    port = kwargs.pop("port", None)
    protocol = kwargs.pop("protocol", None)
    service = kwargs.pop("service", None)
    scan_status = kwargs.pop("scan_status", "success")
    return normalize_finding(kwargs, source_module=source_module, ip=ip, asset_id=asset_id, port=port, protocol=protocol, service=service, scan_status=scan_status)


def validate_finding(item: dict) -> list[str]:
    errors: list[str] = []
    nullable = {"ip", "port", "protocol", "service", "risk_score", "risk_delta"}
    missing = sorted(k for k in REQUIRED_FINDING_FIELDS if k not in item)
    if missing:
        errors.append("Trūksta laukų: " + ", ".join(missing))
    for key in REQUIRED_FINDING_FIELDS - nullable:
        if key in item and item.get(key) in (None, ""):
            errors.append(f"Trūksta privalomo lauko reikšmės: {key}")
    if item.get("severity") not in SEVERITY_LEVELS:
        errors.append("Neteisingas severity laukas")
    if item.get("confidence") not in CONFIDENCE_LEVELS:
        errors.append("Neteisingas confidence laukas")
    if item.get("scan_status") not in SCAN_STATUS_VALUES:
        errors.append("Neteisingas scan_status laukas")
    if item.get("remediation_status") not in REMEDIATION_STATUSES:
        errors.append("Neteisingas remediation_status laukas")
    if item.get("verification_status") not in VERIFICATION_STATUSES:
        errors.append("Neteisingas verification_status laukas")
    if not isinstance(item.get("evidence"), list):
        errors.append("evidence turi būti sąrašas")
    if not isinstance(item.get("verification_steps"), list):
        errors.append("verification_steps turi būti sąrašas")
    return errors
