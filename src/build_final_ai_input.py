#!/usr/bin/env python3
from __future__ import annotations

import os
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from common import BASE_DIR, get_run_paths, latest_file_in_dir, load_json, save_json, timestamp_now


# -----------------------------------------------------------------------------
# Sistemos / modelių versijos metaduomenys
# -----------------------------------------------------------------------------
# Šios konstantos naudojamos galutiniame ai_evidence dokumente, kad kiekvienas
# paleidimas būtų atsekamas ir tinkamas aprašyti magistrinio darbo realizacijoje.
SYSTEM_VERSION = "academic-network-assessment-v1.0"
RISK_MODEL_VERSION = "risk-model-v1.0"
CORRELATION_RULES_VERSION = "correlation-rules-v1.0"
AI_PROMPT_VERSION = "ai-evidence-prompt-v1.0"
REPORT_SCHEMA_VERSION = "ai-evidence-schema-v1.0"

LATEST_DIR = Path(os.environ.get("NETWORK_THESIS_LATEST_RUN_DIR", str(BASE_DIR / "latest"))).expanduser()
LATEST_DIR.mkdir(parents=True, exist_ok=True)


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def load_optional(path: Path | None) -> dict:
    if path and path.exists():
        try:
            return load_json(path)
        except Exception as exc:
            return {"_load_error": str(exc), "_source_file": path.name}
    return {}


def latest(paths: dict, directory_key: str, pattern: str) -> Path | None:
    return latest_file_in_dir(paths[directory_key], pattern)


def severity_rank(level: str | None) -> int:
    return {
        "kritinė": 4,
        "kritine": 4,
        "aukšta": 3,
        "auksta": 3,
        "vidutinė": 2,
        "vidutine": 2,
        "žema": 1,
        "zema": 1,
        "informacinė": 0,
        "informacine": 0,
        "info": 0,
    }.get(str(level or "").strip().lower(), 0)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def build_asset_identity_from_host(host: dict | None) -> dict:
    if not isinstance(host, dict):
        return {}
    existing = host.get("asset_identity") if isinstance(host.get("asset_identity"), dict) else {}
    return {
        "asset_id": host.get("asset_id") or existing.get("asset_id"),
        "hostname": host.get("hostname") or existing.get("hostname"),
        "mac": host.get("mac") or existing.get("mac"),
        "vendor": host.get("vendor") or existing.get("vendor"),
        "device_class": host.get("device_class") or existing.get("device_class"),
        "first_seen": host.get("first_seen") or existing.get("first_seen"),
        "last_seen": host.get("last_seen") or existing.get("last_seen"),
    }


def build_host_index(hosts: list[dict]) -> dict:
    by_ip: dict[str, dict] = {}
    by_asset: dict[str, dict] = {}
    for host in hosts:
        if not isinstance(host, dict):
            continue
        if host.get("ip"):
            by_ip[str(host.get("ip"))] = host
        if host.get("asset_id"):
            by_asset[str(host.get("asset_id"))] = host
    return {"by_ip": by_ip, "by_asset": by_asset}


def host_for_finding(finding: dict, host_index: dict) -> dict | None:
    asset_id = finding.get("asset_id")
    ip = finding.get("ip")
    if asset_id and str(asset_id) in host_index.get("by_asset", {}):
        return host_index["by_asset"][str(asset_id)]
    if ip and str(ip) in host_index.get("by_ip", {}):
        return host_index["by_ip"][str(ip)]
    return None


def is_scanner_artifact(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return text.startswith("whatweb ") or text.startswith("whatweb/") or text == "whatweb" or "scanner tool" in text


def split_target_and_scanner_evidence(evidence: Any) -> tuple[list[str], list[str]]:
    target: list[str] = []
    scanner: list[str] = []
    for item in as_list(evidence):
        text = str(item)
        if is_scanner_artifact(text):
            scanner.append(text)
        else:
            target.append(text)
    return target, scanner


def cis_controls_for_rule(rule_id: str | None) -> list[str]:
    rule = str(rule_id or "").lower()
    if "smb" in rule:
        return [
            "Secure Configuration of Enterprise Assets and Software",
            "Access Control Management",
            "Audit Log Management",
        ]
    if "web" in rule or "admin" in rule:
        return [
            "Secure Configuration of Enterprise Assets and Software",
            "Access Control Management",
            "Network Infrastructure Management",
        ]
    if "new_host" in rule or "many_ports" in rule:
        return [
            "Inventory and Control of Enterprise Assets",
            "Network Monitoring and Defense",
            "Secure Configuration of Enterprise Assets and Software",
        ]
    if "eset" in rule or "endpoint" in rule or "threat" in rule or "malware" in rule:
        return [
            "Malware Defenses",
            "Audit Log Management",
            "Incident Response Management",
        ]
    if "rdp" in rule:
        return ["Access Control Management", "Account Management", "Network Monitoring and Defense"]
    if "snmp" in rule:
        return ["Network Infrastructure Management", "Access Control Management"]
    if "tls" in rule:
        return ["Secure Configuration of Enterprise Assets and Software", "Data Protection"]
    if "cve" in rule:
        return ["Continuous Vulnerability Management", "Patch Management"]
    return ["Continuous Vulnerability Management"]


def mitre_for_rule(rule_id: str | None, existing: Any) -> list:
    current = as_list(existing)
    if current:
        return current
    rule = str(rule_id or "").lower()
    if "smb" in rule:
        return [{"tactic": "Lateral Movement", "technique": "T1021.002 SMB/Windows Admin Shares"}]
    if "rdp" in rule:
        return [{"tactic": "Lateral Movement", "technique": "T1021.001 Remote Desktop Protocol"}]
    if "new_host" in rule or "many_ports" in rule:
        return [{"tactic": "Discovery", "technique": "T1046 Network Service Discovery"}]
    if "web" in rule or "admin" in rule:
        return [{"tactic": "Initial Access", "technique": "T1190 Exploit Public-Facing Application"}]
    if "eset" in rule or "endpoint" in rule or "threat" in rule or "malware" in rule:
        return [{"tactic": "Defense Evasion", "technique": "T1562 Impair Defenses"}]
    return []


def expected_after_fix_state(rule_id: str | None) -> list[str]:
    rule = str(rule_id or "").lower()
    if "smb" in rule:
        return ["SMBv1 neaptinkamas", "SMB signing įjungtas arba reikalaujamas", "guest/share autentifikacija išjungta", "SMB pasiekiamas tik būtiniems hostams arba VLAN"]
    if "web" in rule or "admin" in rule:
        return ["Administravimo sąsaja nepasiekiama iš bendro LAN segmento", "pasiekiamumas leidžiamas tik valdymo IP/VPN/VLAN", "nebūtini banneriai ir versijos neatskleidžiami"]
    if "new_host" in rule or "many_ports" in rule:
        return ["Įrenginys įtrauktas į inventorių", "paskirtas atsakingas savininkas", "palikti tik būtini atviri prievadai", "baseline atnaujintas tik po patvirtinimo"]
    if "eset" in rule or "endpoint" in rule or "threat" in rule or "malware" in rule:
        return ["Originalios ESET eilutės peržiūrėtos", "incidentas patvirtintas arba atmestas", "jei reikia, endpoint izoliuotas ir nuskenuotas", "pakartotini threat indicator įvykiai nebesikartoja"]
    if "tls" in rule:
        return ["Naudojami TLS 1.2/1.3", "silpni šifrai išjungti", "sertifikatas galiojantis"]
    if "rdp" in rule:
        return ["RDP pasiekiamas tik iš administravimo segmento arba VPN", "NLA įjungtas", "nesėkmingi prisijungimai sumažėję"]
    if "snmp" in rule:
        return ["SNMPv1/v2c arba viešos community reikšmės nenaudojamos", "SNMP prieiga ribojama valdymo segmentui"]
    return ["Pakartotinis skenavimas radinio nebefiksuoja"]


def finding_status_for(finding: dict, target_evidence_valid: bool = True) -> tuple[str, bool, str]:
    rule = str(finding.get("rule_id") or "").lower()
    source = str(finding.get("source_module") or "").lower()
    title = str(finding.get("title") or "").lower()
    if not target_evidence_valid:
        return "scanner_metadata_only", False, "scanner_metadata"
    if any(x in rule + source + title for x in ["eset", "endpoint", "threat", "malware"]):
        return "requires_human_review", False, "endpoint_security_event"
    if finding.get("cve") or "cve" in rule:
        return "potential_cve_requires_validation", False, "vulnerability_candidate"
    if any(x in rule for x in ["smb", "rdp", "snmp", "tls", "web", "dns", "router", "new_host", "many_ports"]):
        return "confirmed_configuration_issue", True, "configuration_or_exposure"
    return "observed_technical_finding", False, "technical_observation"


def confidence_reason_for(finding: dict, target_evidence_valid: bool = True) -> str:
    if not target_evidence_valid:
        return "Aptikta tik skenavimo įrankio metaduomenų reikšmė, todėl ji nelaikoma taikinio technologijos įrodymu."
    confidence = str(finding.get("confidence") or "vidutinis").lower()
    source = finding.get("source_module") or "nežinomas modulis"
    evidence_count = len(as_list(finding.get("evidence")))
    if confidence.startswith("auk"):
        return f"Radinys patvirtintas iš modulio {source}; įrodymų kiekis: {evidence_count}."
    if confidence.startswith("žem") or confidence.startswith("zem"):
        return f"Radinys turi ribotą įrodymų kiekį arba netiesioginį susiejimą; modulis: {source}."
    return f"Radinys pagrįstas techniniais požymiais, tačiau prieš keitimus rekomenduojama administratoriaus peržiūra; modulis: {source}."


def enrich_finding_context(finding: dict, host_index: dict, default_source_module: str) -> dict:
    item = dict(finding)
    item["source_module"] = item.get("source_module") or default_source_module
    host = host_for_finding(item, host_index)
    if host:
        item["asset_id"] = item.get("asset_id") or host.get("asset_id")
        item["asset_identity"] = build_asset_identity_from_host(host)
        item["risk_score"] = item.get("risk_score") if item.get("risk_score") is not None else host.get("official_risk_score")
        item["risk_level"] = item.get("risk_level") or item.get("severity") or host.get("official_risk_level")
        item["risk_components"] = item.get("risk_components") or host.get("risk_components") or {}
    else:
        item["asset_identity"] = build_asset_identity_from_host(None)
        item["risk_score"] = item.get("risk_score")
        item["risk_level"] = item.get("risk_level") or item.get("severity") or "nežinoma"
        item["risk_components"] = item.get("risk_components") or {}

    item["risk_delta"] = item.get("risk_delta") if item.get("risk_delta") is not None else item.get("risk_increase")

    target_evidence, scanner_evidence = split_target_and_scanner_evidence(item.get("evidence"))
    target_evidence_valid = True
    if str(item.get("source_module") or "").endswith("web_fingerprint.py") and str(item.get("rule_id") or "") == "web_server_version_exposed":
        if scanner_evidence and not target_evidence:
            target_evidence_valid = False
            item["scanner_metadata"] = [{"tool": "WhatWeb", "value": value, "note": "Tai naudoto skenavimo įrankio versija, ne taikinio web serverio technologija."} for value in scanner_evidence]
            item["evidence"] = []
            item["title"] = "Žiniatinklio versijos atskleidimas nepatvirtintas"
            item["severity"] = "informacinė"
            item["confidence"] = "žemas"
        elif scanner_evidence:
            item["scanner_metadata"] = [{"tool": "WhatWeb", "value": value, "note": "Skenerio metaduomenys atskirti nuo taikinio įrodymų."} for value in scanner_evidence]
            item["evidence"] = target_evidence

    status, incident_confirmed, category = finding_status_for(item, target_evidence_valid=target_evidence_valid)
    item["finding_status"] = item.get("finding_status") or status
    item["incident_confirmed"] = bool(item.get("incident_confirmed")) if item.get("incident_confirmed") is not None else incident_confirmed
    item["finding_category"] = item.get("finding_category") or category
    item["confidence_reason"] = item.get("confidence_reason") or confidence_reason_for(item, target_evidence_valid=target_evidence_valid)
    item["mitre_attack"] = mitre_for_rule(item.get("rule_id"), item.get("mitre_attack"))
    item["cis_controls"] = as_list(item.get("cis_controls")) or cis_controls_for_rule(item.get("rule_id"))
    item["cve_based"] = bool(item.get("cve") or item.get("cvss"))
    item["configuration_based"] = not item["cve_based"] and item["finding_status"] in {"confirmed_configuration_issue", "observed_technical_finding"}
    item["remediation_status"] = item.get("remediation_status") or "open"
    item["verification_status"] = item.get("verification_status") or "not_checked"
    item["expected_after_fix_state"] = as_list(item.get("expected_after_fix_state")) or expected_after_fix_state(item.get("rule_id"))
    item["target_evidence_valid"] = target_evidence_valid
    return item


def build_top_risks(findings: list[dict], limit: int = 10) -> list[dict]:
    usable = [f for f in findings if f.get("finding_status") != "scanner_metadata_only"]
    usable = sorted(
        usable,
        key=lambda f: (severity_rank(f.get("risk_level") or f.get("severity")), safe_float(f.get("risk_score")), safe_float(f.get("risk_delta"))),
        reverse=True,
    )
    rows = []
    for priority, item in enumerate(usable[:limit], start=1):
        rows.append({
            "priority": priority,
            "host": item.get("ip"),
            "asset_id": item.get("asset_id"),
            "finding_id": item.get("finding_id"),
            "finding": item.get("title") or item.get("rule_id"),
            "risk_score": item.get("risk_score"),
            "risk_level": item.get("risk_level") or item.get("severity"),
            "confidence": item.get("confidence"),
            "finding_status": item.get("finding_status"),
            "action": (item.get("recommended_fix") or "Peržiūrėti ir pašalinti pagal rekomendacijų dokumentą."),
        })
    return rows


def ip_sort_key(ip: str | None):
    try:
        return tuple(int(x) for x in str(ip).split("."))
    except Exception:
        return (999, 999, 999, 999)


def compact_host(host: dict, risk_by_ip: dict[str, dict]) -> dict:
    ip = host.get("ip")
    profile = host.get("normalized_security_profile") or {}
    risk = risk_by_ip.get(ip or "", {})
    ports = profile.get("tcp_open_ports") or [p.get("port") for p in as_list(host.get("ports")) if isinstance(p, dict)]
    return {
        "ip": ip,
        "asset_id": host.get("asset_id"),
        "asset_identity": host.get("asset_identity", {}),
        "hostname": host.get("hostname"),
        "mac": host.get("mac"),
        "vendor": host.get("vendor"),
        "state": host.get("state"),
        "status_reason": host.get("status_reason"),
        "device_class": profile.get("device_class") or risk.get("device_class"),
        "classification_reasons": profile.get("classification_reasons", []),
        "tcp_open_ports": ports,
        "udp_open_ports": profile.get("udp_open_ports", []),
        "service_names": profile.get("service_names", []),
        "smb": profile.get("smb", {}),
        "ssh": profile.get("ssh", {}),
        "rdp": profile.get("rdp", {}),
        "web": profile.get("web", {}),
        "tls": profile.get("tls", {}),
        "snmp": profile.get("snmp", {}),
        "vulnerabilities": profile.get("vulnerabilities", {}),
        "change_summary": host.get("change_summary", {}),
        "risk_flags": host.get("evidence_summary", []),
        "official_risk_score": risk.get("risk_score"),
        "official_risk_level": risk.get("risk_level"),
        "risk_components": risk.get("risk_components", {}),
        "risk_explanation": risk.get("explanation", []),
        "legacy_priority_score": host.get("legacy_priority_score"),
        "legacy_priority_level": host.get("legacy_priority_level"),
    }


def strip_correlation(item: dict) -> dict:
    """Paliekami techniniai įrodymai, bet pašalinamas šabloninis taisymo tekstas."""
    return {
        "finding_id": item.get("finding_id"),
        "rule_id": item.get("rule_id"),
        "source_module": item.get("source_module") or "correlation_engine.py",
        "ip": item.get("ip"),
        "asset_id": item.get("asset_id"),
        "title": item.get("title"),
        "severity": item.get("severity"),
        "confidence": item.get("confidence"),
        "risk_increase": item.get("risk_increase"),
        "risk_delta": item.get("risk_delta") or item.get("risk_increase"),
        "evidence": item.get("evidence", []),
        "mitre_attack": item.get("mitre_attack", []),
        "cis_controls": item.get("cis_controls", []),
    }


def compact_normalized_findings(data: dict) -> list[dict]:
    findings = []
    for item in as_list(data.get("findings")):
        if not isinstance(item, dict):
            continue
        findings.append({
            "finding_id": item.get("finding_id"),
            "rule_id": item.get("rule_id"),
            "source_module": item.get("source_module"),
            "asset_id": item.get("asset_id"),
            "ip": item.get("ip"),
            "port": item.get("port"),
            "protocol": item.get("protocol"),
            "service": item.get("service"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "title": item.get("title"),
            "description": item.get("description"),
            "evidence": item.get("evidence", []),
            "impact": item.get("impact"),
            "cve": item.get("cve"),
            "cvss": item.get("cvss"),
            "scan_status": item.get("scan_status"),
            "risk_score": item.get("risk_score"),
            "risk_level": item.get("risk_level"),
            "risk_delta": item.get("risk_delta") or item.get("risk_increase"),
            "risk_components": item.get("risk_components", {}),
            "mitre_attack": item.get("mitre_attack", []),
            "cis_controls": item.get("cis_controls", []),
            "validation": item.get("validation"),
            "recommended_fix": item.get("recommended_fix"),
        })
    return sorted(findings, key=lambda x: (severity_rank(x.get("severity")), str(x.get("ip") or "")), reverse=True)


def endpoint_summary(endpoint: dict) -> dict:
    summary = endpoint.get("summary") or {}
    stats = endpoint.get("stats") or {}
    eset_rows_sample = endpoint.get("eset_csv_rows_sample") or endpoint.get("eset_csv_rows") or []
    high_eset = endpoint.get("high_value_eset_rows_sample") or summary.get("high_value_eset_rows_sample", [])
    # Keep both high-value rows and a small general sample. Otherwise normal ESET rows are counted
    # in summary but disappear from the final LLM evidence document.
    return {
        "summary": summary,
        "stats": stats,
        "high_value_windows_events_sample": endpoint.get("high_value_windows_events_sample") or summary.get("high_value_windows_events_sample", []),
        "high_value_eset_rows_sample": high_eset,
        "eset_csv_rows_sample": as_list(high_eset)[:25] + [x for x in as_list(eset_rows_sample)[:50] if x not in as_list(high_eset)[:25]],
        "eset_files": as_list(endpoint.get("eset_files"))[:50],
        "payload_summaries": as_list(endpoint.get("payload_summaries"))[-10:],
        "aggregated_findings": endpoint.get("aggregated_findings") or summary.get("aggregated_findings", []),
    }


def build_markdown(evidence: dict) -> str:
    lines = []
    lines.append("# DI techninių įrodymų dokumentas")
    lines.append("")
    lines.append(f"Run ID: `{evidence.get('run_id')}`")
    lines.append(f"Tinklas: `{evidence.get('network')}`")
    lines.append(f"Sugeneruota: `{evidence.get('generated_at')}`")
    lines.append("")
    lines.append("## Santrauka")
    for k, v in (evidence.get("executive_summary") or {}).items():
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("## Top rizikos")
    top_risks = as_list(evidence.get("top_risks"))
    if top_risks:
        lines.append("| Prioritetas | Hostas | Finding ID | Rizika | Balas | Confidence | Statusas |")
        lines.append("|---:|---|---|---|---:|---|---|")
        for row in top_risks[:10]:
            lines.append(f"| {row.get('priority')} | {row.get('host') or ''} | {row.get('finding_id') or ''} | {row.get('risk_level') or ''} | {row.get('risk_score') if row.get('risk_score') is not None else ''} | {row.get('confidence') or ''} | {row.get('finding_status') or ''} |")
    else:
        lines.append("- Aukšto prioriteto radinių nėra arba jie nebuvo formalizuoti.")
    lines.append("")
    lines.append("## Svarbiausi techniniai radiniai")
    for item in as_list((evidence.get("technical_findings") or {}).get("correlated_findings"))[:20]:
        evidence_txt = "; ".join(as_list(item.get("evidence"))[:5])
        lines.append(f"- **{item.get('risk_level') or item.get('severity')}** {item.get('ip')} — {item.get('title')} | risk_score: {item.get('risk_score')}; statusas: {item.get('finding_status')}; įrodymai: {evidence_txt}")
    lines.append("")
    lines.append("## Top hostai pagal riziką")
    for host in as_list(evidence.get("hosts_for_ai"))[:15]:
        lines.append(f"- **{host.get('ip')}** — risk_score: {host.get('official_risk_score')}, lygis: {host.get('official_risk_level')}, klasė: {host.get('device_class')}, portai: {host.get('tcp_open_ports')}")
    lines.append("")
    lines.append("## Endpoint / ESET")
    ep = evidence.get("endpoint_context") or {}
    ep_sum = ep.get("summary") or {}
    lines.append(f"- Windows įvykių kiekis: {ep_sum.get('windows_events_count', 0)}")
    lines.append(f"- ESET CSV eilučių kiekis: {ep_sum.get('eset_csv_rows_count', 0)}")
    ep_stats = ep.get("stats") or {}
    if ep_stats.get("legacy_eset_csv_rows_in_context") is not None:
        lines.append(f"- Iš legacy ESET failų normalizuota eilučių: {ep_stats.get('legacy_eset_csv_rows_in_context')}")
    if ep.get("eset_files"):
        lines.append(f"- ESET failų santraukų kiekis DI kontekste: {len(ep.get('eset_files') or [])}")
    lines.append("")
    lines.append("Šis failas yra DI įvestis. Jame nėra šabloninių galutinių rekomendacijų; galutines rekomendacijas turi sugeneruoti LLM modulis.")
    return "\n".join(lines) + "\n"


def main() -> None:
    paths = get_run_paths()
    ts = timestamp_now()

    files = {
        "assessment": latest(paths, "reports_dir", "assessment_*.json"),
        "risk_scores": latest(paths, "reports_dir", "risk_scores_*.json"),
        "epss_kev": latest(paths, "reports_dir", "epss_kev_enrichment_*.json"),
        "normalized_findings": latest(paths, "reports_dir", "normalized_findings_*.json"),
        "correlated_findings": latest(paths, "reports_dir", "correlated_findings_*.json"),
        "endpoint_events": latest(paths, "reports_dir", "endpoint_events_*.json"),
        "remediation_status": latest(paths, "reports_dir", "remediation_status_*.json"),
        "experimental_validation": latest(paths, "reports_dir", "experimental_validation_*.json"),
        "pipeline_audit": latest(paths, "reports_dir", "pipeline_audit_*.json"),
        "schema_validation": latest(paths, "reports_dir", "schema_validation_*.json"),
        "html_report": latest(paths, "reports_dir", "final_report_*.html"),
    }

    assessment = load_optional(files["assessment"])
    risk_scores = load_optional(files["risk_scores"])
    epss_kev = load_optional(files["epss_kev"])
    normalized = load_optional(files["normalized_findings"])
    correlated = load_optional(files["correlated_findings"])
    endpoint = load_optional(files["endpoint_events"])
    remediation = load_optional(files["remediation_status"])
    experimental = load_optional(files["experimental_validation"])
    pipeline_audit = load_optional(files["pipeline_audit"])
    schema_validation = load_optional(files["schema_validation"])

    risk_by_ip = {h.get("ip"): h for h in as_list(risk_scores.get("hosts")) if isinstance(h, dict) and h.get("ip")}
    hosts = [compact_host(h, risk_by_ip) for h in as_list(assessment.get("hosts")) if isinstance(h, dict)]
    hosts = sorted(hosts, key=lambda h: (safe_float(h.get("official_risk_score")), len(h.get("tcp_open_ports") or [])), reverse=True)
    host_index = build_host_index(hosts)

    normalized_findings = [enrich_finding_context(f, host_index, "finding_normalizer.py") for f in compact_normalized_findings(normalized)]
    correlated_findings = [enrich_finding_context(strip_correlation(f), host_index, "correlation_engine.py") for f in as_list(correlated.get("findings")) if isinstance(f, dict)]
    correlated_findings = sorted(correlated_findings, key=lambda f: (severity_rank(f.get("risk_level") or f.get("severity")), safe_float(f.get("risk_score")), safe_float(f.get("risk_delta"))), reverse=True)
    top_risks = build_top_risks(correlated_findings + normalized_findings, limit=10)

    vuln_cves = []
    for h in hosts:
        vulns = h.get("vulnerabilities") or {}
        for c in as_list(vulns.get("all_cves")) + as_list(vulns.get("critical_cves")):
            if isinstance(c, str):
                vuln_cves.append(c)
            elif isinstance(c, dict) and (c.get("cve") or c.get("id")):
                vuln_cves.append(c.get("cve") or c.get("id"))

    high_norm = [f for f in normalized_findings if f.get("finding_status") != "scanner_metadata_only" and severity_rank(f.get("risk_level") or f.get("severity")) >= 3]
    high_corr = [f for f in correlated_findings if f.get("finding_status") != "scanner_metadata_only" and severity_rank(f.get("risk_level") or f.get("severity")) >= 3]

    summary = {
        "total_hosts": len(hosts),
        "hosts_with_open_tcp_ports": sum(1 for h in hosts if h.get("tcp_open_ports")),
        "highest_risk_score": max([safe_float(h.get("official_risk_score")) for h in hosts] or [0]),
        "official_risk_scores_0_100": True,
        "critical_or_high_hosts_by_official_score": sum(1 for h in hosts if severity_rank(h.get("official_risk_level")) >= 3),
        "correlated_findings_count": len(correlated_findings),
        "high_or_critical_correlated_findings": len(high_corr),
        "normalized_findings_count": len(normalized_findings),
        "high_or_critical_normalized_findings": len(high_norm),
        "cve_count": len(set(vuln_cves)) or int(((epss_kev.get("summary") or {}).get("unique_cves") or 0)),
        "kev_count": int(((epss_kev.get("summary") or {}).get("cves_in_cisa_kev") or 0)),
        "endpoint_events_count": int(((endpoint.get("summary") or {}).get("total_events") or (endpoint.get("stats") or {}).get("events_in_context") or 0)),
        "technical_findings_require_llm_analysis": bool(high_norm or high_corr or vuln_cves),
    }

    evidence = {
        "document_type": "ai_evidence",
        "generated_at": ts,
        "run_id": paths["run_id"],
        "run_dir": str(paths["run_dir"]),
        "network": assessment.get("network"),
        "purpose": "Vienas oficialus techninių DI įrodymų dokumentas. Šiame faile pateikiami techniniai radiniai, o ne galutinės šabloninės rekomendacijos.",
        "system_metadata": {
            "system_version": SYSTEM_VERSION,
            "risk_model_version": str((risk_scores.get("risk_model") or {}).get("version") or "1.0"),
            "correlation_rules_version": str((correlated.get("rules_version") or correlated.get("version") or "1.0")),
            "finding_schema_version": "2.1-master-ready",
            "ai_prompt_version": AI_PROMPT_VERSION,
            "latest_dir": str(LATEST_DIR),
        },
        "instruction_for_llm": (
            "Remkis tik šiame dokumente pateiktais techniniais įrodymais. "
            "Kiekvienai rekomendacijai privaloma naudoti recommendation_id, finding_id, source_module, host/ip, asset_id, "
            "risk_score, risk_level, risk_delta, risk_components, confidence, confidence_reason, finding_status, evidence_used, "
            "recommended_actions, verification_steps, expected_after_fix_state ir remediation_status. "
            "WhatWeb arba kito skenerio versiją laikyk scanner metadata, ne taikinio technologija. "
            "Jeigu CVE/EPSS/KEV nėra, aiškiai nurodyk, kad radinys konfigūracinis, ne CVE pagrįstas. "
            "Endpoint/ESET radinius žymėk requires_human_review, jei incidentas dar nepatvirtintas."
        ),
        "source_files": {k: (v.name if isinstance(v, Path) else None) for k, v in files.items()},
        "executive_summary": summary,
        "risk_model": risk_scores.get("risk_model", {}),
        "risk_summary": risk_scores.get("summary", {}),
        "hosts_for_ai": hosts,
        "top_risks": top_risks,
        "technical_findings": {
            "normalized_summary": normalized.get("summary", {}),
            "normalized_findings": normalized_findings[:250],
            "correlated_summary": correlated.get("summary", {}),
            "correlated_findings": correlated_findings[:100],
        },
        "cve_epss_kev": {
            "summary": epss_kev.get("summary", {}),
            "items": epss_kev.get("items") or epss_kev.get("top_cves") or [],
        },
        "endpoint_context": endpoint_summary(endpoint),
        "remediation_tracking": {
            "summary": remediation.get("summary", {}),
            "finding_status": remediation.get("finding_status", [])[:100],
            "risk_score_status": remediation.get("risk_score_status", [])[:100],
        },
        "validation_context": {
            "experimental_validation": experimental.get("summary", {}),
            "pipeline_audit": pipeline_audit.get("summary", pipeline_audit.get("overall", {})),
            "schema_validation": schema_validation.get("summary", {}),
        },
        "known_limitations": [
            "CVE/EPSS/KEV nebuvimas nereiškia, kad įrenginys neturi pažeidžiamumų; tai reiškia, kad šiame skenavime jos nebuvo patvirtintos pagal turimus įrodymus.",
            "Endpoint/ESET įvykiai yra indikatoriai ir turi būti peržiūrėti žmogaus, jei incidentas nepatvirtintas.",
            "WhatWeb ir kitų skenerių versijos atskiriamos kaip scanner_metadata ir nelaikomos taikinio technologijomis.",
            "IP adresas gali keistis DHCP aplinkoje, todėl turto identifikavimui naudojamas asset_id.",
        ],
        "report_requirements": {
            "language": "lt",
            "audience": "IT sistemų administratorius ir akademinis vertintojas",
            "required_sections": [
                "AI ir audito metaduomenys", "Santrauka vadovui", "Top rizikų lentelė",
                "Prioritetinės rekomendacijos", "Remediation verification plan",
                "MITRE ATT&CK / CIS Controls kontekstas",
                "Neapibrėžtumas ir klaidingų teigiamų radinių sąlygos",
                "Pakartotinio patikrinimo komandos"
            ],
            "required_recommendation_fields": [
                "recommendation_id", "finding_id", "source_module", "host", "asset_id",
                "risk_score", "risk_level", "risk_delta", "risk_components", "confidence",
                "confidence_reason", "finding_status", "evidence_used", "recommended_actions",
                "verification_steps", "expected_after_fix_state", "remediation_status", "verification_status"
            ]
        },
        "html_report_file": files["html_report"].name if isinstance(files["html_report"], Path) else None,
    }

    json_path = paths["ai_dir"] / f"ai_evidence_{ts}.json"
    md_path = paths["ai_dir"] / f"ai_evidence_{ts}.md"
    save_json(json_path, evidence)
    md_text = build_markdown(evidence)
    md_path.write_text(md_text, encoding="utf-8")

    latest_json = LATEST_DIR / "ai_evidence_latest.json"
    latest_md = LATEST_DIR / "ai_evidence_latest.md"
    shutil.copy2(json_path, latest_json)
    shutil.copy2(md_path, latest_md)

    print(f"DI techninių įrodymų JSON: {json_path}")
    print(f"DI techninių įrodymų MD: {md_path}")
    print(f"Naujausias JSON: {latest_json}")
    print(f"Naujausias MD: {latest_md}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
