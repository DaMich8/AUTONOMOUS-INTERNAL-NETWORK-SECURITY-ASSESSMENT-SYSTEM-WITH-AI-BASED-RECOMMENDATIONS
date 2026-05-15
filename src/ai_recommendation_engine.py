#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

import os

from common import BASE_DIR, get_run_paths, latest_file_in_dir, load_json, save_json, timestamp_now

LATEST_DIR = Path(os.environ.get("NETWORK_THESIS_LATEST_RUN_DIR", str(BASE_DIR / "latest"))).expanduser()
LATEST_DIR.mkdir(parents=True, exist_ok=True)

PROMPT_VERSION = "v2.0-formal-risk-asset-recommendations"
MODEL_USED = "deterministic-evidence-recommender-v2"
PROMPT_TEMPLATE = """
Naudok tik pateiktus techninius įrodymus: hosts_for_ai, top_risks, normalized_findings,
correlated_findings, risk_scores, endpoint_events, epss_kev_enrichment ir remediation_tracking.
Kiekvienai rekomendacijai privaloma pateikti: recommendation_id, finding_id,
source_module, host/ip, asset_id, asset_identity, risk_score, risk_level, risk_delta,
risk_components, confidence, confidence_reason, finding_status, evidence_used,
recommended_actions, verification_steps, expected_after_fix_state, remediation_status,
verification_status, MITRE ATT&CK ir CIS Controls.
WhatWeb arba kito skenerio versija yra scanner metadata, ne taikinio technologija.
Jei nėra CVE/EPSS/KEV, pažymėk, kad radinys konfigūracinis, ne CVE pagrįstas.
Endpoint/ESET radinius žymėk requires_human_review, jei incidentas dar nepatvirtintas.
""".strip()


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def stable_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def severity_rank(value: str | None) -> int:
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
    }.get(str(value or "").strip().lower(), 0)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def asset_identity_from_host(host: dict | None) -> dict:
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


def rule_text(finding: dict) -> str:
    return " ".join(str(finding.get(k) or "") for k in ("rule_id", "source_module", "title", "description")).lower()


def is_scanner_artifact(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return text.startswith("whatweb ") or text.startswith("whatweb/") or text == "whatweb" or "scanner tool" in text


def cis_controls_for_rule(rule: str) -> list[str]:
    if "smb" in rule:
        return ["Secure Configuration of Enterprise Assets and Software", "Access Control Management", "Audit Log Management"]
    if "web" in rule or "admin" in rule or "router" in rule:
        return ["Secure Configuration of Enterprise Assets and Software", "Access Control Management", "Network Infrastructure Management"]
    if "new_host" in rule or "many_ports" in rule:
        return ["Inventory and Control of Enterprise Assets", "Network Monitoring and Defense", "Secure Configuration of Enterprise Assets and Software"]
    if "endpoint" in rule or "eset" in rule or "threat" in rule or "malware" in rule:
        return ["Malware Defenses", "Audit Log Management", "Incident Response Management"]
    if "rdp" in rule:
        return ["Access Control Management", "Account Management", "Network Monitoring and Defense"]
    if "snmp" in rule:
        return ["Network Infrastructure Management", "Access Control Management"]
    if "tls" in rule:
        return ["Secure Configuration of Enterprise Assets and Software", "Data Protection"]
    if "cve" in rule:
        return ["Continuous Vulnerability Management", "Patch Management"]
    return ["Continuous Vulnerability Management"]


def mitre_attack_for_rule(rule: str, existing: Any) -> list:
    current = as_list(existing)
    if current:
        return current
    if "smb" in rule:
        return [{"tactic": "Lateral Movement", "technique": "T1021.002 SMB/Windows Admin Shares"}]
    if "rdp" in rule:
        return [{"tactic": "Lateral Movement", "technique": "T1021.001 Remote Desktop Protocol"}]
    if "new_host" in rule or "many_ports" in rule:
        return [{"tactic": "Discovery", "technique": "T1046 Network Service Discovery"}]
    if "web" in rule or "admin" in rule or "router" in rule:
        return [{"tactic": "Initial Access", "technique": "T1190 Exploit Public-Facing Application"}]
    if "endpoint" in rule or "eset" in rule or "threat" in rule or "malware" in rule:
        return [{"tactic": "Defense Evasion", "technique": "T1562 Impair Defenses"}]
    return []


def finding_status_for(finding: dict) -> tuple[str, bool, str]:
    status = finding.get("finding_status")
    if status:
        return str(status), bool(finding.get("incident_confirmed", False)), str(finding.get("finding_category") or "technical_observation")
    text = rule_text(finding)
    if "scanner_metadata_only" in text or finding.get("target_evidence_valid") is False:
        return "scanner_metadata_only", False, "scanner_metadata"
    if any(x in text for x in ["endpoint", "eset", "threat", "malware"]):
        return "requires_human_review", False, "endpoint_security_event"
    if finding.get("cve") or "cve" in text:
        return "potential_cve_requires_validation", False, "vulnerability_candidate"
    if any(x in text for x in ["smb", "rdp", "snmp", "tls", "web", "router", "dns", "new_host", "many_ports"]):
        return "confirmed_configuration_issue", True, "configuration_or_exposure"
    return "observed_technical_finding", False, "technical_observation"


def confidence_reason_for(finding: dict) -> str:
    if finding.get("confidence_reason"):
        return str(finding.get("confidence_reason"))
    if finding.get("finding_status") == "scanner_metadata_only":
        return "Aptikta tik skenavimo įrankio metaduomenų reikšmė, todėl ji nelaikoma taikinio technologijos įrodymu."
    confidence = str(finding.get("confidence") or "vidutinis").lower()
    source = finding.get("source_module") or "nežinomas modulis"
    count = len(as_list(finding.get("evidence")))
    if confidence.startswith("auk"):
        return f"Radinys patvirtintas iš modulio {source}; įrodymų kiekis: {count}."
    if confidence.startswith("žem") or confidence.startswith("zem"):
        return f"Radinio patikimumas ribotas, todėl prieš keitimus būtina administratoriaus peržiūra; modulis: {source}."
    return f"Radinys pagrįstas techniniais požymiais, tačiau sprendimą rekomenduojama patvirtinti administratoriui; modulis: {source}."


def recommendation_text(finding: dict) -> str:
    rule = str(finding.get("rule_id") or "").lower()
    title = finding.get("title") or "saugumo radinys"
    if "rdp" in rule:
        return "Apriboti RDP prieigą tik administravimo segmentui arba VPN, įjungti paskyrų blokavimo politiką ir peržiūrėti nesėkmingų prisijungimų šaltinius."
    if "smb" in rule:
        return "Išjungti SMBv1 ir guest prieigą, įjungti SMB signing ir riboti SMB tik būtiniems vidinio tinklo segmentams."
    if "snmp" in rule:
        return "Pakeisti numatytąsias SNMP community reikšmes, pereiti prie SNMPv3 ir riboti SNMP prieigą valdymo segmentui."
    if "tls" in rule:
        return "Sutvarkyti TLS konfigūraciją: išjungti SSLv2/SSLv3/TLS 1.0/1.1 bei silpnus cipher suites, naudoti TLS 1.2/1.3 ir galiojantį sertifikatą."
    if "cve" in rule or finding.get("cve"):
        return "Patikrinti tikslią paslaugos versiją, patvirtinti CVE aktualumą ir taikyti gamintojo pataisas arba laikinai riboti paveiktos paslaugos pasiekiamumą."
    if "audit_log_cleared" in rule:
        return "Skubiai patikrinti administratorių veiksmus, atkurti audito žurnalų vientisumą ir įjungti centralizuotą logų kopijavimą."
    if "account_change" in rule:
        return "Peržiūrėti paskyrų ir grupių pakeitimus, patvirtinti jų teisėtumą ir patikrinti administratorių grupės narius."
    if "powershell" in rule:
        return "Peržiūrėti PowerShell įvykių turinį, įjungti script block logging ir riboti neautorizuotų scriptų vykdymą."
    if finding.get("recommended_fix"):
        return str(finding.get("recommended_fix"))
    return f"Peržiūrėti radinį „{title}“, suplanuoti pataisymo veiksmus pagal pateiktus įrodymus ir pakartotinai patikrinti rezultatą."



def recommended_actions(finding: dict) -> list[str]:
    rule = rule_text(finding)
    if "smb" in rule:
        return ["Išjungti SMBv1", "Išjungti guest/share autentifikaciją", "Įjungti arba reikalauti SMB signing", "Apriboti SMB prieigą tik būtiniems hostams arba VLAN"]
    if "web" in rule or "admin" in rule or "router" in rule:
        return ["Apriboti administravimo sąsajos pasiekiamumą valdymo IP/VPN/VLAN", "Peržiūrėti autentifikacijos nustatymus", "Sumažinti nebūtiną bannerių ir versijų atskleidimą"]
    if "new_host" in rule or "many_ports" in rule:
        return ["Patvirtinti įrenginį inventoriuje", "Nustatyti savininką ir paskirtį", "Uždaryti nebūtinus prievadus", "Atnaujinti baseline tik po patvirtinimo"]
    if "endpoint" in rule or "eset" in rule or "threat" in rule or "malware" in rule:
        return ["Peržiūrėti originalias ESET įvykių eilutes", "Patikrinti, ar įvykiai nėra administracinio darbo pasekmė", "Jei požymiai pasitvirtina, izoliuoti endpoint ir atlikti AV/EDR patikrą"]
    if "tls" in rule:
        return ["Išjungti pasenusias TLS/SSL versijas", "Išjungti silpnus šifrus", "Patikrinti sertifikato galiojimą"]
    if "rdp" in rule:
        return ["Riboti RDP tik iš VPN arba administravimo segmento", "Įjungti NLA", "Peržiūrėti prisijungimų įvykius"]
    if "snmp" in rule:
        return ["Pereiti prie SNMPv3", "Pakeisti numatytąsias community reikšmes", "Riboti SNMP prieigą valdymo segmentui"]
    if finding.get("recommended_fix"):
        return [str(finding.get("recommended_fix"))]
    return [recommendation_text(finding)]


def expected_after_fix_state(finding: dict) -> list[str]:
    existing = as_list(finding.get("expected_after_fix_state"))
    if existing:
        return existing
    rule = rule_text(finding)
    if "smb" in rule:
        return ["SMBv1 neaptinkamas", "SMB signing įjungtas arba reikalaujamas", "guest/share autentifikacija išjungta", "SMB pasiekiamas tik būtiniems hostams arba VLAN"]
    if "web" in rule or "admin" in rule or "router" in rule:
        return ["Administravimo sąsaja nepasiekiama iš bendro LAN", "Prieiga leidžiama tik valdymo IP/VPN/VLAN", "Nebūtini banneriai ir versijos neatskleidžiami"]
    if "new_host" in rule or "many_ports" in rule:
        return ["Įrenginys patvirtintas inventoriuje", "palikti tik būtini prievadai", "baseline atnaujintas tik po patvirtinimo"]
    if "endpoint" in rule or "eset" in rule or "threat" in rule or "malware" in rule:
        return ["Originalūs endpoint įvykiai peržiūrėti", "incidentas patvirtintas arba atmestas", "pakartotiniai threat indicator įvykiai nebesikartoja"]
    if "tls" in rule:
        return ["Naudojami TLS 1.2/1.3", "silpni šifrai išjungti", "sertifikatas galiojantis"]
    if "rdp" in rule:
        return ["RDP pasiekiamas tik iš VPN arba administravimo segmento", "NLA įjungtas", "nesėkmingi prisijungimai sumažėję"]
    if "snmp" in rule:
        return ["SNMPv1/v2c arba viešos community reikšmės nenaudojamos", "SNMP prieiga ribojama valdymo segmentui"]
    return ["Pakartotinis skenavimas radinio nebefiksuoja"]

def verification_steps(finding: dict) -> list[str]:
    ip = finding.get("ip")
    port = finding.get("port")
    rule = str(finding.get("rule_id") or "").lower()
    steps: list[str] = []
    if ip and port:
        steps.append(f"nmap -Pn -sV -p{port} {ip}")
    elif ip:
        steps.append(f"nmap -Pn -sV {ip}")
    if "tls" in rule and ip and port:
        steps.append(f"sslscan --no-colour {ip}:{port}")
    if "rdp" in rule and ip:
        steps.append(f"nmap -Pn -p3389 {ip}")
        steps.append("Patikrinti Windows 4625/4624 įvykių kiekį po pataisymo")
    if "smb" in rule and ip:
        steps.append(f"nmap -Pn -p139,445 --script smb-protocols,smb-security-mode {ip}")
    if "snmp" in rule and ip:
        steps.append(f"nmap -sU -p161 --script snmp-info {ip}")
    if "cve" in rule and ip:
        steps.append("Pakartoti vuln_enrichment.py ir patikrinti, ar CVE nebėra sąraše")
    if not steps:
        steps.append("Pakartoti full_assessment.py ir patikrinti normalized_findings/correlated_findings")
    return steps


def collect_findings(evidence: dict) -> list[dict]:
    technical = evidence.get("technical_findings") or {}
    findings = []
    for item in as_list(technical.get("correlated_findings")):
        if isinstance(item, dict):
            work = dict(item)
            work["source_module"] = work.get("source_module") or "correlation_engine.py"
            findings.append(work)
    for item in as_list(technical.get("normalized_findings")):
        if isinstance(item, dict):
            work = dict(item)
            work["source_module"] = work.get("source_module") or "finding_normalizer.py"
            findings.append(work)

    # Endpoint/ESET aggregate findings are not always host-mapped, but they still must be
    # available to the reproducible recommendation layer. Convert them to pseudo-findings.
    endpoint = evidence.get("endpoint_context") or {}
    for idx, item in enumerate(as_list(endpoint.get("aggregated_findings")), start=1):
        if not isinstance(item, dict):
            continue
        rule = str(item.get("type") or "endpoint_aggregated_finding")
        findings.append({
            "finding_id": f"endpoint_{rule}_{idx:03d}",
            "rule_id": rule,
            "source_module": "endpoint_event_normalizer.py",
            "ip": item.get("ip") or item.get("host"),
            "severity": item.get("severity") or "vidutinė",
            "confidence": "vidutinis" if item.get("host") else "žemas",
            "title": rule.replace("_", " "),
            "evidence": [f"count: {item.get('count')}"] if item.get("count") is not None else [],
            "recommended_fix": item.get("recommendation"),
            "scan_status": "success",
            "risk_increase": 10,
        })

    # De-duplicate by finding_id/rule/ip/port.
    out = []
    seen = set()
    for item in findings:
        if not isinstance(item, dict):
            continue
        key = item.get("finding_id") or "|".join(str(item.get(k) or "") for k in ("rule_id", "ip", "port"))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return sorted(out, key=lambda f: (severity_rank(f.get("severity")), float(f.get("risk_increase") or 0)), reverse=True)


def host_for_recommendation(evidence: dict, ip: str | None, asset_id: str | None) -> dict | None:
    for host in as_list(evidence.get("hosts_for_ai")):
        if not isinstance(host, dict):
            continue
        if (asset_id and host.get("asset_id") == asset_id) or (ip and host.get("ip") == ip):
            return host
    return None


def risk_for_host(evidence: dict, ip: str | None, asset_id: str | None) -> tuple[str, float | None, dict, dict]:
    host = host_for_recommendation(evidence, ip, asset_id)
    if host:
        return (
            str(host.get("official_risk_level") or host.get("risk_level") or "nežinoma"),
            host.get("official_risk_score"),
            host.get("risk_components") if isinstance(host.get("risk_components"), dict) else {},
            asset_identity_from_host(host),
        )
    return "nežinoma", None, {}, {}


def build_recommendations(evidence: dict, input_hash: str) -> list[dict]:
    recommendations = []
    prompt_template_hash = stable_hash({"prompt_template": PROMPT_TEMPLATE, "prompt_version": PROMPT_VERSION})
    run_date = str(evidence.get("run_id") or datetime.now().strftime("%Y-%m-%d"))[:10]
    findings = [f for f in collect_findings(evidence) if isinstance(f, dict)]
    findings = sorted(
        findings,
        key=lambda f: (
            severity_rank(f.get("risk_level") or f.get("severity")),
            safe_float(f.get("risk_score")),
            safe_float(f.get("risk_delta") or f.get("risk_increase")),
        ),
        reverse=True,
    )

    for idx, finding in enumerate(findings[:120], start=1):
        ip = finding.get("ip")
        asset_id = finding.get("asset_id")
        host_risk_level, host_risk_score, host_risk_components, asset_identity = risk_for_host(evidence, ip, asset_id)
        risk_level = finding.get("risk_level") or finding.get("severity") or (host_risk_level if host_risk_level != "nežinoma" else None)
        risk_score = finding.get("risk_score") if finding.get("risk_score") is not None else host_risk_score
        risk_components = finding.get("risk_components") if isinstance(finding.get("risk_components"), dict) and finding.get("risk_components") else host_risk_components
        rule = rule_text(finding)
        evidence_items = [str(x) for x in as_list(finding.get("evidence"))[:10]]
        if (finding.get("source_module") == "web_fingerprint.py" or "web_fingerprint" in rule) and finding.get("rule_id") == "web_server_version_exposed":
            non_scanner = [x for x in evidence_items if not is_scanner_artifact(x)]
            scanner = [x for x in evidence_items if is_scanner_artifact(x)]
            if scanner and not non_scanner:
                finding = dict(finding)
                finding["finding_status"] = "scanner_metadata_only"
                finding["incident_confirmed"] = False
                finding["finding_category"] = "scanner_metadata"
                finding["confidence"] = "žemas"
                finding["confidence_reason"] = "Aptikta tik WhatWeb skenerio versija; ji nėra taikinio web serverio technologijos įrodymas."
                finding["scanner_metadata"] = [{"tool": "WhatWeb", "value": x} for x in scanner]
                evidence_items = []
                risk_level = "informacinė"
            else:
                evidence_items = non_scanner
        finding_status, incident_confirmed, finding_category = finding_status_for(finding)
        if finding_status == "scanner_metadata_only":
            # Tai nėra tikslinio įrenginio radinys, todėl jis neįtraukiamas kaip taisymo rekomendacija.
            # Skenerio metaduomenys lieka ai_evidence dokumente ir gali būti paminėti neapibrėžtumo pastabose.
            continue
        evidence_used = evidence_items
        if risk_score is not None:
            evidence_used.append(f"risk_score: {risk_score}")
        if finding.get("risk_delta") or finding.get("risk_increase"):
            evidence_used.append(f"risk_delta: {finding.get('risk_delta') or finding.get('risk_increase')}")
        if finding.get("scan_status"):
            evidence_used.append(f"scan_status: {finding.get('scan_status')}")
        if finding.get("cve"):
            evidence_used.append(f"cve: {finding.get('cve')}")
        if finding.get("scanner_metadata"):
            evidence_used.append("scanner_metadata atskirta nuo taikinio technologijų")

        rec = {
            "recommendation_id": f"REC-{run_date}-{idx:03d}",
            "finding_id": finding.get("finding_id") or f"{finding.get('rule_id') or 'finding'}_{str(ip or asset_id or 'global').replace('.', '_')}",
            "rule_id": finding.get("rule_id"),
            "source_module": finding.get("source_module") or "unknown",
            "host": ip,
            "asset_id": asset_id,
            "asset_identity": finding.get("asset_identity") if isinstance(finding.get("asset_identity"), dict) and finding.get("asset_identity") else asset_identity,
            "port": finding.get("port"),
            "protocol": finding.get("protocol"),
            "service": finding.get("service"),
            "risk_level": risk_level,
            "risk": risk_level,  # backward compatibility
            "risk_score": risk_score,
            "risk_delta": finding.get("risk_delta") if finding.get("risk_delta") is not None else finding.get("risk_increase"),
            "risk_components": risk_components,
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence") or "vidutinis",
            "confidence_reason": confidence_reason_for(finding),
            "finding_status": finding_status,
            "incident_confirmed": incident_confirmed,
            "finding_category": finding.get("finding_category") or finding_category,
            "cve_based": bool(finding.get("cve") or finding.get("cvss")),
            "configuration_based": not bool(finding.get("cve") or finding.get("cvss")) and finding_status in {"confirmed_configuration_issue", "observed_technical_finding"},
            "mitre_attack": mitre_attack_for_rule(rule, finding.get("mitre_attack")),
            "cis_controls": as_list(finding.get("cis_controls")) or cis_controls_for_rule(rule),
            "evidence_used": evidence_used,
            "ai_recommendation": recommendation_text(finding),
            "recommended_actions": recommended_actions(finding),
            "verification": verification_steps(finding),
            "verification_steps": verification_steps(finding),
            "expected_after_fix_state": expected_after_fix_state(finding),
            "remediation_status": finding.get("remediation_status") or "open",
            "verification_status": finding.get("verification_status") or "not_checked",
            "model_used": MODEL_USED,
            "prompt_version": PROMPT_VERSION,
            "prompt_template_hash": prompt_template_hash,
            "input_hash": input_hash,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        }
        rec["output_hash"] = stable_hash({k: v for k, v in rec.items() if k != "output_hash"})
        recommendations.append(rec)
    return recommendations

def main() -> None:
    paths = get_run_paths()
    ts = timestamp_now()
    input_file = Path(str(LATEST_DIR / "ai_evidence_latest.json"))
    if not input_file.exists():
        candidate = latest_file_in_dir(paths["ai_dir"], "ai_evidence_*.json")
        if candidate:
            input_file = candidate
    if not input_file.exists():
        raise FileNotFoundError("Nerastas ai_evidence JSON. Pirmiausia paleisk build_final_ai_input.py")

    evidence = load_json(input_file)
    ih = file_hash(input_file)
    recommendations = build_recommendations(evidence, ih)
    output = {
        "report_type": "ai_recommendations",
        "document_type": "ai_recommendations",
        "generated_at": ts,
        "status": "success",
        "model_used": MODEL_USED,
        "prompt_version": PROMPT_VERSION,
        "prompt_template": PROMPT_TEMPLATE,
        "prompt_template_hash": stable_hash({"prompt_template": PROMPT_TEMPLATE, "prompt_version": PROMPT_VERSION}),
        "source_input_file": str(input_file),
        "input_hash": ih,
        "recommendations_count": len(recommendations),
        "recommendations": recommendations,
        "output_hash": stable_hash(recommendations),
        "note": "Tai struktūruotų rekomendacijų sluoksnis, atkuriamas pagal DI įrodymų dokumentą. Jei LOCAL_LLM_ENABLED=1, papildomas laisvo teksto LLM atsakymas generuojamas per local_llm_recommendation_engine.py.",
    }

    out_file = paths["reports_dir"] / f"ai_recommendations_{ts}.json"
    ai_out = paths["ai_dir"] / f"ai_recommendations_{ts}.json"
    save_json(out_file, output)
    save_json(ai_out, output)
    shutil.copy2(ai_out, LATEST_DIR / "ai_recommendations_latest.json")
    print(f"[GERAI] Struktūruotos DI rekomendacijos atkurtos: {out_file}")
    print(f"[INFO] Rekomendacijų skaičius: {len(recommendations)}")


if __name__ == "__main__":
    main()
