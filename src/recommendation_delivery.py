#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
import shutil
import smtplib
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any

from common import BASE_DIR, get_run_paths, load_json, save_json, timestamp_now
from recommendation_pdf import markdown_to_pdf

LATEST_DIR = Path(os.environ.get("NETWORK_THESIS_LATEST_RUN_DIR", str(BASE_DIR / "latest"))).expanduser()
LATEST_DIR.mkdir(parents=True, exist_ok=True)

STATE_DIR = Path(os.environ.get("NETWORK_THESIS_STATE_DIR", str(BASE_DIR / "state"))).expanduser()
STATE_DIR.mkdir(parents=True, exist_ok=True)

PROMPT_VERSION = "openai-api-pdf-email-v2.0-formal-risk-report"
DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name, "")
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def stable_hash_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def stable_hash_text(text: str) -> str:
    return stable_hash_bytes(text.encode("utf-8", errors="replace"))


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def read_latest_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return load_json(path)
    except Exception:
        return {}


OPENAI_GUARD_CACHE = STATE_DIR / "openai_api_guard_latest.json"


SEVERITY_ORDER = {
    "informacinė": 0,
    "informacine": 0,
    "žema": 1,
    "zema": 1,
    "low": 1,
    "vidutinė": 2,
    "vidutine": 2,
    "medium": 2,
    "aukšta": 3,
    "auksta": 3,
    "high": 3,
    "kritinė": 4,
    "kritine": 4,
    "critical": 4,
}


def env_int(name: str, default: int) -> int:
    try:
        return int(str(os.getenv(name, str(default))).strip())
    except Exception:
        return default


def env_float(name: str, default: float) -> float:
    try:
        return float(str(os.getenv(name, str(default))).strip())
    except Exception:
        return default


def canonical_json_hash(data: Any) -> str:
    raw = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8", errors="replace")
    return stable_hash_bytes(raw)


def trim_text(value: Any, max_len: int = 1200) -> Any:
    if isinstance(value, str):
        return value if len(value) <= max_len else value[:max_len] + "... [sutrumpinta]"
    return value


def compact_list(items: Any, limit: int) -> list:
    if not isinstance(items, list):
        return []
    return items[:max(0, limit)]


def compact_host(host: dict) -> dict:
    web = host.get("web") if isinstance(host.get("web"), dict) else {}
    smb = host.get("smb") if isinstance(host.get("smb"), dict) else {}
    ssh = host.get("ssh") if isinstance(host.get("ssh"), dict) else {}
    rdp = host.get("rdp") if isinstance(host.get("rdp"), dict) else {}
    tls = host.get("tls") if isinstance(host.get("tls"), dict) else {}
    snmp = host.get("snmp") if isinstance(host.get("snmp"), dict) else {}
    vulns = host.get("vulnerabilities") if isinstance(host.get("vulnerabilities"), dict) else {}
    change = host.get("change_summary") if isinstance(host.get("change_summary"), dict) else {}
    return {
        "ip": host.get("ip"),
        "asset_id": host.get("asset_id"),
        "asset_identity": host.get("asset_identity", {}),
        "hostname": host.get("hostname"),
        "mac": host.get("mac"),
        "vendor": host.get("vendor"),
        "device_class": host.get("device_class"),
        "state": host.get("state"),
        "tcp_open_ports": compact_list(host.get("tcp_open_ports"), 80),
        "udp_open_ports": compact_list(host.get("udp_open_ports"), 40),
        "service_names": compact_list(host.get("service_names"), 40),
        "smb": {
            "present": smb.get("present"),
            "protocols": compact_list(smb.get("protocols"), 20),
            "smbv1_enabled": smb.get("smbv1_enabled"),
            "signing_disabled": smb.get("signing_disabled"),
            "guest_or_share_auth": smb.get("guest_or_share_auth"),
            "authentication_mode": smb.get("authentication_mode"),
        },
        "ssh": {
            "present": ssh.get("present"),
            "version": ssh.get("version"),
            "weak_algorithms": compact_list(ssh.get("weak_algorithms"), 30),
            "requires_patch_review": ssh.get("requires_patch_review"),
        },
        "rdp": {
            "present": rdp.get("present"),
            "nla_enabled": rdp.get("nla_enabled"),
            "security_layers": compact_list(rdp.get("security_layers"), 10),
            "encryption_level": rdp.get("encryption_level"),
        },
        "web": {
            "present": web.get("present"),
            "ports": compact_list(web.get("ports"), 40),
            "titles": [trim_text(x, 180) for x in compact_list(web.get("titles"), 20)],
            "methods": compact_list(web.get("methods"), 20),
            "servers": compact_list(web.get("servers"), 20),
            "security_headers": compact_list(web.get("security_headers"), 30),
            "login_page_detected": web.get("login_page_detected"),
            "admin_interface_detected": web.get("admin_interface_detected"),
            "technologies": compact_list(web.get("technologies"), 30),
            "scanner_metadata": web.get("scanner_metadata"),
        },
        "tls": {
            "present": tls.get("present"),
            "versions": compact_list(tls.get("versions"), 20),
            "weak_ciphers_present": tls.get("weak_ciphers_present"),
            "certificate_subject": tls.get("certificate_subject"),
            "certificate_issuer": tls.get("certificate_issuer"),
        },
        "snmp": {
            "present": snmp.get("present"),
            "community_strings_detected": compact_list(snmp.get("community_strings_detected"), 20),
            "device_info_flags": compact_list(snmp.get("device_info_flags"), 30),
            "interface_flags": compact_list(snmp.get("interface_flags"), 30),
        },
        "vulnerabilities": {
            "has_known_vulns": vulns.get("has_known_vulns"),
            "vuln_count": vulns.get("vuln_count"),
            "highest_cvss": vulns.get("highest_cvss"),
            "critical_cves": compact_list(vulns.get("critical_cves"), 30),
            "confirmed_cves": compact_list(vulns.get("confirmed_cves"), 30),
            "potential_cves": compact_list(vulns.get("potential_cves"), 30),
        },
        "change_summary": {
            "is_new_host_since_baseline": change.get("is_new_host_since_baseline"),
            "missing_since_baseline": change.get("missing_since_baseline"),
            "new_ports_since_baseline": compact_list(change.get("new_ports_since_baseline"), 40),
            "closed_ports_since_baseline": compact_list(change.get("closed_ports_since_baseline"), 40),
            "changed_services_since_baseline": compact_list(change.get("changed_services_since_baseline"), 40),
        },
        "risk_flags": compact_list(host.get("risk_flags"), 40),
        "official_risk_score": host.get("official_risk_score"),
        "official_risk_level": host.get("official_risk_level"),
        "risk_components": host.get("risk_components"),
        "risk_explanation": [trim_text(x, 300) for x in compact_list(host.get("risk_explanation"), 25)],
        "legacy_priority_score": host.get("legacy_priority_score"),
        "legacy_priority_level": host.get("legacy_priority_level"),
    }


def compact_finding(finding: dict) -> dict:
    return {
        "finding_id": finding.get("finding_id"),
        "rule_id": finding.get("rule_id"),
        "source_module": finding.get("source_module"),
        "ip": finding.get("ip"),
        "asset_id": finding.get("asset_id"),
        "asset_identity": finding.get("asset_identity"),
        "port": finding.get("port"),
        "protocol": finding.get("protocol"),
        "service": finding.get("service"),
        "severity": finding.get("severity"),
        "risk_level": finding.get("risk_level"),
        "risk_score": finding.get("risk_score"),
        "risk_delta": finding.get("risk_delta") or finding.get("risk_increase"),
        "risk_components": finding.get("risk_components"),
        "confidence": finding.get("confidence"),
        "confidence_reason": finding.get("confidence_reason"),
        "finding_status": finding.get("finding_status"),
        "incident_confirmed": finding.get("incident_confirmed"),
        "finding_category": finding.get("finding_category"),
        "title": finding.get("title"),
        "description": trim_text(finding.get("description"), 800),
        "evidence": [trim_text(x, 600) for x in compact_list(finding.get("evidence"), 12)],
        "impact": trim_text(finding.get("impact"), 800),
        "cve": finding.get("cve"),
        "cvss": finding.get("cvss"),
        "cve_based": finding.get("cve_based"),
        "configuration_based": finding.get("configuration_based"),
        "mitre_attack": finding.get("mitre_attack"),
        "cis_controls": finding.get("cis_controls"),
        "scanner_metadata": finding.get("scanner_metadata"),
        "remediation_status": finding.get("remediation_status"),
        "verification_status": finding.get("verification_status"),
        "expected_after_fix_state": finding.get("expected_after_fix_state"),
        "risk_increase": finding.get("risk_increase"),
    }


def compact_evidence(data: dict) -> dict:
    host_limit = env_int("OPENAI_API_MAX_HOSTS", 40)
    finding_limit = env_int("OPENAI_API_MAX_FINDINGS", 80)
    cve_limit = env_int("OPENAI_API_MAX_CVES", 80)

    hosts = as_list(data.get("hosts_for_ai"))
    hosts_sorted = sorted(
        hosts,
        key=lambda h: float(h.get("official_risk_score") or h.get("legacy_priority_score") or 0),
        reverse=True,
    )

    tf = data.get("technical_findings") if isinstance(data.get("technical_findings"), dict) else {}
    compact = {
        "document_type": data.get("document_type"),
        "network": data.get("network"),
        "purpose": data.get("purpose"),
        "executive_summary": data.get("executive_summary"),
        "risk_model": data.get("risk_model"),
        "risk_summary": data.get("risk_summary"),
        "top_risks": compact_list(data.get("top_risks"), 15),
        "hosts_for_ai": [compact_host(h) for h in compact_list(hosts_sorted, host_limit) if isinstance(h, dict)],
        "technical_findings": {
            "normalized_summary": tf.get("normalized_summary"),
            "correlated_summary": tf.get("correlated_summary"),
            "normalized_findings": [compact_finding(x) for x in compact_list(tf.get("normalized_findings"), finding_limit) if isinstance(x, dict)],
            "correlated_findings": [compact_finding(x) for x in compact_list(tf.get("correlated_findings"), finding_limit) if isinstance(x, dict)],
        },
        "cve_epss_kev": {
            "summary": (data.get("cve_epss_kev") or {}).get("summary") if isinstance(data.get("cve_epss_kev"), dict) else None,
            "items": compact_list((data.get("cve_epss_kev") or {}).get("items"), cve_limit) if isinstance(data.get("cve_epss_kev"), dict) else [],
        },
        "endpoint_context": data.get("endpoint_context"),
        "remediation_tracking": data.get("remediation_tracking"),
        "validation_context": data.get("validation_context"),
    }
    return compact


def evidence_need_reasons(data: dict) -> list[str]:
    reasons: list[str] = []
    summary = data.get("executive_summary") if isinstance(data.get("executive_summary"), dict) else {}
    risk_summary = data.get("risk_summary") if isinstance(data.get("risk_summary"), dict) else {}
    by_level = risk_summary.get("by_level") if isinstance(risk_summary.get("by_level"), dict) else {}

    if int(summary.get("kev_count") or 0) > 0:
        reasons.append("aptikta CVE iš CISA KEV katalogo")
    if int(summary.get("cve_count") or 0) > 0:
        reasons.append("aptikta CVE radinių")
    if int(summary.get("critical_or_high_hosts_by_official_score") or 0) > 0:
        reasons.append("yra aukštos arba kritinės rizikos įrenginių pagal oficialų rizikos balą")
    if int(summary.get("high_or_critical_correlated_findings") or 0) > 0:
        reasons.append("yra aukšto arba kritinio prioriteto koreliuotų techninių radinių")
    if int(summary.get("high_or_critical_normalized_findings") or 0) > 0:
        reasons.append("yra aukšto arba kritinio prioriteto normalizuotų techninių radinių")

    for key, value in by_level.items():
        if SEVERITY_ORDER.get(str(key).strip().lower(), -1) >= 3 and int(value or 0) > 0:
            reasons.append(f"rizikos santraukoje yra lygis „{key}“")

    min_score = env_float("OPENAI_API_MIN_RISK_SCORE", 70.0)
    try:
        highest = float(summary.get("highest_risk_score") or 0)
    except Exception:
        highest = 0.0
    if highest >= min_score:
        reasons.append(f"didžiausias rizikos balas {highest:g} pasiekė nustatytą ribą {min_score:g}")

    tf = data.get("technical_findings") if isinstance(data.get("technical_findings"), dict) else {}
    for group_name in ("normalized_findings", "correlated_findings"):
        for finding in as_list(tf.get(group_name)):
            sev = str((finding or {}).get("severity") or "").strip().lower()
            if SEVERITY_ORDER.get(sev, -1) >= 3:
                title = (finding or {}).get("title") or (finding or {}).get("rule_id") or "radinys"
                reasons.append(f"{title}: {sev}")
                break

    # Pašaliname pasikartojimus, bet paliekame pradinę eilę.
    unique: list[str] = []
    for reason in reasons:
        if reason not in unique:
            unique.append(reason)
    return unique


def load_guard_cache() -> dict:
    return read_latest_json(OPENAI_GUARD_CACHE)


def save_guard_cache(cache: dict) -> None:
    cache["updated_at"] = datetime.now().isoformat(timespec="seconds")
    save_json(OPENAI_GUARD_CACHE, cache)


def count_guard_calls(cache: dict, prefix: str) -> int:
    calls = as_list(cache.get("api_calls"))
    return sum(1 for item in calls if str((item or {}).get("date", "")).startswith(prefix))


def prepare_openai_evidence_file(evidence_file: Path, paths: dict, ts: str) -> tuple[Path, dict, str]:
    raw_data = load_json(evidence_file)
    compact = compact_evidence(raw_data)
    evidence_hash = canonical_json_hash(compact)
    compact_path = paths["ai_dir"] / f"openai_compact_evidence_{ts}.json"
    save_json(compact_path, compact)
    latest_compact = LATEST_DIR / "openai_compact_evidence_latest.json"
    shutil.copy2(compact_path, latest_compact)
    return compact_path, raw_data, evidence_hash


def evaluate_openai_guard(evidence_data: dict, evidence_hash: str, api_enabled: bool, api_force: bool, local_failed: bool) -> dict:
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    month = now.strftime("%Y-%m")
    cache = load_guard_cache()
    reasons = evidence_need_reasons(evidence_data)

    result: dict[str, Any] = {
        "allowed": False,
        "reason": "",
        "need_reasons": reasons,
        "evidence_hash": evidence_hash,
        "cache": cache,
    }

    if not api_enabled:
        result["reason"] = "OpenAI API etapas išjungtas."
        return result

    require_approval = env_bool("OPENAI_API_REQUIRE_MANUAL_APPROVAL", True)
    approval_present = env_bool("OPENAI_API_ALLOW_RUN", False)
    if require_approval and not approval_present:
        result["reason"] = "OpenAI API nekviestas, nes nėra vienkartinio leidimo OPENAI_API_ALLOW_RUN=1."
        return result

    api_mode = os.getenv("OPENAI_API_MODE", "when_needed").strip().lower()
    fallback_only_modes = {"fallback", "fallback_only", "only_if_local_failed"}
    if not (local_failed or api_force) and api_mode in fallback_only_modes:
        result["reason"] = "OpenAI API nekviestas, nes vietinis LLM jau grąžino sėkmingą rezultatą, o OPENAI_API_MODE nustatytas kaip fallback."
        return result

    only_when_high_risk = env_bool("OPENAI_API_ONLY_WHEN_NEEDED", True)
    if only_when_high_risk and not reasons and not api_force:
        result["reason"] = "OpenAI API nekviestas, nes įrodymuose nėra aukšto prioriteto požymių pagal nustatytas taisykles."
        return result

    if env_bool("OPENAI_API_SKIP_IF_EVIDENCE_UNCHANGED", True):
        last_success_hash = cache.get("last_success_evidence_hash")
        if last_success_hash == evidence_hash and not api_force:
            result["reason"] = "OpenAI API nekviestas, nes kompaktiniai techniniai įrodymai nepasikeitė nuo paskutinio sėkmingo ChatGPT generavimo."
            return result

    max_day = env_int("OPENAI_API_MAX_CALLS_PER_DAY", 1)
    if max_day >= 0 and count_guard_calls(cache, today) >= max_day and not api_force:
        result["reason"] = f"OpenAI API nekviestas, nes pasiekta dienos riba: {max_day}."
        return result

    max_month = env_int("OPENAI_API_MAX_CALLS_PER_MONTH", 5)
    if max_month >= 0 and count_guard_calls(cache, month) >= max_month and not api_force:
        result["reason"] = f"OpenAI API nekviestas, nes pasiekta mėnesio riba: {max_month}."
        return result

    result["allowed"] = True
    result["reason"] = "OpenAI API leidžiamas: yra vienkartinis leidimas, įrodymai atitinka saugiklius ir neviršytos kvietimų ribos."
    return result


def remember_openai_success(cache: dict, evidence_hash: str, model: str | None, response_id: str | None, need_reasons: list[str]) -> None:
    today = datetime.now().strftime("%Y-%m-%d")
    calls = as_list(cache.get("api_calls"))
    calls.append({
        "date": today,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "evidence_hash": evidence_hash,
        "model": model,
        "response_id": response_id,
        "need_reasons": need_reasons[:20],
    })
    cache["api_calls"] = calls[-200:]
    cache["last_success_evidence_hash"] = evidence_hash
    cache["last_success_at"] = datetime.now().isoformat(timespec="seconds")
    cache["last_success_model"] = model
    save_guard_cache(cache)


def local_llm_failed_or_fallback() -> bool:
    status_file = LATEST_DIR / "llm_recommendations_latest.json"
    status = read_latest_json(status_file).get("status")
    if not status:
        return True
    return status != "success" and status != "success_openai_api_fallback"


def build_api_instructions() -> str:
    return """
Tu esi kibernetinio saugumo analitikas ir rengiantis formalizuotą vidinio tinklo saugumo vertinimo rekomendacijų ataskaitą. Tekstas turi būti aiškus IT sistemų administratoriui ir tinkamas akademinei / techninei demonstracijai.

Bendros taisyklės:
- Atsakyk taisyklinga lietuvių kalba.
- Remkis tik pateiktais techniniais įrodymais ir struktūruotomis rekomendacijomis.
- Nekurk radinių, CVE, portų, hostų, MAC, gamintojų ar incidentų, kurių nėra dokumentuose.
- Jeigu nėra CVE/EPSS/KEV įrašų, aiškiai rašyk: „Radinys yra konfigūracinis, ne CVE pagrįstas.“
- WhatWeb ar kito skenerio versija yra scanner metadata. Jos neskaičiuok kaip taikinio web serverio technologijos arba versijos.
- Endpoint/ESET radinius, kuriems trūksta originalių eilučių peržiūros, žymėk kaip requires_human_review, o ne kaip confirmed_incident.
- Atskirk „patvirtinta“ nuo „reikia patikrinti“.
- Veiksmus formuluok taip, kad administratorius galėtų juos tiesiogiai perkelti į darbų sąrašą.

Privaloma Markdown struktūra:
# Saugumo rekomendacijos
## AI ir audito metaduomenys
Paminėk generatorių, modelį, šaltinio failą, input/output hash, jei jie pateikti.

## Santrauka vadovui
Trumpai paaiškink bendrą rizikos būklę, svarbiausius hostus ir kodėl reikia administratoriaus veiksmų.

## Top rizikų lentelė
Lentelės stulpeliai: Prioritetas, Hostas, Asset ID, Finding ID, Radinys, Risk score, Risk level, Confidence, Statusas, Veiksmas.

## Prioritetiniai veiksmai
Kiekvienai rekomendacijai privaloma pateikti šiuos laukus:
- Recommendation ID
- Finding ID
- Source module
- Host / IP
- Asset ID
- Hostname / MAC / Vendor / Device class, jei pateikta
- Risk score
- Risk level
- Risk delta, jei pateikta
- Risk components, jei pateikta
- Confidence
- Confidence reason
- Finding status
- Incident confirmed
- CVE status: CVE pagrįstas arba konfigūracinis, ne CVE pagrįstas
- MITRE ATT&CK
- CIS Controls
- Evidence used
- Recommended actions
- Expected after fix state
- Remediation status
- Verification status
- Verification steps

## Tinklo filtravimo ir segmentavimo pasiūlymai
Nurodyk konkrečius prievadus, protokolus ir segmentus, kuriuose prieiga turėtų būti ribojama.

## Pakartotinio patikrinimo komandos
Pateik komandas, kurios tiesiogiai patikrina, ar rekomendacija įvykdyta.

## Pastabos dėl neapibrėžtumo ir klaidingų teigiamų radinių
Aiškiai išvardyk, kurie radiniai yra patvirtinti, kurie reikalauja žmogaus peržiūros ir kurie yra tik skenerio metaduomenys.
""".strip()

def build_api_text_prompt(evidence_file: Path, structured_file: Path | None) -> str:
    parts = [
        "Sugeneruok galutines formalizuotas rekomendacijas pagal pridėtą techninių įrodymų failą. Būtina išlaikyti recommendation_id/finding_id/asset_id/risk_score/confidence/finding_status/remediation_status laukus ir top rizikų lentelę.",
        f"Techninių įrodymų failo pavadinimas: {evidence_file.name}",
    ]
    if structured_file and structured_file.exists():
        parts.append(
            "Papildomai naudok toliau pateiktą struktūruotų rekomendacijų JSON santrauką kaip prioritetų ir įrodymų pagrindą."
        )
        try:
            structured = load_json(structured_file)
            recommendations = as_list(structured.get("recommendations"))[:80]
            compact = {
                "document_type": structured.get("document_type"),
                "generated_at": structured.get("generated_at"),
                "run_id": structured.get("run_id"),
                "recommendations_count": len(as_list(structured.get("recommendations"))),
                "recommendations": recommendations,
            }
            parts.append(json.dumps(compact, ensure_ascii=False, separators=(",", ":"))[:60000])
        except Exception as exc:
            parts.append(f"Nepavyko perskaityti struktūruotų rekomendacijų failo: {exc}")
    return "\n\n".join(parts)



def extract_response_text(payload: dict) -> str:
    """Extract text from OpenAI Responses API JSON without requiring the openai SDK."""
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    parts: list[str] = []
    for item in as_list(payload.get("output")):
        if not isinstance(item, dict):
            continue
        for content in as_list(item.get("content")):
            if not isinstance(content, dict):
                continue
            txt = content.get("text") or content.get("output_text")
            if isinstance(txt, str) and txt.strip():
                parts.append(txt.strip())
    if parts:
        return "\n\n".join(parts).strip()
    # Some API variants return a message object.
    for key in ("message", "content"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def call_openai_responses_api(evidence_file: Path, structured_file: Path | None) -> tuple[str, dict]:
    """Call OpenAI/ChatGPT API using only Python standard library.

    This avoids the previous Kali/Raspberry Pi problem where the `openai` Python
    package was missing. The function sends the compact AI evidence JSON inline,
    protected by OPENAI_API_MAX_INPUT_CHARS, and keeps the same guard logic from
    the caller.
    """
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("Nenustatytas OPENAI_API_KEY aplinkos kintamasis.")

    model = os.getenv("OPENAI_API_MODEL", DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL
    timeout = float(os.getenv("OPENAI_API_TIMEOUT", "240"))
    max_input_chars = env_int("OPENAI_API_MAX_INPUT_CHARS", 220000)
    max_output_tokens = env_int("OPENAI_API_MAX_OUTPUT_TOKENS", 7000)

    raw_evidence = evidence_file.read_text(encoding="utf-8", errors="replace")
    truncated = False
    if max_input_chars > 0 and len(raw_evidence) > max_input_chars:
        raw_evidence = raw_evidence[:max_input_chars]
        truncated = True

    user_prompt = build_api_text_prompt(evidence_file, structured_file)
    if truncated:
        user_prompt += (
            "\n\nPastaba sistemai: kompaktinis DI įrodymų JSON sutrumpintas pagal "
            "OPENAI_API_MAX_INPUT_CHARS ribą. Nepridėk radinių, kurių nėra pateiktoje ištraukoje."
        )
    user_prompt += "\n\nKompaktinis techninių įrodymų JSON:\n```json\n" + raw_evidence + "\n```"

    request_payload: dict[str, Any] = {
        "model": model,
        "instructions": build_api_instructions(),
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": user_prompt}
                ],
            }
        ],
    }
    if max_output_tokens > 0:
        request_payload["max_output_tokens"] = max_output_tokens

    req = urllib.request.Request(
        os.getenv("OPENAI_RESPONSES_URL", "https://api.openai.com/v1/responses"),
        data=json.dumps(request_payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response_payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        raise RuntimeError(f"OpenAI API HTTP klaida {exc.code}: {body or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OpenAI API ryšio klaida: {exc.reason}") from exc

    text = extract_response_text(response_payload)
    if not text:
        raise RuntimeError("OpenAI API grąžino tuščią tekstinį atsakymą.")

    meta = {
        "model": model,
        "response_id": response_payload.get("id"),
        "api_transport": "urllib_standard_library",
        "input_chars_sent": len(user_prompt),
        "evidence_truncated": truncated,
        "max_input_chars": max_input_chars,
        "max_output_tokens": max_output_tokens,
    }
    return text, meta


def read_existing_markdown() -> tuple[str, dict]:
    md_path = LATEST_DIR / "llm_recommendations_latest.md"
    json_path = LATEST_DIR / "llm_recommendations_latest.json"
    if md_path.exists():
        return md_path.read_text(encoding="utf-8"), read_latest_json(json_path)

    structured_file = LATEST_DIR / "ai_recommendations_latest.json"
    structured = read_latest_json(structured_file)
    recommendations = as_list(structured.get("recommendations"))
    lines = [
        "# Saugumo rekomendacijos",
        "",
        "**Pastaba:** vietinis LLM ir OpenAI API etapas nebuvo panaudoti arba nepavyko, todėl pateikiama struktūruotų rekomendacijų santrauka.",
        "",
        "## Top rizikų lentelė",
        "",
        "| Prioritetas | Hostas | Asset ID | Finding ID | Rizika | Confidence | Statusas | Veiksmas |",
        "|---:|---|---|---|---|---|---|---|",
        "## Prioritetiniai veiksmai",
    ]
    table_rows = []
    detail_rows = []
    for idx, rec in enumerate(recommendations[:30], start=1):
        table_rows.append(f"| {idx} | {rec.get('host') or ''} | {rec.get('asset_id') or ''} | {rec.get('finding_id') or ''} | {rec.get('risk_level') or rec.get('risk') or rec.get('severity') or ''} | {rec.get('confidence') or ''} | {rec.get('finding_status') or rec.get('remediation_status') or ''} | {rec.get('ai_recommendation') or ''} |")
        detail_rows.extend([
            f"### {idx}. {rec.get('rule_id') or rec.get('finding_id') or 'radinys'}",
            f"- Recommendation ID: {rec.get('recommendation_id')}",
            f"- Finding ID: {rec.get('finding_id')}",
            f"- Source module: {rec.get('source_module')}",
            f"- Įrenginys: {rec.get('host') or rec.get('asset_id')}",
            f"- Asset ID: {rec.get('asset_id')}",
            f"- Rizika: {rec.get('risk_level') or rec.get('risk') or rec.get('severity')} | risk_score: {rec.get('risk_score')} | risk_delta: {rec.get('risk_delta')}",
            f"- Confidence: {rec.get('confidence')} — {rec.get('confidence_reason')}",
            f"- Finding status: {rec.get('finding_status')}",
            f"- CVE statusas: {'CVE pagrįstas' if rec.get('cve_based') else 'konfigūracinis, ne CVE pagrįstas'}",
            f"- MITRE ATT&CK: {rec.get('mitre_attack')}",
            f"- CIS Controls: {rec.get('cis_controls')}",
            f"- Įrodymai: {'; '.join(as_list(rec.get('evidence_used'))[:8])}",
            f"- Ką atlikti: {'; '.join(as_list(rec.get('recommended_actions'))[:8]) or rec.get('ai_recommendation')}",
            f"- Tikėtina būsena po pataisymo: {'; '.join(as_list(rec.get('expected_after_fix_state'))[:8])}",
            f"- Remediation status: {rec.get('remediation_status') or 'open'}",
            f"- Verification status: {rec.get('verification_status') or 'not_checked'}",
            f"- Kaip patikrinti: {'; '.join(as_list(rec.get('verification_steps') or rec.get('verification'))[:5])}",
            "",
        ])
    insert_at = lines.index("## Prioritetiniai veiksmai")
    lines[insert_at:insert_at] = table_rows + [""]
    lines.extend(detail_rows)
    metadata = {
        "status": "fallback_structured_recommendations",
        "generator": "structured_recommendations_without_llm",
        "source_input_file": str(structured_file),
    }
    return "\n".join(lines).rstrip() + "\n", metadata


def save_final_recommendations(markdown_text: str, metadata: dict, status: str, generator: str, paths: dict, ts: str) -> tuple[Path, Path]:
    input_file = Path(metadata.get("source_input_file") or LATEST_DIR / "ai_evidence_latest.json")
    output_hash = stable_hash_text(markdown_text)
    payload = {
        "document_type": "final_recommendations",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "status": status,
        "generator": generator,
        "model_used": metadata.get("model") or metadata.get("model_used"),
        "prompt_version": PROMPT_VERSION,
        "source_input_file": str(input_file),
        "source_input_hash": stable_hash_bytes(input_file.read_bytes()) if input_file.exists() else None,
        "output_hash": output_hash,
        "response": markdown_text,
        "openai_metadata": {k: v for k, v in metadata.items() if k not in {"source_input_file", "response"}},
    }
    json_path = paths["ai_dir"] / f"final_recommendations_{ts}.json"
    md_path = paths["ai_dir"] / f"final_recommendations_{ts}.md"
    save_json(json_path, payload)
    md_path.write_text(markdown_text, encoding="utf-8")
    shutil.copy2(json_path, LATEST_DIR / "final_recommendations_latest.json")
    shutil.copy2(md_path, LATEST_DIR / "final_recommendations_latest.md")

    return json_path, md_path


def generate_pdf(markdown_text: str, metadata: dict, paths: dict, ts: str) -> tuple[Path, Path]:
    pdf_path = paths["reports_dir"] / f"recommendations_{ts}.pdf"
    markdown_to_pdf(markdown_text, pdf_path, metadata=metadata, title="Saugumo rekomendacijos")
    latest_pdf = LATEST_DIR / "recommendations_latest.pdf"
    shutil.copy2(pdf_path, latest_pdf)
    return pdf_path, latest_pdf


def build_email(pdf_path: Path, markdown_text: str, metadata: dict) -> EmailMessage:
    to_addr = env_first("RECOMMENDATION_EMAIL_TO", "SMTP_TO", "EMAIL_TO")
    from_addr = env_first("RECOMMENDATION_EMAIL_FROM", "EMAIL_FROM", "SMTP_FROM", "SMTP_USER", default="network-thesis@localhost")
    subject = os.getenv("RECOMMENDATION_EMAIL_SUBJECT", "Autonominės vidinio tinklo saugumo vertinimo rekomendacijos")
    run_id = metadata.get("run_id") or os.getenv("ASSESSMENT_RUN_ID") or ""

    msg = EmailMessage()
    msg["Subject"] = subject + (f" ({run_id})" if run_id else "")
    msg["From"] = from_addr
    msg["To"] = to_addr or "neuzpildytas-gavejas@example.local"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="network-thesis.local")

    status = str(metadata.get("status") or "")
    generator = str(metadata.get("generator") or "")
    if status == "success_openai_api_fallback" or "openai" in generator.lower():
        source_line = "Rekomendacijų tekstas sugeneruotas naudojant ChatGPT / OpenAI API pagal šio paleidimo techninius įrodymus."
    elif "local_llm" in generator.lower() or status == "success":
        source_line = "Rekomendacijų tekstas parengtas pagal vietinio LLM arba vietinių rekomendacijų rezultatą."
    else:
        source_line = "Rekomendacijų tekstas parengtas pagal vietinius struktūruotus techninius radinius; ChatGPT API šiam PDF nebuvo kviestas."

    body = os.getenv("RECOMMENDATION_EMAIL_BODY") or (
        "Sveiki,\n\n"
        "Prisegama automatinio vidinio tinklo saugumo vertinimo rekomendacijų ataskaita PDF formatu.\n"
        f"{source_line}\n\n"
        "Dokumentą prieš taikant pakeitimus rekomenduojama peržiūrėti administratoriui, nes sistema automatiškai nekeičia tinklo, serverių ar galinių įrenginių konfigūracijos.\n"
    )
    msg.set_content(body)

    preview = markdown_text[:4000]
    html_preview = "<pre style='white-space: pre-wrap; font-family: sans-serif;'>" + preview.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") + "</pre>"
    msg.add_alternative("<html><body>" + html_preview + "</body></html>", subtype="html")

    maintype, subtype = (mimetypes.guess_type(str(pdf_path))[0] or "application/pdf").split("/", 1)
    msg.add_attachment(pdf_path.read_bytes(), maintype=maintype, subtype=subtype, filename=pdf_path.name)
    return msg


def write_eml(msg: EmailMessage, paths: dict, ts: str) -> tuple[Path, Path]:
    eml_path = paths["reports_dir"] / f"recommendations_email_{ts}.eml"
    eml_path.write_bytes(bytes(msg))
    latest_eml = LATEST_DIR / "recommendations_email_latest.eml"
    shutil.copy2(eml_path, latest_eml)
    return eml_path, latest_eml


def send_email(msg: EmailMessage) -> None:
    to_addr = env_first("RECOMMENDATION_EMAIL_TO", "SMTP_TO", "EMAIL_TO")
    smtp_host = env_first("SMTP_HOST", "RECOMMENDATION_SMTP_HOST")
    smtp_port = int(env_first("SMTP_PORT", "RECOMMENDATION_SMTP_PORT", default="587"))
    smtp_user = env_first("SMTP_USER", "RECOMMENDATION_SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD") or os.getenv("RECOMMENDATION_SMTP_PASSWORD") or ""
    if not to_addr:
        raise RuntimeError("Nenustatytas el. pašto gavėjas. Nustatyk RECOMMENDATION_EMAIL_TO arba SMTP_TO.")
    if not smtp_host:
        raise RuntimeError("Nenustatytas SMTP serveris. Nustatyk SMTP_HOST arba RECOMMENDATION_SMTP_HOST.")

    use_ssl = env_bool("SMTP_SSL", False)
    use_starttls = env_bool("SMTP_STARTTLS", True) and not use_ssl

    cls = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    with cls(smtp_host, smtp_port, timeout=float(os.getenv("SMTP_TIMEOUT", "60"))) as smtp:
        if use_starttls:
            smtp.starttls()
        if smtp_user:
            smtp.login(smtp_user, smtp_password)
        smtp.send_message(msg)


def main() -> None:
    paths = get_run_paths()
    ts = timestamp_now()
    evidence_file = Path(os.getenv("AI_EVIDENCE_FILE", str(LATEST_DIR / "ai_evidence_latest.json")))
    structured_file = Path(os.getenv("AI_STRUCTURED_RECOMMENDATIONS_FILE", str(LATEST_DIR / "ai_recommendations_latest.json")))
    if not evidence_file.exists():
        raise FileNotFoundError(f"Nerastas DI įrodymų failas: {evidence_file}")

    compact_evidence_file, evidence_data, evidence_hash = prepare_openai_evidence_file(evidence_file, paths, ts)

    api_enabled = env_bool("OPENAI_API_ENABLED", False) or env_bool("OPENAI_API_FALLBACK_ENABLED", False)
    api_force = env_bool("OPENAI_API_FORCE", False)
    local_failed = local_llm_failed_or_fallback()
    guard = evaluate_openai_guard(evidence_data, evidence_hash, api_enabled, api_force, local_failed)
    should_call_api = bool(guard.get("allowed"))

    status = "success_existing_local_llm"
    generator = "existing_local_llm_or_structured_fallback"
    api_error = None
    api_meta: dict[str, Any] = {
        "source_input_file": str(evidence_file),
        "openai_compact_input_file": str(compact_evidence_file),
        "openai_compact_input_hash": evidence_hash,
        "openai_guard": {k: v for k, v in guard.items() if k != "cache"},
    }

    if should_call_api:
        try:
            print("[INFO] OpenAI/ChatGPT API leidžiamas pagal saugiklius; siunčiamas kompaktinis techninių įrodymų failas.", flush=True)
            for reason in as_list(guard.get("need_reasons"))[:8]:
                print(f"[INFO] API poreikio priežastis: {reason}", flush=True)
            markdown_text, openai_meta = call_openai_responses_api(compact_evidence_file, structured_file if structured_file.exists() else None)
            api_meta.update(openai_meta)
            api_meta["source_input_file"] = str(evidence_file)
            api_meta["openai_compact_input_file"] = str(compact_evidence_file)
            api_meta["openai_compact_input_hash"] = evidence_hash
            api_meta["openai_guard"] = {k: v for k, v in guard.items() if k != "cache"}
            remember_openai_success(
                guard.get("cache") if isinstance(guard.get("cache"), dict) else {},
                evidence_hash,
                api_meta.get("model"),
                api_meta.get("response_id"),
                as_list(guard.get("need_reasons")),
            )
            status = "success_openai_api_fallback"
            generator = "openai_responses_api_guarded_fallback"
            print("[GERAI] OpenAI API sugeneravo rekomendacijas ir saugiklio būsena atnaujinta.", flush=True)
        except Exception as exc:
            api_error = str(exc)
            print(f"[KLAIDA] OpenAI API etapas nepavyko: {api_error}", flush=True)
            markdown_text, existing_meta = read_existing_markdown()
            api_meta.update(existing_meta)
            api_meta["api_error"] = api_error
            status = "fallback_existing_recommendations_after_openai_error"
            generator = "existing_recommendations_after_openai_error"
    else:
        markdown_text, existing_meta = read_existing_markdown()
        api_meta.update(existing_meta)
        api_meta["source_input_file"] = str(evidence_file)
        api_meta["openai_compact_input_file"] = str(compact_evidence_file)
        api_meta["openai_compact_input_hash"] = evidence_hash
        api_meta["openai_guard"] = {k: v for k, v in guard.items() if k != "cache"}
        status = "api_not_called_existing_recommendations"
        generator = "existing_recommendations_openai_guard"
        print(f"[INFO] {guard.get('reason')}", flush=True)
        if api_enabled:
            print("[INFO] PDF generuojamas iš jau turimų vietinių arba struktūruotų rekomendacijų.", flush=True)
        else:
            print("[INFO] OpenAI API etapas išjungtas; PDF generuojamas iš esamų rekomendacijų.", flush=True)

    json_path, md_path = save_final_recommendations(markdown_text, api_meta, status, generator, paths, ts)
    final_meta = read_latest_json(json_path)
    pdf_path, latest_pdf = generate_pdf(markdown_text, final_meta, paths, ts)
    msg = build_email(pdf_path, markdown_text, final_meta)
    eml_path, latest_eml = write_eml(msg, paths, ts)

    email_status = "draft_created"
    email_error = None
    if env_bool("EMAIL_SEND_ENABLED", False):
        try:
            send_email(msg)
            email_status = "sent"
            print(f"[GERAI] Rekomendacijų PDF išsiųstas el. paštu: {env_first('RECOMMENDATION_EMAIL_TO', 'SMTP_TO', 'EMAIL_TO')}", flush=True)
        except Exception as exc:
            email_status = "send_failed"
            email_error = str(exc)
            print(f"[KLAIDA] El. pašto siuntimas nepavyko: {email_error}", flush=True)
            raise
    else:
        print("[INFO] EMAIL_SEND_ENABLED nėra įjungtas; sukurtas .eml juodraštis su PDF priedu.", flush=True)

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "status": status,
        "generator": generator,
        "api_enabled": api_enabled,
        "api_called": should_call_api,
        "api_error": api_error,
        "api_guard": {k: v for k, v in guard.items() if k != "cache"},
        "openai_compact_input_file": str(compact_evidence_file),
        "openai_compact_input_hash": evidence_hash,
        "recommendations_json": str(json_path),
        "recommendations_markdown": str(md_path),
        "recommendations_pdf": str(pdf_path),
        "latest_pdf": str(latest_pdf),
        "email_status": email_status,
        "email_error": email_error,
        "email_draft": str(eml_path),
        "latest_email_draft": str(latest_eml),
    }
    summary_path = paths["reports_dir"] / f"recommendation_delivery_{ts}.json"
    save_json(summary_path, summary)
    shutil.copy2(summary_path, LATEST_DIR / "recommendation_delivery_latest.json")

    print(f"Rekomendacijų JSON: {LATEST_DIR / 'final_recommendations_latest.json'}", flush=True)
    print(f"Rekomendacijų MD: {LATEST_DIR / 'final_recommendations_latest.md'}", flush=True)
    print(f"Rekomendacijų PDF: {latest_pdf}", flush=True)
    print(f"El. laiško .eml juodraštis: {latest_eml}", flush=True)


if __name__ == "__main__":
    main()
