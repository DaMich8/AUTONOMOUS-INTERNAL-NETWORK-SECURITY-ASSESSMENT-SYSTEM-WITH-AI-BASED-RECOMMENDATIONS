#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from common import BASE_DIR, get_run_paths, latest_file_in_dir, load_json, save_json, timestamp_now

LATEST_DIR = Path(os.environ.get("NETWORK_THESIS_LATEST_RUN_DIR", str(BASE_DIR / "latest"))).expanduser()
LATEST_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_MODEL = "qwen2.5:7b-instruct"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
PROMPT_VERSION = "v5.0-formal-risk-asset-report"


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def stable_hash_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def stable_hash_text(text: str) -> str:
    return stable_hash_bytes(text.encode("utf-8", errors="replace"))


def enabled() -> bool:
    return str(os.getenv("LOCAL_LLM_ENABLED", "")).strip().lower() in {"1", "true", "yes", "y", "on"}


def fallback_enabled() -> bool:
    # Praktiniame magistrinio darbo vykdymo procese geriau turėti naudingą automatiškai atkurtą rezultatą,
    # net jei vietinis LLM neatsakė. Griežtam režimui galima nustatyti LOCAL_LLM_STRICT=1.
    return str(os.getenv("LOCAL_LLM_STRICT", "")).strip().lower() not in {"1", "true", "yes", "y", "on"}


def read_input() -> tuple[Path, dict]:
    input_file = Path(os.getenv("AI_EVIDENCE_FILE", str(LATEST_DIR / "ai_evidence_latest.json")))
    if not input_file.exists():
        raise FileNotFoundError(f"Nerastas DI įrodymų failas: {input_file}. Pirmiausia paleisk build_final_ai_input.py")
    with input_file.open("r", encoding="utf-8") as f:
        return input_file, json.load(f)


def severity_rank(level: str | None) -> int:
    return {"kritinė": 4, "aukšta": 3, "vidutinė": 2, "žema": 1}.get(str(level or "").lower(), 0)


def evidence_sort_key(item: dict) -> tuple[int, int, str]:
    return (
        severity_rank(item.get("severity")),
        int(item.get("risk_increase") or 0),
        str(item.get("finding_id") or item.get("rule_id") or ""),
    )


def compact_finding(item: dict) -> dict:
    return {
        "finding_id": item.get("finding_id"),
        "rule_id": item.get("rule_id"),
        "source_module": item.get("source_module"),
        "ip": item.get("ip"),
        "asset_id": item.get("asset_id"),
        "port": item.get("port"),
        "protocol": item.get("protocol"),
        "service": item.get("service"),
        "severity": item.get("severity"),
        "risk_level": item.get("risk_level"),
        "risk_score": item.get("risk_score"),
        "risk_delta": item.get("risk_delta") or item.get("risk_increase"),
        "risk_components": item.get("risk_components"),
        "confidence": item.get("confidence"),
        "confidence_reason": item.get("confidence_reason"),
        "finding_status": item.get("finding_status"),
        "incident_confirmed": item.get("incident_confirmed"),
        "finding_category": item.get("finding_category"),
        "title": item.get("title"),
        "evidence": as_list(item.get("evidence"))[:6],
        "impact": item.get("impact"),
        "scan_status": item.get("scan_status"),
        "risk_increase": item.get("risk_increase"),
        "remediation_status": item.get("remediation_status"),
        "verification_status": item.get("verification_status"),
        "expected_after_fix_state": as_list(item.get("expected_after_fix_state"))[:8],
        "mitre_attack": as_list(item.get("mitre_attack"))[:5],
        "cis_controls": as_list(item.get("cis_controls"))[:8],
        "cve": item.get("cve"),
        "cvss": item.get("cvss"),
        "cve_based": item.get("cve_based"),
        "configuration_based": item.get("configuration_based"),
        "scanner_metadata": item.get("scanner_metadata"),
    }


def compact_endpoint_context(endpoint: dict) -> dict:
    summary = endpoint.get("summary") or {}
    stats = endpoint.get("stats") or {}
    aggregated = endpoint.get("aggregated_findings") or summary.get("aggregated_findings") or []
    win_sample = endpoint.get("high_value_windows_events_sample") or summary.get("high_value_windows_events_sample") or []
    high_eset = endpoint.get("high_value_eset_rows_sample") or summary.get("high_value_eset_rows_sample") or []
    general_eset = endpoint.get("eset_csv_rows_sample") or endpoint.get("eset_csv_rows") or []
    combined_eset = as_list(high_eset)[:10] + [x for x in as_list(general_eset)[:15] if x not in as_list(high_eset)[:10]]
    return {
        "summary": summary,
        "stats": stats,
        "aggregated_findings": as_list(aggregated)[:20],
        "high_value_windows_events_sample": as_list(win_sample)[:10],
        "high_value_eset_rows_sample": as_list(high_eset)[:10],
        "eset_csv_rows_sample": combined_eset[:20],
        "eset_files": as_list(endpoint.get("eset_files"))[:10],
    }


def compact_for_llm(data: dict) -> dict:
    hosts = []
    for h in as_list(data.get("hosts_for_ai"))[:20]:
        if not isinstance(h, dict):
            continue
        hosts.append({
            "ip": h.get("ip"),
            "asset_id": h.get("asset_id"),
            "asset_identity": h.get("asset_identity", {}),
            "hostname": h.get("hostname"),
            "mac": h.get("mac"),
            "vendor": h.get("vendor"),
            "device_class": h.get("device_class"),
            "official_risk_score": h.get("official_risk_score"),
            "official_risk_level": h.get("official_risk_level"),
            "tcp_open_ports": as_list(h.get("tcp_open_ports"))[:30],
            "udp_open_ports": as_list(h.get("udp_open_ports"))[:15],
            "service_names": as_list(h.get("service_names"))[:30],
            "smb": h.get("smb"),
            "ssh": h.get("ssh"),
            "rdp": h.get("rdp"),
            "web": h.get("web"),
            "tls": h.get("tls"),
            "snmp": h.get("snmp"),
            "vulnerabilities": h.get("vulnerabilities"),
            "change_summary": h.get("change_summary"),
            "risk_components": h.get("risk_components"),
            "risk_explanation": as_list(h.get("risk_explanation"))[:8],
        })

    technical = data.get("technical_findings") or {}
    correlated = [compact_finding(x) for x in as_list(technical.get("correlated_findings")) if isinstance(x, dict)]
    normalized = [compact_finding(x) for x in as_list(technical.get("normalized_findings")) if isinstance(x, dict)]
    correlated = sorted(correlated, key=evidence_sort_key, reverse=True)[:40]
    normalized = sorted(normalized, key=evidence_sort_key, reverse=True)[:80]

    epss = data.get("cve_epss_kev") or {}
    epss_items = []
    for item in as_list(epss.get("items"))[:25]:
        if isinstance(item, dict):
            epss_items.append({
                "cve": item.get("cve") or item.get("id"),
                "ip": item.get("ip"),
                "port": item.get("port"),
                "epss": item.get("epss"),
                "kev": item.get("kev"),
                "status": item.get("status"),
                "confidence": item.get("confidence"),
            })

    return {
        "document_type": data.get("document_type"),
        "run_id": data.get("run_id"),
        "network": data.get("network"),
        "executive_summary": data.get("executive_summary"),
        "risk_summary": data.get("risk_summary"),
        "top_risks": as_list(data.get("top_risks"))[:10],
        "hosts": hosts,
        "technical_findings": {
            "correlated_findings": correlated,
            "normalized_findings": normalized,
        },
        "cve_epss_kev": {"summary": epss.get("summary"), "items": epss_items},
        "endpoint_context": compact_endpoint_context(data.get("endpoint_context") or {}),
        "remediation_tracking": {"summary": (data.get("remediation_tracking") or {}).get("summary")},
    }


def enforce_payload_size(compact: dict, max_bytes: int) -> dict:
    """Mažina LLM įvestį iki realiai mažo paketo.

    Ankstesnėje versijoje buvo trumpinamas tik pradinis JSON, bet po instrukcijų
    pridėjimo galutinis promptas vis tiek galėjo viršyti ribas. Ši funkcija turi
    agresyvų paskutinį režimą, kad net Raspberry Pi su 7B modeliu gautų mažą
    ir koncentruotą užduotį, o ne automatiškai pereitų į atsarginį rezultatą.
    """
    work = json.loads(json.dumps(compact, ensure_ascii=False))

    def size(obj: dict) -> int:
        return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    if size(work) <= max_bytes:
        return work

    for norm_limit, corr_limit, host_limit, endpoint_limit, cve_limit in [
        (60, 30, 15, 12, 20),
        (40, 25, 12, 8, 15),
        (25, 15, 10, 5, 10),
        (15, 10, 8, 3, 8),
        (8, 6, 5, 2, 5),
    ]:
        work["technical_findings"]["normalized_findings"] = work["technical_findings"].get("normalized_findings", [])[:norm_limit]
        work["technical_findings"]["correlated_findings"] = work["technical_findings"].get("correlated_findings", [])[:corr_limit]
        work["hosts"] = work.get("hosts", [])[:host_limit]
        work["cve_epss_kev"] = {
            "summary": (work.get("cve_epss_kev") or {}).get("summary"),
            "items": (work.get("cve_epss_kev") or {}).get("items", [])[:cve_limit],
        }
        ep = work.get("endpoint_context") or {}
        work["endpoint_context"] = {
            "summary": ep.get("summary"),
            "stats": ep.get("stats"),
            "aggregated_findings": as_list(ep.get("aggregated_findings"))[:endpoint_limit],
            "high_value_windows_events_sample": as_list(ep.get("high_value_windows_events_sample"))[:endpoint_limit],
            "high_value_eset_rows_sample": as_list(ep.get("high_value_eset_rows_sample"))[:endpoint_limit],
            "eset_csv_rows_sample": as_list(ep.get("eset_csv_rows_sample"))[:endpoint_limit],
            "eset_files": as_list(ep.get("eset_files"))[:endpoint_limit],
        }
        if size(work) <= max_bytes:
            return work

    # Agresyvus režimas: paliekami tik tie laukai, kurie svarbiausi galutinei
    # rekomendacijai. Didelės neapdorotos hostų/Web/ESET struktūros pašalinamos.
    minimal_hosts = []
    for h in as_list(work.get("hosts"))[:4]:
        if not isinstance(h, dict):
            continue
        minimal_hosts.append({
            "ip": h.get("ip"),
            "asset_id": h.get("asset_id"),
            "asset_identity": h.get("asset_identity", {}),
            "hostname": h.get("hostname"),
            "mac": h.get("mac"),
            "vendor": h.get("vendor"),
            "device_class": h.get("device_class"),
            "official_risk_score": h.get("official_risk_score"),
            "official_risk_level": h.get("official_risk_level"),
            "tcp_open_ports": as_list(h.get("tcp_open_ports"))[:12],
            "service_names": as_list(h.get("service_names"))[:12],
            "risk_components": h.get("risk_components"),
        })

    ep = work.get("endpoint_context") or {}
    ep_summary = ep.get("summary") or {}
    ep_stats = ep.get("stats") or {}
    minimal = {
        "document_type": work.get("document_type"),
        "run_id": work.get("run_id"),
        "network": work.get("network"),
        "executive_summary": work.get("executive_summary"),
        "risk_summary": work.get("risk_summary"),
        "hosts": minimal_hosts,
        "technical_findings": {
            "correlated_findings": work.get("technical_findings", {}).get("correlated_findings", [])[:5],
            "normalized_findings": work.get("technical_findings", {}).get("normalized_findings", [])[:8],
        },
        "cve_epss_kev": {
            "summary": (work.get("cve_epss_kev") or {}).get("summary"),
            "items": (work.get("cve_epss_kev") or {}).get("items", [])[:4],
        },
        "endpoint_context": {
            "summary": {
                "total_events": ep_summary.get("total_events"),
                "windows_events_count": ep_summary.get("windows_events_count"),
                "eset_csv_rows_count": ep_summary.get("eset_csv_rows_count"),
                "eset_file_summaries_count": ep_summary.get("eset_file_summaries_count"),
            },
            "stats": {
                "eset_csv_rows_in_context": ep_stats.get("eset_csv_rows_in_context"),
                "legacy_eset_csv_rows_in_context": ep_stats.get("legacy_eset_csv_rows_in_context"),
                "windows_events_in_context": ep_stats.get("windows_events_in_context"),
            },
            "aggregated_findings": as_list(ep.get("aggregated_findings"))[:5],
            "high_value_eset_rows_sample": as_list(ep.get("high_value_eset_rows_sample"))[:3],
        },
        "remediation_tracking": work.get("remediation_tracking"),
    }

    if size(minimal) <= max_bytes:
        return minimal

    # Paskutinis garantuotas režimas: tik santraukos ir top radiniai.
    minimal["hosts"] = minimal.get("hosts", [])[:2]
    minimal["technical_findings"]["correlated_findings"] = minimal["technical_findings"].get("correlated_findings", [])[:3]
    minimal["technical_findings"]["normalized_findings"] = minimal["technical_findings"].get("normalized_findings", [])[:4]
    minimal["endpoint_context"].pop("high_value_eset_rows_sample", None)
    minimal["endpoint_context"].pop("aggregated_findings", None)
    minimal["cve_epss_kev"]["items"] = minimal["cve_epss_kev"].get("items", [])[:2]
    return minimal


def trim_prompt_to_limit(compact: dict, max_prompt_bytes: int) -> tuple[dict, str]:
    """Iteratyviai trumpina ne tik JSON, bet ir patį galutinį promptą."""
    prompt = build_prompt(compact)
    if len(prompt.encode("utf-8")) <= max_prompt_bytes:
        return compact, prompt

    for payload_limit in (9000, 6500, 4500, 3000, 2000, 1400):
        compact = enforce_payload_size(compact, payload_limit)
        prompt = build_prompt(compact)
        if len(prompt.encode("utf-8")) <= max_prompt_bytes:
            return compact, prompt

    # Jei ilgos instrukcijos vis dar neleidžia tilpti, naudojama trumpesnė
    # instrukcija, bet struktūra išlieka pakankama magistrinio atsekamumui.
    evidence_text = json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
    prompt = (
        "Tu esi kibernetinio saugumo analitikas. Remkis tik pateiktais JSON techniniais įrodymais. "
        "Atsakyk taisyklinga lietuvių kalba. Pateik: 1) santrauką, 2) top rizikų lentelę, "
        "3) prioritetinius veiksmus su recommendation_id, finding_id, asset_id, risk_score, confidence, finding_status, "
        "evidence, taisymo veiksmais, expected_after_fix_state ir patikrinimo komandomis. "
        "Nekurk radinių, kurių nėra įrodymuose. WhatWeb versija yra skenerio metaduomuo, ne taikinio technologija. JSON įrodymai: " + evidence_text
    )
    return compact, prompt

def build_prompt(compact: dict) -> str:
    evidence_text = json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
    return f"""
Tu esi kibernetinio saugumo analitikas. Tau pateikiamas automatinio vidinio tinklo saugumo vertinimo techninių įrodymų dokumentas.

Svarbios taisyklės:
- Rekomendacijas generuok tik pagal pateiktus techninius įrodymus.
- Nekurk radinių, IP adresų, prievadų, CVE ar įrenginių, kurių nėra įrodymuose.
- Kiekvienoje rekomendacijoje naudok: recommendation_id, finding_id, source_module, host/ip, asset_id, risk_score, risk_level, risk_delta, risk_components, confidence, confidence_reason, finding_status, evidence_used, recommended_actions, verification_steps, expected_after_fix_state, remediation_status ir verification_status.
- WhatWeb arba kito skenerio versija yra scanner metadata, ne taikinio web serverio technologija.
- Jei CVE/EPSS/KEV nėra, aiškiai rašyk, kad radinys yra konfigūracinis, ne CVE pagrįstas.
- Endpoint/ESET radinius, kurie gali turėti administracinį paaiškinimą, žymėk kaip requires_human_review ir incident_confirmed=false.
- Įtrauk MITRE ATT&CK ir CIS Controls kontekstą, jei jis pateiktas įrodymuose.
- Atsakyk taisyklinga lietuvių kalba, praktiškai ir konkrečiai.
- Tekstas turi būti suprantamas IT sistemų administratoriui.

Privaloma struktūra:

# Saugumo rekomendacijos

## Santrauka vadovui
- Bendra išvada:
- Aptiktų įrenginių skaičius:
- Svarbiausi radiniai:
- CVE / KEV būsena:
- Endpoint / ESET būsena:

## Top rizikų lentelė
Naudok lentelę su stulpeliais: Prioritetas, Hostas, Asset ID, Finding ID, Radinys, Risk score, Risk level, Confidence, Statusas, Veiksmas.

## Prioritetiniai veiksmai
Kiekvienai rekomendacijai pateik:
- Recommendation ID:
- Finding ID:
- Source module:
- Įrenginys:
- Asset ID:
- Rizikos balas ir lygis:
- Rizikos komponentai:
- Confidence ir confidence_reason:
- Finding status:
- Incident confirmed:
- CVE statusas:
- MITRE ATT&CK:
- CIS Controls:
- Techniniai įrodymai:
- Ką atlikti:
- Tikėtina būsena po pataisymo:
- Remediation status:
- Verification status:
- Kaip patikrinti:

## Tinklo filtravimo ir segmentavimo pasiūlymai
- Nurodyk konkrečius prievadus, protokolus ir segmentus, kuriuose prieiga turėtų būti ribojama.

## Pakartotinio patikrinimo komandos
- Pateik nmap arba kitų naudotų įrankių komandas, kurios tiesiogiai patikrina radinius.

## Pastabos dėl neapibrėžtumo
- Aiškiai atskirk patvirtintus konfigūracinius radinius, CVE kandidatus, endpoint įvykius, kuriems reikia žmogaus peržiūros, ir skenerio metaduomenis.

Techniniai įrodymai:
```json
{evidence_text}
```
""".strip()

def call_ollama(model: str, prompt: str, timeout: int) -> dict:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": 0,
        "options": {
            "temperature": float(os.getenv("LOCAL_LLM_TEMPERATURE", "0.1")),
            "top_p": float(os.getenv("LOCAL_LLM_TOP_P", "0.8")),
            "num_predict": int(os.getenv("LOCAL_LLM_NUM_PREDICT", "900")),
            "num_ctx": int(os.getenv("LOCAL_LLM_NUM_CTX", "4096")),
        },
    }
    req = urllib.request.Request(
        os.getenv("OLLAMA_GENERATE_URL", DEFAULT_OLLAMA_URL),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        raise RuntimeError(f"Ollama HTTP klaida {exc.code}: {body or exc.reason}") from exc


def read_structured_recommendations() -> dict | None:
    path = Path(os.getenv("AI_STRUCTURED_RECOMMENDATIONS_FILE", str(LATEST_DIR / "ai_recommendations_latest.json")))
    if not path.exists():
        paths = get_run_paths()
        candidate = latest_file_in_dir(paths["reports_dir"], "ai_recommendations_*.json")
        if candidate:
            path = candidate
    if not path.exists():
        return None
    try:
        data = load_json(path)
        data["_source_file"] = str(path)
        return data
    except Exception:
        return None


def build_structured_fallback_markdown(evidence: dict, structured: dict | None, reason: str) -> str:
    summary = evidence.get("executive_summary") or {}
    lines = [
        "# Galutinės rekomendacijos",
        "",
        "**Pastaba:** vietinis Ollama LLM etapas nepavyko, todėl pateikiama automatiškai atkurta struktūruotų rekomendacijų santrauka iš `ai_recommendation_engine.py`.",
        f"Priežastis: `{reason}`",
        "",
        "## Saugumo vertinimo santrauka",
    ]
    for key, value in summary.items():
        lines.append(f"- {key}: {value}")

    recommendations = []
    if structured:
        recommendations = as_list(structured.get("recommendations"))
    lines.extend(["", "## Top rizikų lentelė", "", "| Prioritetas | Hostas | Asset ID | Finding ID | Rizika | Confidence | Statusas | Veiksmas |", "|---:|---|---|---|---|---|---|---|"])
    for idx, rec in enumerate(recommendations[:10], start=1):
        lines.append(f"| {idx} | {rec.get('host') or ''} | {rec.get('asset_id') or ''} | {rec.get('finding_id') or ''} | {rec.get('risk_level') or rec.get('risk') or rec.get('severity') or ''} | {rec.get('confidence') or ''} | {rec.get('finding_status') or rec.get('remediation_status') or ''} | {rec.get('ai_recommendation') or ''} |")
    lines.extend(["", "## Prioritetiniai veiksmai"])
    if not recommendations:
        lines.append("- Struktūruotų rekomendacijų failas nerastas. Patikrink, ar sėkmingai įvykdytas `ai_recommendation_engine.py` etapas.")
    for idx, rec in enumerate(recommendations[:20], start=1):
        evidence_used = "; ".join(as_list(rec.get("evidence_used"))[:6])
        verification = "; ".join(as_list(rec.get("verification"))[:5])
        lines.extend([
            f"### {idx}. {rec.get('rule_id') or rec.get('finding_id') or 'radinys'}",
            f"- Recommendation ID: {rec.get('recommendation_id')}",
            f"- Finding ID: {rec.get('finding_id')}",
            f"- Source module: {rec.get('source_module')}",
            f"- Prioritetas / rizika: {rec.get('risk_level') or rec.get('risk') or rec.get('severity')} | risk_score: {rec.get('risk_score')} | risk_delta: {rec.get('risk_delta')}",
            f"- Įrenginys: {rec.get('host') or rec.get('asset_id')}",
            f"- Asset ID: {rec.get('asset_id')}",
            f"- Finding status: {rec.get('finding_status')}",
            f"- CVE statusas: {'CVE pagrįstas' if rec.get('cve_based') else 'konfigūracinis, ne CVE pagrįstas'}",
            f"- MITRE ATT&CK: {rec.get('mitre_attack')}",
            f"- CIS Controls: {rec.get('cis_controls')}",
            f"- Techniniai įrodymai: {evidence_used}",
            f"- Ką atlikti: {'; '.join(as_list(rec.get('recommended_actions'))[:8]) or rec.get('ai_recommendation')}",
            f"- Tikėtina būsena po pataisymo: {'; '.join(as_list(rec.get('expected_after_fix_state'))[:8])}",
            f"- Remediation status: {rec.get('remediation_status') or 'open'}",
            f"- Verification status: {rec.get('verification_status') or 'not_checked'}",
            f"- Kaip patikrinti: {verification}",
            f"- Pasitikėjimo lygis: {rec.get('confidence')} — {rec.get('confidence_reason')}",
            "",
        ])
    lines.extend([
        "## Pakartotinio patikrinimo komandos",
        "- Vykdyti `python3 full_assessment.py` po pataisymų.",
        "- Papildomai tikrinti konkrečius portus ir protokolus pagal kiekvienos rekomendacijos `verification` lauką.",
    ])
    return "\n".join(lines).rstrip() + "\n"


def write_disabled_output(paths: dict, input_file: Path) -> None:
    ts = timestamp_now()
    input_hash = stable_hash_bytes(input_file.read_bytes())
    out = {
        "document_type": "llm_recommendations",
        "generated_at": ts,
        "status": "skipped",
        "reason": "LOCAL_LLM_ENABLED nėra įjungtas",
        "source_input_file": str(input_file),
        "source_input_hash": input_hash,
        "model_used": None,
        "prompt_version": PROMPT_VERSION,
        "response": "LLM rekomendacijos negeneruotos, nes LOCAL_LLM_ENABLED nėra įjungtas.",
    }
    json_path = paths["ai_dir"] / f"llm_recommendations_{ts}.json"
    md_path = paths["ai_dir"] / f"llm_recommendations_{ts}.md"
    save_json(json_path, out)
    md_path.write_text(out["response"] + "\n", encoding="utf-8")
    shutil.copy2(json_path, LATEST_DIR / "llm_recommendations_latest.json")
    shutil.copy2(md_path, LATEST_DIR / "llm_recommendations_latest.md")
    print(f"LLM rekomendacijos praleistos: {out['reason']}", flush=True)


def main() -> None:
    paths = get_run_paths()
    input_file, data = read_input()

    if not enabled():
        write_disabled_output(paths, input_file)
        return

    ts = timestamp_now()
    model = os.getenv("LOCAL_LLM_MODEL", DEFAULT_MODEL)
    timeout = int(os.getenv("LOCAL_LLM_TIMEOUT", "180"))
    max_input_bytes = int(os.getenv("LOCAL_LLM_MAX_INPUT_BYTES", "12000"))
    max_prompt_bytes = int(os.getenv("LOCAL_LLM_MAX_PROMPT_BYTES", "18000"))
    hard_prompt_limit = int(os.getenv("LOCAL_LLM_HARD_PROMPT_LIMIT_BYTES", "26000"))

    compact = enforce_payload_size(compact_for_llm(data), max_input_bytes)
    compact, prompt = trim_prompt_to_limit(compact, max_prompt_bytes)

    print(f"[INFO] Kreipiamasi į Ollama modelį: {model}", flush=True)
    print("[INFO] LLM įvestis: techniniai įrodymai iš ai_evidence_latest.json, be iš anksto sugeneruotų galutinių rekomendacijų.", flush=True)
    print(f"[INFO] LLM prompt dydis: {len(prompt.encode('utf-8'))} baitų", flush=True)
    print(f"[INFO] LLM timeout: {timeout} s; prompt riba: {max_prompt_bytes} baitų; hard riba: {hard_prompt_limit} baitų", flush=True)

    result: dict[str, Any] = {}
    response = ""
    status = "success"
    error: str | None = None
    used_fallback = False

    try:
        if len(prompt.encode("utf-8")) > hard_prompt_limit:
            raise TimeoutError(
                f"Promptas per didelis vietiniam LLM etapui ({len(prompt.encode('utf-8'))} baitų > {hard_prompt_limit}). "
                "Naudojamas atsarginis struktūruotas rezultatas, kad vykdymo grandinė nebūtų blokuojama."
            )
        result = call_ollama(model, prompt, timeout)
        response = str(result.get("response", "")).strip()
        if not response:
            status = "empty_response"
            error = "Ollama grąžino tuščią response lauką."
    except Exception as exc:
        status = "error"
        error = str(exc)

    if status != "success":
        print(f"[KLAIDA] Ollama LLM etapas nepavyko: {error or status}", flush=True)
        if fallback_enabled():
            structured = read_structured_recommendations()
            response = build_structured_fallback_markdown(data, structured, error or status)
            status = "fallback_structured_recommendations"
            used_fallback = True
            print("[ĮSPĖJIMAS] Vietoje LLM atsakymo naudojama automatiškai atkurta struktūruotų rekomendacijų santrauka.", flush=True)

    input_hash = stable_hash_bytes(input_file.read_bytes())
    prompt_hash = stable_hash_text(prompt)
    output_hash = stable_hash_text(response)
    prompt_path = paths["ai_dir"] / f"llm_prompt_{ts}.txt"
    prompt_path.write_text(prompt, encoding="utf-8")

    output = {
        "document_type": "llm_recommendations",
        "generated_at": ts,
        "status": status,
        "generator": "ollama_local_llm" if not used_fallback else "structured_fallback_after_ollama_failure",
        "model_used": model,
        "prompt_version": PROMPT_VERSION,
        "source_input_file": str(input_file),
        "source_input_hash": input_hash,
        "prompt_hash": prompt_hash,
        "prompt_saved_file": str(prompt_path),
        "output_hash": output_hash,
        "evidence_pack_size_bytes": len(json.dumps(compact, ensure_ascii=False).encode("utf-8")),
        "prompt_size_bytes": len(prompt.encode("utf-8")),
        "max_input_bytes": max_input_bytes,
        "max_prompt_bytes": max_prompt_bytes,
        "hard_prompt_limit_bytes": hard_prompt_limit,
        "response": response,
        "error": error,
        "fallback_used": used_fallback,
        "strict_mode": not fallback_enabled(),
        "ollama_metadata": {k: v for k, v in result.items() if k != "response"},
    }

    json_path = paths["ai_dir"] / f"llm_recommendations_{ts}.json"
    md_path = paths["ai_dir"] / f"llm_recommendations_{ts}.md"
    save_json(json_path, output)
    md_path.write_text(response + "\n", encoding="utf-8")

    shutil.copy2(json_path, LATEST_DIR / "llm_recommendations_latest.json")
    shutil.copy2(md_path, LATEST_DIR / "llm_recommendations_latest.md")

    print(f"LLM rekomendacijos JSON: {LATEST_DIR / 'llm_recommendations_latest.json'}", flush=True)
    print(f"LLM rekomendacijos MD: {LATEST_DIR / 'llm_recommendations_latest.md'}", flush=True)
    print(f"[INFO] LLM rekomendacijų statusas: {status}", flush=True)

    if status != "success" and not used_fallback:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
