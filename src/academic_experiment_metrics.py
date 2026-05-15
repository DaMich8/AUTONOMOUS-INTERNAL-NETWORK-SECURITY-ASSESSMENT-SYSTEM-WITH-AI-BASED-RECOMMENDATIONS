#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from common import BASE_DIR, RUNS_DIR, get_run_paths, latest_file_in_dir, load_json, save_json, timestamp_now

REQUIRED_RECOMMENDATION_FIELDS = [
    "recommendation_id",
    "finding_id",
    "source_module",
    "host",
    "asset_id",
    "risk_score",
    "risk_level",
    "risk_components",
    "confidence",
    "finding_status",
    "evidence_used",
    "recommended_actions",
    "verification_steps",
    "expected_after_fix_state",
    "remediation_status",
]

STRUCTURE_WEIGHT = {
    "recommendation_id": 8,
    "finding_id": 8,
    "source_module": 4,
    "host": 4,
    "asset_id": 6,
    "risk_score": 8,
    "risk_level": 6,
    "risk_components": 6,
    "confidence": 7,
    "finding_status": 7,
    "evidence_used": 8,
    "recommended_actions": 8,
    "verification_steps": 8,
    "expected_after_fix_state": 7,
    "remediation_status": 5,
}

SEVERITY_ORDER = {"informacinė": 0, "žema": 1, "vidutinė": 2, "aukšta": 3, "kritinė": 4, "low": 1, "medium": 2, "high": 3, "critical": 4}


def as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def sha256_file(path: Path | None) -> str | None:
    if not path or not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json_safely(path: Path | None) -> Any:
    if not path or not path.exists():
        return None
    try:
        return load_json(path)
    except Exception:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None


def latest_run_latest_dir() -> Path:
    env_dir = os.environ.get("NETWORK_THESIS_LATEST_RUN_DIR", "").strip()
    if env_dir:
        p = Path(env_dir).expanduser()
        p.mkdir(parents=True, exist_ok=True)
        return p
    paths = get_run_paths()
    p = paths["run_dir"] / "latest"
    p.mkdir(parents=True, exist_ok=True)
    return p


def latest_any(pattern: str) -> Path | None:
    files = sorted(RUNS_DIR.glob(pattern))
    return files[-1] if files else None


def current_files(paths: dict, latest_dir: Path) -> dict[str, Path | None]:
    files = {
        "assessment": latest_file_in_dir(paths["reports_dir"], "assessment_*.json") or latest_any("**/reports/assessment_*.json"),
        "risk_scores": latest_file_in_dir(paths["reports_dir"], "risk_scores_*.json") or latest_any("**/reports/risk_scores_*.json"),
        "correlated_findings": latest_file_in_dir(paths["reports_dir"], "correlated_findings_*.json") or latest_any("**/reports/correlated_findings_*.json"),
        "normalized_findings": latest_file_in_dir(paths["reports_dir"], "normalized_findings_*.json") or latest_any("**/reports/normalized_findings_*.json"),
        "pipeline_audit": latest_file_in_dir(paths["reports_dir"], "pipeline_audit_*.json") or latest_any("**/reports/pipeline_audit_*.json"),
        "validation_metrics": latest_file_in_dir(paths["reports_dir"], "validation_metrics_*.json") or latest_any("**/reports/validation_metrics_*.json"),
        "risk_sensitivity": latest_file_in_dir(paths["reports_dir"], "risk_sensitivity_*.json") or latest_any("**/reports/risk_sensitivity_*.json"),
        "power_summary_csv": latest_file_in_dir(paths["reports_dir"], "power_summary_*.csv") or latest_any("**/reports/power_summary_*.csv"),
        "ai_evidence": latest_dir / "ai_evidence_latest.json",
        "ai_recommendations": latest_dir / "ai_recommendations_latest.json",
        "llm_recommendations": latest_dir / "llm_recommendations_latest.json",
        "final_recommendations": latest_dir / "final_recommendations_latest.json",
        "final_recommendations_md": latest_dir / "final_recommendations_latest.md",
        "recommendations_pdf": latest_dir / "recommendations_latest.pdf",
        "delivery_summary": latest_dir / "recommendation_delivery_latest.json",
    }
    return files


def extract_recommendations(data: Any) -> list[dict]:
    if not isinstance(data, dict):
        return []
    candidates = [
        data.get("recommendations"),
        data.get("final_recommendations"),
        data.get("items"),
        data.get("prioritized_recommendations"),
    ]
    for c in candidates:
        if isinstance(c, list):
            return [x for x in c if isinstance(x, dict)]
    # Kai kurie LLM failai turi tekstą, bet neturi struktūruotų rec. Tokiu atveju grąžiname tuščią sąrašą.
    return []


def normalize_rec_fields(rec: dict) -> dict:
    """Leidžia vertinti ir senesnius, ir naujesnius rekomendacijų formatus."""
    out = dict(rec)
    if "host" not in out and "ip" in out:
        out["host"] = out.get("ip")
    if "evidence_used" not in out:
        out["evidence_used"] = out.get("evidence") or out.get("technical_evidence") or []
    if "recommended_actions" not in out:
        actions = out.get("recommended_actions") or out.get("actions") or out.get("recommended_fix") or out.get("recommendation")
        out["recommended_actions"] = as_list(actions) if actions else []
    if "verification_steps" not in out:
        steps = out.get("verification_steps") or out.get("verification") or out.get("validation") or out.get("retest_commands")
        out["verification_steps"] = as_list(steps) if steps else []
    if "expected_after_fix_state" not in out:
        out["expected_after_fix_state"] = out.get("expected_state") or out.get("expected_after_fix") or []
    if "remediation_status" not in out:
        out["remediation_status"] = out.get("status") or "open"
    if "risk_level" not in out:
        out["risk_level"] = out.get("severity") or out.get("priority")
    if "risk_components" not in out:
        out["risk_components"] = out.get("risk_breakdown") or {}
    return out


def non_empty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def recommendation_quality(recommendations: list[dict]) -> dict:
    recs = [normalize_rec_fields(r) for r in recommendations]
    total = len(recs)
    field_counts = Counter()
    weighted_total = sum(STRUCTURE_WEIGHT.values())
    scores = []
    evidence_counts = []
    action_counts = []
    verification_counts = []
    mitre_count = 0
    cis_count = 0
    status_counter = Counter()
    confidence_counter = Counter()
    risk_level_counter = Counter()

    for rec in recs:
        score = 0
        for field in REQUIRED_RECOMMENDATION_FIELDS:
            if non_empty(rec.get(field)):
                field_counts[field] += 1
                score += STRUCTURE_WEIGHT.get(field, 1)
        scores.append(round((score / weighted_total) * 100, 2) if weighted_total else 0)
        evidence_counts.append(len(as_list(rec.get("evidence_used"))))
        action_counts.append(len(as_list(rec.get("recommended_actions"))))
        verification_counts.append(len(as_list(rec.get("verification_steps"))))
        if non_empty(rec.get("mitre_attack")):
            mitre_count += 1
        if non_empty(rec.get("cis_controls")):
            cis_count += 1
        status_counter[str(rec.get("finding_status") or "unknown")] += 1
        confidence_counter[str(rec.get("confidence") or "unknown")] += 1
        risk_level_counter[str(rec.get("risk_level") or "unknown")] += 1

    return {
        "recommendation_count": total,
        "required_field_coverage_percent": {
            field: round((field_counts[field] / total) * 100, 2) if total else 0.0
            for field in REQUIRED_RECOMMENDATION_FIELDS
        },
        "structural_quality_score_avg": round(sum(scores) / total, 2) if total else 0.0,
        "structural_quality_score_min": min(scores) if scores else 0.0,
        "evidence_items_avg": round(sum(evidence_counts) / total, 2) if total else 0.0,
        "recommended_actions_avg": round(sum(action_counts) / total, 2) if total else 0.0,
        "verification_steps_avg": round(sum(verification_counts) / total, 2) if total else 0.0,
        "mitre_mapping_coverage_percent": round((mitre_count / total) * 100, 2) if total else 0.0,
        "cis_mapping_coverage_percent": round((cis_count / total) * 100, 2) if total else 0.0,
        "finding_status_distribution": dict(status_counter),
        "confidence_distribution": dict(confidence_counter),
        "risk_level_distribution": dict(risk_level_counter),
    }


def extract_text_metrics(md_path: Path | None) -> dict:
    if not md_path or not md_path.exists():
        return {"exists": False}
    text = md_path.read_text(encoding="utf-8", errors="replace")
    words = re.findall(r"\w+", text, flags=re.UNICODE)
    commands = re.findall(r"(?:nmap|sslscan|whatweb|nikto|curl|smbclient|rpcclient)\b[^\n`]*", text, flags=re.IGNORECASE)
    sections = re.findall(r"^#{1,4}\s+(.+)$", text, flags=re.MULTILINE)
    return {
        "exists": True,
        "characters": len(text),
        "words": len(words),
        "sections_count": len(sections),
        "verification_command_mentions": len(commands),
        "has_top_risk_table": "|" in text and ("Rizik" in text or "risk" in text.lower()),
        "has_uncertainty_section": any(x in text.lower() for x in ["neapibrėž", "klaiding", "false positive"]),
    }


def parse_power_summary(csv_path: Path | None) -> dict:
    if not csv_path or not csv_path.exists():
        return {}
    try:
        rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", errors="replace")))
        if rows:
            row = rows[-1]
            return {k: _num(v) for k, v in row.items()}
    except Exception:
        return {"error": "Nepavyko nuskaityti power_summary CSV"}
    return {}


def _num(value: Any) -> Any:
    if value is None:
        return None
    s = str(value).strip()
    if s == "":
        return ""
    try:
        if "." in s:
            return float(s)
        return int(s)
    except Exception:
        return s


def summarize_assessment(assessment: dict | None, evidence: dict | None, risk_scores: dict | None) -> dict:
    hosts = as_list((assessment or {}).get("hosts"))
    evidence_summary = (evidence or {}).get("executive_summary") or (evidence or {}).get("summary") or {}
    risk_items = as_list((risk_scores or {}).get("hosts") or (risk_scores or {}).get("host_scores"))
    scores = []
    for item in risk_items:
        try:
            scores.append(float(item.get("risk_score", 0) or 0))
        except Exception:
            pass
    return {
        "total_hosts": evidence_summary.get("total_hosts") or len(hosts),
        "hosts_with_open_tcp_ports": evidence_summary.get("hosts_with_open_tcp_ports"),
        "open_tcp_ports_total": evidence_summary.get("open_tcp_ports_total"),
        "normalized_findings_count": evidence_summary.get("normalized_findings_count"),
        "correlated_findings_count": evidence_summary.get("correlated_findings_count"),
        "cve_count": evidence_summary.get("cve_count"),
        "kev_count": evidence_summary.get("kev_count"),
        "endpoint_events_count": evidence_summary.get("endpoint_events_count"),
        "highest_risk_score": max(scores) if scores else evidence_summary.get("highest_risk_score"),
        "average_risk_score": round(sum(scores) / len(scores), 2) if scores else None,
        "risk_score_items": len(scores),
    }


def pipeline_summary(pipeline: dict | None) -> dict:
    if not isinstance(pipeline, dict):
        return {}
    summary = pipeline.get("summary") or {}
    steps = as_list(pipeline.get("steps"))
    durations = [float(s.get("duration_seconds", 0) or 0) for s in steps if isinstance(s, dict)]
    failed = [s for s in steps if isinstance(s, dict) and str(s.get("status")) not in {"success", "skipped"}]
    return {
        "pipeline_health_percent": summary.get("pipeline_health_percent"),
        "total_steps": summary.get("total_steps") or len(steps),
        "successful_steps": summary.get("successful_steps"),
        "failed_or_warn_steps": len(failed),
        "measured_duration_seconds": round(sum(durations), 2) if durations else None,
    }


def validation_summary(validation: dict | None) -> dict:
    if not isinstance(validation, dict):
        return {}
    summary = validation.get("summary") or {}
    return {
        "enabled_scenarios": summary.get("enabled_scenarios", 0),
        "tp": summary.get("tp", 0),
        "fp": summary.get("fp", 0),
        "fn": summary.get("fn", 0),
        "precision": summary.get("precision", 0),
        "recall": summary.get("recall", 0),
        "f1": summary.get("f1", 0),
    }


def delivery_summary(delivery: dict | None) -> dict:
    if not isinstance(delivery, dict):
        return {}
    openai = delivery.get("openai_api") or delivery.get("api") or {}
    if not isinstance(openai, dict):
        openai = {}
    return {
        "generator": delivery.get("generator") or delivery.get("source_generator") or delivery.get("recommendation_source"),
        "openai_status": openai.get("status") or delivery.get("openai_status"),
        "openai_model": openai.get("model") or delivery.get("model_used"),
        "openai_was_called": bool(openai.get("called") or openai.get("used") or str(openai.get("status", "")).startswith("success")),
        "estimated_input_chars": openai.get("input_chars") or delivery.get("input_chars"),
        "estimated_output_chars": openai.get("output_chars") or delivery.get("output_chars"),
    }


def method_metrics(name: str, path: Path | None, md_path: Path | None = None) -> dict:
    data = read_json_safely(path)
    recs = extract_recommendations(data)
    q = recommendation_quality(recs)
    output = {
        "method": name,
        "json_exists": bool(path and path.exists()),
        "json_file": str(path) if path else None,
        "json_size_bytes": path.stat().st_size if path and path.exists() else 0,
        "json_sha256": sha256_file(path),
        "recommendation_quality": q,
    }
    if isinstance(data, dict):
        output.update({
            "status": data.get("status"),
            "generator": data.get("generator") or data.get("source_generator"),
            "model_used": data.get("model_used") or data.get("model"),
            "input_hash": data.get("input_hash"),
            "output_hash": data.get("output_hash"),
        })
    if md_path:
        output["markdown_metrics"] = extract_text_metrics(md_path)
    return output


def write_csv(path: Path, report: dict) -> None:
    rows = []
    base = {
        "run_id": report.get("run_id"),
        "timestamp": report.get("timestamp"),
        **{f"assessment_{k}": v for k, v in report.get("assessment_metrics", {}).items()},
        **{f"pipeline_{k}": v for k, v in report.get("pipeline_metrics", {}).items()},
        **{f"validation_{k}": v for k, v in report.get("validation_metrics", {}).items()},
        **{f"power_{k}": v for k, v in report.get("power_metrics", {}).items()},
    }
    for method in report.get("ai_method_metrics", []):
        q = method.get("recommendation_quality", {})
        row = dict(base)
        row.update({
            "method": method.get("method"),
            "method_status": method.get("status"),
            "method_generator": method.get("generator"),
            "method_model_used": method.get("model_used"),
            "method_json_exists": method.get("json_exists"),
            "method_json_size_bytes": method.get("json_size_bytes"),
            "recommendation_count": q.get("recommendation_count"),
            "structural_quality_score_avg": q.get("structural_quality_score_avg"),
            "evidence_items_avg": q.get("evidence_items_avg"),
            "recommended_actions_avg": q.get("recommended_actions_avg"),
            "verification_steps_avg": q.get("verification_steps_avg"),
            "mitre_mapping_coverage_percent": q.get("mitre_mapping_coverage_percent"),
            "cis_mapping_coverage_percent": q.get("cis_mapping_coverage_percent"),
        })
        rows.append(row)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        rows = [base]
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def write_markdown(path: Path, report: dict) -> None:
    a = report.get("assessment_metrics", {})
    p = report.get("pipeline_metrics", {})
    v = report.get("validation_metrics", {})
    power = report.get("power_metrics", {})
    lines = []
    lines.append("# Eksperimentinių metrikų santrauka")
    lines.append("")
    lines.append(f"Paleidimas: `{report.get('run_id')}`")
    lines.append(f"Laikas: `{report.get('timestamp')}`")
    lines.append("")
    lines.append("## Ką matuoti magistriniame darbe")
    lines.append("")
    lines.append("Rekomenduojami trys eksperimentiniai palyginimai:")
    lines.append("1. **Deterministinis struktūruotas generatorius** – be LLM, naudojamas kaip kontrolinis metodas.")
    lines.append("2. **Vietinis Ollama LLM** – vertinama kokybė ir laikas ribotų Raspberry Pi išteklių sąlygomis.")
    lines.append("3. **ChatGPT/OpenAI API** – vertinama geriausia rekomendacijų kokybė, atsekamumas ir kaina.")
    lines.append("")
    lines.append("## Sistemos paleidimo metrikos")
    lines.append("")
    lines.append("| Metrika | Reikšmė |")
    lines.append("|---|---:|")
    lines.append(f"| Aktyvių hostų skaičius | {a.get('total_hosts')} |")
    lines.append(f"| Hostai su atvirais TCP prievadais | {a.get('hosts_with_open_tcp_ports')} |")
    lines.append(f"| Koreliuoti radiniai | {a.get('correlated_findings_count')} |")
    lines.append(f"| Normalizuoti radiniai | {a.get('normalized_findings_count')} |")
    lines.append(f"| Didžiausias rizikos balas | {a.get('highest_risk_score')} |")
    lines.append(f"| Vidutinis rizikos balas | {a.get('average_risk_score')} |")
    lines.append(f"| Pipeline būklė, % | {p.get('pipeline_health_percent')} |")
    lines.append(f"| Pipeline žingsnių skaičius | {p.get('total_steps')} |")
    if power:
        lines.append(f"| Vidutinė galia, W | {power.get('avg_est_board_power_w')} |")
        lines.append(f"| Maksimali temperatūra, °C | {power.get('max_temp_c')} |")
        lines.append(f"| Energijos sąnaudos, Wh | {power.get('estimated_energy_wh')} |")
    lines.append("")
    lines.append("## AI rekomendacijų metodų palyginimas")
    lines.append("")
    lines.append("| Metodas | Statusas | Rekomendacijų sk. | Struktūros kokybė, % | Įrodymų vid. | Veiksmų vid. | Patikrų vid. | MITRE, % | CIS, % |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for method in report.get("ai_method_metrics", []):
        q = method.get("recommendation_quality", {})
        lines.append(
            f"| {method.get('method')} | {method.get('status') or ''} | {q.get('recommendation_count')} | "
            f"{q.get('structural_quality_score_avg')} | {q.get('evidence_items_avg')} | "
            f"{q.get('recommended_actions_avg')} | {q.get('verification_steps_avg')} | "
            f"{q.get('mitre_mapping_coverage_percent')} | {q.get('cis_mapping_coverage_percent')} |"
        )
    lines.append("")
    lines.append("## Validacijos metrikos")
    lines.append("")
    lines.append("| Metrika | Reikšmė |")
    lines.append("|---|---:|")
    lines.append(f"| Scenarijų skaičius | {v.get('enabled_scenarios', 0)} |")
    lines.append(f"| TP | {v.get('tp', 0)} |")
    lines.append(f"| FP | {v.get('fp', 0)} |")
    lines.append(f"| FN | {v.get('fn', 0)} |")
    lines.append(f"| Precision | {v.get('precision', 0)} |")
    lines.append(f"| Recall | {v.get('recall', 0)} |")
    lines.append(f"| F1 | {v.get('f1', 0)} |")
    lines.append("")
    lines.append("## Siūlomos diagramos magistriniam darbui")
    lines.append("")
    lines.append("1. Stulpelinė diagrama: trijų metodų struktūros kokybės balas.")
    lines.append("2. Stulpelinė diagrama: rekomendacijų skaičius pagal metodą.")
    lines.append("3. Stulpelinė diagrama: vidutinis įrodymų / veiksmų / patikrinimo žingsnių skaičius.")
    lines.append("4. Linijinė arba stulpelinė diagrama: vykdymo trukmė ir energijos sąnaudos pagal skenavimo profilį.")
    lines.append("5. Lentelė: Precision, Recall ir F1 pagal laboratorinius scenarijus.")
    lines.append("")
    lines.append("## Trečias bandymas")
    lines.append("")
    lines.append("Trečiu bandymu naudok ne dar vieną LLM, o **kontrolinį deterministinį generatorių**. Jis svarbus todėl, kad leidžia parodyti, kiek kokybės gaunama be išorinio DI ir kiek papildomos vertės suteikia vietinis LLM arba ChatGPT API.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    paths = get_run_paths()
    latest_dir = latest_run_latest_dir()
    timestamp = timestamp_now()
    files = current_files(paths, latest_dir)

    assessment = read_json_safely(files["assessment"])
    evidence = read_json_safely(files["ai_evidence"])
    risk_scores = read_json_safely(files["risk_scores"])
    pipeline = read_json_safely(files["pipeline_audit"])
    validation = read_json_safely(files["validation_metrics"])
    delivery = read_json_safely(files["delivery_summary"])

    report = {
        "report_type": "academic_experiment_metrics",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "run_id": paths.get("run_id"),
        "run_dir": str(paths["run_dir"]),
        "latest_dir": str(latest_dir),
        "source_files": {k: str(v) if v else None for k, v in files.items()},
        "file_hashes": {k: sha256_file(v) for k, v in files.items() if v},
        "assessment_metrics": summarize_assessment(assessment, evidence, risk_scores),
        "pipeline_metrics": pipeline_summary(pipeline),
        "validation_metrics": validation_summary(validation),
        "power_metrics": parse_power_summary(files["power_summary_csv"]),
        "delivery_metrics": delivery_summary(delivery),
        "ai_method_metrics": [
            method_metrics("structured_rules", files["ai_recommendations"]),
            method_metrics("local_ollama_llm", files["llm_recommendations"], latest_dir / "llm_recommendations_latest.md"),
            method_metrics("chatgpt_openai_or_final", files["final_recommendations"], files["final_recommendations_md"]),
        ],
        "recommended_experimental_design": {
            "experiment_1": "Kontrolinis deterministinis struktūruotas generatorius be LLM.",
            "experiment_2": "Vietinis Ollama LLM su tuo pačiu ai_evidence_latest.json.",
            "experiment_3": "ChatGPT/OpenAI API su saugikliais ir tuo pačiu ai_evidence_latest.json.",
            "primary_metrics": [
                "recommendation_count",
                "structural_quality_score_avg",
                "required_field_coverage_percent",
                "evidence_items_avg",
                "recommended_actions_avg",
                "verification_steps_avg",
                "mitre_mapping_coverage_percent",
                "cis_mapping_coverage_percent",
                "duration_seconds",
                "estimated_energy_wh",
                "estimated_cost",
                "precision",
                "recall",
                "f1",
            ],
        },
    }

    json_path = latest_dir / "academic_experiment_metrics_latest.json"
    csv_path = latest_dir / "academic_experiment_metrics_latest.csv"
    md_path = latest_dir / "academic_experiment_summary_latest.md"
    save_json(json_path, report)
    write_csv(csv_path, report)
    write_markdown(md_path, report)

    # Kopija reports kataloge, kad run būtų savarankiškas net jei latest katalogas archyvuojamas.
    save_json(paths["reports_dir"] / f"academic_experiment_metrics_{timestamp}.json", report)
    write_csv(paths["reports_dir"] / f"academic_experiment_metrics_{timestamp}.csv", report)
    write_markdown(paths["reports_dir"] / f"academic_experiment_summary_{timestamp}.md", report)

    print(f"[GERAI] Akademinių metrikų JSON: {json_path}")
    print(f"[GERAI] Akademinių metrikų CSV: {csv_path}")
    print(f"[GERAI] Akademinių metrikų santrauka: {md_path}")


if __name__ == "__main__":
    main()
