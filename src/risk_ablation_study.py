#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
risk_ablation_study.py

Rizikos modelio abliacijos eksperimentas magistrinio darbo prototipui.

Tikslas:
- įvertinti, kaip pasikeistų rizikos įverčiai pašalinus atskiras rizikos modelio dedamąsias;
- parodyti, kurios dedamosios labiausiai veikia galutinį rizikos prioritetizavimą;
- sukurti struktūruotą JSON ir žmogui skaitomą MD ataskaitą.

Skriptas sąmoningai nenaudoja papildomų išorinių bibliotekų, kad veiktų Kali/Raspberry Pi aplinkoje.
"""
from __future__ import annotations

import json
import os
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

REPORT_TYPE = "risk_ablation_study"
REPORT_VERSION = "1.0"

DEFAULT_COMPONENT_LABELS = {
    "V": "Pažeidžiamumai / CVE",
    "E": "Eksploitavimo tikimybė / EPSS",
    "K": "CISA KEV / žinomas aktyvus išnaudojimas",
    "C": "Konfigūraciniai ir koreliuoti radiniai",
    "L": "Žurnalų / endpoint įvykių indikatoriai",
    "A": "Turto ekspozicija / paslaugų paviršius",
}

# Naudojami tik tada, kai risk_scores JSON faile nėra aiškiai pateiktų svorių.
# Suma normalizuojama automatiškai.
DEFAULT_WEIGHTS = {
    "V": 0.25,
    "E": 0.20,
    "K": 0.20,
    "C": 0.20,
    "L": 0.10,
    "A": 0.05,
}


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def detect_project_dir() -> Path:
    env_base = os.environ.get("NETWORK_THESIS_BASE")
    if env_base:
        return Path(env_base).expanduser().resolve()
    return Path(__file__).resolve().parents[1]


def detect_paths() -> dict[str, Path]:
    """Naudoja projekto common.py, jei jis prieinamas. Jei ne — veikia savarankiškai."""
    try:
        from common import get_run_paths  # type: ignore

        paths = get_run_paths()
        run_dir = Path(paths["run_dir"])
        reports_dir = Path(paths["reports_dir"])
        latest_dir = Path(paths.get("latest_dir") or (run_dir / "latest"))
        return {"run_dir": run_dir, "reports_dir": reports_dir, "latest_dir": latest_dir}
    except Exception:
        project_dir = detect_project_dir()
        run_dir_env = os.environ.get("RUN_DIR") or os.environ.get("NETWORK_THESIS_RUN_DIR")
        if run_dir_env:
            run_dir = Path(run_dir_env).expanduser().resolve()
        else:
            candidates = [p for p in (project_dir / "runs").glob("*/*") if p.is_dir()]
            if not candidates:
                run_dir = project_dir
            else:
                run_dir = max(candidates, key=lambda p: p.stat().st_mtime)
        return {
            "run_dir": run_dir,
            "reports_dir": run_dir / "reports",
            "latest_dir": run_dir / "latest",
        }


def latest_file(directory: Path, patterns: list[str]) -> Path | None:
    candidates: list[Path] = []
    for pattern in patterns:
        candidates.extend(directory.glob(pattern))
    candidates = [p for p in candidates if p.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def normalize_key(key: str) -> str:
    k = str(key or "").strip()
    aliases = {
        "vulnerability": "V",
        "vulnerabilities": "V",
        "cve": "V",
        "epss": "E",
        "exploitability": "E",
        "kev": "K",
        "cisa_kev": "K",
        "configuration": "C",
        "correlation": "C",
        "config": "C",
        "logs": "L",
        "endpoint": "L",
        "events": "L",
        "asset": "A",
        "exposure": "A",
        "attack_surface": "A",
    }
    if k in DEFAULT_COMPONENT_LABELS:
        return k
    return aliases.get(k.lower(), k)


def normalize_components(raw: Any) -> dict[str, float]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, float] = {}
    for key, value in raw.items():
        nk = normalize_key(str(key))
        out[nk] = as_float(value)
    return out


def normalize_weights(raw: Any, component_keys: set[str]) -> dict[str, float]:
    weights: dict[str, float] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            nk = normalize_key(str(key))
            weights[nk] = as_float(value)
    if not weights:
        weights = dict(DEFAULT_WEIGHTS)
    for key in component_keys:
        weights.setdefault(key, DEFAULT_WEIGHTS.get(key, 0.05))
    total = sum(v for v in weights.values() if v > 0)
    if total <= 0:
        return {k: 1.0 / len(weights) for k in weights} if weights else {}
    return {k: round(max(v, 0.0) / total, 6) for k, v in weights.items()}


def risk_level(score: float) -> str:
    if score >= 80:
        return "kritinė"
    if score >= 60:
        return "aukšta"
    if score >= 40:
        return "vidutinė"
    if score >= 20:
        return "žema"
    return "informacinė"


def weighted_score(components: dict[str, float], weights: dict[str, float]) -> float:
    return round(sum(as_float(components.get(k)) * as_float(weights.get(k)) for k in weights), 2)


def find_weights(data: Any) -> dict[str, float]:
    if not isinstance(data, dict):
        return {}
    candidates = [
        data.get("weights"),
        data.get("risk_weights"),
        data.get("risk_model_weights"),
        (data.get("risk_model") or {}).get("weights") if isinstance(data.get("risk_model"), dict) else None,
        (data.get("metadata") or {}).get("weights") if isinstance(data.get("metadata"), dict) else None,
    ]
    for candidate in candidates:
        if isinstance(candidate, dict):
            return normalize_weights(candidate, set())
    return {}


def looks_like_host_score(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    has_score = any(k in obj for k in ("risk_score", "score", "total_score", "official_risk_score"))
    has_host = any(k in obj for k in ("ip", "host", "asset_id", "hostname"))
    has_components = any(k in obj for k in ("risk_components", "components", "component_scores"))
    return bool(has_score and (has_host or has_components))


def extract_host_scores(data: Any) -> list[dict[str, Any]]:
    """Iš įvairių galimų risk_scores JSON formų ištraukia hostų rizikos įrašus."""
    found: list[dict[str, Any]] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            if looks_like_host_score(obj):
                found.append(obj)
                return
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)

    dedup: dict[str, dict[str, Any]] = {}
    for item in found:
        ip = str(item.get("ip") or item.get("host") or item.get("address") or "unknown")
        asset_id = str(item.get("asset_id") or "unknown")
        key = f"{asset_id}|{ip}|{item.get('hostname') or ''}"
        dedup[key] = item
    return list(dedup.values())


def host_identifier(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "host": item.get("ip") or item.get("host") or item.get("address") or "unknown",
        "asset_id": item.get("asset_id") or "unknown",
        "hostname": item.get("hostname"),
        "mac": item.get("mac"),
        "vendor": item.get("vendor"),
    }


def extract_score(item: dict[str, Any], components: dict[str, float], weights: dict[str, float]) -> float:
    for key in ("risk_score", "official_risk_score", "total_score", "score"):
        if key in item:
            return round(as_float(item.get(key)), 2)
    return weighted_score(components, weights)


def ablation_for_hosts(host_scores: list[dict[str, Any]], weights: dict[str, float]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    all_component_keys: set[str] = set(weights.keys())
    normalized_hosts: list[dict[str, Any]] = []

    for item in host_scores:
        components = normalize_components(
            item.get("risk_components") or item.get("components") or item.get("component_scores") or {}
        )
        all_component_keys.update(components.keys())
        normalized_hosts.append({"raw": item, "components": components})

    weights = normalize_weights(weights, all_component_keys)

    host_results: list[dict[str, Any]] = []
    component_impacts: dict[str, list[float]] = {k: [] for k in sorted(all_component_keys)}
    level_changes: dict[str, int] = {k: 0 for k in sorted(all_component_keys)}

    for nh in normalized_hosts:
        item = nh["raw"]
        components = nh["components"]
        computed_baseline = weighted_score(components, weights)
        original_score = extract_score(item, components, weights)
        base_level = risk_level(original_score)

        result = {
            **host_identifier(item),
            "original_score": original_score,
            "computed_baseline_score": computed_baseline,
            "original_risk_level": item.get("risk_level") or base_level,
            "risk_components": components,
            "ablation": [],
        }

        for component in sorted(all_component_keys):
            ablated_components = dict(components)
            ablated_components[component] = 0.0
            ablated_score = weighted_score(ablated_components, weights)
            delta = round(computed_baseline - ablated_score, 2)
            after_level = risk_level(ablated_score)
            changed_level = risk_level(computed_baseline) != after_level
            component_impacts[component].append(delta)
            if changed_level:
                level_changes[component] += 1
            result["ablation"].append({
                "removed_component": component,
                "component_label": DEFAULT_COMPONENT_LABELS.get(component, component),
                "score_without_component": ablated_score,
                "score_delta": delta,
                "risk_level_without_component": after_level,
                "risk_level_changed": changed_level,
            })
        host_results.append(result)

    component_summary: list[dict[str, Any]] = []
    for component, deltas in component_impacts.items():
        if not deltas:
            continue
        top_hosts = sorted(
            [
                {
                    "host": h.get("host"),
                    "asset_id": h.get("asset_id"),
                    "score_delta": next((a["score_delta"] for a in h["ablation"] if a["removed_component"] == component), 0.0),
                }
                for h in host_results
            ],
            key=lambda x: x["score_delta"],
            reverse=True,
        )[:5]
        component_summary.append({
            "component": component,
            "component_label": DEFAULT_COMPONENT_LABELS.get(component, component),
            "average_score_delta": round(statistics.mean(deltas), 2),
            "median_score_delta": round(statistics.median(deltas), 2),
            "max_score_delta": round(max(deltas), 2),
            "risk_level_changes": level_changes.get(component, 0),
            "top_affected_hosts": top_hosts,
        })

    component_summary.sort(key=lambda x: (x["average_score_delta"], x["max_score_delta"]), reverse=True)

    global_summary = {
        "host_count": len(host_results),
        "component_count": len(component_summary),
        "most_influential_component": component_summary[0] if component_summary else None,
        "weights_used": weights,
        "interpretation": "Abliacijos eksperimentas parodo, kaip keistųsi rizikos balas pašalinus atskiras rizikos modelio dedamąsias.",
    }

    return component_summary, host_results, global_summary


def build_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Rizikos modelio abliacijos eksperimentas")
    lines.append("")
    lines.append(f"Ataskaitos laikas: {report.get('timestamp')}")
    lines.append(f"Įvesties failas: `{report.get('input_file')}`")
    lines.append("")
    summary = report.get("summary") or {}
    lines.append("## Santrauka")
    lines.append("")
    lines.append(f"- Įvertintų turto objektų skaičius: {summary.get('host_count', 0)}")
    lines.append(f"- Analizuotų rizikos dedamųjų skaičius: {summary.get('component_count', 0)}")
    most = summary.get("most_influential_component") or {}
    if most:
        lines.append(f"- Didžiausią įtaką turėjusi dedamoji: {most.get('component')} – {most.get('component_label')}")
    lines.append("")
    lines.append("## Dedamųjų įtakos lentelė")
    lines.append("")
    lines.append("| Dedamoji | Reikšmė | Vidutinis balo pokytis | Maksimalus pokytis | Rizikos lygio pokyčių sk. |")
    lines.append("|---|---|---:|---:|---:|")
    for item in report.get("component_impacts", []):
        lines.append(
            f"| {item.get('component')} | {item.get('component_label')} | "
            f"{item.get('average_score_delta')} | {item.get('max_score_delta')} | {item.get('risk_level_changes')} |"
        )
    lines.append("")
    lines.append("## Interpretacija magistriniam darbui")
    lines.append("")
    lines.append(
        "Šis eksperimentas naudojamas įvertinti rizikos modelio dedamųjų svarbą. "
        "Kiekvieno bandymo metu viena dedamoji pašalinama iš skaičiavimo, o po to vertinama, "
        "kiek pasikeičia bendras rizikos balas ir ar pasikeičia rizikos lygio kategorija. "
        "Tokiu būdu galima pagrįsti, kurios dedamosios turi didžiausią įtaką prioritetizavimui."
    )
    lines.append("")
    lines.append("## Pastabos")
    lines.append("")
    lines.append(
        "Jeigu pradiniame rizikos modelio faile nepateikti tikslūs svoriai, naudojami numatytieji svoriai, "
        "kurie įrašomi JSON ataskaitos `summary.weights_used` lauke."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    paths = detect_paths()
    reports_dir = paths["reports_dir"]
    latest_dir = paths["latest_dir"]
    latest_dir.mkdir(parents=True, exist_ok=True)

    input_file = latest_file(reports_dir, ["risk_scores_*.json"])
    if not input_file:
        report = {
            "report_type": REPORT_TYPE,
            "report_version": REPORT_VERSION,
            "timestamp": now_iso(),
            "status": "no_input",
            "message": "Nerastas risk_scores_*.json failas, todėl abliacijos eksperimentas neatliktas.",
            "input_file": None,
            "summary": {"host_count": 0, "component_count": 0},
            "component_impacts": [],
            "host_results": [],
        }
    else:
        data = read_json(input_file)
        host_scores = extract_host_scores(data)
        weights = find_weights(data)
        component_impacts, host_results, summary = ablation_for_hosts(host_scores, weights)
        report = {
            "report_type": REPORT_TYPE,
            "report_version": REPORT_VERSION,
            "timestamp": now_iso(),
            "status": "success" if host_scores else "no_host_scores",
            "input_file": str(input_file),
            "summary": summary,
            "component_impacts": component_impacts,
            "host_results": host_results,
        }

    ts = now_ts()
    json_path = reports_dir / f"risk_ablation_study_{ts}.json"
    md_path = reports_dir / f"risk_ablation_study_{ts}.md"
    latest_json = latest_dir / "risk_ablation_study_latest.json"
    latest_md = latest_dir / "risk_ablation_study_latest.md"

    write_json(json_path, report)
    write_json(latest_json, report)
    md = build_markdown(report)
    write_text(md_path, md)
    write_text(latest_md, md)

    print(f"[GERAI] Rizikos modelio abliacijos eksperimentas: {json_path}", flush=True)
    print(f"[INFO] MD santrauka: {md_path}", flush=True)
    if report.get("summary", {}).get("most_influential_component"):
        mic = report["summary"]["most_influential_component"]
        print(
            f"[INFO] Didžiausią įtaką turėjusi dedamoji: {mic.get('component')} "
            f"({mic.get('component_label')})",
            flush=True,
        )


if __name__ == "__main__":
    main()
