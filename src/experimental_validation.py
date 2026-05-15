#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_FILE = BASE_DIR / "config" / "expected_findings.json"


def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def find_latest_run_with_findings() -> Path:
    runs_dir = BASE_DIR / "runs"
    candidates = []

    for run_dir in sorted(runs_dir.glob("*/*"), reverse=True):
        if not run_dir.is_dir():
            continue
        if list((run_dir / "reports").glob("normalized_findings_*.json")):
            candidates.append(run_dir)

    if not candidates:
        raise FileNotFoundError("Nerastas nė vienas run katalogas su reports/normalized_findings_*.json")

    return candidates[0]


def latest_file(pattern_dir: Path, pattern: str) -> Path | None:
    files = sorted(pattern_dir.glob(pattern), reverse=True)
    return files[0] if files else None


def extract_findings(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if isinstance(data, dict):
        for key in ("findings", "normalized_findings", "items", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]

    return []


def normalize_host(value: Any) -> str:
    return str(value or "").strip()


def finding_host(f: dict) -> str:
    return normalize_host(f.get("ip") or f.get("host") or f.get("target"))


def finding_rule(f: dict) -> str:
    return str(f.get("rule_id") or "").strip()


def expected_matches_detection(expected: dict, detected: dict) -> bool:
    erule = str(expected.get("rule_id") or "").strip()
    ehost = normalize_host(expected.get("host"))

    drule = finding_rule(detected)
    dhost = finding_host(detected)

    if not erule or erule != drule:
        return False

    if ehost in {"", "*", "multiple", "any"}:
        return True

    return ehost == dhost


def unique_detected_keys(findings: list[dict]) -> set[tuple[str, str]]:
    keys = set()
    for f in findings:
        rule = finding_rule(f)
        host = finding_host(f)
        if rule:
            keys.add((rule, host))
    return keys


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", default="", help="Konkretaus paleidimo katalogas")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve() if args.run_dir else find_latest_run_with_findings()

    if not CONFIG_FILE.exists():
        raise FileNotFoundError(f"Nerastas laukiamų radinių failas: {CONFIG_FILE}")

    expected_doc = load_json(CONFIG_FILE)
    expected = expected_doc.get("expected_findings", [])
    if not isinstance(expected, list):
        raise ValueError("expected_findings.json faile laukas expected_findings turi būti sąrašas")

    findings_file = latest_file(run_dir / "reports", "normalized_findings_*.json")
    if not findings_file:
        raise FileNotFoundError(f"Nerastas normalized_findings_*.json kataloge: {run_dir / 'reports'}")

    findings_data = load_json(findings_file)
    detected_findings = extract_findings(findings_data)

    detected_unique = unique_detected_keys(detected_findings)

    tp_expected = []
    fn_expected = []

    for exp in expected:
        matched = any(expected_matches_detection(exp, det) for det in detected_findings)
        if matched:
            tp_expected.append(exp)
        else:
            fn_expected.append(exp)

    fp_detected = []
    for rule, host in sorted(detected_unique):
        pseudo = {"rule_id": rule, "ip": host}
        if not any(expected_matches_detection(exp, pseudo) for exp in expected):
            fp_detected.append({"rule_id": rule, "host": host})

    tp = len(tp_expected)
    fp = len(fp_detected)
    fn = len(fn_expected)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    hosts = sorted({finding_host(f) for f in detected_findings if finding_host(f)})
    rules = sorted({finding_rule(f) for f in detected_findings if finding_rule(f)})

    report = {
        "document_type": "experimental_validation",
        "generated_at": ts(),
        "run_dir": str(run_dir),
        "expected_file": str(CONFIG_FILE),
        "normalized_findings_file": str(findings_file),
        "coverage": {
            "hosts_with_findings": len(hosts),
            "unique_rule_ids": len(rules),
            "detected_findings_total": len(detected_findings),
            "detected_unique_rule_host_pairs": len(detected_unique),
            "expected_findings_total": len(expected),
        },
        "metrics": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "true_positive_expected": tp_expected,
        "false_negative_expected": fn_expected,
        "false_positive_detected": fp_detected,
        "detected_rules": rules,
        "detected_hosts": hosts,
    }

    out_json = run_dir / "reports" / f"experimental_validation_{ts()}.json"
    out_md = run_dir / "reports" / f"experimental_validation_{ts()}.md"

    save_json(out_json, report)

    md = []
    md.append("# Eksperimentinės validacijos ataskaita")
    md.append("")
    md.append(f"Run katalogas: `{run_dir}`")
    md.append(f"Naudotas laukiamų radinių failas: `{CONFIG_FILE}`")
    md.append(f"Naudotas aptiktų radinių failas: `{findings_file}`")
    md.append("")
    md.append("## Aprėptis")
    md.append("")
    md.append(f"- Hostai su radiniais: {len(hosts)}")
    md.append(f"- Unikalūs rule_id: {len(rules)}")
    md.append(f"- Aptiktų radinių skaičius: {len(detected_findings)}")
    md.append(f"- Unikalių rule_id + host porų: {len(detected_unique)}")
    md.append(f"- Laukiamų radinių skaičius: {len(expected)}")
    md.append("")
    md.append("## Metrikos")
    md.append("")
    md.append(f"- TP: {tp}")
    md.append(f"- FP: {fp}")
    md.append(f"- FN: {fn}")
    md.append(f"- Precision: {precision:.4f}")
    md.append(f"- Recall: {recall:.4f}")
    md.append(f"- F1: {f1:.4f}")
    md.append("")
    md.append("## Neaptikti laukti radiniai")
    md.append("")
    if fn_expected:
        for item in fn_expected:
            md.append(f"- `{item.get('rule_id')}` hostas `{item.get('host')}` – {item.get('reason', '')}")
    else:
        md.append("- Visi laukiamų radinių rinkinyje aprašyti radiniai buvo aptikti.")
    md.append("")
    md.append("## Papildomai aptikti radiniai")
    md.append("")
    if fp_detected:
        for item in fp_detected[:100]:
            md.append(f"- `{item.get('rule_id')}` hostas `{item.get('host')}`")
        if len(fp_detected) > 100:
            md.append(f"- ... papildomų įrašų: {len(fp_detected) - 100}")
    else:
        md.append("- Papildomų, laukiamų radinių rinkinyje neaprašytų radinių nėra.")

    out_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    latest_dir = run_dir / "latest"
    latest_dir.mkdir(parents=True, exist_ok=True)
    save_json(latest_dir / "experimental_validation_latest.json", report)
    (latest_dir / "experimental_validation_latest.md").write_text(out_md.read_text(encoding="utf-8"), encoding="utf-8")

    print(f"[GERAI] Eksperimentinės validacijos ataskaita: {out_json}")
    print(f"[INFO] MD santrauka: {out_md}")
    print(f"[INFO] Latest MD: {latest_dir / 'experimental_validation_latest.md'}")
    print(
        f"[INFO] TP={tp}, FP={fp}, FN={fn}, "
        f"Precision={precision:.4f}, Recall={recall:.4f}, F1={f1:.4f}"
    )


if __name__ == "__main__":
    main()
