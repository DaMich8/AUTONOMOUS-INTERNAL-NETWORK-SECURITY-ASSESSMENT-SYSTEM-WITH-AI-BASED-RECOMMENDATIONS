#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from common import BASE_DIR, get_run_paths, save_json, timestamp_now

PYTHON = sys.executable
SRC_DIR = Path(os.getenv("NETWORK_THESIS_SRC", str(BASE_DIR / "src"))).expanduser()


def run_script(script: str, env: dict) -> dict:
    path = SRC_DIR / script
    if not path.exists():
        return {"script": script, "status": "skipped", "reason": f"Nerastas skriptas: {path}", "duration_seconds": 0}
    started = time.time()
    result = subprocess.run([PYTHON, str(path)], cwd=str(SRC_DIR), env=env, text=True, capture_output=True)
    duration = round(time.time() - started, 2)
    return {
        "script": script,
        "status": "success" if result.returncode == 0 else "failed",
        "returncode": result.returncode,
        "duration_seconds": duration,
        "stdout_tail": result.stdout[-4000:],
        "stderr_tail": result.stderr[-4000:],
    }


def mode_env(base: dict, mode: str) -> dict:
    env = dict(base)
    env.setdefault("NETWORK_THESIS_BASE", str(BASE_DIR))
    env.setdefault("NETWORK_THESIS_SRC", str(SRC_DIR))
    if mode == "structured_rules":
        env["LOCAL_LLM_ENABLED"] = "0"
        env["OPENAI_API_ENABLED"] = "0"
        env["OPENAI_API_FALLBACK_ENABLED"] = "0"
        env["RECOMMENDATION_DELIVERY_ENABLED"] = "0"
    elif mode == "local_ollama_llm":
        env["LOCAL_LLM_ENABLED"] = "1"
        env.setdefault("LOCAL_LLM_TIMEOUT", "3600")
        env["OPENAI_API_ENABLED"] = "0"
        env["OPENAI_API_FALLBACK_ENABLED"] = "0"
        env["RECOMMENDATION_DELIVERY_ENABLED"] = "0"
    elif mode == "chatgpt_openai":
        env["LOCAL_LLM_ENABLED"] = "0"
        env["RECOMMENDATION_DELIVERY_ENABLED"] = "1"
        env["OPENAI_API_ENABLED"] = "1"
        env["OPENAI_API_FALLBACK_ENABLED"] = "1"
        env["OPENAI_API_ALLOW_RUN"] = "1"
        env.setdefault("OPENAI_API_REQUIRE_MANUAL_APPROVAL", "1")
        env.setdefault("OPENAI_API_SKIP_IF_EVIDENCE_UNCHANGED", "1")
        env.setdefault("OPENAI_API_ONLY_WHEN_NEEDED", "1")
    else:
        raise ValueError(f"Nežinomas metodas: {mode}")
    return env


def main() -> None:
    parser = argparse.ArgumentParser(description="Palygina AI rekomendacijų generavimo metodus iš jau parengto ai_evidence_latest.json.")
    parser.add_argument("--mode", choices=["structured_rules", "local_ollama_llm", "chatgpt_openai", "all_safe"], default="all_safe")
    parser.add_argument("--allow-chatgpt", action="store_true", help="Leidžia vykdyti ChatGPT/OpenAI metodą. Be šio parametro all_safe jo nekvies.")
    args = parser.parse_args()

    paths = get_run_paths()
    latest_dir = Path(os.getenv("NETWORK_THESIS_LATEST_RUN_DIR", str(paths["run_dir"] / "latest"))).expanduser()
    latest_dir.mkdir(parents=True, exist_ok=True)
    base_env = os.environ.copy()
    base_env["ASSESSMENT_RUN_ID"] = str(paths["run_id"])
    base_env["ASSESSMENT_RUN_DIR"] = str(paths["run_dir"])
    base_env["NETWORK_THESIS_LATEST_RUN_DIR"] = str(latest_dir)

    if args.mode == "all_safe":
        modes = ["structured_rules", "local_ollama_llm"]
        if args.allow_chatgpt:
            modes.append("chatgpt_openai")
    else:
        modes = [args.mode]

    results = []
    for mode in modes:
        print(f"\n================================================================================")
        print(f"AI metodo bandymas: {mode}")
        print(f"================================================================================")
        env = mode_env(base_env, mode)
        scripts = ["ai_recommendation_engine.py"]
        if mode == "local_ollama_llm":
            scripts.append("local_llm_recommendation_engine.py")
        if mode == "chatgpt_openai":
            scripts.append("recommendation_delivery.py")
        for script in scripts:
            result = run_script(script, env)
            result["mode"] = mode
            results.append(result)
            print(f"[{result['status'].upper()}] {script} | {result.get('duration_seconds')} s")
            if result["status"] != "success":
                print(result.get("stderr_tail") or result.get("stdout_tail") or "")

    # Po metodų paleidimo sugeneruojame bendras metrikas.
    metrics_result = run_script("academic_experiment_metrics.py", base_env)
    results.append({**metrics_result, "mode": "metrics"})

    report = {
        "report_type": "ai_method_experiment_runner",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "run_id": paths.get("run_id"),
        "latest_dir": str(latest_dir),
        "mode_requested": args.mode,
        "chatgpt_allowed": bool(args.allow_chatgpt),
        "results": results,
    }
    out = latest_dir / "ai_method_experiment_runner_latest.json"
    save_json(out, report)
    save_json(paths["reports_dir"] / f"ai_method_experiment_runner_{timestamp_now()}.json", report)
    print(f"\n[GERAI] AI metodų bandymo ataskaita: {out}")


if __name__ == "__main__":
    main()
