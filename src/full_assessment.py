#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

from experiment_mode import apply_experiment_mode, print_experiment_mode_summary

from common import get_run_paths, save_json, timestamp_now, write_run_context

BASE_DIR = Path(os.getenv("NETWORK_THESIS_BASE", str(Path.home() / "network-thesis-GIT"))).expanduser()
SRC_DIR = Path(os.getenv("NETWORK_THESIS_SRC", str(BASE_DIR / "src"))).expanduser()
PYTHON = sys.executable


@dataclass(frozen=True)
class Step:
    script: str
    description: str
    phase: str
    required: bool = True
    args: tuple[str, ...] = field(default_factory=tuple)


CORE_STEPS = [
    Step("preflight_check.py", "Pradinė sistemos patikra", "core", required=False),
    Step("scan_network.py", "Aktyvių įrenginių aptikimas", "core"),
    Step("parse_discovery.py", "Įrenginių aptikimo rezultatų apdorojimas", "core"),
    Step("service_scan.py", "Paslaugų ir atvirų prievadų skenavimas", "core"),
    Step("parse_services.py", "Paslaugų skenavimo rezultatų apdorojimas", "core"),
]

ENRICHMENT_STEPS = [
    Step("service_enrichment.py", "Paslaugų duomenų praturtinimas", "enrichment", required=False),
    Step("udp_scan.py", "UDP paslaugų patikra", "enrichment", required=False),
    Step("vuln_enrichment.py", "Galimų pažeidžiamumų paieška pagal paslaugų versijas", "enrichment", required=False),
    Step("l2_inventory.py", "L2 įrenginių inventorizacija", "enrichment", required=False),
    Step("smb_enrichment.py", "SMB paslaugų papildoma analizė", "enrichment", required=False),
    Step("web_fingerprint.py", "Žiniatinklio paslaugų technologijų nustatymas", "enrichment", required=False),
    Step("tls_audit.py", "TLS konfigūracijos auditas", "enrichment", required=False),
    Step("snmp_enrichment.py", "SNMP paslaugų papildoma analizė", "enrichment", required=False),
]

OPTIONAL_AUDIT_STEPS = [
    Step("ssh_policy_audit.py", "SSH konfigūracijos auditas", "audit", required=False),
    Step("rdp_policy_audit.py", "RDP prieigos auditas", "audit", required=False),
    Step("rpc_nfs_audit.py", "RPC/NFS paslaugų auditas", "audit", required=False),
    Step("dns_router_audit.py", "DNS ir maršrutizatoriaus sąsajų patikra", "audit", required=False),
    Step("web_deep_audit.py", "Išsamesnis žiniatinklio paslaugų auditas", "audit", required=False),
    Step("endpoint_event_normalizer.py", "Galinių įrenginių ir ESET įvykių normalizavimas", "audit", required=False),
]

# Ši grandinė parengia techninius radinius, atkuriamą struktūruotų rekomendacijų sluoksnį
# ir, jei įjungta LOCAL_LLM_ENABLED=1, papildomą laisvo teksto Ollama LLM etapą.
ANALYSIS_AND_REPORTING_STEPS = [
    Step("compare_scans.py", "Įrenginių pokyčių palyginimas", "analysis", required=False),
    Step("compare_services.py", "Paslaugų pokyčių palyginimas", "analysis", required=False),
    Step("merge_assessment.py", "Bendro saugumo vertinimo sudarymas", "analysis"),
    Step("finding_normalizer.py", "Radinių suvienodinimas pagal bendrą schemą", "analysis", required=False),
    Step("epss_kev_enrichment.py", "CVE praturtinimas EPSS ir CISA KEV duomenimis", "analysis", required=False),
    Step("risk_engine.py", "Rizikos balo skaičiavimas", "analysis"),
    Step("correlation_engine.py", "Techninių radinių ir įvykių koreliacija", "analysis", required=False),
    Step("storage.py", "Rezultatų įrašymas į SQLite duomenų bazę", "analysis", required=False),
    Step("remediation_tracker.py", "Pataisymų pokyčių patikra", "analysis", required=False),
    Step("report_generator.py", "HTML ataskaitos generavimas", "reporting", required=False),
    Step("schema_validator.py", "Pagrindinių JSON failų schemų patikra", "quality", required=False, args=("--all-current",)),
    Step("pipeline_audit.py", "Vykdymo grandinės audito ataskaita", "quality", required=False),
    Step("validation_metrics.py", "Eksperimentinės validacijos metrikų skaičiavimas", "quality", required=False),
    Step("risk_sensitivity_analysis.py", "Rizikos modelio jautrumo analizė", "quality", required=False),
    Step("risk_ablation_study.py", "Rizikos modelio abliacijos eksperimentas", "quality", required=False),
    Step("experimental_validation.py", "Eksperimentinė sistemos validacija", "quality", required=False),
    Step("retention_cleanup.py", "Senų duomenų tvarkymas", "maintenance", required=False),
    Step("build_final_ai_input.py", "Galutinio techninių DI įrodymų dokumento sudarymas", "ai_input", required=True),
    Step("ai_recommendation_engine.py", "Struktūruotų DI rekomendacijų atkūrimas pagal techninius įrodymus", "ai_input", required=False),
]

BASE_STEPS = CORE_STEPS + ENRICHMENT_STEPS + OPTIONAL_AUDIT_STEPS + ANALYSIS_AND_REPORTING_STEPS


def print_header(title: str) -> None:
    print("\n" + "=" * 80, flush=True)
    print(title, flush=True)
    print("=" * 80, flush=True)


def env_enabled(env: dict, name: str) -> bool:
    return str(env.get(name, "")).strip().lower() in {"1", "true", "yes", "y", "on"}


def llm_enabled(env: dict) -> bool:
    return env_enabled(env, "LOCAL_LLM_ENABLED")


def recommendation_delivery_enabled(env: dict) -> bool:
    """Ar paleisti recommendation_delivery.py etapą.

    Svarbu: EMAIL_SEND_ENABLED pats vienas nebeįjungia šio etapo.
    EMAIL_SEND_ENABLED nurodo tik tai, ar jau paleistas pristatymo etapas turi
    siųsti el. laišką. Tai būtina 4 eksperimentui, kuriame reikia išsiųsti
    rankinio AI įkėlimo paketą, bet negalima generuoti ir siųsti galutinio
    rekomendacijų PDF.
    """
    return (
        env_enabled(env, "RECOMMENDATION_DELIVERY_ENABLED")
        or env_enabled(env, "OPENAI_API_ENABLED")
        or env_enabled(env, "OPENAI_API_FALLBACK_ENABLED")
    )


def first_env_value(env: dict, *names: str) -> str:
    for name in names:
        value = str(env.get(name, "")).strip()
        if value:
            return value
    return ""


def apply_runtime_env_aliases(env: dict, paths: dict) -> None:
    """Normalizuoja senus ir naujus .env kintamuosius vienoje vietoje.

    Visi vėlesni skriptai gauna tą patį `env`, todėl full_assessment.py galima
    paleisti tiesiogiai be papildomo wrapper skripto.
    """
    run_latest_dir = Path(paths["run_dir"]) / "latest"
    run_latest_dir.mkdir(parents=True, exist_ok=True)

    env["ASSESSMENT_RUN_ID"] = str(paths["run_id"])
    env["ASSESSMENT_RUN_DIR"] = str(paths["run_dir"])
    env["NETWORK_THESIS_LATEST_RUN_DIR"] = str(run_latest_dir)
    env.setdefault("NETWORK_THESIS_BASE", str(BASE_DIR))
    env.setdefault("NETWORK_THESIS_SRC", str(SRC_DIR))

    # El. pašto gavėjo/siuntėjo alias'ai. Nauji recommendation_delivery.py
    # kintamieji turi prioritetą, bet seni SMTP_* ir EMAIL_FROM lieka palaikomi.
    env["RECOMMENDATION_EMAIL_TO"] = first_env_value(env, "RECOMMENDATION_EMAIL_TO", "SMTP_TO", "EMAIL_TO")
    env["RECOMMENDATION_EMAIL_FROM"] = first_env_value(env, "RECOMMENDATION_EMAIL_FROM", "EMAIL_FROM", "SMTP_FROM", "SMTP_USER")
    env["SMTP_HOST"] = first_env_value(env, "SMTP_HOST", "RECOMMENDATION_SMTP_HOST")
    env["SMTP_PORT"] = first_env_value(env, "SMTP_PORT", "RECOMMENDATION_SMTP_PORT") or "587"
    env["SMTP_USER"] = first_env_value(env, "SMTP_USER", "RECOMMENDATION_SMTP_USER")
    env["SMTP_PASSWORD"] = first_env_value(env, "SMTP_PASSWORD", "RECOMMENDATION_SMTP_PASSWORD")

    # OPENAI_API_ENABLED yra pagrindinis naujas jungiklis. Paliekamas ir senas
    # OPENAI_API_FALLBACK_ENABLED pavadinimas suderinamumui.
    if env_enabled(env, "OPENAI_API_ENABLED") and not env.get("OPENAI_API_FALLBACK_ENABLED"):
        env["OPENAI_API_FALLBACK_ENABLED"] = "1"

    # Rankinio ChatGPT paketo siuntimas gali naudoti atskirą jungiklį, bet seni
    # skriptai tikrina EMAIL_ENABLED, todėl paduodame saugų alias'ą.
    if env_enabled(env, "CHATGPT_PACKAGE_EMAIL_ENABLED") and not env.get("EMAIL_ENABLED"):
        env["EMAIL_ENABLED"] = "1"

    # Atnaujiname ir dabartinio proceso aplinką, nes finalinis blokas bei
    # funkcijos žemiau skaito os.environ, o ne tik subprocess env.
    os.environ.update({k: str(v) for k, v in env.items()})


def current_latest_dir() -> Path:
    return Path(os.environ.get("NETWORK_THESIS_LATEST_RUN_DIR", str(BASE_DIR / "latest"))).expanduser()


def runtime_steps(env: dict) -> list[Step]:
    steps = list(BASE_STEPS)
    if llm_enabled(env):
        steps.append(Step("local_llm_recommendation_engine.py", "Galutinių rekomendacijų generavimas per vietinį Ollama LLM", "llm", required=False))
    if recommendation_delivery_enabled(env):
        steps.append(Step("recommendation_delivery.py", "Atsarginis ChatGPT API etapas, PDF parengimas ir el. pašto pristatymas", "delivery", required=False))
    # Šis etapas visada vykdomas pabaigoje, nes magistriniam darbui reikia
    # ne tik ataskaitos, bet ir pamatuojamų rezultatų: kokybė, trukmė,
    # energijos sąnaudos, recommendation field coverage ir AI metodų palyginimas.
    steps.append(Step("academic_experiment_metrics.py", "Akademinių eksperimento metrikų suvestinė", "quality", required=False))
    return steps


def latest_power_csv(run_paths: dict) -> Path | None:
    files = sorted(run_paths["power_dir"].glob("*.csv"))
    return files[-1] if files else None


def apply_scan_profile(env: dict) -> dict:
    resolver = SRC_DIR / "scan_profile_resolver.py"
    if resolver.exists():
        try:
            code = (
                "import json; "
                "from scan_profile_resolver import apply_profile_environment; "
                "print(json.dumps(apply_profile_environment(write_context=True), ensure_ascii=False))"
            )
            result = subprocess.run(
                [PYTHON, "-c", code],
                cwd=str(SRC_DIR),
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            info = json.loads(result.stdout.strip().splitlines()[-1])
            for key, value in (info.get("environment_applied") or {}).items():
                env[key] = str(value)
            return info
        except Exception as exc:
            return {
                "profile": env.get("SERVICE_SCAN_PROFILE", "balanced"),
                "source": "fallback",
                "warning": f"Nepavyko pritaikyti scan_profile_resolver.py: {exc}",
                "environment_applied": {},
            }

    profile = env.get("SERVICE_SCAN_PROFILE") or ("balanced" if 7 <= datetime.now().hour < 19 else "deep")
    env["SERVICE_SCAN_PROFILE"] = profile
    return {"profile": profile, "source": "fallback_time_rule", "environment_applied": {"SERVICE_SCAN_PROFILE": profile}}


def snapshot_files(paths: dict) -> set[str]:
    sections = ["discovery_dir", "services_dir", "reports_dir", "ai_dir", "logs_dir", "power_dir", "meta_dir"]
    files: set[str] = set()
    for section in sections:
        directory = paths.get(section)
        if directory and Path(directory).exists():
            files.update(str(p) for p in Path(directory).glob("*"))
    return files


def detect_output_files(paths: dict, before: set[str]) -> list[str]:
    return sorted(snapshot_files(paths) - before)


def relative_files(paths: dict, files: Iterable[str], limit: int | None = None) -> list[str]:
    run_dir = Path(paths["run_dir"])
    result: list[str] = []
    for file in sorted(files):
        try:
            result.append(str(Path(file).relative_to(run_dir)))
        except Exception:
            result.append(str(file))
        if limit is not None and len(result) >= limit:
            break
    return result


def write_step_log(
    paths: dict,
    step: Step,
    status: str,
    returncode: int | None,
    duration_s: float,
    outputs: Iterable[str],
    error: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    input_files: Iterable[str] | None = None,
) -> None:
    safe_name = step.script.replace(".py", "").replace("/", "_")
    payload = {
        "step": step.script,
        "description": step.description,
        "phase": step.phase,
        "required": step.required,
        "status": status,
        "returncode": returncode,
        "started_at": started_at or datetime.now().isoformat(timespec="seconds"),
        "finished_at": finished_at or datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": round(duration_s, 3),
        "input_files": relative_files(paths, input_files or [], limit=80),
        "output_files": relative_files(paths, outputs),
        "error": error,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }
    save_json(paths["logs_dir"] / f"pipeline_step_{timestamp_now()}_{safe_name}.json", payload)


def run_step(step: Step, paths: dict, env: dict) -> bool:
    script_path = SRC_DIR / step.script
    if not script_path.exists():
        status = "skipped_missing_optional" if not step.required else "missing_required"
        print(f"[PRALEISTA] {step.description}: skriptas nerastas ({step.script}).", flush=True)
        now = datetime.now().isoformat(timespec="seconds")
        write_step_log(paths, step, status, None, 0.0, [], f"Skriptas nerastas: {script_path}", started_at=now, finished_at=now)
        if step.required:
            raise SystemExit(2)
        return False

    print_header(f"{step.description} ({step.script})")
    before = snapshot_files(paths)
    started_at = datetime.now().isoformat(timespec="seconds")
    start = time.time()
    try:
        result = subprocess.run([PYTHON, str(script_path), *step.args], cwd=str(SRC_DIR), env=env)
        duration = time.time() - start
        outputs = detect_output_files(paths, before)
        if result.returncode == 0:
            print(f"[GERAI] Etapas baigtas: {step.description}. Trukmė: {duration:.2f} s", flush=True)
            write_step_log(paths, step, "success", result.returncode, duration, outputs, started_at=started_at, finished_at=datetime.now().isoformat(timespec="seconds"), input_files=before)
            return True

        status = "failed_required" if step.required else "failed_optional"
        print(f"[KLAIDA] Etapas nepavyko: {step.description}. Grąžinimo kodas: {result.returncode}", flush=True)
        write_step_log(paths, step, status, result.returncode, duration, outputs, started_at=started_at, finished_at=datetime.now().isoformat(timespec="seconds"), input_files=before)
        if step.required:
            raise SystemExit(result.returncode)
        return False
    except SystemExit:
        raise
    except Exception as exc:
        duration = time.time() - start
        outputs = detect_output_files(paths, before)
        print(f"[KLAIDA] Etapas nutrūko: {step.description}. Priežastis: {exc}", flush=True)
        write_step_log(paths, step, "exception", None, duration, outputs, str(exc), started_at=started_at, finished_at=datetime.now().isoformat(timespec="seconds"), input_files=before)
        if step.required:
            raise
        return False


def start_power_logger(run_id: str, env: dict) -> subprocess.Popen | None:
    script = SRC_DIR / "power_logger.py"
    if not script.exists():
        print("[INFO] Energijos sąnaudų registravimas praleistas: power_logger.py nerastas.", flush=True)
        return None
    try:
        return subprocess.Popen(
            [PYTHON, str(script), run_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(SRC_DIR),
            env=env,
        )
    except Exception as exc:
        print(f"[ĮSPĖJIMAS] Nepavyko paleisti energijos sąnaudų registravimo: {exc}", flush=True)
        return None


def stop_power_logger(proc: subprocess.Popen | None) -> None:
    if not proc:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_power_summary(paths: dict, env: dict) -> None:
    summary_script = SRC_DIR / "power_summary.py"
    csv_file = latest_power_csv(paths)
    if not summary_script.exists() or not csv_file:
        return
    print_header("Energijos sąnaudų santraukos generavimas")
    subprocess.run([PYTHON, str(summary_script), str(csv_file)], cwd=str(SRC_DIR), env=env, check=False)


def read_latest_llm_status() -> dict | None:
    path = Path(os.environ.get("NETWORK_THESIS_LATEST_RUN_DIR", str(BASE_DIR / "latest"))) / "llm_recommendations_latest.json"
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        data["_path"] = str(path)
        return data
    except Exception as exc:
        return {"status": "unreadable", "error": str(exc), "_path": str(path)}

def latest_structured_recommendations_path() -> Path:
    return current_latest_dir() / "ai_recommendations_latest.json"


def main() -> None:
    run_id = time.strftime("%Y-%m-%d_%H-%M-%S")
    paths = get_run_paths(run_id)
    env = os.environ.copy()
    apply_runtime_env_aliases(env, paths)

    profile_info = apply_scan_profile(env)
    steps = runtime_steps(env)

    write_run_context({
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "scan_profile": profile_info,
        "pipeline_steps": [
            {"script": s.script, "description": s.description, "phase": s.phase, "required": s.required, "args": list(s.args)}
            for s in steps
        ],
        "pipeline_note": (
            "Sistema generuoja techninius radinius, vieną ai_evidence dokumentą, "
            "struktūruotų rekomendacijų sluoksnį ir, kai LOCAL_LLM_ENABLED=1, "
            "papildomą Ollama LLM rekomendacijų tekstą. Jei Ollama neatsako, local_llm_recommendation_engine.py "
            "gali sukurti atsarginį struktūruotą dokumentą, nebent LOCAL_LLM_STRICT=1. "
            "Kai įjungtas RECOMMENDATION_DELIVERY_ENABLED arba OPENAI_API_FALLBACK_ENABLED, "
            "recommendation_delivery.py parengia PDF ir prireikus naudoja OpenAI/ChatGPT API atsarginį etapą."
        ),
        "risk_model_note": "Oficialus rizikos balas skaičiuojamas 0-100 skalėje risk_engine.py modulyje.",
    })

    print_header("Automatinis vidinio tinklo saugumo vertinimas")
    print_experiment_mode_summary(env)
    print(f"[INFO] Paleidimo identifikatorius: {run_id}", flush=True)
    print(f"[INFO] Rezultatų katalogas: {paths['run_dir']}", flush=True)
    print(f"[INFO] DI katalogas: {paths['ai_dir']}", flush=True)
    print(f"[INFO] Šio paleidimo latest katalogas: {current_latest_dir()}", flush=True)
    print(f"[INFO] Pasirinktas skenavimo profilis: {profile_info.get('profile')} ({profile_info.get('source')})", flush=True)
    print(f"[INFO] Ollama LLM etapas: {'įjungtas' if llm_enabled(env) else 'išjungtas'}", flush=True)
    print(f"[INFO] PDF ir el. pašto rekomendacijų pristatymo etapas: {'įjungtas' if recommendation_delivery_enabled(env) else 'išjungtas'}", flush=True)
    if profile_info.get("warning"):
        print(f"[ĮSPĖJIMAS] {profile_info['warning']}", flush=True)

    power_proc = start_power_logger(run_id, env)
    start = time.time()
    failed_required = False
    step_results: list[dict] = []
    try:
        for step in steps:
            ok = run_step(step, paths, env)
            step_results.append({
                "script": step.script,
                "description": step.description,
                "phase": step.phase,
                "required": step.required,
                "script_exists": (SRC_DIR / step.script).exists(),
                "success": bool(ok),
            })
    except SystemExit:
        failed_required = True
        raise
    finally:
        stop_power_logger(power_proc)
        run_power_summary(paths, env)
        total_duration = round(time.time() - start, 2)
        optional_failures = [
            r for r in step_results
            if not r.get("required") and r.get("script_exists") and not r.get("success")
        ]
        llm_status = read_latest_llm_status() if llm_enabled(env) else None
        summary = {
            "report_type": "full_assessment_execution_summary",
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "status": "failed" if failed_required else "success",
            "duration_seconds": total_duration,
            "run_dir": str(paths["run_dir"]),
            "ai_dir": str(paths["ai_dir"]),
            "profile": profile_info,
            "local_llm_enabled": llm_enabled(env),
            "recommendation_delivery_enabled": recommendation_delivery_enabled(env),
            "step_results": step_results,
            "optional_failures_count": len(optional_failures),
            "optional_failures": optional_failures,
            "llm_recommendations_status": llm_status,
        }
        save_json(paths["reports_dir"] / f"full_assessment_summary_{timestamp_now()}.json", summary)

    optional_failures = [
        r for r in step_results
        if not r.get("required") and r.get("script_exists") and not r.get("success")
    ]
    llm_status = read_latest_llm_status() if llm_enabled(env) else None

    print_header("Saugumo vertinimas baigtas")
    print("[GERAI] Visi būtini etapai baigti sėkmingai.", flush=True)
    if optional_failures:
        names = ", ".join(r["script"] for r in optional_failures[:8])
        print(f"[ĮSPĖJIMAS] Nepavyko vienas ar keli neprivalomi etapai: {names}", flush=True)
    else:
        print("[GERAI] Neprivalomi etapai neužfiksavo klaidų.", flush=True)

    latest_dir = current_latest_dir()
    print(f"[INFO] Rezultatų katalogas: {paths['run_dir']}", flush=True)
    print(f"[INFO] Šio paleidimo latest katalogas: {latest_dir}", flush=True)
    print(f"[INFO] Galutinis DI techninių įrodymų dokumentas: {latest_dir / 'ai_evidence_latest.json'}", flush=True)
    print(f"[INFO] Struktūruotų rekomendacijų failas: {latest_dir / 'ai_recommendations_latest.json'}", flush=True)

    final_json = latest_dir / "final_recommendations_latest.json"
    final_md = latest_dir / "final_recommendations_latest.md"
    pdf_path = latest_dir / "recommendations_latest.pdf"
    if final_json.exists():
        print(f"[INFO] Galutinių rekomendacijų JSON: {final_json}", flush=True)
    if final_md.exists():
        print(f"[INFO] Galutinių rekomendacijų MD: {final_md}", flush=True)
    if pdf_path.exists():
        print(f"[INFO] Rekomendacijų PDF dokumentas: {pdf_path}", flush=True)

    metrics_json = latest_dir / "academic_experiment_metrics_latest.json"
    metrics_csv = latest_dir / "academic_experiment_metrics_latest.csv"
    metrics_md = latest_dir / "academic_experiment_summary_latest.md"
    if metrics_json.exists():
        print(f"[INFO] Akademinių metrikų JSON: {metrics_json}", flush=True)
    if metrics_csv.exists():
        print(f"[INFO] Akademinių metrikų CSV: {metrics_csv}", flush=True)
    if metrics_md.exists():
        print(f"[INFO] Akademinių metrikų santrauka: {metrics_md}", flush=True)

    if llm_enabled(env):
        llm_path = latest_dir / "llm_recommendations_latest.md"
        status = (llm_status or {}).get("status")
        if status == "success":
            print(f"[GERAI] Vietinės Ollama LLM rekomendacijos: {llm_path}", flush=True)
        elif str(status or "").startswith("fallback_"):
            print(f"[ĮSPĖJIMAS] Ollama negrąžino sėkmingo atsakymo, todėl naudotas atsarginis struktūruotas rezultatas: {llm_path}", flush=True)
            if (llm_status or {}).get("error"):
                print(f"[INFO] Ollama klaida: {(llm_status or {}).get('error')}", flush=True)
        elif status:
            print(f"[INFO] Vietinio LLM statusas: {status}. Failas: {llm_path}", flush=True)
        else:
            print(f"[INFO] Vietinio LLM statuso failas nerastas: {llm_path}", flush=True)
    else:
        print("[INFO] LLM rekomendacijos negeneruotos, nes LOCAL_LLM_ENABLED nėra įjungtas.", flush=True)


if __name__ == "__main__":
    main()

# === CHATGPT_MANUAL_PACKAGE_START ===
# Šis blokas paruošia ir išsiunčia rankinio AI įkėlimo paketą tik tada,
# kai aiškiai įjungtas CHATGPT_PACKAGE_EMAIL_ENABLED=1.
try:
    import os as _chatgpt_pkg_os

    _manual_pkg_enabled = str(_chatgpt_pkg_os.environ.get("CHATGPT_PACKAGE_EMAIL_ENABLED", "0")).strip().lower() in {"1", "true", "yes", "y", "on"}
    _manual_pkg_disabled = str(_chatgpt_pkg_os.environ.get("CHATGPT_MANUAL_PACKAGE_DISABLED", "0")).strip().lower() in {"1", "true", "yes", "y", "on"}

    if _manual_pkg_disabled:
        print("[INFO] ChatGPT rankinio įkėlimo paketo generavimas išjungtas per CHATGPT_MANUAL_PACKAGE_DISABLED=1.")
    elif _manual_pkg_enabled:
        from chatgpt_manual_email_package import prepare_chatgpt_manual_package as _prepare_chatgpt_manual_package

        _chatgpt_pkg_status = _prepare_chatgpt_manual_package(
            run_dir=None,
            send_email=True,
        )

        print("[INFO] ChatGPT rankinio įkėlimo paketas paruoštas:", _chatgpt_pkg_status.package_dir)
        if _chatgpt_pkg_status.email_sent:
            print("[INFO] ChatGPT rankinio įkėlimo paketas išsiųstas el. paštu.")
        elif _chatgpt_pkg_status.email_error:
            print("[WARN] ChatGPT paketas paruoštas, bet laiško išsiųsti nepavyko:", _chatgpt_pkg_status.email_error)
        else:
            print("[INFO] ChatGPT rankinio įkėlimo paketas paruoštas, bet laiškas nesiųstas.")
    else:
        print("[INFO] ChatGPT rankinio įkėlimo paketas neparuoštas, nes CHATGPT_PACKAGE_EMAIL_ENABLED nėra 1.")

except Exception as _chatgpt_pkg_exc:
    print("[WARN] Nepavyko paruošti ChatGPT rankinio įkėlimo paketo:", _chatgpt_pkg_exc)
# === CHATGPT_MANUAL_PACKAGE_END ===

