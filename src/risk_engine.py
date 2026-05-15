from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from common import BASE_DIR, RUNS_DIR, get_run_paths, latest_current_file, load_json, save_json, timestamp_now

CONFIG_DIR = BASE_DIR / "config"
RISK_MODEL_FILE = CONFIG_DIR / "risk_model.json"

EVENT_ID_NAMES = {
    1102: "audit_log_cleared",
    4624: "successful_logon",
    4625: "failed_logon",
    4634: "logoff",
    4647: "user_initiated_logoff",
    4648: "explicit_credentials_logon",
    4672: "special_privileges_assigned",
    4688: "process_created",
    4697: "service_installed",
    4720: "user_account_created",
    4722: "user_account_enabled",
    4723: "password_change_attempt",
    4724: "password_reset_attempt",
    4725: "user_account_disabled",
    4726: "user_account_deleted",
    4732: "member_added_to_local_group",
    4733: "member_removed_from_local_group",
    4738: "user_account_changed",
    4740: "account_locked_out",
    4776: "ntlm_credential_validation",
    4103: "powershell_module_logging",
    4104: "powershell_scriptblock_logging",
    5857: "wmi_activity",
    5858: "wmi_activity",
    5859: "wmi_activity",
    5860: "wmi_activity",
    5861: "wmi_activity",
}


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    return max(minimum, min(maximum, value))


def ip_sort_key(ip: str):
    try:
        return tuple(int(part) for part in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def latest_optional(directory: Path, pattern: str) -> Path | None:
    files = sorted(directory.glob(pattern))
    return files[-1] if files else None


def latest_global(pattern: str) -> Path | None:
    files = sorted(RUNS_DIR.glob(f"**/{pattern}"))
    return files[-1] if files else None


def load_model() -> dict:
    if not RISK_MODEL_FILE.exists():
        raise FileNotFoundError(f"Nerastas rizikos modelio konfigūracijos failas: {RISK_MODEL_FILE}")
    model = load_json(RISK_MODEL_FILE)
    validate_model(model)
    return model


def validate_model(model: dict) -> None:
    weights = model.get("weights") or {}
    required = {"V", "E", "K", "C", "L", "A"}
    missing = sorted(required - set(weights.keys()))
    if missing:
        raise ValueError(f"risk_model.json trūksta svorių: {', '.join(missing)}")

    total = sum(float(weights[k]) for k in required)
    require_sum = (model.get("validation") or {}).get("require_weights_sum_to_one", True)
    if require_sum and abs(total - 1.0) > 0.0001:
        raise ValueError(f"risk_model.json svorių suma yra {total:.4f}, bet turi būti 1.0000")

    for level in as_list(model.get("risk_levels")):
        if not {"level", "min", "max"}.issubset(level):
            raise ValueError("risk_model.json risk_levels įrašas turi turėti level, min ir max laukus")


def risk_level(score: float, model: dict) -> str:
    for level in as_list(model.get("risk_levels")):
        if float(level["min"]) <= score <= float(level["max"]):
            return str(level["level"])
    if score >= 80:
        return "kritinė"
    if score >= 60:
        return "aukšta"
    if score >= 30:
        return "vidutinė"
    return "žema"


def get_profile(host: dict) -> dict:
    profile = host.get("normalized_security_profile")
    return profile if isinstance(profile, dict) else {}


def get_tcp_ports(profile: dict, host: dict) -> list[int]:
    ports = profile.get("tcp_open_ports")
    if isinstance(ports, list):
        return [int(p) for p in ports if str(p).isdigit()]
    result = []
    for port in as_list(host.get("ports")):
        p = port.get("port")
        if isinstance(p, int):
            result.append(p)
    return sorted(set(result))


def get_vulnerability_component(profile: dict, model: dict) -> tuple[float, list[str]]:
    vulns = profile.get("vulnerabilities") or profile.get("known_vulns") or {}
    highest_cvss = vulns.get("highest_cvss", (model.get("missing_data_policy") or {}).get("cvss_default", 0))
    try:
        v = clamp(float(highest_cvss) * 10.0)
    except Exception:
        v = 0.0

    explanation = []
    if v > 0:
        explanation.append(f"Didžiausias aptiktas CVSS: {highest_cvss}")
    return v, explanation


def iter_vulnerability_items(profile: dict):
    vulns = profile.get("vulnerabilities") or profile.get("known_vulns") or {}
    for key in ("all_cves", "cves", "vulnerabilities"):
        for item in as_list(vulns.get(key)):
            if isinstance(item, dict):
                yield item
            elif isinstance(item, str):
                yield {"cve": item}


def get_epss_component(profile: dict, model: dict) -> tuple[float, list[str]]:
    best = None
    best_cve = None
    for item in iter_vulnerability_items(profile):
        for key in ("epss", "epss_score", "exploit_probability"):
            if key in item:
                try:
                    val = float(item[key])
                    if val <= 1.0:
                        val *= 100.0
                    if best is None or val > best:
                        best = val
                        best_cve = item.get("cve") or item.get("id")
                except Exception:
                    pass
    if best is None:
        best = float((model.get("missing_data_policy") or {}).get("epss_default", 0))
    explanation = []
    if best > 0:
        if best_cve:
            explanation.append(f"Didžiausias EPSS balas susietas su {best_cve}: {round(best, 2)}")
        else:
            explanation.append(f"Didžiausias EPSS balas: {round(best, 2)}")
    return clamp(best), explanation


def get_kev_component(profile: dict, model: dict) -> tuple[float, list[str]]:
    kev_cves = []
    for item in iter_vulnerability_items(profile):
        if any(bool(item.get(k)) for k in ("kev", "cisa_kev", "is_kev", "known_exploited")):
            kev_cves.append(item.get("cve") or item.get("id") or "unknown")
    if kev_cves:
        return 100.0, ["Aptikta CISA KEV / žinomai išnaudojamo pažeidžiamumo požymių: " + ", ".join(sorted(set(kev_cves))[:5])]
    return float((model.get("missing_data_policy") or {}).get("kev_default", 0)), []


def get_criticality_component(profile: dict, model: dict) -> tuple[float, list[str]]:
    device_class = profile.get("device_class") or "unclassified_network_host"
    criticality_map = model.get("device_criticality") or {}
    validation = model.get("validation") or {}
    score = criticality_map.get(device_class, validation.get("unknown_device_class_score", 40))
    return clamp(float(score)), [f"Įrenginio klasė: {device_class}; kritiškumo balas: {score}"]


def get_attack_surface_component(profile: dict, host: dict, model: dict) -> tuple[float, list[str]]:
    rules = model.get("attack_surface_rules") or {}
    risky_ports = rules.get("risky_tcp_ports") or {}
    service_flags = rules.get("service_flags") or {}
    max_score = float(rules.get("max_score", 100))

    total = 0.0
    explanation = []
    tcp_ports = get_tcp_ports(profile, host)

    for port in tcp_ports:
        port_score = risky_ports.get(str(port))
        if port_score:
            total += float(port_score)
            explanation.append(f"Atviras rizikingas TCP prievadas {port} (+{port_score})")

    smb = profile.get("smb") or {}
    rdp = profile.get("rdp") or {}
    web = profile.get("web") or {}
    tls = profile.get("tls") or {}
    snmp = profile.get("snmp") or {}
    ssh = profile.get("ssh") or {}

    flag_checks = [
        ("smbv1_enabled", bool(smb.get("smbv1_enabled")), "Aptiktas SMBv1"),
        ("smb_signing_disabled", bool(smb.get("signing_disabled")), "SMB signing išjungtas"),
        ("smb_guest_or_share_auth", bool(smb.get("guest_or_share_auth")), "SMB guest/share autentifikacija"),
        ("rdp_present", bool(rdp.get("present")), "Aptiktas RDP"),
        ("web_admin_interface", bool(web.get("admin_interface_detected") or web.get("login_page_detected")), "Aptikta web prisijungimo/admin sąsaja"),
        ("weak_tls", bool(tls.get("weak_ciphers_present") or any(v in {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"} for v in as_list(tls.get("versions")))), "Silpni arba pasenę TLS požymiai"),
        ("snmp_present", bool(snmp.get("present")), "Aptikta SNMP tarnyba"),
        ("snmp_default_community", any(c in {"public", "private"} for c in as_list(snmp.get("community_strings_detected"))), "SNMP public/private community"),
        ("weak_ssh_algorithms", bool(as_list(ssh.get("weak_algorithms"))), "Silpni SSH algoritmai"),
    ]

    for flag, present, text in flag_checks:
        if present:
            value = float(service_flags.get(flag, 0))
            total += value
            if value:
                explanation.append(f"{text} (+{int(value)})")

    open_bonus = rules.get("open_ports_bonus") or {}
    threshold = int(open_bonus.get("threshold", 0))
    if threshold and len(tcp_ports) >= threshold:
        bonus = float(open_bonus.get("score", 0))
        total += bonus
        explanation.append(f"Daug atvirų TCP prievadų ({len(tcp_ports)}) (+{int(bonus)})")

    return clamp(total, 0, max_score), explanation[:12]


def event_host_candidates(event: dict) -> set[str]:
    candidates = set()

    def walk(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_l = str(key).lower()
                if key_l in {"ip", "host_ip", "source_ip", "src_ip", "collector_seen_ip", "computer_ip"} and isinstance(value, str):
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
                        candidates.add(value)
                walk(value)
        elif isinstance(obj, list):
            for x in obj:
                walk(x)

    walk(event)
    return candidates


def extract_event_id(event: dict) -> int | None:
    for path in (
        ("event", "id"),
        ("event_id",),
        ("id",),
        ("EventID",),
    ):
        cur = event
        ok = True
        for key in path:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                ok = False
                break
        if ok:
            try:
                return int(cur)
            except Exception:
                return None
    return None


def endpoint_events_from_data(data: dict | None) -> list[dict]:
    if not data:
        return []
    events = []
    for key in ("normalized_events", "events", "normalized_events_sample", "endpoint_events", "eset_csv_rows", "eset_csv_rows_sample", "high_value_eset_rows_sample"):
        value = data.get(key)
        if isinstance(value, list):
            events.extend([x for x in value if isinstance(x, dict)])
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    if isinstance(summary.get("high_value_eset_rows_sample"), list):
        events.extend([x for x in summary["high_value_eset_rows_sample"] if isinstance(x, dict)])
    # Some normalizers store payload under endpoint_events.events
    endpoint = data.get("endpoint_events")
    if isinstance(endpoint, dict):
        for key in ("normalized_events", "events", "normalized_events_sample", "eset_csv_rows", "eset_csv_rows_sample", "high_value_eset_rows_sample"):
            value = endpoint.get(key)
            if isinstance(value, list):
                events.extend([x for x in value if isinstance(x, dict)])
        nested_summary = endpoint.get("summary") if isinstance(endpoint.get("summary"), dict) else {}
        if isinstance(nested_summary.get("high_value_eset_rows_sample"), list):
            events.extend([x for x in nested_summary["high_value_eset_rows_sample"] if isinstance(x, dict)])
    # The same ESET row may appear both in high_value_eset_rows_sample and eset_csv_rows_sample.
    # De-duplicate before building risk indexes so the L component is not inflated.
    deduped = []
    seen = set()
    for event in events:
        key = event.get("dedupe_key") if isinstance(event, dict) else None
        if not key and isinstance(event, dict):
            try:
                key = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            except Exception:
                key = str(id(event))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def load_endpoint_data(paths: dict) -> dict | None:
    file = latest_optional(paths["reports_dir"], "endpoint_events_*.json")
    if file is None:
        file = latest_global("endpoint_events_*.json")
    if file and file.exists():
        data = load_json(file)
        data["_source_file"] = file.name
        return data
    return None


def build_endpoint_index(endpoint_data: dict | None) -> dict[str, dict]:
    index = defaultdict(lambda: {"event_ids": Counter(), "events": 0, "eset_rows": 0})
    events = endpoint_events_from_data(endpoint_data)

    for event in events:
        ips = event_host_candidates(event)
        event_id = extract_event_id(event)
        if not ips:
            continue
        for ip in ips:
            index[ip]["events"] += 1
            if event_id is not None:
                index[ip]["event_ids"][event_id] += 1
            source_type = str(event.get("source_type") or event.get("event", {}).get("source_type") or "").lower()
            if "eset" in source_type:
                index[ip]["eset_rows"] += 1

    return index


def score_failed_logons(count: int, model: dict) -> float:
    thresholds = as_list((model.get("log_anomaly_rules") or {}).get("failed_logon_thresholds"))
    score = 0.0
    for item in thresholds:
        try:
            if count >= int(item.get("count", 0)):
                score = max(score, float(item.get("score", 0)))
        except Exception:
            continue
    return score


def get_log_anomaly_component(ip: str, endpoint_index: dict, model: dict) -> tuple[float, list[str]]:
    rules = model.get("log_anomaly_rules") or {}
    max_score = float(rules.get("max_score", 100))
    data = endpoint_index.get(ip)
    if not data:
        return float((model.get("missing_data_policy") or {}).get("log_anomaly_default", 0)), []

    ids = data.get("event_ids") or Counter()
    total = 0.0
    explanation = []

    failed = ids.get(4625, 0)
    if failed:
        val = score_failed_logons(failed, model)
        total = max(total, val)
        explanation.append(f"Nesėkmingi prisijungimai 4625: {failed} (L≥{int(val)})")

    direct_scores = [
        (4740, "account_lockout_score", "Paskyros užrakinimas"),
        (4672, "special_privilege_logon_score", "Specialių privilegijų prisijungimas"),
        (4720, "new_user_created_score", "Sukurta nauja paskyra"),
        (4732, "user_added_to_admin_group_score", "Naudotojas pridėtas į grupę"),
        (1102, "audit_log_cleared_score", "Išvalytas audito žurnalas"),
        (4104, "powershell_scriptblock_score", "PowerShell ScriptBlock įvykiai"),
        (5858, "wmi_activity_score", "WMI veiklos įvykiai"),
    ]

    for event_id, rule_key, label in direct_scores:
        count = ids.get(event_id, 0)
        if count:
            val = float(rules.get(rule_key, 0))
            total = max(total, val)
            explanation.append(f"{label} ({event_id}): {count} (L≥{int(val)})")

    if data.get("eset_rows", 0):
        val = float(rules.get("eset_detection_score", 0))
        total = max(total, val)
        explanation.append(f"ESET įvykių eilutės: {data.get('eset_rows')} (L≥{int(val)})")

    return clamp(total, 0, max_score), explanation[:10]


def calculate_host_risk(host: dict, model: dict, endpoint_index: dict) -> dict:
    profile = get_profile(host)
    ip = host.get("ip")

    components = {}
    explanations = []

    components["V"], exp = get_vulnerability_component(profile, model)
    explanations.extend(exp)

    components["E"], exp = get_epss_component(profile, model)
    explanations.extend(exp)

    components["K"], exp = get_kev_component(profile, model)
    explanations.extend(exp)

    components["C"], exp = get_criticality_component(profile, model)
    explanations.extend(exp)

    components["L"], exp = get_log_anomaly_component(ip, endpoint_index, model)
    explanations.extend(exp)

    components["A"], exp = get_attack_surface_component(profile, host, model)
    explanations.extend(exp)

    weights = model.get("weights") or {}
    weighted_parts = {key: round(float(weights[key]) * float(components[key]), 4) for key in components}
    score = clamp(sum(weighted_parts.values()))
    level = risk_level(score, model)

    return {
        "ip": ip,
        "asset_id": host.get("asset_id"),
        "hostname": host.get("hostname"),
        "mac": host.get("mac"),
        "vendor": host.get("vendor"),
        "device_class": profile.get("device_class"),
        "risk_score": round(score, 2),
        "risk_level": level,
        "risk_components": {k: round(v, 2) for k, v in components.items()},
        "weighted_parts": weighted_parts,
        "weights_used": weights,
        "explanation": explanations[:15],
        "source_legacy_priority_score_previous_engine": host.get("legacy_priority_score", host.get("priority_score")),
        "source_legacy_priority_level_previous_engine": host.get("legacy_priority_level", host.get("priority_level")),
    }


def risk_identity_key(item: dict) -> str | None:
    return item.get("asset_id") or item.get("ip")


def previous_risk_scores(current_file: Path | None = None) -> dict[str, dict]:
    files = sorted(RUNS_DIR.glob("**/risk_scores_*.json"))
    if current_file:
        files = [f for f in files if f != current_file]
    if not files:
        return {}
    try:
        data = load_json(files[-1])
    except Exception:
        return {}
    out = {}
    for h in as_list(data.get("hosts")):
        if not isinstance(h, dict):
            continue
        key = risk_identity_key(h)
        if key:
            out[key] = h
        if h.get("ip"):
            out.setdefault(h.get("ip"), h)
    return out


def add_delta(host_scores: list[dict], previous: dict[str, dict]) -> None:
    for item in host_scores:
        prev = previous.get(risk_identity_key(item)) or previous.get(item.get("ip"))
        if not prev:
            item["risk_delta"] = None
            item["previous_risk_score"] = None
            item["previous_risk_level"] = None
            continue
        prev_score = float(prev.get("risk_score", 0))
        cur_score = float(item.get("risk_score", 0))
        item["previous_risk_score"] = prev.get("risk_score")
        item["previous_risk_level"] = prev.get("risk_level")
        item["risk_delta"] = round(cur_score - prev_score, 2)


def build_summary(host_scores: list[dict]) -> dict:
    by_level = Counter(h.get("risk_level") for h in host_scores)
    avg = round(sum(float(h.get("risk_score", 0)) for h in host_scores) / len(host_scores), 2) if host_scores else 0
    return {
        "hosts_scored": len(host_scores),
        "average_risk_score": avg,
        "by_level": dict(by_level),
        "top_10": [
            {
                "ip": h.get("ip"),
                "asset_id": h.get("asset_id"),
                "device_class": h.get("device_class"),
                "risk_score": h.get("risk_score"),
                "risk_level": h.get("risk_level"),
                "top_reasons": h.get("explanation", [])[:5],
            }
            for h in sorted(host_scores, key=lambda x: x.get("risk_score", 0), reverse=True)[:10]
        ],
    }


def update_ai_payload(paths: dict, risk_file: Path, report: dict) -> Path | None:
    payload_file = latest_optional(paths["ai_dir"], "ai_recommendation_payload_*.json")
    if payload_file is None:
        return None
    try:
        payload = load_json(payload_file)
    except Exception:
        return None

    payload["risk_model"] = {
        "source_file": risk_file.name,
        "model_name": report.get("risk_model", {}).get("model_name"),
        "version": report.get("risk_model", {}).get("version"),
        "formula": report.get("risk_model", {}).get("formula"),
        "weights": report.get("risk_model", {}).get("weights"),
    }
    payload["risk_scores"] = {
        "summary": report.get("summary"),
        "hosts": report.get("hosts", [])[:50],
    }
    save_json(payload_file, payload)
    return payload_file


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    model = load_model()

    assessment_file = latest_current_file("reports_dir", "assessment_*.json")
    if assessment_file is None:
        assessment_file = latest_global("assessment_*.json")
    if assessment_file is None:
        raise FileNotFoundError("Nerastas assessment_*.json failas. Pirmiausia paleisk merge_assessment.py")

    assessment = load_json(assessment_file)
    endpoint_data = load_endpoint_data(paths)
    endpoint_index = build_endpoint_index(endpoint_data)

    host_scores = []
    for host in as_list(assessment.get("hosts")):
        if not host.get("ip"):
            continue
        host_scores.append(calculate_host_risk(host, model, endpoint_index))

    host_scores = sorted(host_scores, key=lambda h: (-h.get("risk_score", 0), ip_sort_key(h.get("ip", "0.0.0.0"))))
    add_delta(host_scores, previous_risk_scores())

    report = {
        "report_type": "risk_scores",
        "timestamp": timestamp,
        "network": assessment.get("network"),
        "assessment_file": assessment_file.name,
        "endpoint_events_file": endpoint_data.get("_source_file") if endpoint_data else None,
        "risk_model": {
            "model_name": model.get("model_name"),
            "version": model.get("version"),
            "formula": model.get("formula"),
            "weights": model.get("weights"),
            "component_labels": model.get("component_labels"),
            "risk_levels": model.get("risk_levels"),
        },
        "summary": build_summary(host_scores),
        "hosts": host_scores,
    }

    out_file = paths["reports_dir"] / f"risk_scores_{timestamp}.json"
    save_json(out_file, report)

    ai_context = {
        "payload_type": "risk_model_context",
        "timestamp": timestamp,
        "source_file": out_file.name,
        "instruction": "Naudok šiuos konfigūruojamo rizikos modelio balus prioritetizuodamas rekomendacijas.",
        "risk_model": report["risk_model"],
        "summary": report["summary"],
        "hosts": host_scores[:50],
    }
    ai_file = paths["ai_dir"] / f"risk_model_context_{timestamp}.json"
    save_json(ai_file, ai_context)

    updated_payload = update_ai_payload(paths, out_file, report)

    print(f"Rizikos modelio ataskaita: {out_file}")
    print(f"Rizikos modelio AI kontekstas: {ai_file}")
    if updated_payload:
        print(f"Atnaujintas AI rekomendacijų payload: {updated_payload}")
    print(f"Įvertintų hostų skaičius: {len(host_scores)}")
    print(f"Vidutinis rizikos balas: {report['summary']['average_risk_score']}")


if __name__ == "__main__":
    main()
