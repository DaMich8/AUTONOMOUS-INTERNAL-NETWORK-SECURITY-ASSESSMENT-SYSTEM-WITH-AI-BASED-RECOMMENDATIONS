from __future__ import annotations

import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from common import BASE_DIR, RUNS_DIR, get_run_paths, latest_file_in_dir, load_json, save_json, timestamp_now
from finding_schema import normalize_finding

CONFIG_FILE = BASE_DIR / "config" / "correlation_rules.json"
CORRELATION_RULES_VERSION = os.getenv("CORRELATION_RULES_VERSION", "v1.0")
CORRELATION_TIME_WINDOW_HOURS = int(os.getenv("CORRELATION_TIME_WINDOW_HOURS", "24"))


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def load_json_optional(path: Path | None) -> dict | None:
    if path and path.exists():
        try:
            return load_json(path)
        except Exception:
            return None
    return None


def latest_in_current_or_runs(paths: dict, current_pattern: str, recursive_pattern: str) -> Path | None:
    current = latest_file_in_dir(paths["reports_dir"], current_pattern)
    if current:
        return current
    files = sorted(RUNS_DIR.glob(recursive_pattern))
    return files[-1] if files else None


def default_rules() -> dict:
    return {
        "thresholds": {
            "failed_logons_medium": 5,
            "failed_logons_high": 20,
            "failed_logons_critical": 50,
            "new_host_many_ports": 8,
            "many_open_ports": 10,
            "powershell_events_medium": 10,
            "eset_rows_medium": 5,
            "eset_rows_high": 20,
        },
        "risk_increase": {
            "rdp_failed_logons": 25,
            "rdp_success_after_failures": 30,
            "smb_legacy_or_guest": 30,
            "snmp_default_community": 25,
            "new_host_many_ports": 20,
            "web_admin_with_vulns": 25,
            "weak_tls_web": 15,
            "powershell_activity": 15,
            "eset_activity": 20,
            "audit_log_cleared": 40,
            "account_change": 30,
        },
        "mitre_mapping": {},
    }


def load_rules() -> dict:
    base = default_rules()
    if CONFIG_FILE.exists():
        try:
            custom = load_json(CONFIG_FILE)
            for key, value in custom.items():
                if isinstance(value, dict) and isinstance(base.get(key), dict):
                    base[key].update(value)
                else:
                    base[key] = value
        except Exception:
            pass
    return base


def extract_event_id(event: dict) -> int | None:
    for key in ("event_id", "id", "EventID", "eventId"):
        value = event.get(key)
        if value is not None:
            try:
                return int(value)
            except Exception:
                return None
    nested = event.get("event") if isinstance(event.get("event"), dict) else {}
    value = nested.get("id")
    try:
        return int(value) if value is not None else None
    except Exception:
        return None


def extract_log_name(event: dict) -> str:
    for key in ("log_name", "channel", "LogName"):
        if event.get(key):
            return str(event.get(key))
    nested = event.get("event") if isinstance(event.get("event"), dict) else {}
    if nested.get("channel"):
        return str(nested.get("channel"))
    return "unknown"


def extract_computer(event: dict) -> str | None:
    for key in ("computer", "Computer", "host", "hostname"):
        if event.get(key):
            return str(event.get(key)).lower()
    src = event.get("source") if isinstance(event.get("source"), dict) else {}
    if src.get("computer"):
        return str(src.get("computer")).lower()
    return None


def extract_ip(event: dict) -> str | None:
    candidates = []
    for key in ("ip", "collector_seen_ip", "src_ip", "source_ip", "IpAddress"):
        if event.get(key):
            candidates.append(str(event.get(key)))
    source = event.get("source") if isinstance(event.get("source"), dict) else {}
    network = event.get("network") if isinstance(event.get("network"), dict) else {}
    data = event.get("event_data") if isinstance(event.get("event_data"), dict) else {}
    for obj in (source, network, data):
        for key in ("collector_seen_ip", "src_ip", "SourceNetworkAddress", "IpAddress", "ip"):
            if obj.get(key):
                candidates.append(str(obj.get(key)))
    for value in candidates:
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", value) and value not in {"0.0.0.0", "127.0.0.1", "-"}:
            return value
    return None


def collect_endpoint_events(endpoint_data: dict | None) -> list[dict]:
    if not endpoint_data:
        return []
    for key in ("normalized_events", "events", "normalized_events_sample"):
        if isinstance(endpoint_data.get(key), list):
            return endpoint_data[key]
    # In some payloads endpoint context is nested.
    if isinstance(endpoint_data.get("endpoint_events"), dict):
        nested = endpoint_data["endpoint_events"]
        for key in ("normalized_events", "events", "normalized_events_sample"):
            if isinstance(nested.get(key), list):
                return nested[key]
    return []


def collect_eset_rows(endpoint_data: dict | None) -> list[dict]:
    if not endpoint_data:
        return []
    for key in ("eset_csv_rows", "eset_csv_rows_sample", "high_value_eset_rows_sample", "eset_events", "normalized_eset_events"):
        if isinstance(endpoint_data.get(key), list):
            return endpoint_data[key]
    summary = endpoint_data.get("summary") if isinstance(endpoint_data.get("summary"), dict) else {}
    if isinstance(summary.get("high_value_eset_rows_sample"), list):
        return summary["high_value_eset_rows_sample"]
    if isinstance(endpoint_data.get("endpoint_events"), dict):
        nested = endpoint_data["endpoint_events"]
        for key in ("eset_csv_rows", "eset_csv_rows_sample", "high_value_eset_rows_sample", "eset_events", "normalized_eset_events"):
            if isinstance(nested.get(key), list):
                return nested[key]
        nested_summary = nested.get("summary") if isinstance(nested.get("summary"), dict) else {}
        if isinstance(nested_summary.get("high_value_eset_rows_sample"), list):
            return nested_summary["high_value_eset_rows_sample"]
    return []


def index_endpoint(endpoint_data: dict | None) -> dict:
    events = collect_endpoint_events(endpoint_data)
    eset_rows = collect_eset_rows(endpoint_data)
    by_ip = defaultdict(list)
    by_computer = defaultdict(list)
    global_events = []

    for event in events:
        if not isinstance(event, dict):
            continue
        ip = extract_ip(event)
        computer = extract_computer(event)
        if ip:
            by_ip[ip].append(event)
        elif computer:
            by_computer[computer].append(event)
        else:
            global_events.append(event)

    eset_by_ip = defaultdict(list)
    eset_by_computer = defaultdict(list)
    for row in eset_rows:
        if not isinstance(row, dict):
            continue
        ip = extract_ip(row)
        computer = extract_computer(row)
        if ip:
            eset_by_ip[ip].append(row)
        elif computer:
            eset_by_computer[computer].append(row)

    return {
        "events": events,
        "eset_rows": eset_rows,
        "by_ip": by_ip,
        "by_computer": by_computer,
        "global_events": global_events,
        "eset_by_ip": eset_by_ip,
        "eset_by_computer": eset_by_computer,
    }


def match_host_events(host: dict, endpoint_index: dict) -> list[dict]:
    ip = host.get("ip")
    hostname = str(host.get("hostname") or "").lower()
    events = []
    if ip:
        events.extend(endpoint_index["by_ip"].get(ip, []))
    if hostname:
        events.extend(endpoint_index["by_computer"].get(hostname, []))
    # If there is only one host and endpoint events do not contain IP, include them as context.
    return events


def match_host_eset(host: dict, endpoint_index: dict) -> list[dict]:
    ip = host.get("ip")
    hostname = str(host.get("hostname") or "").lower()
    rows = []
    if ip:
        rows.extend(endpoint_index["eset_by_ip"].get(ip, []))
    if hostname:
        rows.extend(endpoint_index["eset_by_computer"].get(hostname, []))
    return rows


def host_profile(host: dict) -> dict:
    return host.get("normalized_security_profile") or {}


def open_tcp_ports(profile: dict, host: dict) -> list[int]:
    ports = profile.get("tcp_open_ports")
    if isinstance(ports, list):
        return [int(p) for p in ports if str(p).isdigit()]
    out = []
    for p in as_list(host.get("ports")):
        try:
            out.append(int(p.get("port")))
        except Exception:
            pass
    return sorted(set(out))


def severity_from_failed(count: int, thresholds: dict) -> str:
    if count >= thresholds.get("failed_logons_critical", 50):
        return "kritinė"
    if count >= thresholds.get("failed_logons_high", 20):
        return "aukšta"
    if count >= thresholds.get("failed_logons_medium", 5):
        return "vidutinė"
    return "žema"


def add_finding(findings: list, *, rule_id: str, ip: str | None, title: str, severity: str, evidence: list[str], recommendation: str, risk_increase: int, mitre: list[dict] | None = None, confidence: str = "vidutinis", asset_id: str | None = None):
    finding_id = f"{rule_id}_{(ip or 'global').replace('.', '_')}"
    normalized = normalize_finding({
        "finding_id": finding_id,
        "rule_id": rule_id,
        "ip": ip,
        "asset_id": asset_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": [e for e in evidence if e],
        "impact": "Koreliuotas radinys rodo, kad techninis požymis sutampa su endpoint įvykiais, konfigūracijos rizika arba pokyčiais tinkle.",
        "recommended_fix": recommendation,
        "validation": "Pakartoti susijusį skenavimo etapą ir endpoint įvykių normalizavimą, tada dar kartą paleisti correlation_engine.py.",
        "mitre_attack": mitre or [],
    }, source_module="correlation_engine.py", ip=ip, asset_id=asset_id, scan_status="success")
    normalized["risk_increase"] = risk_increase
    normalized["rule_version"] = CORRELATION_RULES_VERSION
    normalized["correlation_time_window_hours"] = CORRELATION_TIME_WINDOW_HOURS
    normalized["confidence_formula"] = "aukštas kai sutampa techninis požymis ir konkretus endpoint/rizikos indikatorius; vidutinis kai sutampa tik techninis požymis; žemas kai trūksta tiesioginio host susiejimo"
    # Backward compatibility for old report/risk code that reads `recommendation`.
    normalized["recommendation"] = normalized.get("recommended_fix")
    findings.append(normalized)


def analyze_host(host: dict, endpoint_index: dict, rules: dict) -> list[dict]:
    findings = []
    thresholds = rules.get("thresholds", {})
    increases = rules.get("risk_increase", {})
    mitre = rules.get("mitre_mapping", {})
    profile = host_profile(host)
    ip = host.get("ip")
    asset_id = host.get("asset_id")
    ports = open_tcp_ports(profile, host)
    smb = profile.get("smb") or {}
    rdp = profile.get("rdp") or {}
    web = profile.get("web") or {}
    tls = profile.get("tls") or {}
    snmp = profile.get("snmp") or {}
    vulns = profile.get("vulnerabilities") or profile.get("known_vulns") or {}
    change = host.get("change_summary") or {}
    events = match_host_events(host, endpoint_index)
    eset_rows = match_host_eset(host, endpoint_index)
    event_ids = Counter(extract_event_id(e) for e in events if extract_event_id(e) is not None)
    log_names = Counter(extract_log_name(e) for e in events)

    failed = event_ids.get(4625, 0)
    success = event_ids.get(4624, 0)
    if (rdp.get("present") or 3389 in ports) and failed >= thresholds.get("failed_logons_medium", 5):
        add_finding(
            findings,
            rule_id="rdp_failed_logons",
            ip=ip,
            title="Atviras RDP ir nesėkmingi prisijungimai",
            severity=severity_from_failed(failed, thresholds),
            evidence=[f"3389/tcp arba RDP paslauga aptikta hoste {ip}", f"Windows 4625 failed logon įvykių: {failed}"],
            recommendation="Riboti RDP prieigą ugniasienėje tik iš administravimo IP arba VPN segmento, įjungti paskyrų blokavimo politiką ir peržiūrėti šaltinio IP adresus.",
            risk_increase=increases.get("rdp_failed_logons", 25),
            mitre=mitre.get("rdp_failed_logons", []),
            confidence="aukštas",
        )
    if (rdp.get("present") or 3389 in ports) and failed >= thresholds.get("failed_logons_medium", 5) and success > 0:
        add_finding(
            findings,
            rule_id="rdp_success_after_failures",
            ip=ip,
            title="Sėkmingi prisijungimai po nesėkmingų bandymų",
            severity="aukšta",
            evidence=[f"Windows 4625 failed logon: {failed}", f"Windows 4624 successful logon: {success}", "Hoste aptiktas RDP"],
            recommendation="Patikrinti, ar sėkmingi prisijungimai buvo teisėti, peržiūrėti paskyrų istoriją, įjungti MFA/VPN ir riboti RDP pasiekiamumą.",
            risk_increase=increases.get("rdp_success_after_failures", 30),
            mitre=mitre.get("rdp_success_after_failures", []),
            confidence="vidutinis",
        )

    smb_flags = []
    if smb.get("smbv1_enabled"):
        smb_flags.append("SMBv1 įjungtas")
    if smb.get("signing_disabled"):
        smb_flags.append("SMB signing išjungtas")
    if smb.get("guest_or_share_auth"):
        smb_flags.append("guest/share autentifikacija")
    if smb_flags:
        add_finding(
            findings,
            rule_id="smb_legacy_or_guest",
            ip=ip,
            title="Rizikinga SMB konfigūracija",
            severity="aukšta" if smb.get("smbv1_enabled") or smb.get("guest_or_share_auth") else "vidutinė",
            evidence=smb_flags + ["139/445 arba SMB paslauga aptikta"],
            recommendation="Išjungti SMBv1, įjungti SMB signing, išjungti guest/share prieigą ir riboti SMB tik reikalingiems segmentams.",
            risk_increase=increases.get("smb_legacy_or_guest", 30),
            mitre=mitre.get("smb_legacy_or_guest", []),
            confidence="aukštas",
        )

    communities = set(str(c).lower() for c in as_list(snmp.get("community_strings_detected")))
    if communities.intersection({"public", "private"}):
        add_finding(
            findings,
            rule_id="snmp_default_community",
            ip=ip,
            title="SNMP su numatytomis community reikšmėmis",
            severity="aukšta",
            evidence=[f"Aptiktos community reikšmės: {', '.join(sorted(communities))}"],
            recommendation="Pakeisti numatytąsias SNMP community reikšmes, naudoti SNMPv3 ir riboti SNMP prieigą tik valdymo segmentui.",
            risk_increase=increases.get("snmp_default_community", 25),
            mitre=mitre.get("snmp_default_community", []),
            confidence="aukštas",
        )

    if change.get("is_new_host_since_baseline") and len(ports) >= thresholds.get("new_host_many_ports", 8):
        add_finding(
            findings,
            rule_id="new_host_many_ports",
            ip=ip,
            title="Naujas hostas su dideliu atakos paviršiumi",
            severity="aukšta",
            evidence=["Hostas naujas lyginant su baseline", f"Atvirų TCP portų skaičius: {len(ports)}"],
            recommendation="Identifikuoti įrenginį, patikrinti jo paskirtį, savininką ir uždaryti nereikalingas paslaugas arba izoliuoti į atskirą segmentą.",
            risk_increase=increases.get("new_host_many_ports", 20),
            mitre=mitre.get("new_host_many_ports", []),
            confidence="vidutinis",
        )

    if web.get("present") and (web.get("admin_interface_detected") or web.get("login_page_detected")) and vulns.get("has_known_vulns"):
        add_finding(
            findings,
            rule_id="web_admin_with_vulns",
            ip=ip,
            title="Web administravimo sąsaja su žinomais pažeidžiamumais",
            severity="aukšta" if vulns.get("highest_cvss", 0) >= 7 else "vidutinė",
            evidence=["Aptikta web administravimo arba prisijungimo sąsaja", f"CVE kiekis: {vulns.get('vuln_count', 0)}", f"Didžiausias CVSS: {vulns.get('highest_cvss', 0)}"],
            recommendation="Apriboti web administravimo sąsają pagal IP/VPN, atnaujinti komponentus ir pakartoti web/TLS patikrą.",
            risk_increase=increases.get("web_admin_with_vulns", 25),
            mitre=mitre.get("web_admin_with_vulns", []),
            confidence="aukštas",
        )

    if web.get("present") and tls.get("weak_ciphers_present"):
        add_finding(
            findings,
            rule_id="weak_tls_web",
            ip=ip,
            title="Web/TLS paslauga su silpnais šifrais",
            severity="vidutinė",
            evidence=["Aptikta HTTP/HTTPS paslauga", "TLS auditas rodo silpnus cipherius arba senas protokolų versijas"],
            recommendation="Išjungti SSLv3/TLS1.0/TLS1.1 ir silpnus cipherius, palikti TLS1.2/1.3 su stipriais rinkiniais.",
            risk_increase=increases.get("weak_tls_web", 15),
            mitre=mitre.get("weak_tls_web", []),
            confidence="vidutinis",
        )

    ps_count = sum(c for name, c in log_names.items() if "powershell" in name.lower()) + event_ids.get(4103, 0) + event_ids.get(4104, 0)
    if ps_count >= thresholds.get("powershell_events_medium", 10):
        add_finding(
            findings,
            rule_id="powershell_activity",
            ip=ip,
            title="Padidintas PowerShell aktyvumas endpoint loguose",
            severity="vidutinė",
            evidence=[f"PowerShell susijusių įvykių kiekis: {ps_count}"],
            recommendation="Peržiūrėti PowerShell įvykių turinį, įjungti script block logging ir riboti nesankcionuotų scriptų vykdymą.",
            risk_increase=increases.get("powershell_activity", 15),
            mitre=mitre.get("powershell_activity", []),
            confidence="žemas",
        )

    if event_ids.get(1102, 0) > 0:
        add_finding(
            findings,
            rule_id="audit_log_cleared",
            ip=ip,
            title="Išvalytas Windows audito žurnalas",
            severity="kritinė",
            evidence=[f"Windows 1102 įvykių kiekis: {event_ids.get(1102, 0)}"],
            recommendation="Skubiai patikrinti, kas išvalė audito žurnalą, peržiūrėti administratorių veiksmus ir užtikrinti centralizuotą logų kopijavimą.",
            risk_increase=increases.get("audit_log_cleared", 40),
            mitre=mitre.get("audit_log_cleared", []),
            confidence="aukštas",
        )

    account_change_count = sum(event_ids.get(i, 0) for i in (4720, 4722, 4726, 4732, 4738, 4740))
    if account_change_count > 0:
        add_finding(
            findings,
            rule_id="account_change",
            ip=ip,
            title="Paskyrų arba grupių pakeitimai endpoint loguose",
            severity="aukšta" if event_ids.get(4732, 0) or event_ids.get(4720, 0) else "vidutinė",
            evidence=[f"Paskyrų/grupių susijusių įvykių kiekis: {account_change_count}"],
            recommendation="Patikrinti paskyrų pakeitimus, administratorių grupės narius ir ar pakeitimai buvo planuoti.",
            risk_increase=increases.get("account_change", 30),
            mitre=mitre.get("account_change", []),
            confidence="vidutinis",
        )

    high_eset_rows = []
    for row in eset_rows:
        ev = row.get("event") if isinstance(row.get("event"), dict) else {}
        if ev.get("severity") in {"aukšta", "kritinė"}:
            high_eset_rows.append(row)
    if len(eset_rows) >= thresholds.get("eset_rows_medium", 5) or high_eset_rows:
        sev = "aukšta" if high_eset_rows or len(eset_rows) >= thresholds.get("eset_rows_high", 20) else "vidutinė"
        sample = []
        for row in (high_eset_rows or eset_rows)[:5]:
            ev = row.get("event") if isinstance(row.get("event"), dict) else {}
            sec = row.get("security") if isinstance(row.get("security"), dict) else {}
            sample.append(str(ev.get("name") or sec.get("action") or "ESET įvykis"))
        add_finding(
            findings,
            rule_id="eset_activity",
            ip=ip,
            title="ESET žurnaluose aptiktas saugumo aktyvumas",
            severity=sev,
            evidence=[f"ESET CSV eilučių kiekis susietas su hostu: {len(eset_rows)}", f"Aukštos/kritinės ESET eilutės: {len(high_eset_rows)}"] + sample,
            recommendation="Peržiūrėti ESET aptikimus/blokuotus URL, įvertinti vartotojo veiksmus ir patikrinti, ar nėra pasikartojančių indikatorių.",
            risk_increase=increases.get("eset_activity", 20),
            mitre=mitre.get("eset_activity", []),
            confidence="aukštas" if high_eset_rows else "vidutinis",
        )

    for item in findings:
        if asset_id:
            item["asset_id"] = asset_id
    return findings


def global_endpoint_findings(endpoint_index: dict, rules: dict, host_count: int) -> list[dict]:
    findings = []
    all_events = endpoint_index["events"]
    all_eset = endpoint_index["eset_rows"]
    if not all_events and not all_eset:
        return findings

    thresholds = rules.get("thresholds", {})
    increases = rules.get("risk_increase", {})
    mitre = rules.get("mitre_mapping", {})

    # Windows įvykius be host susiejimo automatiškai keliame tik vieno hosto laboratorijoje.
    if host_count == 1:
        event_ids = Counter(extract_event_id(e) for e in all_events if extract_event_id(e) is not None)
        failed = event_ids.get(4625, 0)
        if failed >= thresholds.get("failed_logons_medium", 5):
            add_finding(
                findings,
                rule_id="endpoint_failed_logons_global",
                ip=None,
                title="Endpoint loguose aptikti nesėkmingi prisijungimai",
                severity=severity_from_failed(failed, thresholds),
                evidence=[f"Windows 4625 failed logon įvykių: {failed}"],
                recommendation="Susieti endpoint hostą su inventorizacijos įrašu ir patikrinti prisijungimų šaltinius bei paskyras.",
                risk_increase=10,
                mitre=mitre.get("rdp_failed_logons", []),
                confidence="žemas",
            )

    # ESET eilutės turi patekti į galutinę koreliaciją net kai jų nepavyksta pririšti prie konkretaus hosto.
    # Tokiu atveju finding yra globalus ir žemesnio confidence, bet DI/ataskaita jo nebepameta.
    unmapped_eset = [r for r in all_eset if not extract_ip(r) and not extract_computer(r)]
    high_unmapped_eset = []
    for row in unmapped_eset:
        ev = row.get("event") if isinstance(row.get("event"), dict) else {}
        if ev.get("severity") in {"aukšta", "kritinė"}:
            high_unmapped_eset.append(row)
    if len(unmapped_eset) >= thresholds.get("eset_rows_medium", 5) or high_unmapped_eset:
        sev = "aukšta" if high_unmapped_eset or len(unmapped_eset) >= thresholds.get("eset_rows_high", 20) else "vidutinė"
        sample_names = []
        for row in (high_unmapped_eset or unmapped_eset)[:5]:
            ev = row.get("event") if isinstance(row.get("event"), dict) else {}
            src = row.get("source") if isinstance(row.get("source"), dict) else {}
            sample_names.append(str(ev.get("name") or src.get("filename") or "ESET row"))
        add_finding(
            findings,
            rule_id="eset_activity_unmapped",
            ip=None,
            title="ESET žurnaluose aptiktas saugumo aktyvumas be host susiejimo",
            severity=sev,
            evidence=[f"Nesusietų ESET CSV eilučių kiekis: {len(unmapped_eset)}"] + sample_names,
            recommendation="Patikrinti ESET eksportavimo skriptą, kad jis siųstų computer arba collector_seen_ip lauką; peržiūrėti ESET aptikimus/blokuotus URL ir susieti juos su inventoriaus hostais.",
            risk_increase=increases.get("eset_activity", 20),
            mitre=mitre.get("eset_activity", []),
            confidence="žemas",
        )
    return findings


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    rules = load_rules()

    assessment_file = latest_in_current_or_runs(paths, "assessment_*.json", "**/reports/assessment_*.json")
    endpoint_file = latest_in_current_or_runs(paths, "endpoint_events_*.json", "**/reports/endpoint_events_*.json")
    risk_scores_file = latest_in_current_or_runs(paths, "risk_scores_*.json", "**/reports/risk_scores_*.json")

    assessment = load_json_optional(assessment_file) or {"hosts": []}
    endpoint = load_json_optional(endpoint_file)
    risk_scores = load_json_optional(risk_scores_file)
    endpoint_index = index_endpoint(endpoint)

    findings = []
    for host in as_list(assessment.get("hosts")):
        if isinstance(host, dict):
            findings.extend(analyze_host(host, endpoint_index, rules))
    findings.extend(global_endpoint_findings(endpoint_index, rules, len(as_list(assessment.get("hosts")))))

    severity_order = {"kritinė": 4, "aukšta": 3, "vidutinė": 2, "žema": 1}
    findings = sorted(findings, key=lambda f: (severity_order.get(f.get("severity"), 0), f.get("risk_increase", 0)), reverse=True)

    summary = {
        "total_correlated_findings": len(findings),
        "by_severity": dict(Counter(f.get("severity", "nežinoma") for f in findings)),
        "by_rule": dict(Counter(f.get("rule_id", "unknown") for f in findings)),
        "hosts_with_correlations": len({f.get("ip") for f in findings if f.get("ip")}),
    }

    output = {
        "report_type": "correlated_findings",
        "timestamp": timestamp,
        "assessment_file": assessment_file.name if assessment_file else None,
        "endpoint_events_file": endpoint_file.name if endpoint_file else None,
        "risk_scores_file": risk_scores_file.name if risk_scores_file else None,
        "rules_file": str(CONFIG_FILE) if CONFIG_FILE.exists() else None,
        "rules_version": CORRELATION_RULES_VERSION,
        "correlation_time_window_hours": CORRELATION_TIME_WINDOW_HOURS,
        "rules_metadata": {
            "thresholds": rules.get("thresholds", {}),
            "risk_increase": rules.get("risk_increase", {}),
            "confidence_formula": "confidence nustatomas pagal techninio radinio, endpoint įvykio ir host susiejimo stiprumą",
        },
        "summary": summary,
        "findings": findings,
    }

    out_file = paths["reports_dir"] / f"correlated_findings_{timestamp}.json"
    save_json(out_file, output)

    # Add a compact context to latest AI payload if it exists.
    ai_files = sorted(paths["ai_dir"].glob("ai_recommendation_payload_*.json"))
    if ai_files:
        ai_file = ai_files[-1]
        try:
            ai = load_json(ai_file)
            ai["correlated_findings"] = {
                "source_file": out_file.name,
                "summary": summary,
                "top_findings": findings[:20],
            }
            save_json(ai_file, ai)
        except Exception:
            pass

    print(f"Koreliacijos ataskaita: {out_file}")
    print(f"Koreliuotų radinių: {len(findings)}")


if __name__ == "__main__":
    main()
