import json
import re
import shutil
import subprocess
from pathlib import Path

from common import detect_runtime_network, get_run_paths, latest_current_file, latest_json_by_prefix, load_json, save_json, timestamp_now
from finding_schema import normalize_finding

WEB_SERVICE_NAMES = {"http", "https", "ssl/http", "http-proxy", "http-alt"}
WEB_PORTS = {80, 81, 443, 591, 8000, 8008, 8080, 8081, 8443, 8888}
VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9_\-\.]+)\s*/?\s*(\d+(?:\.\d+){1,3})")
WHATWEB_VERSION_RE = re.compile(r"WhatWeb\s+v?([0-9]+(?:\.[0-9]+){1,3})", re.IGNORECASE)


def scanner_artifact(value: str) -> bool:
    text = str(value or "").strip().lower()
    return text.startswith("whatweb ") or text.startswith("whatweb/") or text == "whatweb"


def extract_scanner_metadata(text: str) -> dict:
    match = WHATWEB_VERSION_RE.search(text or "")
    return {
        "tool": "WhatWeb",
        "version": match.group(1) if match else None,
        "note": "Tai skenavimo įrankio metaduomenys. Ši reikšmė nelaikoma taikinio web serverio technologija.",
    }


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def build_targets(services_data: dict) -> list[dict]:
    targets = []
    seen = set()
    for host in services_data.get("hosts", []):
        ip = host.get("ip")
        if not ip:
            continue
        for port in host.get("ports", []):
            p = port.get("port")
            service_name = (port.get("service_name") or "").lower()
            tunnel = (port.get("tunnel") or "").lower()
            if p in WEB_PORTS or service_name in WEB_SERVICE_NAMES:
                scheme = "https" if p == 443 or tunnel == "ssl" or service_name == "https" else "http"
                url = f"{scheme}://{ip}:{p}"
                if url not in seen:
                    targets.append({"ip": ip, "asset_id": host.get("asset_id"), "port": p, "url": url, "protocol": port.get("protocol", "tcp")})
                    seen.add(url)
    return targets


def load_json_file(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def flatten_whatweb(parsed) -> str:
    return json.dumps(parsed, ensure_ascii=False) if parsed is not None else ""


def normalize_web_result(target: dict, parsed, stdout: str) -> dict:
    text = flatten_whatweb(parsed) + "\n" + (stdout or "")
    scanner_metadata = extract_scanner_metadata(text)

    raw_technologies = sorted(set(re.findall(r'"?([A-Za-z][A-Za-z0-9_\-\. ]{1,40})"?\s*:', text)))
    technologies = [item for item in raw_technologies if not scanner_artifact(item)][:30]

    raw_versions = sorted(set(" ".join(m.groups()) for m in VERSION_RE.finditer(text)))
    exposed_versions = [item for item in raw_versions if not scanner_artifact(item)][:20]

    lowered = text.lower()
    risk_hints = []
    if exposed_versions:
        risk_hints.append("server_version_exposed")
    if any(x in lowered for x in ["admin", "login", "router", "dashboard", "management"]):
        risk_hints.append("admin_interface_possible")
    if any(x in lowered for x in ["wordpress", "joomla", "drupal", "phpmyadmin"]):
        risk_hints.append("cms_or_admin_tool_detected")
    if "directory listing" in lowered or "index of /" in lowered:
        risk_hints.append("directory_listing_possible")
    return {
        "ip": target["ip"],
        "asset_id": target.get("asset_id"),
        "port": target["port"],
        "url": target["url"],
        "scanner_metadata": scanner_metadata,
        "technologies": technologies,
        "exposed_versions": exposed_versions,
        "risk_hints": sorted(set(risk_hints)),
    }


def build_findings(target: dict, normalized: dict) -> list[dict]:
    findings = []
    if "admin_interface_possible" in normalized.get("risk_hints", []):
        findings.append(normalize_finding({
            "finding_id": f"WEB_ADMIN_INTERFACE_POSSIBLE_{target['ip'].replace('.', '_')}_{target['port']}",
            "rule_id": "web_admin_interface_possible",
            "severity": "vidutinė",
            "confidence": "vidutinis",
            "title": "Galimai aptikta administravimo žiniatinklio sąsaja",
            "evidence": [target["url"], *normalized.get("risk_hints", [])],
            "impact": "Administravimo sąsajos neturėtų būti pasiekiamos iš bendro tinklo segmento, nes jos didina atakos paviršių.",
            "recommended_fix": "Apriboti administravimo sąsają valdymo IP/VLAN arba VPN segmentui ir peržiūrėti autentifikacijos nustatymus.",
            "validation": f"Pakartoti web patikrą ir patikrinti pasiekiamumą: {target['url']}",
            "cis_controls": ["Access Control Management", "Secure Configuration of Enterprise Assets and Software"],
        }, source_module="web_fingerprint.py", ip=target["ip"], asset_id=target.get("asset_id"), port=target["port"], protocol="tcp", service="web"))
    if normalized.get("exposed_versions"):
        findings.append(normalize_finding({
            "finding_id": f"WEB_SERVER_VERSION_EXPOSED_{target['ip'].replace('.', '_')}_{target['port']}",
            "rule_id": "web_server_version_exposed",
            "severity": "žema",
            "confidence": "vidutinis",
            "title": "Žiniatinklio paslauga atskleidžia technologijų arba versijų informaciją",
            "evidence": normalized.get("exposed_versions")[:10],
            "impact": "Versijų atskleidimas palengvina tikslinę pažeidžiamumų paiešką.",
            "recommended_fix": "Sumažinti serverio banner ir klaidų puslapiuose rodomą versijų informaciją, jei ji nėra būtina.",
            "validation": f"Pakartoti WhatWeb arba http-headers patikrą: {target['url']}",
        }, source_module="web_fingerprint.py", ip=target["ip"], asset_id=target.get("asset_id"), port=target["port"], protocol="tcp", service="web"))
    return findings


def main() -> None:
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()
    timestamp = timestamp_now()
    services_file = latest_current_file("services_dir", "services_*.json") or latest_json_by_prefix("services", network=network)
    if services_file is None:
        raise FileNotFoundError("Nerastas paslaugų JSON failas.")

    services_data = load_json(services_file)
    targets = build_targets(services_data)
    output_json = paths["services_dir"] / f"web_fingerprint_{timestamp}.json"
    log_json = paths["logs_dir"] / f"web_fingerprint_run_{timestamp}.json"
    parts_dir = paths["services_dir"] / f"web_parts_{timestamp}"
    parts_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("whatweb"):
        payload = {"scan_type": "web_fingerprint", "timestamp": timestamp, "network": network, "status": "skipped", "scan_status": "skipped", "reason": "whatweb tool not found", "targets": [], "findings": []}
        save_json(output_json, payload); save_json(log_json, payload)
        print(f"[PRALEISTA] Žiniatinklio technologijų patikra neatlikta, nes nerastas WhatWeb įrankis: {output_json}")
        return

    results = []
    runs = []
    all_findings = []
    for idx, target in enumerate(targets, start=1):
        url = target["url"]
        out_json = parts_dir / f"{target['ip'].replace('.', '_')}_{target['port']}_whatweb.json"
        cmd = ["whatweb", url, f"--log-json={out_json}", "--color=never"]
        print(f"[{idx}/{len(targets)}] Tikrinama žiniatinklio paslauga: {url}", flush=True)
        rc, out, err = run_cmd(cmd)
        parsed = load_json_file(out_json)
        normalized = normalize_web_result(target, parsed, out)
        findings = build_findings(target, normalized)
        if rc != 0:
            findings.append(normalize_finding({
                "finding_id": f"WEB_FINGERPRINT_FAILED_{target['ip'].replace('.', '_')}_{target['port']}",
                "rule_id": "web_fingerprint_failed",
                "severity": "žema",
                "confidence": "vidutinis",
                "title": "Žiniatinklio technologijų patikra nebuvo pilnai užbaigta",
                "evidence": [f"whatweb returncode={rc}", err],
                "impact": "Nepilna web technologijų patikra mažina šio hosto web rizikos vertinimo patikimumą.",
                "recommended_fix": "Patikrinti paslaugos pasiekiamumą ir pakartoti web_fingerprint.py.",
                "validation": f"whatweb {url}",
                "scan_status": "partial",
            }, source_module="web_fingerprint.py", ip=target["ip"], asset_id=target.get("asset_id"), port=target["port"], protocol="tcp", service="web", scan_status="partial"))
        all_findings.extend(findings)
        results.append({"ip": target["ip"], "asset_id": target.get("asset_id"), "port": target["port"], "url": url, "tool_output": parsed, "normalized": normalized, "findings": findings, "stdout": out if not parsed else None, "returncode": rc, "scan_status": "success" if rc == 0 else "partial"})
        runs.append({"url": url, "command": " ".join(cmd), "returncode": rc, "json_file": str(out_json), "stderr": err, "scan_status": "success" if rc == 0 else "partial"})

    save_json(output_json, {"scan_type": "web_fingerprint", "timestamp": timestamp, "network": network, "interface": interface, "source_ip": source_ip, "source_services_file": services_file.name, "targets_count": len(targets), "findings_count": len(all_findings), "targets": results, "findings": all_findings, "scan_status": "success"})
    save_json(log_json, {"scan_type": "web_fingerprint", "timestamp": timestamp, "runs": runs})
    print(f"[GERAI] Žiniatinklio technologijų patikros JSON failas sukurtas: {output_json}")
    print(f"[INFO] Patikrintos žiniatinklio paslaugos: {len(targets)}; radiniai: {len(all_findings)}")


if __name__ == "__main__":
    main()
