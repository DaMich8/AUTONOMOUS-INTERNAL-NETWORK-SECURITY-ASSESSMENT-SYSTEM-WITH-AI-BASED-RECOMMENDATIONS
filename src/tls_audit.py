#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from common import detect_runtime_network, get_run_paths, latest_current_file, latest_json_by_prefix, load_json, save_json, timestamp_now
from finding_schema import normalize_finding

TLS_SERVICE_NAMES = {"https", "ssl/http", "ssl", "tls"}
TLS_PORTS = {443, 465, 636, 853, 8443, 9443}
PROTOCOL_RE = re.compile(r"^(SSLv\d|TLSv\d(?:\.\d)?)\s+(enabled|disabled|accepted|rejected)", re.IGNORECASE)
CIPHER_RE = re.compile(r"^\s*(Accepted|Preferred)\s+(.+)$", re.IGNORECASE)

LEGACY_PROTOCOLS = {
    "SSLV2": "kritinė",
    "SSLV3": "kritinė",
    "TLSV1.0": "aukšta",
    "TLSV1.1": "vidutinė",
}
LEGACY_PROTOCOL_FINDING_CODES = {
    "SSLV2": "TLS_SSLV2_ENABLED",
    "SSLV3": "TLS_SSLV3_ENABLED",
    "TLSV1.0": "TLS_TLS10_ENABLED",
    "TLSV1.1": "TLS_TLS11_ENABLED",
}
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "ADH", "ANULL", "AECDH")
FS_TOKENS = ("ECDHE", "DHE", "TLS_AES", "TLS_CHACHA20")


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def proto_key(value: str | None) -> str:
    return str(value or "").strip().upper().replace(" ", "")


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
            if p in TLS_PORTS or service_name in TLS_SERVICE_NAMES or tunnel == "ssl":
                key = f"{ip}:{p}"
                if key not in seen:
                    targets.append({
                        "ip": ip,
                        "asset_id": host.get("asset_id"),
                        "port": p,
                        "protocol": port.get("protocol", "tcp"),
                        "service": service_name or ("https" if p in {443, 8443, 9443} else "tls"),
                    })
                    seen.add(key)
    return targets


def parse_sslscan_text(output: str) -> dict:
    protocols = []
    accepted_ciphers = []
    cert = {"expired": False, "self_signed": False, "hostname_mismatch": False, "subject": None, "issuer": None}
    for original_line in output.splitlines():
        line = original_line.strip()
        m = PROTOCOL_RE.match(line)
        if m:
            status = m.group(2).lower()
            protocols.append({"protocol": m.group(1), "status": "enabled" if status in {"enabled", "accepted"} else "disabled"})
            continue
        m = CIPHER_RE.match(line)
        if m:
            accepted_ciphers.append(m.group(2).strip())
        lower = line.lower()
        if "expired" in lower:
            cert["expired"] = True
        if "self-signed" in lower or "self signed" in lower:
            cert["self_signed"] = True
        if "hostname" in lower and "mismatch" in lower:
            cert["hostname_mismatch"] = True
        if lower.startswith("subject:"):
            cert["subject"] = line.split(":", 1)[1].strip()
        if lower.startswith("issuer:"):
            cert["issuer"] = line.split(":", 1)[1].strip()
    return {"protocols": protocols, "accepted_ciphers": accepted_ciphers[:120], "certificate": cert}


def finding_id_part(text: str) -> str:
    return text.upper().replace(".", "").replace(" ", "_")


def build_tls_findings(summary: dict, target: dict | None = None, rc: int = 0) -> list[dict]:
    target = target or {
        "ip": summary.get("ip"),
        "asset_id": summary.get("asset_id"),
        "port": summary.get("port"),
        "protocol": summary.get("protocol") or "tcp",
        "service": summary.get("service") or "tls",
    }
    ip_slug = str(target.get("ip") or "GLOBAL").replace(".", "_")
    port = target.get("port")
    findings: list[dict] = []

    enabled = {proto_key(p.get("protocol")) for p in as_list(summary.get("protocols")) if p.get("status") == "enabled"}
    for proto, severity in LEGACY_PROTOCOLS.items():
        if proto in enabled:
            findings.append(normalize_finding({
                "finding_id": f"{LEGACY_PROTOCOL_FINDING_CODES.get(proto, 'TLS_LEGACY_PROTOCOL')}_{ip_slug}_{port}",
                "rule_id": "tls_legacy_protocol",
                "severity": severity,
                "confidence": "aukštas",
                "title": f"Įjungtas pasenęs TLS/SSL protokolas: {proto}",
                "evidence": [f"{proto} enabled"],
                "impact": "Pasenę TLS/SSL protokolai didina šifravimo silpnumo ir suderinamumo režimų išnaudojimo riziką.",
                "recommended_fix": "Išjungti SSLv2, SSLv3, TLS 1.0 ir TLS 1.1; palikti TLS 1.2 ir TLS 1.3 su stipriais šifravimo rinkiniais.",
                "validation": f"Pakartoti TLS auditą: sslscan --no-colour {target.get('ip')}:{port}",
                "cis_controls": ["Secure Configuration of Enterprise Assets and Software", "Data Protection"],
            }, source_module="tls_audit.py", ip=target.get("ip"), asset_id=target.get("asset_id"), port=port, protocol="tcp", service="tls"))

    weak = []
    for cipher in as_list(summary.get("accepted_ciphers")):
        upper = str(cipher).upper()
        if any(token in upper for token in WEAK_CIPHER_TOKENS):
            weak.append(str(cipher))
    if weak:
        findings.append(normalize_finding({
            "finding_id": f"TLS_WEAK_CIPHER_{ip_slug}_{port}",
            "rule_id": "tls_weak_cipher",
            "severity": "aukšta",
            "confidence": "aukštas",
            "title": "Aptiktas silpnas TLS šifravimo rinkinys",
            "evidence": weak[:10],
            "impact": "Silpni šifravimo rinkiniai gali mažinti komunikacijos konfidencialumą ir neatitikti gerosios praktikos reikalavimų.",
            "recommended_fix": "Išjungti RC4, 3DES, NULL, EXPORT, MD5, anoniminius DH/ECDH ir kitus pasenusius cipher suites.",
            "validation": f"Pakartoti sslscan patikrą {target.get('ip')}:{port} ir įsitikinti, kad silpni rinkiniai nebepriimami.",
            "cis_controls": ["Data Protection"],
        }, source_module="tls_audit.py", ip=target.get("ip"), asset_id=target.get("asset_id"), port=port, protocol="tcp", service="tls"))

    ciphers = [str(c).upper() for c in as_list(summary.get("accepted_ciphers"))]
    if ciphers and not any(any(token in c for token in FS_TOKENS) for c in ciphers):
        findings.append(normalize_finding({
            "finding_id": f"TLS_NO_FORWARD_SECRECY_{ip_slug}_{port}",
            "rule_id": "tls_no_forward_secrecy",
            "severity": "vidutinė",
            "confidence": "vidutinis",
            "title": "TLS konfigūracijoje neaptikta forward secrecy požymių",
            "evidence": as_list(summary.get("accepted_ciphers"))[:10],
            "impact": "Be forward secrecy praeities srautas gali būti labiau pažeidžiamas, jeigu vėliau nutekinamas serverio privatus raktas.",
            "recommended_fix": "Įjungti ECDHE/DHE pagrindu veikiančius modernius TLS cipher suites ir TLS 1.3.",
            "validation": f"Pakartoti sslscan patikrą {target.get('ip')}:{port} ir patikrinti ECDHE/DHE arba TLS 1.3 rinkinius.",
        }, source_module="tls_audit.py", ip=target.get("ip"), asset_id=target.get("asset_id"), port=port, protocol="tcp", service="tls"))

    cert = summary.get("certificate") or {}
    for flag, finding_code, rule_id, title, sev in [
        ("expired", "TLS_EXPIRED_CERT", "tls_expired_cert", "TLS sertifikatas yra pasibaigęs", "aukšta"),
        ("self_signed", "TLS_SELF_SIGNED_CERT", "tls_self_signed_cert", "TLS paslauga naudoja savarankiškai pasirašytą sertifikatą", "vidutinė"),
        ("hostname_mismatch", "TLS_CERT_HOSTNAME_MISMATCH", "tls_cert_hostname_mismatch", "TLS sertifikato vardas neatitinka paslaugos adreso", "vidutinė"),
    ]:
        if cert.get(flag):
            findings.append(normalize_finding({
                "finding_id": f"{finding_code}_{ip_slug}_{port}",
                "rule_id": rule_id,
                "severity": sev,
                "confidence": "vidutinis",
                "title": title,
                "evidence": [cert.get("subject"), cert.get("issuer")],
                "impact": "Netinkamas sertifikatas mažina naudotojų pasitikėjimą ir gali slėpti neteisingą TLS konfigūraciją.",
                "recommended_fix": "Įdiegti galiojantį sertifikatą su teisingu CN/SAN vardu ir patikima sertifikavimo grandine.",
                "validation": f"Pakartoti TLS patikrą: sslscan --no-colour {target.get('ip')}:{port}",
            }, source_module="tls_audit.py", ip=target.get("ip"), asset_id=target.get("asset_id"), port=port, protocol="tcp", service="tls"))
    return findings


def build_findings(target: dict, summary: dict | None, rc: int) -> list[dict]:
    if summary is None:
        return [normalize_finding({
            "finding_id": f"TLS_SCAN_FAILED_{target['ip'].replace('.', '_')}_{target['port']}",
            "rule_id": "tls_scan_failed",
            "severity": "vidutinė",
            "confidence": "vidutinis",
            "title": "TLS patikra nebuvo užbaigta",
            "evidence": [f"sslscan returncode={rc}"],
            "impact": "Nepilna TLS patikra mažina vertinimo patikimumą.",
            "recommended_fix": "Patikrinti, ar paslauga pasiekiama, ir pakartoti TLS auditą.",
            "validation": f"sslscan --no-colour {target['ip']}:{target['port']}",
            "scan_status": "failed",
        }, source_module="tls_audit.py", ip=target["ip"], asset_id=target.get("asset_id"), port=target["port"], protocol="tcp", service="tls", scan_status="failed")]
    return build_tls_findings(summary, target, rc)


def main() -> None:
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()
    timestamp = timestamp_now()

    services_file = latest_current_file("services_dir", "services_*.json") or latest_json_by_prefix("services", network=network)
    if services_file is None:
        raise FileNotFoundError("Nerastas paslaugų JSON failas.")

    services_data = load_json(services_file)
    targets = build_targets(services_data)
    output_json = paths["services_dir"] / f"tls_audit_{timestamp}.json"
    log_json = paths["logs_dir"] / f"tls_audit_run_{timestamp}.json"

    if not shutil.which("sslscan"):
        payload = {"scan_type": "tls_audit", "timestamp": timestamp, "network": network, "status": "skipped", "scan_status": "skipped", "reason": "sslscan tool not found", "targets": [], "findings": []}
        save_json(output_json, payload); save_json(log_json, payload)
        print(f"[PRALEISTA] TLS auditas neatliktas, nes nerastas sslscan įrankis: {output_json}")
        return

    results = []
    runs = []
    all_findings = []
    for idx, target in enumerate(targets, start=1):
        host_port = f"{target['ip']}:{target['port']}"
        cmd = ["sslscan", "--no-colour", host_port]
        print(f"[{idx}/{len(targets)}] Tikrinama TLS paslauga: {host_port}", flush=True)
        rc, out, err = run_cmd(cmd)
        summary = parse_sslscan_text(out) if rc == 0 else None
        findings = build_findings(target, summary, rc)
        all_findings.extend(findings)
        results.append({"ip": target["ip"], "asset_id": target.get("asset_id"), "port": target["port"], "host_port": host_port, "summary": summary, "findings": findings, "stdout": out, "returncode": rc, "scan_status": "success" if rc == 0 else "failed"})
        runs.append({"host_port": host_port, "command": " ".join(cmd), "returncode": rc, "stderr": err, "scan_status": "success" if rc == 0 else "failed"})

    save_json(output_json, {"scan_type": "tls_audit", "timestamp": timestamp, "network": network, "interface": interface, "source_ip": source_ip, "source_services_file": services_file.name, "targets_count": len(targets), "findings_count": len(all_findings), "targets": results, "findings": all_findings, "scan_status": "success"})
    save_json(log_json, {"scan_type": "tls_audit", "timestamp": timestamp, "runs": runs})
    print(f"[GERAI] TLS audito JSON failas sukurtas: {output_json}")
    print(f"[INFO] Patikrintos TLS paslaugos: {len(targets)}; radiniai: {len(all_findings)}")


if __name__ == "__main__":
    main()
