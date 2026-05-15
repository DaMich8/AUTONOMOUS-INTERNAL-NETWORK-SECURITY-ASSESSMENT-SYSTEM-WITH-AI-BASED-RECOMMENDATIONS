import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from common import detect_runtime_network, get_run_paths, latest_current_file, latest_json_by_prefix, load_json, save_json, timestamp_now
from finding_schema import normalize_finding

SSH_PORTS = {22}
SSH_SERVICE_NAMES = {"ssh"}
WEAK_PATTERNS = {
    "diffie-hellman-group1-sha1": ("aukšta", "kex", "Labai senas SSH raktų apsikeitimo algoritmas."),
    "diffie-hellman-group14-sha1": ("vidutinė", "kex", "SHA1 pagrindu veikiantis SSH raktų apsikeitimo algoritmas."),
    "diffie-hellman-group-exchange-sha1": ("vidutinė", "kex", "SHA1 pagrindu veikiantis SSH raktų apsikeitimo algoritmas."),
    "ssh-dss": ("aukšta", "host_key", "DSA host key algoritmas laikomas pasenusiu."),
    "ssh-rsa": ("vidutinė", "host_key", "ssh-rsa su SHA1 parašais yra pasenęs algoritmas."),
    "arcfour": ("aukšta", "cipher", "RC4/ARCFOUR šifras yra nesaugus."),
    "3des-cbc": ("vidutinė", "cipher", "3DES CBC šifras yra pasenęs."),
    "blowfish-cbc": ("vidutinė", "cipher", "Blowfish CBC šifras yra pasenęs."),
    "aes128-cbc": ("vidutinė", "cipher", "CBC režimo šifrai turėtų būti keičiami CTR/GCM/ChaCha20 algoritmais."),
    "aes192-cbc": ("vidutinė", "cipher", "CBC režimo šifrai turėtų būti keičiami CTR/GCM/ChaCha20 algoritmais."),
    "aes256-cbc": ("vidutinė", "cipher", "CBC režimo šifrai turėtų būti keičiami CTR/GCM/ChaCha20 algoritmais."),
    "hmac-md5": ("aukšta", "mac", "MD5 pagrindu veikiantis MAC algoritmas yra pasenęs."),
    "hmac-sha1-96": ("vidutinė", "mac", "Sutrumpintas SHA1 MAC algoritmas yra pasenęs."),
    "hmac-md5-96": ("aukšta", "mac", "Sutrumpintas MD5 MAC algoritmas yra pasenęs."),
}


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def select_targets(services_data: dict) -> list[dict]:
    targets = []
    for host in services_data.get("hosts", []):
        ip = host.get("ip")
        if not ip:
            continue
        ports = []
        for port in host.get("ports", []):
            service = (port.get("service_name") or "").lower()
            if port.get("port") in SSH_PORTS or service in SSH_SERVICE_NAMES:
                ports.append(port.get("port") or 22)
        if ports:
            targets.append({"ip": ip, "asset_id": host.get("asset_id"), "ports": sorted(set(ports))})
    return targets


def parse_scripts(xml_file: Path) -> list[dict]:
    if not xml_file.exists():
        return []
    tree = ET.parse(xml_file)
    root = tree.getroot()
    return [{"id": script.get("id"), "output": script.get("output") or ""} for script in root.findall(".//port/script")]


def build_findings(ip: str, port: int, scripts: list[dict], asset_id: str | None = None) -> list[dict]:
    text = "\n".join(s.get("output") or "" for s in scripts)
    lowered = text.lower()
    findings = []
    seen = set()

    for token, (severity, algorithm_type, description) in WEAK_PATTERNS.items():
        if token in lowered and token not in seen:
            rule = f"ssh_weak_{algorithm_type}_{token}".replace("-", "_").replace(".", "_")
            findings.append(normalize_finding({
                "finding_id": f"{rule.upper()}_{ip.replace('.', '_')}_{port}",
                "rule_id": rule,
                "severity": severity,
                "confidence": "aukštas",
                "title": f"SSH paslauga naudoja silpną arba pasenusį algoritmą: {token}",
                "evidence": [token, f"algorithm_type={algorithm_type}"],
                "impact": description,
                "recommended_fix": "Atnaujinti SSH serverį ir sshd_config faile palikti tik modernius KexAlgorithms, Ciphers, MACs ir HostKeyAlgorithms rinkinius.",
                "validation": f"Pakartoti nmap --script ssh2-enum-algos -p{port} {ip} patikrą ir įsitikinti, kad silpnas algoritmas neberodomas.",
                "cis_controls": ["Secure Configuration of Enterprise Assets and Software"],
                "false_positive_conditions": ["Algoritmas gali būti siūlomas tik suderinamumui, bet realiai nenaudojamas, jei klientai jo nesirenka."],
                "algorithm_type": algorithm_type,
                "algorithm_name": token,
            }, source_module="ssh_policy_audit.py", ip=ip, asset_id=asset_id, port=port, protocol="tcp", service="ssh"))
            seen.add(token)

    if re.search(r"\b1024\b.*\bDSA\b|\bDSA\b.*\b1024\b", text, re.IGNORECASE):
        findings.append(normalize_finding({
            "finding_id": f"SSH_WEAK_HOSTKEY_DSA_{ip.replace('.', '_')}_{port}",
            "rule_id": "ssh_weak_hostkey_dsa",
            "severity": "vidutinė",
            "confidence": "vidutinis",
            "title": "SSH paslauga turi seną arba silpną host key tipą",
            "evidence": ["Aptiktas 1024 bitų DSA host key požymis"],
            "impact": "Seni raktų tipai mažina SSH konfigūracijos atsparumą.",
            "recommended_fix": "Sugeneruoti naujus ed25519 arba RSA 3072/4096 host key ir pašalinti DSA raktus.",
            "validation": f"Pakartoti ssh-hostkey patikrą: nmap --script ssh-hostkey -p{port} {ip}",
            "algorithm_type": "host_key",
            "algorithm_name": "DSA 1024",
        }, source_module="ssh_policy_audit.py", ip=ip, asset_id=asset_id, port=port, protocol="tcp", service="ssh"))
    return findings


def main() -> None:
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()
    timestamp = timestamp_now()
    services_file = latest_current_file("services_dir", "services_*.json") or latest_json_by_prefix("services", network=network)
    output_json = paths["services_dir"] / f"ssh_policy_{timestamp}.json"
    log_json = paths["logs_dir"] / f"ssh_policy_run_{timestamp}.json"

    if services_file is None:
        payload = {"scan_type": "ssh_policy_audit", "timestamp": timestamp, "network": network, "status": "skipped", "reason": "paslaugų JSON failas nerastas", "results": [], "findings": []}
        save_json(output_json, payload); save_json(log_json, payload)
        return

    services_data = load_json(services_file)
    targets = select_targets(services_data)
    parts_dir = paths["services_dir"] / f"ssh_policy_parts_{timestamp}"
    parts_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("nmap"):
        payload = {"scan_type": "ssh_policy_audit", "timestamp": timestamp, "network": network, "status": "skipped", "reason": "nmap tool not found", "results": [], "findings": []}
        save_json(output_json, payload); save_json(log_json, payload)
        print(f"[PRALEISTA] SSH auditas neatliktas, nes nerastas nmap įrankis: {output_json}")
        return

    results = []
    runs = []
    all_findings = []
    for idx, target in enumerate(targets, start=1):
        ip = target["ip"]
        asset_id = target.get("asset_id")
        ports = target["ports"]
        xml_file = parts_dir / f"{ip.replace('.', '_')}_ssh_policy.xml"
        txt_file = parts_dir / f"{ip.replace('.', '_')}_ssh_policy.txt"
        cmd = ["nmap", "-Pn", "-n", "-p", ",".join(str(p) for p in ports), "--script", "ssh-hostkey,ssh2-enum-algos,banner", "--script-timeout", "25s", "-oX", str(xml_file), "-oN", str(txt_file), ip]
        print(f"[{idx}/{len(targets)}] Tikrinama SSH konfigūracija: {ip}", flush=True)
        rc, out, err = run_cmd(cmd)
        scripts = parse_scripts(xml_file) if xml_file.exists() else []
        findings = []
        for p in ports:
            findings.extend(build_findings(ip, p, scripts, asset_id=asset_id))
        all_findings.extend(findings)
        results.append({"ip": ip, "asset_id": asset_id, "ports": ports, "scripts": scripts, "findings": findings, "returncode": rc, "stdout": out if rc != 0 else None, "scan_status": "success" if rc == 0 else "failed"})
        runs.append({"ip": ip, "command": " ".join(cmd), "returncode": rc, "stderr": err, "xml_file": str(xml_file), "txt_file": str(txt_file)})

    save_json(output_json, {"scan_type": "ssh_policy_audit", "timestamp": timestamp, "network": network, "interface": interface, "source_ip": source_ip, "source_services_file": services_file.name, "targets_count": len(targets), "findings_count": len(all_findings), "results": results, "findings": all_findings})
    save_json(log_json, {"scan_type": "ssh_policy_audit", "timestamp": timestamp, "runs": runs})
    print(f"[GERAI] SSH audito JSON failas sukurtas: {output_json}")
    print(f"[INFO] Patikrintos SSH paslaugos: {len(targets)}; radiniai: {len(all_findings)}")


if __name__ == "__main__":
    main()
