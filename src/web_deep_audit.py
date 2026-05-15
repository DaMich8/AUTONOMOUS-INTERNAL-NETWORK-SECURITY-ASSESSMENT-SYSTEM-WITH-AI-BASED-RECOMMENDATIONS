import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from asset_identity import build_asset_id
from finding_schema import normalize_finding

from common import (
    detect_runtime_network,
    get_run_paths,
    latest_current_file,
    latest_json_by_prefix,
    load_json,
    save_json,
    timestamp_now,
)

WEB_SERVICE_NAMES = {"http", "https", "ssl/http", "http-proxy", "http-alt"}
WEB_PORTS = {80, 81, 443, 591, 8000, 8008, 8080, 8081, 8443, 8888}
NMAP_WEB_SCRIPTS = os.getenv(
    "WEB_DEEP_NMAP_SCRIPTS",
    "http-title,http-server-header,http-methods,http-headers,http-robots.txt",
)

PROFILE = os.getenv("WEB_DEEP_PROFILE", "balanced").lower()
WEB_DEEP_WORKERS = int(os.getenv("WEB_DEEP_WORKERS", "4"))
WEB_DEEP_RUN_TOOLS_PARALLEL = os.getenv("WEB_DEEP_RUN_TOOLS_PARALLEL", "1") == "1"
WEB_DEEP_MAX_TARGETS = int(os.getenv("WEB_DEEP_MAX_TARGETS", "0"))

# Defaults chosen to keep the same functionality, but avoid one slow Nikto run blocking the whole assessment.
if PROFILE == "fast":
    DEFAULT_NIKTO_ENABLED = "0"
    DEFAULT_NIKTO_TIME = "25"
    DEFAULT_NMAP_SCRIPT_TIMEOUT = "8s"
    DEFAULT_NMAP_HOST_TIMEOUT = "35s"
elif PROFILE == "deep":
    DEFAULT_NIKTO_ENABLED = "1"
    DEFAULT_NIKTO_TIME = "120"
    DEFAULT_NMAP_SCRIPT_TIMEOUT = "25s"
    DEFAULT_NMAP_HOST_TIMEOUT = "120s"
else:
    DEFAULT_NIKTO_ENABLED = "1"
    DEFAULT_NIKTO_TIME = "45"
    DEFAULT_NMAP_SCRIPT_TIMEOUT = "12s"
    DEFAULT_NMAP_HOST_TIMEOUT = "60s"

NIKTO_ENABLED = os.getenv("WEB_DEEP_NIKTO", DEFAULT_NIKTO_ENABLED) == "1"
NIKTO_MAXTIME = os.getenv("WEB_DEEP_NIKTO_TIME", DEFAULT_NIKTO_TIME)
NMAP_SCRIPT_TIMEOUT = os.getenv("WEB_DEEP_NMAP_SCRIPT_TIMEOUT", DEFAULT_NMAP_SCRIPT_TIMEOUT)
NMAP_HOST_TIMEOUT = os.getenv("WEB_DEEP_NMAP_HOST_TIMEOUT", DEFAULT_NMAP_HOST_TIMEOUT)
PROCESS_TIMEOUT = int(os.getenv("WEB_DEEP_PROCESS_TIMEOUT", "180"))


def run_cmd(cmd: list[str], timeout: int | None = None) -> tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return 124, stdout, (stderr + f"\nTimeout after {timeout}s").strip()


def build_targets(services_data: dict) -> list[dict]:
    targets = []
    seen = set()
    for host in services_data.get("hosts", []):
        ip = host.get("ip")
        if not ip:
            continue
        for port in host.get("ports", []):
            p = port.get("port")
            service = (port.get("service_name") or "").lower()
            tunnel = (port.get("tunnel") or "").lower()
            if p in WEB_PORTS or service in WEB_SERVICE_NAMES:
                scheme = "https" if p == 443 or tunnel == "ssl" or service == "https" else "http"
                url = f"{scheme}://{ip}:{p}"
                if url not in seen:
                    targets.append({"ip": ip, "asset_id": host.get("asset_id") or build_asset_id(ip=ip, mac=host.get("mac"), hostname=host.get("hostname"), vendor=host.get("vendor")), "port": p, "scheme": scheme, "url": url})
                    seen.add(url)
    targets = sorted(targets, key=lambda t: (t["ip"], int(t["port"])))
    if WEB_DEEP_MAX_TARGETS > 0:
        targets = targets[:WEB_DEEP_MAX_TARGETS]
    return targets


def parse_scripts(xml_file: Path) -> list[dict]:
    if not xml_file.exists():
        return []
    try:
        tree = ET.parse(xml_file)
    except Exception:
        return []
    root = tree.getroot()
    return [{"id": s.get("id"), "output": s.get("output") or ""} for s in root.findall(".//port/script")]


def load_json_if_possible(path: Path):
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return None


def parse_nikto_findings(nikto_json) -> list[dict]:
    findings = []
    if not nikto_json:
        return findings

    vulnerabilities = []
    if isinstance(nikto_json, dict):
        if isinstance(nikto_json.get("vulnerabilities"), list):
            vulnerabilities = nikto_json.get("vulnerabilities")
        elif isinstance(nikto_json.get("hosts"), list):
            for host in nikto_json.get("hosts", []):
                vulnerabilities.extend(host.get("vulnerabilities", []) or [])
    elif isinstance(nikto_json, list):
        vulnerabilities = nikto_json

    for item in vulnerabilities[:30]:
        if not isinstance(item, dict):
            continue
        msg = item.get("msg") or item.get("message") or item.get("description") or "Nikto web radinys"
        findings.append({
            "finding_id": "WEB_NIKTO_FINDING",
            "severity": "vidutinė",
            "title": "Nikto aptiko web konfigūracijos požymį",
            "evidence": [str(msg)[:500]],
            "impact": "Web serverio konfigūracija arba aplikacija gali turėti papildomų rizikos požymių.",
            "recommended_fix": "Peržiūrėti Nikto radinį, atnaujinti komponentus, pašalinti nereikalingus failus ir apriboti administravimo kelius.",
            "validation": "Pakartoti Nikto arba nmap web patikrą po pataisymo.",
            "confidence": "vidutinis",
        })
    return findings


def build_findings(target: dict, scripts: list[dict], nikto_json) -> list[dict]:
    findings = []
    text = "\n".join(s.get("output") or "" for s in scripts)
    lowered = text.lower()

    header_output = "\n".join(
        s.get("output") or "" for s in scripts if s.get("id") in {"http-headers", "http-server-header"}
    )
    missing_headers = []
    for header in ("X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"):
        if header.lower() not in header_output.lower():
            missing_headers.append(header)

    if missing_headers:
        findings.append({
            "finding_id": "WEB_SECURITY_HEADERS_MISSING",
            "severity": "vidutinė",
            "title": "Trūksta dalies web saugumo antraščių",
            "evidence": missing_headers,
            "impact": "Saugumo antraštės mažina clickjacking, MIME sniffing ir XSS tipo rizikas.",
            "recommended_fix": "Pridėti bent X-Frame-Options, X-Content-Type-Options ir Content-Security-Policy antraštes, pritaikant jas konkrečiai aplikacijai.",
            "validation": "Pakartoti http-headers patikrą.",
            "confidence": "vidutinis",
        })

    server_match = re.search(r"Server:\s*(.+)", header_output)
    if server_match and re.search(r"\d+\.\d+", server_match.group(1)):
        findings.append({
            "finding_id": "WEB_SERVER_VERSION_DISCLOSED",
            "severity": "žema",
            "title": "Web serveris atskleidžia versiją",
            "evidence": [server_match.group(0).strip()],
            "impact": "Versijos atskleidimas palengvina žinomų pažeidžiamumų susiejimą su paslauga.",
            "recommended_fix": "Sumažinti Server antraštės detalumą ir svarbiausia atnaujinti web komponentus.",
            "validation": "Pakartoti http-server-header arba http-headers patikrą.",
            "confidence": "aukštas",
        })

    method_match = re.search(r"Supported Methods:\s*(.+)", text)
    if method_match:
        methods = set(method_match.group(1).split())
        risky = sorted(methods & {"PUT", "DELETE", "TRACE", "CONNECT"})
        if risky:
            findings.append({
                "finding_id": "WEB_RISKY_METHODS",
                "severity": "aukšta" if {"PUT", "DELETE"} & set(risky) else "vidutinė",
                "title": "Web serveris leidžia rizikingus HTTP metodus",
                "evidence": risky,
                "impact": "Nereikalingi HTTP metodai gali didinti aplikacijos atakos paviršių.",
                "recommended_fix": "Išjungti nereikalingus HTTP metodus ir palikti tik reikalingus aplikacijai.",
                "validation": "Pakartoti http-methods patikrą.",
                "confidence": "aukštas",
            })

    if "admin" in lowered or "login" in lowered:
        findings.append({
            "finding_id": "WEB_LOGIN_OR_ADMIN_HINT",
            "severity": "vidutinė",
            "title": "Web sąsajoje matomas prisijungimo arba administravimo požymis",
            "evidence": ["http-title/http-headers tekste aptiktas login/admin požymis"],
            "impact": "Administravimo arba prisijungimo sąsajos neturėtų būti plačiai pasiekiamos iš bendro LAN.",
            "recommended_fix": "Prisijungimo ar administravimo sąsają apriboti pagal IP/VLAN, įjungti stiprią autentifikaciją ir peržiūrėti numatytąsias paskyras.",
            "validation": "Pakartoti web fingerprint ir patikrinti ugniasienės taisykles.",
            "confidence": "vidutinis",
        })

    findings.extend(parse_nikto_findings(nikto_json))
    return findings[:40]



def normalize_target_findings(target: dict, findings: list[dict], scan_status: str = "success") -> list[dict]:
    normalized = []
    for finding in findings:
        raw = dict(finding)
        raw.setdefault("rule_id", str(raw.get("finding_id") or "web_deep_finding").lower())
        normalized.append(normalize_finding(
            raw,
            source_module="web_deep_audit.py",
            ip=target.get("ip"),
            asset_id=target.get("asset_id"),
            port=target.get("port"),
            protocol="tcp",
            service=target.get("scheme") or "http",
            scan_status=raw.get("scan_status") or scan_status,
        ))
    return normalized


def run_nmap_for_target(target: dict, parts_dir: Path, idx: int, total: int) -> dict:
    ip = target["ip"]
    port = target["port"]
    url = target["url"]
    xml_file = parts_dir / f"{ip.replace('.', '_')}_{port}_web_deep.xml"
    txt_file = parts_dir / f"{ip.replace('.', '_')}_{port}_web_deep.txt"
    cmd = [
        "nmap",
        "-Pn",
        "-n",
        "-p", str(port),
        "--script", NMAP_WEB_SCRIPTS,
        "--script-timeout", NMAP_SCRIPT_TIMEOUT,
        "--host-timeout", NMAP_HOST_TIMEOUT,
        "-oX", str(xml_file),
        "-oN", str(txt_file),
        ip,
    ]
    print(f"[{idx}/{total}] Web deep nmap {url}", flush=True)
    rc, out, err = run_cmd(cmd, timeout=PROCESS_TIMEOUT)
    scripts = parse_scripts(xml_file) if xml_file.exists() else []
    return {
        "scripts": scripts,
        "returncode": rc,
        "stdout": out if rc != 0 else None,
        "run": {
            "url": url,
            "tool": "nmap",
            "command": " ".join(cmd),
            "returncode": rc,
            "stderr": err,
            "xml_file": str(xml_file),
            "txt_file": str(txt_file),
        },
    }


def run_nikto_for_target(target: dict, parts_dir: Path, idx: int, total: int, nikto_available: bool) -> dict:
    url = target["url"]
    ip = target["ip"]
    port = target["port"]
    if not nikto_available:
        return {"nikto_json": None, "returncode": None, "run": None}

    nikto_file = parts_dir / f"{ip.replace('.', '_')}_{port}_nikto.json"
    nikto_cmd = [
        "nikto",
        "-h", url,
        "-nointeractive",
        "-Tuning", "x",
        "-maxtime", str(NIKTO_MAXTIME),
        "-Format", "json",
        "-output", str(nikto_file),
    ]
    print(f"[{idx}/{total}] Web deep nikto {url} maxtime={NIKTO_MAXTIME}s", flush=True)
    rc, _out, err = run_cmd(nikto_cmd, timeout=max(int(str(NIKTO_MAXTIME)) + 30, 60))
    nikto_json = load_json_if_possible(nikto_file)
    return {
        "nikto_json": nikto_json,
        "returncode": rc,
        "run": {
            "url": url,
            "tool": "nikto",
            "command": f"nikto -h <url> -nointeractive -maxtime {NIKTO_MAXTIME} -Format json -output <file>",
            "returncode": rc,
            "stderr": err,
            "json_file": str(nikto_file),
        },
    }


def scan_target(target: dict, parts_dir: Path, idx: int, total: int, nikto_available: bool) -> tuple[dict, list[dict]]:
    target_runs = []

    if WEB_DEEP_RUN_TOOLS_PARALLEL and nikto_available:
        with ThreadPoolExecutor(max_workers=2) as executor:
            fut_nmap = executor.submit(run_nmap_for_target, target, parts_dir, idx, total)
            fut_nikto = executor.submit(run_nikto_for_target, target, parts_dir, idx, total, nikto_available)
            nmap_result = fut_nmap.result()
            nikto_result = fut_nikto.result()
    else:
        nmap_result = run_nmap_for_target(target, parts_dir, idx, total)
        nikto_result = run_nikto_for_target(target, parts_dir, idx, total, nikto_available)

    target_runs.append(nmap_result["run"])
    if nikto_result.get("run"):
        target_runs.append(nikto_result["run"])

    scan_status = "success" if nmap_result.get("returncode") == 0 else "partial"
    raw_findings = build_findings(target, nmap_result.get("scripts", []), nikto_result.get("nikto_json"))
    findings = normalize_target_findings(target, raw_findings, scan_status=scan_status)
    result = {
        "ip": target["ip"],
        "asset_id": target.get("asset_id"),
        "port": target["port"],
        "url": target["url"],
        "scripts": nmap_result.get("scripts", []),
        "nikto_available": nikto_available,
        "nikto_returncode": nikto_result.get("returncode"),
        "nikto_output": nikto_result.get("nikto_json"),
        "findings": findings,
        "scan_status": scan_status,
        "returncode": nmap_result.get("returncode"),
        "stdout": nmap_result.get("stdout"),
    }
    return result, target_runs


def main() -> None:
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()
    timestamp = timestamp_now()

    services_file = latest_current_file("services_dir", "services_*.json")
    if services_file is None:
        services_file = latest_json_by_prefix("services", network=network)

    output_json = paths["services_dir"] / f"web_deep_{timestamp}.json"
    log_json = paths["logs_dir"] / f"web_deep_run_{timestamp}.json"

    if services_file is None:
        payload = {
            "scan_type": "web_deep_audit",
            "timestamp": timestamp,
            "network": network,
            "status": "skipped",
            "reason": "services JSON not found",
            "results": [],
        }
        save_json(output_json, payload)
        save_json(log_json, payload)
        return

    services_data = load_json(services_file)
    targets = build_targets(services_data)
    parts_dir = paths["services_dir"] / f"web_deep_parts_{timestamp}"
    parts_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("nmap"):
        payload = {
            "scan_type": "web_deep_audit",
            "timestamp": timestamp,
            "network": network,
            "status": "skipped",
            "reason": "nmap not found",
            "results": [],
        }
        save_json(output_json, payload)
        save_json(log_json, payload)
        print(f"Web deep audit praleistas: nmap nerastas. {output_json}")
        return

    nikto_available = shutil.which("nikto") is not None and NIKTO_ENABLED

    print(
        "Web deep audit nustatymai: "
        f"profile={PROFILE}, targets={len(targets)}, workers={WEB_DEEP_WORKERS}, "
        f"tools_parallel={WEB_DEEP_RUN_TOOLS_PARALLEL}, nikto_enabled={nikto_available}, "
        f"nikto_maxtime={NIKTO_MAXTIME}, nmap_script_timeout={NMAP_SCRIPT_TIMEOUT}, "
        f"nmap_host_timeout={NMAP_HOST_TIMEOUT}",
        flush=True,
    )

    results = []
    runs = []

    if targets:
        with ThreadPoolExecutor(max_workers=max(1, WEB_DEEP_WORKERS)) as executor:
            future_map = {
                executor.submit(scan_target, target, parts_dir, idx, len(targets), nikto_available): target
                for idx, target in enumerate(targets, start=1)
            }
            for future in as_completed(future_map):
                target = future_map[future]
                try:
                    result, target_runs = future.result()
                    results.append(result)
                    runs.extend(target_runs)
                    print(f"[DONE] Web deep {target['url']} findings={len(result.get('findings', []))}", flush=True)
                except Exception as exc:
                    runs.append({"url": target.get("url"), "tool": "web_deep_audit", "returncode": 1, "stderr": str(exc)})
                    results.append({
                        "ip": target.get("ip"),
                        "asset_id": target.get("asset_id"),
                        "port": target.get("port"),
                        "url": target.get("url"),
                        "scripts": [],
                        "nikto_available": nikto_available,
                        "nikto_returncode": None,
                        "nikto_output": None,
                        "findings": [],
                        "scan_status": "failed",
                        "returncode": 1,
                        "stdout": str(exc),
                    })

    results = sorted(results, key=lambda r: (r.get("ip") or "", int(r.get("port") or 0)))

    all_findings = [finding for result in results for finding in result.get("findings", [])]
    save_json(output_json, {
        "scan_type": "web_deep_audit",
        "timestamp": timestamp,
        "network": network,
        "interface": interface,
        "source_ip": source_ip,
        "source_services_file": services_file.name,
        "profile": PROFILE,
        "workers": WEB_DEEP_WORKERS,
        "nikto_enabled": nikto_available,
        "nikto_maxtime": NIKTO_MAXTIME,
        "nmap_script_timeout": NMAP_SCRIPT_TIMEOUT,
        "nmap_host_timeout": NMAP_HOST_TIMEOUT,
        "targets_count": len(targets),
        "results": results,
        "findings": all_findings,
        "scan_status": "success" if results else "skipped",
    })
    save_json(log_json, {"scan_type": "web_deep_audit", "timestamp": timestamp, "runs": runs})
    print(f"Sukurtas web deep audit JSON: {output_json}")
    print(f"Web deep target'ai: {len(targets)}")


if __name__ == "__main__":
    main()
