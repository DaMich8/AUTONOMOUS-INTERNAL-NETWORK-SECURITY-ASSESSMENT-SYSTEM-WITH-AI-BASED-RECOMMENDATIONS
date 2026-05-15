from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from common import (
    BASE_DIR,
    detect_runtime_network,
    get_run_paths,
    latest_current_file,
    latest_json_by_prefix,
    load_json,
    save_json,
    timestamp_now,
)

MAX_WORKERS = int(os.getenv("SERVICE_SCAN_WORKERS", "2"))
PROFILE = os.getenv("SERVICE_SCAN_PROFILE", "balanced").lower()

PORT_SCAN_MIN_RATE = os.getenv("SERVICE_SCAN_MIN_RATE", "300")
PORT_SCAN_HOST_TIMEOUT = os.getenv("SERVICE_SCAN_HOST_TIMEOUT", "5m")
VERSION_SCAN_HOST_TIMEOUT = os.getenv("SERVICE_SCAN_VERSION_TIMEOUT", "4m")
MAX_SCAN_DURATION_PER_RUN = int(os.getenv("SERVICE_SCAN_MAX_DURATION_SECONDS", "0") or "0")
EXCLUDE_HOSTS_FILE = Path(os.getenv("SERVICE_SCAN_EXCLUDE_HOSTS_FILE", str(BASE_DIR / "config" / "exclude_hosts.json")))

BALANCED_SCRIPTS = [
    "banner",
    "http-title",
    "http-headers",
    "http-server-header",
    "ssh-hostkey",
    "ssh2-enum-algos",
    "ssl-cert",
    "smb-os-discovery",
    "smb-protocols",
    "smb-security-mode",
    "rdp-enum-encryption",
    "rdp-ntlm-info",
]

DEEP_SCRIPTS = BALANCED_SCRIPTS + [
    "ssl-enum-ciphers",
    "http-methods",
    "http-auth-finder",
    "http-robots.txt",
]


def get_open_ports_from_xml(xml_file: Path) -> list[int]:
    tree = ET.parse(xml_file)
    root = tree.getroot()

    open_ports = []
    for host in root.findall("host"):
        ports_tag = host.find("ports")
        if ports_tag is None:
            continue

        for port in ports_tag.findall("port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                open_ports.append(int(port.get("portid")))

    return sorted(set(open_ports))


def run_command(command: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def nmap_version() -> str | None:
    nmap = shutil.which("nmap")
    if not nmap:
        return None
    try:
        result = subprocess.run([nmap, "--version"], capture_output=True, text=True, timeout=5)
        return (result.stdout or result.stderr).splitlines()[0].strip()
    except Exception:
        return None


def timeout_reason(stderr: str | None) -> str | None:
    text = str(stderr or "").lower()
    if "host timeout" in text or "timed out" in text or "timeout" in text:
        return "nmap_host_timeout"
    return None


def scan_status_from_result(returncode: int, phase: str, stderr: str | None = None) -> str:
    if returncode == 0:
        return "success"
    if timeout_reason(stderr):
        return "timeout"
    if phase == "version_scan_failed":
        return "partial"
    return "failed"


def confidence_penalty_for_status(status: str) -> float:
    return {"success": 0.0, "partial": 0.25, "timeout": 0.4, "failed": 0.6, "host_down": 0.5}.get(status, 0.3)


def scan_intensity_score(profile: str) -> int:
    return {"fast": 35, "balanced": 65, "deep": 90}.get(profile, 65)


def load_excluded_hosts() -> set[str]:
    if not EXCLUDE_HOSTS_FILE.exists():
        return set()
    try:
        data = json.loads(EXCLUDE_HOSTS_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {str(x).strip() for x in data if str(x).strip()}
        if isinstance(data, dict):
            values = data.get("exclude_hosts") or data.get("hosts") or []
            return {str(x).strip() for x in values if str(x).strip()}
    except Exception:
        return set()
    return set()


def build_version_command(ip: str, port_list: str, xml_file: Path, txt_file: Path) -> list[str]:
    cmd = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "-p", port_list,
        "-T4",
        "--reason",
        "--max-retries", "1",
        "--host-timeout", VERSION_SCAN_HOST_TIMEOUT,
        "-oX", str(xml_file),
        "-oN", str(txt_file),
    ]

    if PROFILE == "fast":
        cmd += ["--version-light", ip]
        return cmd

    if PROFILE == "deep":
        script_list = ",".join(DEEP_SCRIPTS)
        cmd += [
            "--version-all",
            "-O",
            "--osscan-guess",
            "--osscan-limit",
            "--script", script_list,
            "--script-timeout", "25s",
            ip
        ]
        return cmd

    script_list = ",".join(BALANCED_SCRIPTS)
    cmd += [
        "--version-all",
        "-O",
        "--osscan-guess",
        "--osscan-limit",
        "--script", script_list,
        "--script-timeout", "20s",
        ip
    ]
    return cmd


def scan_single_host(ip: str, run_dir: Path, batch_start: float) -> dict:
    host_slug = ip.replace(".", "_")

    elapsed_before = time.time() - batch_start
    if MAX_SCAN_DURATION_PER_RUN and elapsed_before >= MAX_SCAN_DURATION_PER_RUN:
        return {
            "ip": ip,
            "returncode": 124,
            "duration_s": 0.0,
            "phase1_duration_s": 0.0,
            "phase2_duration_s": 0.0,
            "xml_file": "",
            "txt_file": "",
            "stderr": "max_scan_duration_per_run exceeded before host scan",
            "phase": "skipped_max_duration",
            "open_ports": [],
            "scan_status": "skipped",
            "timeout_reason": "max_scan_duration_per_run",
            "confidence_penalty": confidence_penalty_for_status("failed"),
        }

    print(f"[START] {ip} | bendras laikas {round(elapsed_before, 2)} s", flush=True)

    ports_xml = run_dir / f"{host_slug}_ports.xml"
    ports_txt = run_dir / f"{host_slug}_ports.txt"

    port_cmd = [
        "nmap",
        "-Pn",
        "-n",
        "-p-",
        "--open",
        "-T4",
        "--reason",
        "--min-rate", PORT_SCAN_MIN_RATE,
        "--max-retries", "1",
        "--host-timeout", PORT_SCAN_HOST_TIMEOUT,
        "-oX", str(ports_xml),
        "-oN", str(ports_txt),
        ip
    ]

    phase1_start = time.time()
    rc1, _out1, err1 = run_command(port_cmd)
    phase1_duration = round(time.time() - phase1_start, 2)

    if rc1 != 0:
        return {
            "ip": ip,
            "returncode": rc1,
            "duration_s": phase1_duration,
            "phase1_duration_s": phase1_duration,
            "phase2_duration_s": 0.0,
            "xml_file": str(ports_xml),
            "txt_file": str(ports_txt),
            "stderr": err1,
            "phase": "port_scan_failed",
            "open_ports": [],
            "scan_status": scan_status_from_result(rc1, "port_scan_failed", err1),
            "timeout_reason": timeout_reason(err1),
            "confidence_penalty": confidence_penalty_for_status(scan_status_from_result(rc1, "port_scan_failed", err1))
        }

    open_ports = get_open_ports_from_xml(ports_xml)

    if MAX_SCAN_DURATION_PER_RUN and (time.time() - batch_start) >= MAX_SCAN_DURATION_PER_RUN:
        return {
            "ip": ip,
            "returncode": 124,
            "duration_s": phase1_duration,
            "phase1_duration_s": phase1_duration,
            "phase2_duration_s": 0.0,
            "xml_file": str(ports_xml),
            "txt_file": str(ports_txt),
            "stderr": "max_scan_duration_per_run exceeded after port discovery",
            "phase": "version_scan_skipped_max_duration",
            "open_ports": open_ports,
            "scan_status": "partial",
            "timeout_reason": "max_scan_duration_per_run",
            "confidence_penalty": confidence_penalty_for_status("partial"),
        }

    if not open_ports:
        return {
            "ip": ip,
            "returncode": 0,
            "duration_s": phase1_duration,
            "phase1_duration_s": phase1_duration,
            "phase2_duration_s": 0.0,
            "xml_file": str(ports_xml),
            "txt_file": str(ports_txt),
            "stderr": "",
            "phase": "no_open_ports",
            "open_ports": [],
            "scan_status": "success",
            "timeout_reason": None,
            "confidence_penalty": 0.0
        }

    services_xml = run_dir / f"{host_slug}_services.xml"
    services_txt = run_dir / f"{host_slug}_services.txt"
    port_list = ",".join(str(p) for p in open_ports)

    version_cmd = build_version_command(ip, port_list, services_xml, services_txt)

    phase2_start = time.time()
    rc2, _out2, err2 = run_command(version_cmd)
    phase2_duration = round(time.time() - phase2_start, 2)

    if rc2 != 0:
        return {
            "ip": ip,
            "returncode": rc2,
            "duration_s": round(phase1_duration + phase2_duration, 2),
            "phase1_duration_s": phase1_duration,
            "phase2_duration_s": phase2_duration,
            "xml_file": str(ports_xml),
            "txt_file": str(ports_txt),
            "stderr": err2,
            "phase": "version_scan_failed",
            "open_ports": open_ports,
            "scan_status": scan_status_from_result(rc2, "version_scan_failed", err2),
            "timeout_reason": timeout_reason(err2),
            "confidence_penalty": confidence_penalty_for_status(scan_status_from_result(rc2, "version_scan_failed", err2))
        }

    return {
        "ip": ip,
        "returncode": 0,
        "duration_s": round(phase1_duration + phase2_duration, 2),
        "phase1_duration_s": phase1_duration,
        "phase2_duration_s": phase2_duration,
        "xml_file": str(services_xml),
        "txt_file": str(services_txt),
        "stderr": "",
        "phase": "ok",
        "open_ports": open_ports,
        "scan_status": "success",
        "timeout_reason": None,
        "confidence_penalty": 0.0
    }


def combine_xml_files(xml_files: list[Path], output_file: Path) -> None:
    root = ET.Element("nmaprun", scanner="nmap", args=f"parallel two-stage service scan profile={PROFILE}")

    for xml_file in xml_files:
        tree = ET.parse(xml_file)
        xml_root = tree.getroot()
        for host in xml_root.findall("host"):
            root.append(host)

    tree = ET.ElementTree(root)
    tree.write(output_file, encoding="utf-8", xml_declaration=True)


def combine_txt_files(txt_files: list[Path], output_file: Path) -> None:
    with open(output_file, "w", encoding="utf-8") as out:
        for txt_file in txt_files:
            out.write(f"\n===== {txt_file.name} =====\n")
            with open(txt_file, "r", encoding="utf-8", errors="ignore") as f:
                out.write(f.read())
                out.write("\n")


def main() -> None:
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()

    discovery_json = latest_current_file("discovery_dir", "discovery_*.json")
    if discovery_json is None:
        discovery_json = latest_json_by_prefix("discovery", network=network)

    if discovery_json is None:
        raise FileNotFoundError(
            f"Nerastas discovery JSON failas tinklui {network}. "
            "Pirmiausia paleisk scan_network.py ir parse_discovery.py."
        )

    discovery_data = load_json(discovery_json)
    ips = [host["ip"] for host in discovery_data.get("hosts", []) if host.get("ip")]
    excluded_hosts = load_excluded_hosts()
    if excluded_hosts:
        before_count = len(ips)
        ips = [ip for ip in ips if ip not in excluded_hosts]
        print(f"[INFO] Exclude hosts: praleista {before_count - len(ips)} hostų iš {EXCLUDE_HOSTS_FILE}")

    if not ips:
        raise RuntimeError("Discovery rezultate nėra aktyvių hostų.")

    timestamp = timestamp_now()
    run_dir = paths["services_dir"] / f"parts_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    combined_xml = paths["services_dir"] / f"services_{timestamp}.xml"
    combined_txt = paths["services_dir"] / f"services_{timestamp}.txt"
    log_file = paths["logs_dir"] / f"service_run_{timestamp}.json"

    print("Service scan pradedamas.")
    print(f"Tinklas: {network}")
    print(f"Sąsaja: {interface}")
    print(f"Hostų skaičius: {len(ips)}")
    print(f"Lygiagrečių užduočių skaičius: {MAX_WORKERS}")
    print(f"Profilis: {PROFILE}")
    print(f"Skenavimo intensyvumo balas: {scan_intensity_score(PROFILE)}")
    print(f"Nmap versija: {nmap_version() or 'nenustatyta'}")
    if MAX_SCAN_DURATION_PER_RUN:
        print(f"Maksimali planuota skenavimo trukmė: {MAX_SCAN_DURATION_PER_RUN} s")
    print("Tikrinami hostai:")
    for ip in ips:
        print(f"[QUEUE] {ip}")

    print("\nNaudojamas dviejų etapų skanavimas:")
    print("1) pilnas atvirų TCP prievadų atradimas")
    print("2) detali analizė tik atviriems portams (versijos, OS, tiksliniai NSE skriptai)\n", flush=True)

    results = []
    completed = 0
    overall_start = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(scan_single_host, ip, run_dir, overall_start): ip for ip in ips}

        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            completed += 1

            if result["returncode"] == 0:
                print(
                    f"[DONE] {completed}/{len(ips)} | {result['ip']} | "
                    f"viso {result['duration_s']} s | "
                    f"1 etapas {result['phase1_duration_s']} s | "
                    f"2 etapas {result['phase2_duration_s']} s | "
                    f"atviri portai {len(result.get('open_ports', []))} | "
                    f"bendras laikas {round(time.time() - overall_start, 2)} s",
                    flush=True
                )
            else:
                print(
                    f"[FAIL] {completed}/{len(ips)} | {result['ip']} | "
                    f"fazė {result.get('phase')} | "
                    f"bendras laikas {round(time.time() - overall_start, 2)} s",
                    flush=True
                )

    total_duration_s = round(time.time() - overall_start, 2)

    successful = [r for r in results if r["returncode"] == 0]
    failed = [r for r in results if r["returncode"] != 0]

    if not successful:
        execution_log = {
            "timestamp": timestamp,
            "scan_type": "services",
            "network": network,
            "interface": interface,
            "source_ip": source_ip,
            "profile": PROFILE,
            "discovery_file": discovery_json.name,
            "target_hosts": ips,
            "workers": MAX_WORKERS,
            "returncode": 1,
            "scan_status": "failed",
            "duration_s": total_duration_s,
            "nmap_version": nmap_version(),
            "scan_intensity_score": scan_intensity_score(PROFILE),
            "exclude_hosts_file": str(EXCLUDE_HOSTS_FILE) if EXCLUDE_HOSTS_FILE.exists() else None,
            "max_scan_duration_per_run": MAX_SCAN_DURATION_PER_RUN or None,
            "host_duration_summary": {"min": None, "max": None, "avg": None},
            "successful_hosts": [],
            "failed_hosts": failed
        }
        save_json(log_file, execution_log)
        print("Service scan nepavyko visiems hostams.")
        raise SystemExit(1)

    successful_xml_files = [Path(r["xml_file"]) for r in successful if r.get("xml_file")]
    successful_txt_files = [Path(r["txt_file"]) for r in successful if r.get("txt_file")]

    combine_xml_files(successful_xml_files, combined_xml)
    combine_txt_files(successful_txt_files, combined_txt)

    durations = [float(r.get("duration_s", 0) or 0) for r in results]
    host_duration_summary = {
        "min": round(min(durations), 2) if durations else None,
        "max": round(max(durations), 2) if durations else None,
        "avg": round(sum(durations) / len(durations), 2) if durations else None,
    }
    run_scan_status = "success" if not failed else "partial"

    execution_log = {
        "timestamp": timestamp,
        "scan_type": "services",
        "network": network,
        "interface": interface,
        "source_ip": source_ip,
        "profile": PROFILE,
        "discovery_file": discovery_json.name,
        "target_hosts": ips,
        "workers": MAX_WORKERS,
        "returncode": 0 if not failed else 2,
        "scan_status": run_scan_status,
        "duration_s": total_duration_s,
        "nmap_version": nmap_version(),
        "scan_intensity_score": scan_intensity_score(PROFILE),
        "exclude_hosts_file": str(EXCLUDE_HOSTS_FILE) if EXCLUDE_HOSTS_FILE.exists() else None,
        "max_scan_duration_per_run": MAX_SCAN_DURATION_PER_RUN or None,
        "host_duration_summary": host_duration_summary,
        "combined_xml_file": str(combined_xml),
        "combined_txt_file": str(combined_txt),
        "successful_hosts": successful,
        "failed_hosts": failed
    }

    save_json(log_file, execution_log)

    print("\nService scan baigtas.")
    print(f"Bendra trukmė: {total_duration_s} s")
    print(f"Sėkmingai nuskenuoti hostai: {len(successful)}")
    print(f"Nepavykę hostai: {len(failed)}")
    print(f"XML rezultatai: {combined_xml}")
    print(f"TXT rezultatai: {combined_txt}")
    print(f"Žurnalas: {log_file}")


if __name__ == "__main__":
    main()
