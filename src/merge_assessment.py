from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from asset_identity import enrich_host_asset_id
from common import (
    detect_runtime_network,
    get_run_paths,
    latest_json_by_prefix,
    load_json,
    save_json,
    timestamp_now,
)

CVE_RE = re.compile(r"(CVE-\d{4}-\d+)\s+([0-9]+(?:\.[0-9]+)?)")


# -----------------------------
# Generic helpers
# -----------------------------
def latest_optional(paths: dict, dir_key: str, pattern: str):
    files = sorted(paths[dir_key].glob(pattern))
    return files[-1] if files else None


def load_optional(path: Path | None):
    if path is None or not path.exists():
        return None
    return load_json(path)


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def ensure_list(obj: dict, key: str) -> list:
    if key not in obj or not isinstance(obj[key], list):
        obj[key] = []
    return obj[key]


def ip_sort_key(ip: str):
    try:
        return tuple(int(part) for part in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def dedupe_preserve_order(items: list[str]) -> list[str]:
    seen = set()
    output = []
    for item in items:
        if item and item not in seen:
            output.append(item)
            seen.add(item)
    return output


# -----------------------------
# Host/port merge primitives
# -----------------------------
def find_host(hosts_by_ip: dict, ip: str):
    if ip not in hosts_by_ip:
        hosts_by_ip[ip] = {
            "ip": ip,
            "asset_id": None,
            "asset_identity": {},
            "mac": None,
            "vendor": None,
            "hostname": None,
            "state": "up",
            "status_reason": None,
            "open_ports_count": 0,
            "extraports": [],
            "os_matches": [],
            "host_scripts": [],
            "ports": [],
            "enrichment_host_scripts": [],
            "udp_ports": [],
            "vuln_host_scripts": [],
            "l2_inventory": {},
            "smb_enrichment": {},
            "web_fingerprint": [],
            "tls_audit": [],
            "snmp_enrichment": {},
            "change_summary": {},
            "normalized_security_profile": {},
            "recommended_actions": [],
            "evidence_summary": [],
            "legacy_priority_score": 0,
            "legacy_priority_level": "žema",
        }
    return hosts_by_ip[ip]


def find_or_create_port(host: dict, port_number: int, protocol: str, from_udp: bool = False):
    container_key = "udp_ports" if from_udp else "ports"
    container = ensure_list(host, container_key)

    for port_obj in container:
        if port_obj.get("port") == port_number and port_obj.get("protocol") == protocol:
            return port_obj

    port_obj = {
        "port": port_number,
        "protocol": protocol,
        "state": "open",
        "reason": None,
        "service_name": None,
        "product": None,
        "version": None,
        "extra_info": None,
        "tunnel": None,
        "method": None,
        "conf": None,
        "service_fingerprint": None,
        "cpes": [],
        "scripts": [],
    }
    if not from_udp:
        port_obj["enrichment_scripts"] = []
        port_obj["vuln_scripts"] = []
    container.append(port_obj)
    return port_obj


def merge_script_list(port_obj: dict, key: str, scripts):
    if not scripts:
        return
    existing = ensure_list(port_obj, key)
    seen = {(s.get("id"), s.get("output")) for s in existing if isinstance(s, dict)}

    for script in as_list(scripts):
        if not isinstance(script, dict):
            continue
        marker = (script.get("id"), script.get("output"))
        if marker not in seen:
            existing.append(script)
            seen.add(marker)


def merge_host_script_list(host: dict, key: str, scripts):
    if not scripts:
        return
    existing = ensure_list(host, key)
    seen = {(s.get("id"), s.get("output")) for s in existing if isinstance(s, dict)}

    for script in as_list(scripts):
        if not isinstance(script, dict):
            continue
        marker = (script.get("id"), script.get("output"))
        if marker not in seen:
            existing.append(script)
            seen.add(marker)


def merge_services_hosts(hosts_by_ip: dict, services_data: dict):
    for raw_host in as_list(services_data.get("hosts")):
        ip = raw_host.get("ip")
        if not ip:
            continue

        host = find_host(hosts_by_ip, ip)
        for key in (
            "mac", "vendor", "hostname", "state", "status_reason",
            "open_ports_count", "extraports", "os_matches"
        ):
            if raw_host.get(key) not in (None, [], {}):
                host[key] = deepcopy(raw_host.get(key))

        merge_host_script_list(host, "host_scripts", raw_host.get("host_scripts"))

        for raw_port in as_list(raw_host.get("ports")):
            port = find_or_create_port(host, raw_port.get("port"), raw_port.get("protocol", "tcp"))
            for key in (
                "state", "reason", "service_name", "product", "version", "extra_info",
                "tunnel", "method", "conf", "service_fingerprint"
            ):
                if raw_port.get(key) is not None:
                    port[key] = raw_port.get(key)
            if raw_port.get("cpes"):
                port["cpes"] = deepcopy(raw_port.get("cpes"))
            merge_script_list(port, "scripts", raw_port.get("scripts"))
            merge_script_list(port, "enrichment_scripts", raw_port.get("enrichment_scripts"))
            merge_script_list(port, "vuln_scripts", raw_port.get("vuln_scripts"))


# -----------------------------
# Merge optional module outputs
# -----------------------------
def merge_structured_results(hosts_by_ip: dict, data: dict | None, mode: str):
    if not data:
        return

    results = as_list(data.get("results"))
    for item in results:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not ip:
            continue

        host = find_host(hosts_by_ip, ip)

        if mode == "enrichment":
            merge_host_script_list(host, "enrichment_host_scripts", item.get("host_scripts"))
            for port_item in as_list(item.get("ports")):
                p = find_or_create_port(host, port_item.get("port"), port_item.get("protocol", "tcp"))
                merge_script_list(p, "enrichment_scripts", port_item.get("scripts"))

        elif mode == "vuln":
            merge_host_script_list(host, "vuln_host_scripts", item.get("host_scripts"))
            if item.get("cves"):
                existing_cves = ensure_list(host, "structured_cves")
                seen_cves = {c.get("cve") for c in existing_cves if isinstance(c, dict)}
                for cve_item in as_list(item.get("cves")):
                    if isinstance(cve_item, dict) and cve_item.get("cve") not in seen_cves:
                        existing_cves.append(deepcopy(cve_item))
                        seen_cves.add(cve_item.get("cve"))
            if item.get("findings"):
                existing_findings = ensure_list(host, "vuln_findings")
                existing_findings.extend(deepcopy(as_list(item.get("findings"))))
            for port_item in as_list(item.get("ports")):
                p = find_or_create_port(host, port_item.get("port"), port_item.get("protocol", "tcp"))
                merge_script_list(p, "vuln_scripts", port_item.get("scripts"))
                if port_item.get("cves"):
                    p["cves"] = deepcopy(as_list(port_item.get("cves")))

        elif mode == "udp":
            for port_item in as_list(item.get("ports")):
                p = find_or_create_port(host, port_item.get("port"), port_item.get("protocol", "udp"), from_udp=True)
                for key in (
                    "state", "reason", "service_name", "product", "version", "extra_info",
                    "tunnel", "method", "conf", "service_fingerprint"
                ):
                    if port_item.get(key) is not None:
                        p[key] = port_item.get(key)
                if port_item.get("cpes"):
                    p["cpes"] = deepcopy(port_item.get("cpes"))
                merge_script_list(p, "scripts", port_item.get("scripts"))


def merge_l2_inventory(hosts_by_ip: dict, l2_data: dict | None):
    if not l2_data:
        return

    for item in as_list(l2_data.get("hosts")):
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not ip:
            continue

        host = find_host(hosts_by_ip, ip)
        if item.get("mac"):
            host["mac"] = item.get("mac")
        if item.get("vendor"):
            host["vendor"] = item.get("vendor")
        if item.get("asset_id"):
            host["asset_id"] = item.get("asset_id")
        enrich_host_asset_id(host)

        host["l2_inventory"] = {
            "seen_by_arp_scan": True,
            "mac": item.get("mac"),
            "vendor": item.get("vendor"),
            "asset_id": host.get("asset_id"),
        }


def merge_generic_results_by_ip(hosts_by_ip: dict, data: dict | None, target_key: str):
    if not data:
        return

    results = []
    for key in ("results", "targets", "hosts"):
        results.extend(as_list(data.get(key)))
    grouped = {}

    for item in results:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not ip:
            continue
        grouped.setdefault(ip, []).append(item)

    for ip, entries in grouped.items():
        host = find_host(hosts_by_ip, ip)
        if target_key in ("web_fingerprint", "tls_audit"):
            host[target_key] = entries
        elif target_key in ("snmp_enrichment", "smb_enrichment"):
            host[target_key] = {"results": entries}


# -----------------------------
# Compare integration
# -----------------------------
def parse_compare_files(hosts_by_ip: dict, discovery_compare: dict | None, services_compare: dict | None):
    disc_new = set()
    disc_missing = set()
    svc_new_hosts = set()
    svc_missing_hosts = set()
    svc_new_ports = {}
    svc_closed_ports = {}
    svc_changed = {}

    if discovery_compare:
        base_cmp = discovery_compare.get("baseline_comparison") or {}
        disc_new = set(as_list(base_cmp.get("new_hosts")))
        disc_missing = set(as_list(base_cmp.get("missing_hosts")))

    if services_compare:
        base_cmp = services_compare.get("baseline_comparison") or {}
        svc_new_hosts = set(as_list(base_cmp.get("new_hosts")))
        svc_missing_hosts = set(as_list(base_cmp.get("missing_hosts")))

        for item in as_list(base_cmp.get("new_ports")):
            if isinstance(item, dict) and item.get("ip"):
                svc_new_ports.setdefault(item["ip"], []).append(item.get("port"))
        for item in as_list(base_cmp.get("closed_ports")):
            if isinstance(item, dict) and item.get("ip"):
                svc_closed_ports.setdefault(item["ip"], []).append(item.get("port"))
        for item in as_list(base_cmp.get("changed_services")):
            if isinstance(item, dict) and item.get("ip"):
                svc_changed.setdefault(item["ip"], []).append(item.get("port"))

    for ip, host in hosts_by_ip.items():
        host["change_summary"] = {
            "is_new_host_since_baseline": ip in disc_new or ip in svc_new_hosts,
            "missing_since_baseline": ip in disc_missing or ip in svc_missing_hosts,
            "new_ports_since_baseline": svc_new_ports.get(ip, []),
            "closed_ports_since_baseline": svc_closed_ports.get(ip, []),
            "changed_services_since_baseline": svc_changed.get(ip, []),
        }


# -----------------------------
# Normalization helpers
# -----------------------------
def get_all_script_outputs(host: dict):
    outputs = []

    for key in ("host_scripts", "enrichment_host_scripts", "vuln_host_scripts"):
        for script in as_list(host.get(key)):
            if isinstance(script, dict):
                outputs.append((script.get("id"), script.get("output") or ""))

    for port in as_list(host.get("ports")):
        for key in ("scripts", "enrichment_scripts", "vuln_scripts"):
            for script in as_list(port.get(key)):
                if isinstance(script, dict):
                    outputs.append((script.get("id"), script.get("output") or ""))

    for port in as_list(host.get("udp_ports")):
        for script in as_list(port.get("scripts")):
            if isinstance(script, dict):
                outputs.append((script.get("id"), script.get("output") or ""))

    return outputs


def collect_port_services(host: dict):
    service_names = []
    tcp_ports = []
    udp_ports = []

    for port in as_list(host.get("ports")):
        if port.get("port") is not None:
            tcp_ports.append(port.get("port"))
        if port.get("service_name"):
            service_names.append(str(port.get("service_name")).lower())

    for port in as_list(host.get("udp_ports")):
        if port.get("port") is not None:
            udp_ports.append(port.get("port"))
        if port.get("service_name"):
            service_names.append(str(port.get("service_name")).lower())

    return sorted(set(tcp_ports)), sorted(set(udp_ports)), sorted(set(service_names))


def parse_vulners(host: dict):
    vulns = []
    for item in as_list(host.get("structured_cves")):
        if isinstance(item, dict) and item.get("cve"):
            vulns.append(deepcopy(item))
    for _script_id, output in get_all_script_outputs(host):
        if not output:
            continue
        for match in CVE_RE.finditer(output):
            cve = match.group(1)
            cvss = float(match.group(2))
            vulns.append({"cve": cve, "cvss": cvss, "source": "script_output", "confidence": "vidutinis", "status": "potential"})

    unique = {}
    for item in vulns:
        cve = item.get("cve")
        if not cve:
            continue
        cvss = float(item.get("cvss") or 0)
        if cve not in unique or cvss > float(unique[cve].get("cvss") or 0):
            unique[cve] = item

    vulns = sorted(unique.values(), key=lambda x: float(x.get("cvss") or 0), reverse=True)
    highest = float(vulns[0].get("cvss") or 0) if vulns else 0.0
    critical = [v["cve"] for v in vulns if float(v.get("cvss") or 0) >= 7.0][:10]

    return {
        "has_known_vulns": bool(vulns),
        "vuln_count": len(vulns),
        "highest_cvss": highest,
        "critical_cves": critical,
        "all_cves": vulns[:25],
        "potential_cves": [v for v in vulns if v.get("status") == "potential"][:25],
        "confirmed_cves": [v for v in vulns if v.get("status") == "confirmed"][:25],
    }


def parse_smb_profile(host: dict):
    protocols = []
    signing_disabled = False
    guest_or_share_auth = False
    auth_mode = None
    os_guess = None
    workgroup = None

    for script_id, output in get_all_script_outputs(host):
        if script_id == "smb-protocols":
            if "NT LM 0.12" in output or "SMBv1" in output:
                protocols.append("SMBv1")
            for proto in ("2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"):
                if proto in output:
                    protocols.append(proto)

        if script_id == "smb-security-mode":
            if "message_signing: disabled" in output:
                signing_disabled = True
            if "authentication_level: share" in output:
                guest_or_share_auth = True
                auth_mode = "share"
            elif "authentication_level:" in output:
                auth_mode = output.split("authentication_level:", 1)[1].splitlines()[0].strip()

        if script_id == "smb-os-discovery":
            os_match = re.search(r"OS:\s*(.+)", output)
            if os_match:
                os_guess = os_match.group(1).strip()
            wg_match = re.search(r"Workgroup:\s*(.+)", output)
            if wg_match:
                workgroup = wg_match.group(1).strip()

    protocols = sorted(set(protocols))
    present = any(p.get("port") in (139, 445) for p in as_list(host.get("ports"))) or bool(protocols)

    return {
        "present": present,
        "protocols": protocols,
        "smbv1_enabled": "SMBv1" in protocols,
        "signing_disabled": signing_disabled,
        "guest_or_share_auth": guest_or_share_auth,
        "authentication_mode": auth_mode,
        "os_guess": os_guess,
        "workgroup": workgroup,
    }


def parse_web_profile(host: dict):
    web_ports = []
    titles = []
    methods = set()
    servers = set()
    login_detected = False
    admin_detected = False
    security_headers = set()
    technologies = set()
    raw_entries = as_list(host.get("web_fingerprint"))

    for port in as_list(host.get("ports")):
        if str(port.get("service_name") or "").lower() not in ("http", "https"):
            continue

        if port.get("port") is not None:
            web_ports.append(port.get("port"))

        for script in as_list(port.get("scripts")) + as_list(port.get("enrichment_scripts")):
            if not isinstance(script, dict):
                continue
            sid = script.get("id")
            out = script.get("output") or ""

            if sid == "http-title" and out:
                titles.append(out.strip())
                if "login" in out.lower():
                    login_detected = True

            if sid == "http-methods":
                method_match = re.search(r"Supported Methods:\s*(.+)", out)
                if method_match:
                    for m in method_match.group(1).split():
                        methods.add(m.strip())

            if sid == "http-headers":
                srv_match = re.search(r"Server:\s*(.+)", out)
                if srv_match:
                    servers.add(srv_match.group(1).strip())

                for header_name in ("X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"):
                    if header_name in out:
                        security_headers.add(header_name)

                lowered = out.lower()
                if "login" in lowered or "sessionid" in lowered:
                    login_detected = True
                if "admin" in lowered:
                    admin_detected = True

            lowered = out.lower()
            if "login" in lowered:
                login_detected = True
            if "admin" in lowered:
                admin_detected = True

    for entry in raw_entries:
        stdout = (entry.get("stdout") or "").strip()
        if not stdout:
            continue
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if not lines:
            continue
        first = lines[0]
        if "Title[" in first:
            for t in re.findall(r"Title\[([^\]]+)\]", first):
                titles.append(t.strip())
                if "login" in t.lower():
                    login_detected = True
        tokens = re.findall(r"([A-Za-z0-9\-\._ ]+)\[[^\]]+\]", first)
        for token in tokens:
            token = token.strip()
            if token.lower() not in {"title", "ip", "country", "server"} and token:
                technologies.add(token)
        if "login" in first.lower():
            login_detected = True
        if "admin" in first.lower():
            admin_detected = True

    return {
        "present": bool(web_ports),
        "ports": sorted(set(web_ports)),
        "titles": dedupe_preserve_order(titles)[:10],
        "methods": sorted(methods),
        "servers": sorted(servers),
        "security_headers": sorted(security_headers),
        "login_page_detected": login_detected,
        "admin_interface_detected": admin_detected,
        "technologies": sorted(technologies),
    }


def parse_ssh_profile(host: dict):
    present = False
    version = None
    weak_algorithms = []
    key_algorithms = []
    encryption_algorithms = []

    for port in as_list(host.get("ports")):
        if str(port.get("service_name") or "").lower() != "ssh":
            continue
        present = True
        version = f"{port.get('product') or ''} {port.get('version') or ''}".strip() or port.get("service_name")

    for script_id, output in get_all_script_outputs(host):
        if script_id == "banner" and "SSH-" in output and not version:
            version = output.strip()

        if script_id == "ssh2-enum-algos":
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith(("rsa-sha2-", "ecdsa-", "ssh-ed25519", "ssh-rsa")):
                    key_algorithms.append(line)
                if "aes" in line or "chacha20" in line:
                    encryption_algorithms.append(line)
                if "hmac-sha1" in line or line == "ssh-rsa":
                    weak_algorithms.append(line)

    return {
        "present": present,
        "version": version,
        "key_algorithms": sorted(set(key_algorithms)),
        "encryption_algorithms": sorted(set(encryption_algorithms)),
        "weak_algorithms": sorted(set(weak_algorithms)),
        "requires_patch_review": present and parse_vulners(host)["has_known_vulns"],
    }


def parse_rdp_profile(host: dict):
    present = False
    nla_enabled = False
    security_layers = []
    encryption_level = None

    for port in as_list(host.get("ports")):
        if port.get("port") == 3389 or str(port.get("service_name") or "").lower() == "ms-wbt-server":
            present = True

    for script_id, output in get_all_script_outputs(host):
        if script_id == "rdp-enum-encryption":
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                if "CredSSP (NLA): SUCCESS" in line:
                    nla_enabled = True
                if line.startswith(("CredSSP", "Native RDP", "RDSTLS", "SSL")) and "SUCCESS" in line:
                    security_layers.append(line.split(":", 1)[0].strip())
                if line.startswith("RDP Encryption level:"):
                    encryption_level = line.split(":", 1)[1].strip()

    return {
        "present": present,
        "nla_enabled": nla_enabled,
        "security_layers": sorted(set(security_layers)),
        "encryption_level": encryption_level,
    }


def parse_tls_profile(host: dict):
    results = as_list(host.get("tls_audit"))
    versions = set()
    weak_ciphers_present = False
    certificate_subject = None
    certificate_issuer = None

    for item in results:
        stdout = (item.get("stdout") or "") + "\n" + (item.get("stderr") or "")
        for proto in re.findall(r"(TLSv1\.[0-3]|SSLv[23])", stdout):
            versions.add(proto)
        if any(token in stdout.upper() for token in ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5")):
            weak_ciphers_present = True
        subj = re.search(r"Subject:\s*(.+)", stdout)
        iss = re.search(r"Issuer:\s*(.+)", stdout)
        if subj and not certificate_subject:
            certificate_subject = subj.group(1).strip()
        if iss and not certificate_issuer:
            certificate_issuer = iss.group(1).strip()

    return {
        "present": bool(results),
        "versions": sorted(versions),
        "weak_ciphers_present": weak_ciphers_present,
        "certificate_subject": certificate_subject,
        "certificate_issuer": certificate_issuer,
    }


def parse_snmp_profile(host: dict):
    results = as_list((host.get("snmp_enrichment") or {}).get("results"))
    present = bool(results)
    communities = set()
    device_info = []
    interfaces = []

    for item in results:
        text = (item.get("stdout") or "") + "\n" + (item.get("stderr") or "")
        for comm in re.findall(r"\[(public|private|manager|admin)\]", text, re.IGNORECASE):
            communities.add(comm.lower())
        if "sysDescr" in text or "system description" in text.lower():
            device_info.append("system_description_present")
        if "Interface" in text or "ifDescr" in text:
            interfaces.append("interfaces_present")

    return {
        "present": present,
        "community_strings_detected": sorted(communities),
        "device_info_flags": sorted(set(device_info)),
        "interface_flags": sorted(set(interfaces)),
    }


def has_tcp_port(host: dict, port_number: int) -> bool:
    return any(p.get("port") == port_number and p.get("protocol") == "tcp" for p in host.get("ports", []))


def has_udp_port(host: dict, port_number: int) -> bool:
    return any(p.get("port") == port_number and p.get("protocol") == "udp" for p in host.get("udp_ports", []))


def get_service_names(host: dict) -> set[str]:
    names = set()
    for port in host.get("ports", []):
        if port.get("service_name"):
            names.add(str(port["service_name"]).lower())
    for port in host.get("udp_ports", []):
        if port.get("service_name"):
            names.add(str(port["service_name"]).lower())
    return names


def get_os_family(host: dict) -> str | None:
    for os_match in host.get("os_matches", []):
        if not isinstance(os_match, dict):
            continue
        name = (os_match.get("name") or "").lower()
        if "windows" in name:
            return "windows"
        if "linux" in name:
            return "linux"
        if "unix" in name:
            return "unix"
        if "router" in name:
            return "network_device"
    for port in host.get("ports", []):
        for cpe in port.get("cpes", []) or []:
            cpe = str(cpe).lower()
            if "microsoft:windows" in cpe:
                return "windows"
            if "linux:linux_kernel" in cpe:
                return "linux"
    return None


def derive_device_class(host: dict, smb: dict, web: dict, ssh: dict, rdp: dict, snmp: dict) -> str:
    service_names = get_service_names(host)
    os_family = get_os_family(host)

    has_dns = has_tcp_port(host, 53) or has_udp_port(host, 53)
    has_http = any(s in service_names for s in {"http", "https"})
    has_smb = smb.get("present", False)
    has_rdp = rdp.get("present", False)
    has_ssh = ssh.get("present", False)
    has_snmp = snmp.get("present", False)

    rpc_like = any(s in service_names for s in {"msrpc", "netbios-ssn", "microsoft-ds"})
    mail_like = any(s in service_names for s in {"smtp", "imap", "pop3"})
    db_like = any(s in service_names for s in {"mysql", "ms-sql-s", "postgresql", "mongodb", "redis"})
    printer_like = any(s in service_names for s in {"ipp", "printer", "jetdirect"})
    iot_like = any(s in service_names for s in {"mqtt", "coap", "upnp", "rtsp"})

    if has_dns and has_http and has_smb:
        return "gateway_or_multi_service_network_device"

    if has_snmp and not (has_ssh or has_rdp):
        return "managed_network_device"

    if has_smb and (has_rdp or rpc_like or os_family == "windows"):
        return "windows_endpoint_or_server"

    if has_ssh and not has_smb and (os_family in {"linux", "unix"} or os_family is None):
        if has_http:
            return "linux_or_unix_server"
        return "linux_or_unix_host"

    if db_like:
        return "database_or_application_server"

    if mail_like:
        return "mail_or_application_server"

    if printer_like:
        return "printer_or_print_service_device"

    if iot_like and not has_smb:
        return "iot_or_embedded_device"

    if has_http and not (has_smb or has_ssh or has_rdp):
        return "web_managed_device"

    if has_smb and not (has_ssh or has_rdp):
        return "file_sharing_device"

    if host.get("open_ports_count", 0) == 0:
        return "unclassified_active_host"

    return "unclassified_network_host"


def build_classification_reasons(host: dict, smb: dict, web: dict, ssh: dict, rdp: dict, snmp: dict) -> list[str]:
    reasons = []

    if ssh.get("present"):
        reasons.append("aptikta SSH paslauga")
    if rdp.get("present"):
        reasons.append("aptikta RDP paslauga")
    if smb.get("present"):
        reasons.append("aptikta SMB/NetBIOS paslauga")
    if web.get("present"):
        reasons.append("aptikta HTTP/HTTPS paslauga")
    if snmp.get("present"):
        reasons.append("aptikta SNMP paslauga")

    if smb.get("smbv1_enabled"):
        reasons.append("aptiktas SMBv1 protokolas")
    if smb.get("signing_disabled"):
        reasons.append("SMB signing išjungtas")
    if smb.get("guest_or_share_auth"):
        reasons.append("aptikta share/guest autentifikacija")

    if host.get("open_ports_count", 0) >= 8:
        reasons.append("hostas turi daug atvirų TCP prievadų")

    return reasons[:10]


def normalize_host(host: dict):
    smb = parse_smb_profile(host)
    web = parse_web_profile(host)
    ssh = parse_ssh_profile(host)
    rdp = parse_rdp_profile(host)
    tls = parse_tls_profile(host)
    snmp = parse_snmp_profile(host)
    vulns = parse_vulners(host)
    tcp_ports, udp_ports, service_names = collect_port_services(host)

    normalized = {
        "seen_by": {
            "nmap": True,
            "arp_scan": bool((host.get("l2_inventory") or {}).get("seen_by_arp_scan")),
        },
        "tcp_open_ports": tcp_ports,
        "udp_open_ports": udp_ports,
        "service_names": service_names,
        "smb": smb,
        "web": web,
        "ssh": ssh,
        "rdp": rdp,
        "tls": tls,
        "snmp": snmp,
        "vulnerabilities": vulns,
        "device_class": derive_device_class(host, smb, web, ssh, rdp, snmp),
        "classification_reasons": build_classification_reasons(host, smb, web, ssh, rdp, snmp),
    }

    return normalized


def build_recommended_actions(host: dict, normalized: dict):
    actions = []

    smb = normalized["smb"]
    web = normalized["web"]
    ssh = normalized["ssh"]
    rdp = normalized["rdp"]
    tls = normalized["tls"]
    snmp = normalized["snmp"]
    vulns = normalized["vulnerabilities"]
    change_summary = host.get("change_summary") or {}
    tcp_ports, _udp_ports, _service_names = collect_port_services(host)

    if smb.get("smbv1_enabled"):
        actions.append("Išjungti SMBv1 ir palikti tik SMBv2/SMBv3.")
    if smb.get("signing_disabled"):
        actions.append("Įjungti SMB signing ir apriboti SMB prieigą tik patikimiems segmentams.")
    if smb.get("guest_or_share_auth"):
        actions.append("Išjungti guest/share lygio autentifikaciją ir taikyti vartotojų autentifikavimą.")
    if rdp.get("present"):
        actions.append("RDP (3389) leisti tik per VPN arba atskirą valdymo segmentą, o ne iš bendro LAN.")
    if ssh.get("present") and vulns.get("has_known_vulns"):
        actions.append("Peržiūrėti ir atnaujinti SSH/OpenSSH paketą pagal rastus CVE ir riboti prieigą pagal ugniasienę.")
    if web.get("login_page_detected") or web.get("admin_interface_detected"):
        actions.append("Apriboti administravimo žiniatinklio sąsają pagal IP arba valdymo VLAN ir peržiūrėti numatytąsias paskyras.")
    if tls.get("weak_ciphers_present"):
        actions.append("Išjungti silpnus TLS/SSL cipherius ir palikti tik stiprius šifravimo rinkinius.")
    if snmp.get("present") and any(c in {"public", "private"} for c in snmp.get("community_strings_detected", [])):
        actions.append("Pakeisti numatytąsias SNMP community reikšmes ir riboti SNMP prieigą tik valdymo segmentui.")
    if vulns.get("highest_cvss", 0) >= 7.0:
        actions.append("Aukšto prioriteto tvarka taikyti pataisas arba laikinai riboti paveiktos paslaugos prieigą.")
    if len(tcp_ports) >= 8:
        actions.append("Peržiūrėti visus atvirus prievadus ir uždaryti nereikalingas paslaugas.")
    if change_summary.get("is_new_host_since_baseline"):
        actions.append("Patikrinti, ar naujai atsiradęs hostas yra leistinas ir tinkamai dokumentuotas.")
    if change_summary.get("new_ports_since_baseline"):
        actions.append("Patikrinti, ar naujai atsiradę prievadai buvo atidaryti planuotai ir ar jiems reikalingos papildomos taisyklės.")

    return dedupe_preserve_order(actions)[:12]


def build_evidence_summary(host: dict, normalized: dict):
    evidence = []

    if normalized["vulnerabilities"]["has_known_vulns"]:
        evidence.append(
            f"Rasti CVE: {normalized['vulnerabilities']['vuln_count']}, didžiausias CVSS {normalized['vulnerabilities']['highest_cvss']}"
        )

    if normalized["smb"]["smbv1_enabled"]:
        evidence.append("Aptiktas SMBv1")
    if normalized["smb"]["signing_disabled"]:
        evidence.append("SMB signing išjungtas")
    if normalized["smb"]["guest_or_share_auth"]:
        evidence.append("SMB autentifikacija share/guest režimu")
    if normalized["rdp"]["present"]:
        evidence.append("Atviras RDP")
    if normalized["web"]["login_page_detected"]:
        evidence.append("Aptikta web prisijungimo sąsaja")
    if normalized["snmp"]["present"]:
        evidence.append("Aptikta SNMP tarnyba")
    if host.get("change_summary", {}).get("is_new_host_since_baseline"):
        evidence.append("Naujas hostas lyginant su baseline")

    return evidence[:10]


def calculate_priority(host: dict, normalized: dict):
    score = 0

    vulns = normalized["vulnerabilities"]
    smb = normalized["smb"]
    web = normalized["web"]
    tls = normalized["tls"]
    snmp = normalized["snmp"]
    rdp = normalized["rdp"]

    score += min(vulns.get("vuln_count", 0) * 5, 30)
    score += int(vulns.get("highest_cvss", 0) * 5)

    if smb.get("smbv1_enabled"):
        score += 30
    if smb.get("signing_disabled"):
        score += 20
    if smb.get("guest_or_share_auth"):
        score += 25
    if rdp.get("present"):
        score += 25
    if web.get("admin_interface_detected") or web.get("login_page_detected"):
        score += 15
    if tls.get("weak_ciphers_present"):
        score += 15
    if snmp.get("present"):
        score += 10

    if host.get("open_ports_count", 0) >= 8:
        score += 15
    if host.get("change_summary", {}).get("is_new_host_since_baseline"):
        score += 10
    if host.get("change_summary", {}).get("new_ports_since_baseline"):
        score += 10

    if score >= 90:
        level = "kritinė"
    elif score >= 60:
        level = "aukšta"
    elif score >= 30:
        level = "vidutinė"
    else:
        level = "žema"

    return score, level


def build_ai_hosts(hosts_by_ip: dict):
    ai_hosts = []

    for ip in sorted(hosts_by_ip.keys(), key=ip_sort_key):
        host = hosts_by_ip[ip]
        enrich_host_asset_id(host)
        normalized = normalize_host(host)
        host["normalized_security_profile"] = normalized
        host["recommended_actions"] = build_recommended_actions(host, normalized)
        host["evidence_summary"] = build_evidence_summary(host, normalized)
        legacy_score, legacy_level = calculate_priority(host, normalized)
        host["legacy_priority_score"] = legacy_score
        host["legacy_priority_level"] = legacy_level
        host["legacy_priority_note"] = (
            "Senas techninių požymių indeksas. Oficialiam prioritetizavimui naudoti "
            "risk_scores.hosts[*].risk_score 0-100 skalėje, kurį prideda risk_engine.py."
        )

        ai_hosts.append(host)

    return ai_hosts


# -----------------------------
# AI package builders
# -----------------------------
def overall_summary(ai_hosts: list[dict]):
    total_hosts = len(ai_hosts)
    hosts_with_open_ports = sum(1 for h in ai_hosts if h.get("open_ports_count", 0) > 0)
    hosts_with_vulns = sum(1 for h in ai_hosts if h.get("normalized_security_profile", {}).get("vulnerabilities", {}).get("has_known_vulns"))
    hosts_with_rdp = sum(1 for h in ai_hosts if h.get("normalized_security_profile", {}).get("rdp", {}).get("present"))
    hosts_with_legacy_smb = sum(1 for h in ai_hosts if h.get("normalized_security_profile", {}).get("smb", {}).get("smbv1_enabled"))
    hosts_with_web_admin = sum(1 for h in ai_hosts if h.get("normalized_security_profile", {}).get("web", {}).get("login_page_detected") or h.get("normalized_security_profile", {}).get("web", {}).get("admin_interface_detected"))
    hosts_new_since_baseline = sum(1 for h in ai_hosts if h.get("change_summary", {}).get("is_new_host_since_baseline"))

    return {
        "total_hosts": total_hosts,
        "hosts_with_open_ports": hosts_with_open_ports,
        "hosts_with_known_vulns": hosts_with_vulns,
        "hosts_with_rdp": hosts_with_rdp,
        "hosts_with_legacy_smb": hosts_with_legacy_smb,
        "hosts_with_web_admin_interfaces": hosts_with_web_admin,
        "hosts_new_since_baseline": hosts_new_since_baseline,
    }


def legacy_top_priorities(ai_hosts: list[dict]):
    top = []
    for host in sorted(ai_hosts, key=lambda h: h.get("legacy_priority_score", 0), reverse=True)[:10]:
        top.append({
            "ip": host.get("ip"),
            "asset_id": host.get("asset_id"),
            "device_class": host.get("normalized_security_profile", {}).get("device_class"),
            "classification_reasons": host.get("normalized_security_profile", {}).get("classification_reasons", []),
            "legacy_priority_score": host.get("legacy_priority_score"),
            "legacy_priority_level": host.get("legacy_priority_level"),
            "priority_note": host.get("legacy_priority_note"),
            "evidence_summary": host.get("evidence_summary", [])[:5],
            "recommended_actions": host.get("recommended_actions", [])[:5],
        })
    return top


def build_recommendation_payload(network: str, ai_hosts: list[dict], assessment_file: str, source_files: dict):
    payload_hosts = []
    for host in sorted(ai_hosts, key=lambda h: h.get("legacy_priority_score", 0), reverse=True):
        profile = host.get("normalized_security_profile", {})
        payload_hosts.append({
            "ip": host.get("ip"),
            "asset_id": host.get("asset_id"),
            "mac": host.get("mac"),
            "vendor": host.get("vendor"),
            "device_class": profile.get("device_class"),
            "classification_reasons": profile.get("classification_reasons", []),
            "legacy_priority_score": host.get("legacy_priority_score"),
            "legacy_priority_level": host.get("legacy_priority_level"),
            "priority_note": host.get("legacy_priority_note"),
            "tcp_open_ports": profile.get("tcp_open_ports", []),
            "udp_open_ports": profile.get("udp_open_ports", []),
            "service_names": profile.get("service_names", []),
            "smb": profile.get("smb", {}),
            "web": profile.get("web", {}),
            "ssh": {
                "present": profile.get("ssh", {}).get("present"),
                "version": profile.get("ssh", {}).get("version"),
                "weak_algorithms": profile.get("ssh", {}).get("weak_algorithms", []),
            },
            "rdp": profile.get("rdp", {}),
            "tls": profile.get("tls", {}),
            "snmp": profile.get("snmp", {}),
            "known_vulns": profile.get("vulnerabilities", {}),
            "change_summary": host.get("change_summary", {}),
            "risk_flags": host.get("evidence_summary", []),
            "recommended_actions": host.get("recommended_actions", [])[:12],
        })

    return {
        "instruction": (
            "Naudok si detalu technini paketa ir pateik prioritetizuotas tinklo apsaugos rekomendacijas. "
            "Kiekvienam hostui ivardink ka koreguoti, kodel tai svarbu, kokius tinklo filtrus ar segmentavimo taisykles taikyti, "
            "ka atnaujinti, kokias paslaugas riboti, ir pateik prioritetu tvarka: ka atlikti nedelsiant, ka trumpuoju laikotarpiu, "
            "ka ilgesniu laikotarpiu. Atsakymas turi buti praktinis, konkretus ir orientuotas i realius tinklo pakeitimus. "
            "Nesiremk gamintojo pavadinimu kaip sprendimo pagrindu — naudok portus, paslaugas, protokolus, autentifikacijos, sifravimo, "
            "SMB, RDP, web, TLS, SNMP ir pažeidžiamumų požymius."
        ),
        "network": network,
        "assessment_file": assessment_file,
        "source_files": source_files,
        "overall_summary": overall_summary(ai_hosts),
        "legacy_top_priorities": legacy_top_priorities(ai_hosts),
        "official_risk_note": "Galutinį 0-100 rizikos balą į šį AI payload po merge_assessment.py įrašo risk_engine.py lauke risk_scores.",
        "hosts_for_action": payload_hosts,
    }


# -----------------------------
# Main
# -----------------------------
def main():
    paths = get_run_paths()
    network, interface, source_ip = detect_runtime_network()
    timestamp = timestamp_now()

    services_file = latest_optional(paths, "services_dir", "services_*.json")
    if services_file is None:
        services_file = latest_json_by_prefix("services", network=network)

    if services_file is None:
        raise FileNotFoundError("Nerastas services JSON failas. Pirmiausia paleisk service scan grandinę.")

    enrichment_file = latest_optional(paths, "services_dir", "enrichment_*.json")
    udp_file = latest_optional(paths, "services_dir", "udp_*.json")
    vuln_file = latest_optional(paths, "services_dir", "vuln_*.json")
    l2_file = latest_optional(paths, "discovery_dir", "l2_inventory_*.json")
    smb_file = latest_optional(paths, "services_dir", "smb_enrichment_*.json")
    web_file = latest_optional(paths, "services_dir", "web_fingerprint_*.json")
    tls_file = latest_optional(paths, "services_dir", "tls_audit_*.json")
    snmp_file = latest_optional(paths, "services_dir", "snmp_enrichment_*.json")
    discovery_compare_file = latest_optional(paths, "reports_dir", "discovery_compare_*.json")
    services_compare_file = latest_optional(paths, "reports_dir", "services_compare_*.json")

    services_data = load_optional(services_file)
    enrichment_data = load_optional(enrichment_file)
    udp_data = load_optional(udp_file)
    vuln_data = load_optional(vuln_file)
    l2_data = load_optional(l2_file)
    smb_data = load_optional(smb_file)
    web_data = load_optional(web_file)
    tls_data = load_optional(tls_file)
    snmp_data = load_optional(snmp_file)
    discovery_compare = load_optional(discovery_compare_file)
    services_compare = load_optional(services_compare_file)

    hosts_by_ip = {}

    merge_services_hosts(hosts_by_ip, services_data or {})
    merge_structured_results(hosts_by_ip, enrichment_data, "enrichment")
    merge_structured_results(hosts_by_ip, udp_data, "udp")
    merge_structured_results(hosts_by_ip, vuln_data, "vuln")
    merge_l2_inventory(hosts_by_ip, l2_data or {})
    merge_generic_results_by_ip(hosts_by_ip, smb_data or {}, "smb_enrichment")
    merge_generic_results_by_ip(hosts_by_ip, web_data or {}, "web_fingerprint")
    merge_generic_results_by_ip(hosts_by_ip, tls_data or {}, "tls_audit")
    merge_generic_results_by_ip(hosts_by_ip, snmp_data or {}, "snmp_enrichment")
    parse_compare_files(hosts_by_ip, discovery_compare, services_compare)

    ai_hosts = build_ai_hosts(hosts_by_ip)

    source_files = {
        "services": services_file.name if services_file else None,
        "enrichment": enrichment_file.name if enrichment_file else None,
        "udp": udp_file.name if udp_file else None,
        "vuln": vuln_file.name if vuln_file else None,
        "l2_inventory": l2_file.name if l2_file else None,
        "smb_enrichment": smb_file.name if smb_file else None,
        "web_fingerprint": web_file.name if web_file else None,
        "tls_audit": tls_file.name if tls_file else None,
        "snmp_enrichment": snmp_file.name if snmp_file else None,
        "discovery_compare": discovery_compare_file.name if discovery_compare_file else None,
        "services_compare": services_compare_file.name if services_compare_file else None,
    }

    assessment = {
        "timestamp": timestamp,
        "network": network,
        "interface": interface,
        "source_ip": source_ip,
        "source_files": source_files,
        "summary": overall_summary(ai_hosts),
        "hosts": ai_hosts,
    }

    assessment_file = paths["reports_dir"] / f"assessment_{timestamp}.json"
    save_json(assessment_file, assessment)

    ai_input = {
        "timestamp": timestamp,
        "network": network,
        "instruction": (
            "Naudok siuos detalizuotus ir normalizuotus techninius duomenis AI rekomendacijoms, "
            "tinklo apsaugos prioritetu nustatymui, segmentavimo, ugniasienes, paslaugu ribojimo, "
            "atnaujinimu, protokolu konfiguracijos ir monitoringo veiksmu planavimui. "
            "Interpretavimas turi buti universalus ir nesiremti konkretaus gamintojo pavadinimu kaip sprendimo pagrindu."
        ),
        "overall_summary": overall_summary(ai_hosts),
        "hosts": ai_hosts,
        "source_files": source_files,
    }

    ai_input_file = paths["ai_dir"] / f"ai_input_{timestamp}.json"
    save_json(ai_input_file, ai_input)

    ai_payload = build_recommendation_payload(
        network=network,
        ai_hosts=ai_hosts,
        assessment_file=assessment_file.name,
        source_files=source_files,
    )

    ai_payload_file = paths["ai_dir"] / f"ai_recommendation_payload_{timestamp}.json"
    save_json(ai_payload_file, ai_payload)

    print(f"Sukurtas assessment JSON: {assessment_file}")
    print(f"Sukurtas AI įvesties JSON: {ai_input_file}")
    print(f"Sukurtas AI rekomendacijų payload: {ai_payload_file}")
    print(f"Hostų skaičius assessment faile: {len(ai_hosts)}")


if __name__ == "__main__":
    main()
