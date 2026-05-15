#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import BASE_DIR, RUNS_DIR, get_run_paths, latest_file_in_dir, load_json, save_json, timestamp_now

CACHE_DIR = Path(os.getenv("THREAT_INTEL_CACHE_DIR", str(BASE_DIR / "cache" / "threat_intel")))
EPSS_CACHE_FILE = CACHE_DIR / "epss_cache.json"
KEV_CACHE_FILE = CACHE_DIR / "cisa_kev_cache.json"
CONFIG_FILE = BASE_DIR / "config" / "epss_kev_config.json"

EPSS_API_BASE = "https://api.first.org/data/v1/epss"
CISA_KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
DEFAULT_TTL_HOURS = int(os.getenv("EPSS_KEV_CACHE_TTL_HOURS", "24"))
HTTP_TIMEOUT = int(os.getenv("EPSS_KEV_HTTP_TIMEOUT", "20"))
OFFLINE = os.getenv("EPSS_KEV_OFFLINE", "0").strip().lower() in {"1", "true", "yes"}


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json_file(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def write_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def http_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "network-thesis-epss-kev/1.0"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        data = resp.read()
    return json.loads(data.decode("utf-8"))


def cache_is_fresh(cache: dict, ttl_hours: int = DEFAULT_TTL_HOURS) -> bool:
    ts = cache.get("fetched_at_epoch")
    try:
        return (time.time() - float(ts)) < ttl_hours * 3600
    except Exception:
        return False


def latest_assessment_file(paths: dict) -> Path | None:
    current = latest_file_in_dir(paths["reports_dir"], "assessment_*.json")
    if current:
        return current
    files = sorted(RUNS_DIR.glob("**/reports/assessment_*.json"))
    return files[-1] if files else None


def latest_ai_payload(paths: dict) -> Path | None:
    files = sorted(paths["ai_dir"].glob("ai_recommendation_payload_*.json"))
    return files[-1] if files else None


def normalize_cve(value: str) -> str:
    m = CVE_RE.search(str(value or ""))
    return m.group(0).upper() if m else ""


def collect_cves_recursive(obj: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(obj, dict):
        for value in obj.values():
            found.update(collect_cves_recursive(value))
    elif isinstance(obj, list):
        for item in obj:
            found.update(collect_cves_recursive(item))
    elif isinstance(obj, str):
        found.update(x.upper() for x in CVE_RE.findall(obj))
    return found


def collect_host_cves(host: dict) -> set[str]:
    profile = host.get("normalized_security_profile") or {}
    vulns = profile.get("vulnerabilities") or profile.get("known_vulns") or {}
    cves: set[str] = set()
    for key in ("all_cves", "cves", "critical_cves", "high_cves", "vulnerabilities"):
        value = vulns.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    for field in ("cve", "id", "cve_id"):
                        c = normalize_cve(item.get(field))
                        if c:
                            cves.add(c)
                    cves.update(collect_cves_recursive(item))
                else:
                    c = normalize_cve(str(item))
                    if c:
                        cves.add(c)
    # Fallback: collect all CVEs from this host object, including NSE outputs.
    cves.update(collect_cves_recursive(host))
    return cves


def fetch_epss_for_cves(cves: list[str]) -> tuple[dict[str, dict], dict]:
    cache = load_json_file(EPSS_CACHE_FILE, {"items": {}, "fetched_at_epoch": 0})
    cached_items = cache.get("items") or {}
    missing = [c for c in cves if c not in cached_items]
    source = "cache"
    errors: list[str] = []

    if missing and not OFFLINE:
        source = "api+cache"
        for i in range(0, len(missing), 100):
            chunk = missing[i:i + 100]
            query = urllib.parse.urlencode({"cve": ",".join(chunk)})
            url = f"{EPSS_API_BASE}?{query}"
            try:
                data = http_json(url)
                for row in data.get("data", []) or []:
                    cve = normalize_cve(row.get("cve"))
                    if not cve:
                        continue
                    epss = row.get("epss")
                    percentile = row.get("percentile")
                    try:
                        epss_f = float(epss)
                    except Exception:
                        epss_f = None
                    try:
                        percentile_f = float(percentile)
                    except Exception:
                        percentile_f = None
                    cached_items[cve] = {
                        "cve": cve,
                        "epss": epss_f,
                        "epss_percentile": percentile_f,
                        "epss_date": row.get("date"),
                        "source": "FIRST EPSS API",
                    }
            except Exception as exc:
                errors.append(f"EPSS API chunk {i // 100 + 1}: {exc}")

        cache = {
            "fetched_at": now_iso(),
            "fetched_at_epoch": time.time(),
            "items": cached_items,
            "last_requested_count": len(cves),
            "errors": errors[-20:],
        }
        write_json_file(EPSS_CACHE_FILE, cache)

    result = {c: cached_items[c] for c in cves if c in cached_items}
    meta = {"source": source if result else "none", "cache_file": str(EPSS_CACHE_FILE), "errors": errors}
    return result, meta


def fetch_kev_catalog() -> tuple[dict[str, dict], dict]:
    cache = load_json_file(KEV_CACHE_FILE, {})
    errors: list[str] = []
    if cache and cache_is_fresh(cache):
        return cache.get("items", {}), {"source": "cache", "cache_file": str(KEV_CACHE_FILE), "errors": []}

    if OFFLINE:
        return cache.get("items", {}) if cache else {}, {"source": "cache_offline", "cache_file": str(KEV_CACHE_FILE), "errors": []}

    for url in CISA_KEV_URLS:
        try:
            data = http_json(url)
            items: dict[str, dict] = {}
            for item in data.get("vulnerabilities", []) or []:
                cve = normalize_cve(item.get("cveID") or item.get("cve"))
                if not cve:
                    continue
                items[cve] = {
                    "cve": cve,
                    "vendor_project": item.get("vendorProject"),
                    "product": item.get("product"),
                    "vulnerability_name": item.get("vulnerabilityName"),
                    "date_added": item.get("dateAdded"),
                    "due_date": item.get("dueDate"),
                    "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
                    "required_action": item.get("requiredAction"),
                    "notes": item.get("notes"),
                    "source": "CISA KEV",
                }
            write_json_file(KEV_CACHE_FILE, {
                "fetched_at": now_iso(),
                "fetched_at_epoch": time.time(),
                "source_url": url,
                "catalog_version": data.get("catalogVersion"),
                "date_released": data.get("dateReleased"),
                "count": len(items),
                "items": items,
            })
            return items, {"source": url, "cache_file": str(KEV_CACHE_FILE), "errors": errors}
        except Exception as exc:
            errors.append(f"{url}: {exc}")

    fallback_items = cache.get("items", {}) if cache else {}
    return fallback_items, {"source": "cache_fallback" if fallback_items else "none", "cache_file": str(KEV_CACHE_FILE), "errors": errors}


def cve_priority_score(cve_item: dict) -> float:
    cvss = cve_item.get("cvss") or cve_item.get("highest_cvss") or 0
    try:
        cvss_f = float(cvss)
    except Exception:
        cvss_f = 0.0
    epss = cve_item.get("epss")
    try:
        epss_f = float(epss or 0)
    except Exception:
        epss_f = 0.0
    # EPSS is stored as 0..1, CVSS 0..10. This is only for sorting CVEs, not host risk R.
    return round((cvss_f * 10 * 0.55) + (epss_f * 100 * 0.30) + (15 if cve_item.get("kev") else 0), 2)


def enrich_vuln_dict(vulns: dict, host_cves: set[str], epss: dict[str, dict], kev: dict[str, dict]) -> dict:
    all_cves = []
    existing_by_cve = {}

    for item in as_list(vulns.get("all_cves")):
        if isinstance(item, dict):
            cve = normalize_cve(item.get("cve") or item.get("id") or json.dumps(item, ensure_ascii=False))
            if cve:
                existing_by_cve[cve] = dict(item, cve=cve)
        else:
            cve = normalize_cve(str(item))
            if cve:
                existing_by_cve[cve] = {"cve": cve}

    for cve in host_cves:
        existing_by_cve.setdefault(cve, {"cve": cve})

    for cve, item in existing_by_cve.items():
        epss_item = epss.get(cve)
        kev_item = kev.get(cve)
        if epss_item:
            item["epss"] = epss_item.get("epss")
            item["epss_score"] = epss_item.get("epss")
            item["epss_percentile"] = epss_item.get("epss_percentile")
            item["epss_date"] = epss_item.get("epss_date")
        if kev_item:
            item["kev"] = True
            item["known_exploited"] = True
            item["cisa_kev"] = kev_item
        else:
            item.setdefault("kev", False)
            item.setdefault("known_exploited", False)
        item["priority_score"] = cve_priority_score(item)
        all_cves.append(item)

    all_cves = sorted(all_cves, key=lambda x: (bool(x.get("kev")), float(x.get("epss") or 0), float(x.get("cvss") or 0)), reverse=True)
    vulns["all_cves"] = all_cves[:100]
    vulns["epss_kev_enriched"] = True
    vulns["epss_available_count"] = sum(1 for x in all_cves if x.get("epss") is not None)
    vulns["kev_count"] = sum(1 for x in all_cves if x.get("kev"))
    vulns["kev_cves"] = [x["cve"] for x in all_cves if x.get("kev")][:25]
    vulns["highest_epss"] = max([float(x.get("epss") or 0) for x in all_cves], default=0)
    vulns["highest_epss_percentile"] = max([float(x.get("epss_percentile") or 0) for x in all_cves], default=0)
    vulns["top_cves_priority"] = [
        {
            "cve": x.get("cve"),
            "cvss": x.get("cvss"),
            "epss": x.get("epss"),
            "epss_percentile": x.get("epss_percentile"),
            "kev": x.get("kev"),
            "priority_score": x.get("priority_score"),
        }
        for x in all_cves[:20]
    ]
    return vulns


def enrich_assessment(assessment: dict, epss: dict[str, dict], kev: dict[str, dict]) -> tuple[dict, dict]:
    host_summaries = []
    cve_hosts = defaultdict(list)

    for host in as_list(assessment.get("hosts")):
        if not isinstance(host, dict):
            continue
        ip = host.get("ip")
        profile = host.setdefault("normalized_security_profile", {})
        vulns = profile.setdefault("vulnerabilities", {})
        host_cves = collect_host_cves(host)
        if not host_cves:
            continue
        for cve in host_cves:
            cve_hosts[cve].append(ip)
        enrich_vuln_dict(vulns, host_cves, epss, kev)
        host_summaries.append({
            "ip": ip,
            "hostname": host.get("hostname"),
            "cve_count": len(host_cves),
            "epss_available_count": vulns.get("epss_available_count"),
            "kev_count": vulns.get("kev_count"),
            "highest_epss": vulns.get("highest_epss"),
            "highest_epss_percentile": vulns.get("highest_epss_percentile"),
            "top_cves_priority": vulns.get("top_cves_priority", [])[:10],
        })

    all_cves = sorted(cve_hosts.keys())
    top_cves = []
    for cve in all_cves:
        epss_item = epss.get(cve, {})
        kev_item = kev.get(cve)
        top_cves.append({
            "cve": cve,
            "hosts": sorted(set(cve_hosts[cve])),
            "epss": epss_item.get("epss"),
            "epss_percentile": epss_item.get("epss_percentile"),
            "epss_date": epss_item.get("epss_date"),
            "kev": bool(kev_item),
            "cisa_kev": kev_item,
        })
    top_cves = sorted(top_cves, key=lambda x: (bool(x.get("kev")), float(x.get("epss") or 0), len(x.get("hosts") or [])), reverse=True)

    summary = {
        "unique_cves": len(all_cves),
        "cves_with_epss": sum(1 for c in all_cves if c in epss),
        "cves_in_cisa_kev": sum(1 for c in all_cves if c in kev),
        "hosts_with_cves": len(host_summaries),
        "top_cves": top_cves[:50],
    }
    return assessment, {"summary": summary, "hosts": host_summaries, "cve_hosts": {k: sorted(set(v)) for k, v in cve_hosts.items()}}


def append_to_ai_payload(paths: dict, report_file: Path, report: dict) -> Path | None:
    ai_file = latest_ai_payload(paths)
    if not ai_file:
        return None
    try:
        payload = load_json(ai_file)
        payload["cve_prioritization"] = {
            "source_file": report_file.name,
            "summary": report.get("summary"),
            "top_cves": report.get("summary", {}).get("top_cves", [])[:25],
            "method": "CVSS from scan data enriched with FIRST EPSS and CISA KEV where available.",
        }
        instruction = payload.get("instruction", "")
        extra = " Naudok cve_prioritization lauką: KEV=true ir aukštas EPSS turi kelti pataisymo prioritetą."
        if isinstance(instruction, str) and "cve_prioritization" not in instruction:
            payload["instruction"] = instruction.rstrip() + extra
        save_json(ai_file, payload)
        return ai_file
    except Exception:
        return None


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    assessment_file = latest_assessment_file(paths)
    if not assessment_file:
        raise FileNotFoundError("Nerastas assessment_*.json. Paleisk merge_assessment.py prieš EPSS/KEV enrichment.")
    assessment = load_json(assessment_file)

    cves = sorted({c for host in as_list(assessment.get("hosts")) if isinstance(host, dict) for c in collect_host_cves(host)})
    epss_data, epss_meta = fetch_epss_for_cves(cves)
    kev_data, kev_meta = fetch_kev_catalog()
    enriched_assessment, enrichment = enrich_assessment(assessment, epss_data, kev_data)

    # Update current assessment in place so risk_engine.py can consume E and K components immediately.
    save_json(assessment_file, enriched_assessment)

    report = {
        "report_type": "epss_kev_enrichment",
        "timestamp": timestamp,
        "assessment_file": assessment_file.name,
        "offline_mode": OFFLINE,
        "sources": {
            "epss": epss_meta,
            "cisa_kev": kev_meta,
        },
        "summary": enrichment["summary"],
        "hosts": enrichment["hosts"],
        "cve_hosts": enrichment["cve_hosts"],
        "notes": [
            "EPSS reikšmės saugomos 0..1 formatu; risk_engine.py jas konvertuoja į 0..100 E komponentą.",
            "KEV požymis įrašomas kaip kev=true ir cisa_kev objektas; risk_engine.py tai naudoja K komponentui.",
        ],
    }
    report_file = paths["reports_dir"] / f"epss_kev_enrichment_{timestamp}.json"
    save_json(report_file, report)
    ai_updated = append_to_ai_payload(paths, report_file, report)

    print(f"EPSS/KEV enrichment ataskaita: {report_file}")
    print(f"Atnaujintas assessment: {assessment_file}")
    print(f"Unikalių CVE: {len(cves)}; EPSS: {report['summary']['cves_with_epss']}; KEV: {report['summary']['cves_in_cisa_kev']}")
    if ai_updated:
        print(f"AI payload papildytas CVE prioritetizavimu: {ai_updated}")


if __name__ == "__main__":
    main()
