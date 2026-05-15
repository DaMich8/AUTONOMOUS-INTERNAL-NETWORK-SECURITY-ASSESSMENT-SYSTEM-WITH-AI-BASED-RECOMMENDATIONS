from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from common import RUNS_DIR, get_run_paths, latest_file_in_dir, load_json, timestamp_now


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def load_optional(path: Path | None) -> dict | None:
    if path and path.exists():
        try:
            return load_json(path)
        except Exception:
            return None
    return None


def latest_current_or_runs(paths: dict, current_pattern: str, recursive_pattern: str) -> Path | None:
    current = latest_file_in_dir(paths["reports_dir"], current_pattern)
    if current:
        return current
    files = sorted(RUNS_DIR.glob(recursive_pattern))
    return files[-1] if files else None


def esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def badge(level: str | None) -> str:
    level = level or "nežinoma"
    cls = {
        "kritinė": "critical",
        "aukšta": "high",
        "vidutinė": "medium",
        "žema": "low",
    }.get(level, "unknown")
    return f'<span class="badge {cls}">{esc(level)}</span>'


def table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["<table>", "<thead><tr>" + "".join(f"<th>{esc(h)}</th>" for h in headers) + "</tr></thead>", "<tbody>"]
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{cell if isinstance(cell, str) and cell.startswith('<') else esc(cell)}</td>" for cell in row) + "</tr>")
    out.append("</tbody></table>")
    return "\n".join(out)


def risk_host_rows(risk_scores: dict | None, limit: int = 10) -> list[list[Any]]:
    rows = []
    items = as_list((risk_scores or {}).get("hosts") or (risk_scores or {}).get("host_scores"))
    items = sorted(items, key=lambda x: x.get("risk_score", 0) if isinstance(x, dict) else 0, reverse=True)
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        comps = item.get("risk_components") or {}
        rows.append([
            item.get("ip"),
            item.get("device_class"),
            item.get("risk_score"),
            badge(item.get("risk_level")),
            ", ".join(f"{k}:{v}" for k, v in comps.items())[:120],
        ])
    return rows


def correlated_rows(correlated: dict | None, limit: int = 20) -> list[list[Any]]:
    rows = []
    for f in as_list((correlated or {}).get("findings"))[:limit]:
        if not isinstance(f, dict):
            continue
        rows.append([
            f.get("ip") or "global",
            f.get("title"),
            badge(f.get("severity")),
            f.get("confidence"),
            "<br>".join(esc(e) for e in as_list(f.get("evidence"))[:4]),
            esc(f.get("recommendation")),
        ])
    return rows


def recommendation_rows(recommendations: dict | None, limit: int = 20) -> list[list[Any]]:
    rows = []
    for r in as_list((recommendations or {}).get("recommendations"))[:limit]:
        if not isinstance(r, dict):
            continue
        rows.append([
            r.get("host") or "global",
            r.get("finding"),
            badge(r.get("risk")),
            "<br>".join(esc(a) for a in as_list(r.get("recommended_actions"))[:4]),
            "<br>".join(esc(v) for v in as_list(r.get("verification"))[:3]),
        ])
    return rows


def asset_rows(assessment: dict | None, limit: int = 50) -> list[list[Any]]:
    rows = []
    for h in as_list((assessment or {}).get("hosts"))[:limit]:
        if not isinstance(h, dict):
            continue
        p = h.get("normalized_security_profile") or {}
        rows.append([
            h.get("ip"),
            h.get("hostname"),
            h.get("vendor"),
            p.get("device_class"),
            len(as_list(p.get("tcp_open_ports"))) if p.get("tcp_open_ports") is not None else h.get("open_ports_count"),
            h.get("legacy_priority_score"),
            badge(h.get("legacy_priority_level")),
        ])
    return rows


def remediation_rows(remediation: dict | None, limit: int = 20) -> list[list[Any]]:
    rows = []
    for item in as_list((remediation or {}).get("finding_status"))[:limit]:
        rows.append([
            item.get("ip") or "global",
            item.get("title"),
            item.get("status"),
            item.get("previous_severity"),
            item.get("current_severity"),
        ])
    return rows


def main() -> None:
    paths = get_run_paths()
    timestamp = timestamp_now()

    assessment_file = latest_current_or_runs(paths, "assessment_*.json", "**/reports/assessment_*.json")
    risk_file = latest_current_or_runs(paths, "risk_scores_*.json", "**/reports/risk_scores_*.json")
    corr_file = latest_current_or_runs(paths, "correlated_findings_*.json", "**/reports/correlated_findings_*.json")
    rec_file = latest_current_or_runs(paths, "ai_recommendations_*.json", "**/reports/ai_recommendations_*.json")
    remediation_file = latest_current_or_runs(paths, "remediation_status_*.json", "**/reports/remediation_status_*.json")
    endpoint_file = latest_current_or_runs(paths, "endpoint_events_*.json", "**/reports/endpoint_events_*.json")
    preflight_file = latest_current_or_runs(paths, "preflight_check_*.json", "**/reports/preflight_check_*.json")

    assessment = load_optional(assessment_file)
    risk_scores = load_optional(risk_file)
    correlated = load_optional(corr_file)
    recommendations = load_optional(rec_file)
    remediation = load_optional(remediation_file)
    endpoint = load_optional(endpoint_file)
    preflight = load_optional(preflight_file)

    summary = (assessment or {}).get("summary", {})
    risk_summary = (risk_scores or {}).get("summary", {})
    corr_summary = (correlated or {}).get("summary", {})
    rec_summary = (recommendations or {}).get("summary", {})
    remediation_summary = (remediation or {}).get("summary", {})
    endpoint_stats = (endpoint or {}).get("stats", {})

    css = """
    body { font-family: Arial, sans-serif; margin: 24px; background: #f6f7f9; color: #1f2937; }
    .container { max-width: 1280px; margin: auto; }
    .card { background: white; border-radius: 14px; padding: 18px; margin: 14px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.06); }
    h1, h2, h3 { margin-top: 0; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #f3f4f6; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
    .metric { background: #f9fafb; padding: 14px; border-radius: 12px; border: 1px solid #e5e7eb; }
    .metric .value { font-size: 28px; font-weight: bold; }
    .badge { padding: 4px 8px; border-radius: 999px; font-weight: bold; font-size: 12px; }
    .critical { background: #fee2e2; color: #991b1b; }
    .high { background: #ffedd5; color: #9a3412; }
    .medium { background: #fef3c7; color: #92400e; }
    .low { background: #dcfce7; color: #166534; }
    .unknown { background: #e5e7eb; color: #374151; }
    .small { color: #6b7280; font-size: 12px; }
    """

    html_doc = f"""<!doctype html>
<html lang="lt">
<head>
<meta charset="utf-8">
<title>Network Thesis saugumo ataskaita {esc(timestamp)}</title>
<style>{css}</style>
</head>
<body><div class="container">
<div class="card">
<h1>Autonominės tinklo saugos įvertinimo ataskaita</h1>
<p class="small">Sugeneruota: {esc(timestamp)}</p>
<p>Ši HTML ataskaita sujungia tinklo skenavimo, endpoint / Windows / ESET logų, rizikos modelio, koreliacijos ir rekomendacijų rezultatus.</p>
</div>

<div class="card">
<h2>Bendra santrauka</h2>
<div class="grid">
<div class="metric"><div>Hostai</div><div class="value">{esc(summary.get('total_hosts') or summary.get('hosts_up') or 0)}</div></div>
<div class="metric"><div>Hostai su atvirais portais</div><div class="value">{esc(summary.get('hosts_with_open_ports') or 0)}</div></div>
<div class="metric"><div>Žinomi pažeidžiamumai</div><div class="value">{esc(summary.get('hosts_with_known_vulns') or 0)}</div></div>
<div class="metric"><div>Koreliuoti radiniai</div><div class="value">{esc(corr_summary.get('total_correlated_findings') or 0)}</div></div>
<div class="metric"><div>Rekomendacijos</div><div class="value">{esc(rec_summary.get('recommendations_count') or 0)}</div></div>
<div class="metric"><div>Endpoint įvykiai</div><div class="value">{esc(endpoint_stats.get('events_in_context') or endpoint_stats.get('normalized_events') or endpoint_stats.get('parsed_lines') or 0)}</div></div>
</div>
</div>

<div class="card">
<h2>Top rizikingiausi hostai pagal konfigūruojamą rizikos formulę</h2>
{table(['IP','Įrenginio klasė','Rizikos balas','Lygis','Komponentai'], risk_host_rows(risk_scores))}
</div>

<div class="card">
<h2>Turto inventorizacija</h2>
{table(['IP','Hostname','Vendor','Klasė','TCP portai','Senas techninis indeksas','Senas indeksas / lygis'], asset_rows(assessment))}
</div>

<div class="card">
<h2>Koreliuoti radiniai</h2>
{table(['IP','Radinys','Rizika','Pasitikėjimas','Įrodymai','Rekomendacija'], correlated_rows(correlated))}
</div>

<div class="card">
<h2>Struktūruotos rekomendacijos</h2>
{table(['Hostas','Problema','Rizika','Veiksmai','Patikrinimas'], recommendation_rows(recommendations))}
</div>

<div class="card">
<h2>Pataisymo verifikacija</h2>
<p class="small">Santrauka: {esc(remediation_summary)}</p>
{table(['IP','Radinys','Statusas','Ankstesnė rizika','Dabartinė rizika'], remediation_rows(remediation))}
</div>

<div class="card">
<h2>Sistemos patikra</h2>
<p>Statusas: {esc((preflight or {}).get('status'))}</p>
<p class="small">Naudoti failai: assessment={esc(assessment_file.name if assessment_file else None)}, risk={esc(risk_file.name if risk_file else None)}, correlations={esc(corr_file.name if corr_file else None)}, recommendations={esc(rec_file.name if rec_file else None)}</p>
</div>

</div></body></html>"""

    out_file = paths["reports_dir"] / f"final_report_{timestamp}.html"
    out_file.write_text(html_doc, encoding="utf-8")

    ai_files = sorted(paths["ai_dir"].glob("ai_recommendation_payload_*.json"))
    if ai_files:
        try:
            ai_file = ai_files[-1]
            ai = load_json(ai_file)
            ai["html_report"] = {"source_file": out_file.name, "path": str(out_file)}
            from common import save_json
            save_json(ai_file, ai)
        except Exception:
            pass

    print(f"HTML ataskaita: {out_file}")


if __name__ == "__main__":
    main()
