#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

from common import BASE_DIR, get_run_paths, load_json, save_json, timestamp_now

LATEST_DIR = BASE_DIR / "latest"
LATEST_DIR.mkdir(parents=True, exist_ok=True)


def _register_fonts() -> tuple[str, str]:
    """Registers Unicode fonts for Lithuanian characters.

    The font file is referenced from the local OS only and is not bundled with the
    project. If DejaVu is unavailable, ReportLab built-in Helvetica is used as a
    fallback, but Lithuanian glyph coverage may be weaker.
    """
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed.ttf",
            "/usr/local/share/fonts/DejaVuSans.ttf",
        ]
        bold_candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed-Bold.ttf",
            "/usr/local/share/fonts/DejaVuSans-Bold.ttf",
        ]
        regular = next((p for p in candidates if Path(p).exists()), None)
        bold = next((p for p in bold_candidates if Path(p).exists()), None)
        if regular:
            pdfmetrics.registerFont(TTFont("DejaVuSans", regular))
            if bold:
                pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", bold))
                return "DejaVuSans", "DejaVuSans-Bold"
            return "DejaVuSans", "DejaVuSans"
    except Exception:
        pass
    return "Helvetica", "Helvetica-Bold"


def _plain_md_text(markdown_text: str) -> str:
    text = re.sub(r"```[a-zA-Z0-9_-]*\n(.*?)```", lambda m: m.group(1), markdown_text, flags=re.S)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    return text


def _escape(text: object) -> str:
    return html.escape(str(text if text is not None else ""), quote=False)


def _paragraphize_inline(text: str) -> str:
    text = _escape(text)
    text = re.sub(r"`([^`]*)`", r"<font face='Courier'>\1</font>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    return text


def _metadata_lines(metadata: dict | None) -> list[str]:
    metadata = metadata or {}
    keys = [
        ("generated_at", "Sugeneruota"),
        ("status", "Statusas"),
        ("generator", "Generatorius"),
        ("model_used", "Modelis"),
        ("source_input_file", "Įvesties failas"),
        ("source_input_hash", "Įvesties hash"),
        ("output_hash", "Išvesties hash"),
    ]
    lines = []
    for key, label in keys:
        value = metadata.get(key)
        if value:
            lines.append(f"{label}: {value}")
    return lines


def markdown_to_pdf(markdown_text: str, output_pdf: Path, metadata: dict | None = None, title: str | None = None) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, Preformatted

    regular_font, bold_font = _register_fonts()
    output_pdf = Path(output_pdf)
    output_pdf.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_pdf),
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.4 * cm,
        title=title or "Saugumo rekomendacijos",
        author="network-thesis",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="LTTitle",
        parent=styles["Title"],
        fontName=bold_font,
        fontSize=18,
        leading=22,
        alignment=TA_CENTER,
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        name="LTH1",
        parent=styles["Heading1"],
        fontName=bold_font,
        fontSize=14,
        leading=18,
        spaceBefore=14,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="LTH2",
        parent=styles["Heading2"],
        fontName=bold_font,
        fontSize=12,
        leading=15,
        spaceBefore=10,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="LTBody",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=9.2,
        leading=12.5,
        alignment=TA_LEFT,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="LTBullet",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=9.0,
        leading=12,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="LTCode",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7.5,
        leading=9,
        leftIndent=6,
        rightIndent=6,
        spaceBefore=4,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="LTMeta",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#404040"),
    ))

    story = []
    story.append(Paragraph(_escape(title or "Saugumo rekomendacijos"), styles["LTTitle"]))
    meta_lines = _metadata_lines(metadata)
    if meta_lines:
        data = [[Paragraph(_escape(line), styles["LTMeta"])] for line in meta_lines]
        table = Table(data, colWidths=[doc.width])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F2F2F2")),
            ("BOX", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D0D0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
        story.append(Spacer(1, 8))

    in_code = False
    code_lines: list[str] = []
    for raw_line in markdown_text.splitlines():
        line = raw_line.rstrip()
        if line.startswith("```"):
            if not in_code:
                in_code = True
                code_lines = []
            else:
                code_text = "\n".join(code_lines).strip()
                if code_text:
                    story.append(Preformatted(code_text[:6000], styles["LTCode"]))
                in_code = False
            continue
        if in_code:
            code_lines.append(line)
            continue

        stripped = line.strip()
        if not stripped:
            story.append(Spacer(1, 4))
            continue
        if stripped == "---":
            story.append(Spacer(1, 8))
            continue
        if stripped.startswith("# "):
            text = stripped[2:].strip()
            if story:
                story.append(Spacer(1, 4))
            story.append(Paragraph(_paragraphize_inline(text), styles["LTH1"]))
        elif stripped.startswith("## "):
            story.append(Paragraph(_paragraphize_inline(stripped[3:].strip()), styles["LTH1"]))
        elif stripped.startswith("### "):
            story.append(Paragraph(_paragraphize_inline(stripped[4:].strip()), styles["LTH2"]))
        elif stripped.startswith("- ") or stripped.startswith("* "):
            story.append(Paragraph("- " + _paragraphize_inline(stripped[2:].strip()), styles["LTBullet"]))
        else:
            story.append(Paragraph(_paragraphize_inline(stripped), styles["LTBody"]))

    if in_code and code_lines:
        story.append(Preformatted("\n".join(code_lines).strip()[:6000], styles["LTCode"]))

    def _footer(canvas, doc_obj):
        canvas.saveState()
        canvas.setFont(regular_font, 7)
        canvas.setFillColor(colors.HexColor("#606060"))
        canvas.drawRightString(doc_obj.pagesize[0] - doc_obj.rightMargin, 0.75 * cm, f"Puslapis {doc_obj.page}")
        canvas.drawString(doc_obj.leftMargin, 0.75 * cm, "Autonominės tinklo saugos įvertinimo sistemos rekomendacijos")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return output_pdf


def build_pdf_from_latest() -> Path:
    paths = get_run_paths()
    ts = timestamp_now()
    md_path = Path(os.getenv("RECOMMENDATIONS_MD_FILE", str(LATEST_DIR / "llm_recommendations_latest.md")))
    json_path = Path(os.getenv("RECOMMENDATIONS_JSON_FILE", str(LATEST_DIR / "llm_recommendations_latest.json")))
    if not md_path.exists():
        raise FileNotFoundError(f"Nerastas rekomendacijų Markdown failas: {md_path}")
    metadata = {}
    if json_path.exists():
        try:
            metadata = load_json(json_path)
        except Exception:
            metadata = {}
    pdf_path = paths["reports_dir"] / f"recommendations_{ts}.pdf"
    markdown_to_pdf(md_path.read_text(encoding="utf-8"), pdf_path, metadata=metadata, title="Saugumo rekomendacijos")
    latest_pdf = LATEST_DIR / "recommendations_latest.pdf"
    latest_pdf.write_bytes(pdf_path.read_bytes())
    save_json(paths["reports_dir"] / f"recommendations_pdf_summary_{ts}.json", {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_markdown": str(md_path),
        "source_json": str(json_path) if json_path.exists() else None,
        "pdf_path": str(pdf_path),
        "latest_pdf": str(latest_pdf),
        "pdf_size_bytes": pdf_path.stat().st_size,
    })
    print(f"Rekomendacijų PDF: {latest_pdf}", flush=True)
    return latest_pdf


def main() -> None:
    build_pdf_from_latest()


if __name__ == "__main__":
    main()
