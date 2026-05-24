# reporter.py
#
# Generates a professional PDF security report from current findings.
# One click in the dashboard → downloadable PDF you can hand to a CISO.
#
# Uses reportlab — pure Python, no external dependencies beyond pip.
# Layout: cover page, executive summary, findings table, full details per finding.

import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any

OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), "data", "outputs")

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


SEVERITY_RGB = {
    "CRITICAL": colors.HexColor("#E24B4A"),
    "HIGH":     colors.HexColor("#EF9F27"),
    "MEDIUM":   colors.HexColor("#378ADD"),
    "LOW":      colors.HexColor("#1D9E75"),
}


import re as _re
def parse_recommendation(text):
    """Split a recommendation string into individual action items.
    Handles "1. Foo. 2. Bar." and "Foo. Bar." formats correctly so the
    numbers don't render as their own bullet points.
    """
    if not text:
        return []
    text = text.strip()
    if _re.search(r"\d+\.\s+", text):
        parts = _re.split(r"\s*\d+\.\s+", text)
    else:
        parts = text.split(". ")
    return [p.strip().rstrip(".") for p in parts if p.strip()]


def generate_pdf_report(output_path: str = None) -> str:
    """
    Generate a full PDF security report from the latest findings.
    Returns the path to the generated PDF.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab not installed. Run: pip install reportlab")

    # Load data
    findings_file = os.path.join(OUTPUTS_DIR, "final_risk_findings.json")
    if not os.path.exists(findings_file):
        raise FileNotFoundError("No findings data. Run the pipeline first.")

    with open(findings_file) as f:
        data = json.load(f)

    findings = data.get("findings", [])
    summary  = data.get("summary", {})
    scored_at = data.get("scored_at", "")
    try:
        dt = datetime.fromisoformat(scored_at.replace("Z", "+00:00"))
        report_date = dt.strftime("%B %d, %Y %H:%M UTC")
    except Exception:
        report_date = datetime.now(timezone.utc).strftime("%B %d, %Y %H:%M UTC")

    if output_path is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(OUTPUTS_DIR, f"security_report_{ts}.pdf")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    story  = []

    # ── Custom styles ─────────────────────────────────────────────────────────
    title_style = ParagraphStyle("Title", parent=styles["Title"],
                                 fontSize=24, spaceAfter=6, textColor=colors.HexColor("#1a1a2e"))
    h1_style    = ParagraphStyle("H1", parent=styles["Heading1"],
                                 fontSize=14, spaceAfter=4, textColor=colors.HexColor("#1a1a2e"))
    h2_style    = ParagraphStyle("H2", parent=styles["Heading2"],
                                 fontSize=11, spaceAfter=4, textColor=colors.HexColor("#374151"))
    body_style  = ParagraphStyle("Body", parent=styles["Normal"],
                                 fontSize=9, spaceAfter=4, leading=13)
    caption_style = ParagraphStyle("Caption", parent=styles["Normal"],
                                   fontSize=8, textColor=colors.HexColor("#6B7280"), spaceAfter=2)

    # ── Cover / Header ────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("🛡️ CyberFusion", title_style))
    story.append(Paragraph("Threat Intelligence Security Report", styles["Heading2"]))
    story.append(Spacer(1, 0.1 * inch))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#E24B4A")))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph(f"Generated: {report_date}", caption_style))
    story.append(Paragraph("Organization: Northstar Analytics  ·  Scope: northstar-analytics.local  ·  Environment: Lab/Demo", caption_style))
    story.append(Spacer(1, 0.2 * inch))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
    story.append(Spacer(1, 0.1 * inch))

    total = sum(summary.values())
    summary_data = [
        ["Total Findings", str(total)],
        ["🔴 Critical",    str(summary.get("critical", 0))],
        ["🟠 High",        str(summary.get("high", 0))],
        ["🔵 Medium",      str(summary.get("medium", 0))],
        ["🟢 Low",         str(summary.get("low", 0))],
    ]
    summary_table = Table(summary_data, colWidths=[2.5 * inch, 1.5 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F3F4F6")),
        ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ("FONTNAME",   (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.2 * inch))

    # ── Findings Overview Table ───────────────────────────────────────────────
    story.append(Paragraph("Findings Overview", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
    story.append(Spacer(1, 0.1 * inch))

    table_data = [["Rule ID", "Finding", "Risk", "Score", "MITRE Technique"]]
    for f in findings:
        table_data.append([
            f.get("rule_id", ""),
            Paragraph(f.get("rule_name", "")[:50], body_style),
            f.get("risk_label", ""),
            str(f.get("risk_score", 0)),
            Paragraph(f.get("mitre_technique", "—")[:40], body_style),
        ])

    col_widths = [0.8*inch, 2.5*inch, 0.8*inch, 0.6*inch, 2.3*inch]
    overview_table = Table(table_data, colWidths=col_widths, repeatRows=1)

    row_styles = [
        ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
    ]
    # Color severity cells
    for i, f in enumerate(findings, start=1):
        sev_color = SEVERITY_RGB.get(f.get("risk_label", "LOW"), colors.grey)
        row_styles.append(("BACKGROUND", (2, i), (2, i), sev_color))
        row_styles.append(("TEXTCOLOR",  (2, i), (2, i), colors.white))
        row_styles.append(("FONTNAME",   (2, i), (2, i), "Helvetica-Bold"))

    overview_table.setStyle(TableStyle(row_styles))
    story.append(overview_table)
    story.append(PageBreak())

    # ── Detailed Findings ─────────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", h1_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#E24B4A")))
    story.append(Spacer(1, 0.15 * inch))

    for i, f in enumerate(findings, 1):
        risk  = f.get("risk_label", "LOW")
        score = f.get("risk_score", 0)
        color = SEVERITY_RGB.get(risk, colors.grey)

        # Finding header
        header_table = Table(
            [[Paragraph(f"<b>[{f['rule_id']}] {f['rule_name']}</b>", body_style),
              Paragraph(f"<b>{risk}  |  Score: {score}</b>", body_style)]],
            colWidths=[5 * inch, 1.8 * inch]
        )
        header_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#F3F4F6")),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
            ("LINEBELOW",    (0, 0), (-1, -1), 2, color),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 0.05 * inch))

        # Description
        story.append(Paragraph(f.get("description", ""), body_style))
        story.append(Spacer(1, 0.05 * inch))

        # MITRE
        mitre = f.get("mitre_technique", "")
        if mitre:
            story.append(Paragraph(f"<b>MITRE ATT&CK:</b> {f.get('mitre_tactic','')} · {mitre}", caption_style))

        # Affected assets
        assets = f.get("affected_assets", [])
        if assets:
            story.append(Paragraph(f"<b>Affected Assets:</b> {', '.join(assets)}", caption_style))

        # Score breakdown
        breakdown = f.get("score_breakdown", [])
        if breakdown:
            story.append(Paragraph(f"<b>Score Breakdown:</b> {' | '.join(breakdown)}", caption_style))

        # Recommendation — use parse_recommendation so numbered lists render
        # as "1. Force password reset..." not as separate "1" / "Force..." bullets.
        rec_steps = parse_recommendation(f.get("recommendation", ""))
        if rec_steps:
            story.append(Spacer(1, 0.05 * inch))
            story.append(Paragraph("<b>Recommended Actions:</b>", body_style))
            for i_step, step in enumerate(rec_steps, 1):
                story.append(Paragraph(f"{i_step}. {step}", body_style))

        story.append(Spacer(1, 0.15 * inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB")))
        story.append(Spacer(1, 0.1 * inch))

    # ── Footer note ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(
        "This report was generated by CyberFusion CTI Platform. "
        "All scan targets are localhost/lab containers only. "
        "Breach data is synthetic unless a real HaveIBeenPwned API key is configured. "
        "This document is for demonstration and educational purposes.",
        caption_style
    ))

    doc.build(story)
    print(f"[Reporter] PDF report generated → {output_path}")
    return output_path


if __name__ == "__main__":
    path = generate_pdf_report()
    print(f"Report saved to: {path}")
