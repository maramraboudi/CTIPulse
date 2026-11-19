from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.config import REPORTS_DIR
from app.db import db_cursor


def generate_report(output: Path | None = None) -> Path:
    output = output or REPORTS_DIR / f"cti-pulse-weekly-{datetime.now(timezone.utc).date().isoformat()}.pdf"
    styles = getSampleStyleSheet()
    story = [
        Paragraph("CTI-Pulse Weekly Intelligence Report", styles["Title"]),
        Paragraph(
            f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            styles["Normal"],
        ),
        Spacer(1, 18),
    ]
    with db_cursor() as conn:
        rows = conn.execute(
            "SELECT cve_id,cvss,epss,in_kev,poc_count,risk_score,priority FROM cves ORDER BY risk_score DESC"
        ).fetchall()
        counts = conn.execute(
            "SELECT COUNT(*) total, SUM(in_kev) kev_count FROM cves"
        ).fetchone()

    story.append(Paragraph(
        f"Knowledge base: {counts['total']} CVEs, including {counts['kev_count'] or 0} CISA KEV entries.",
        styles["Heading2"],
    ))
    table_data = [["CVE", "CVSS", "EPSS", "KEV", "PoC", "Risk", "Priority"]]
    for row in rows:
        table_data.append([
            row["cve_id"],
            f"{row['cvss']:.1f}",
            f"{row['epss']:.2f}",
            "Yes" if row["in_kev"] else "No",
            str(row["poc_count"]),
            f"{row['risk_score']:.1f}",
            row["priority"],
        ])
    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#182430")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#edf2f4")]),
    ]))
    story.append(table)
    story.append(Spacer(1, 18))
    story.append(Paragraph(
        "Method note: risk is a transparent analyst heuristic (25% CVSS, 35% EPSS, "
        "25% CISA KEV, 15% public PoC). It is not an official vendor severity score.",
        styles["Normal"],
    ))
    SimpleDocTemplate(str(output), pagesize=A4).build(story)
    return output
