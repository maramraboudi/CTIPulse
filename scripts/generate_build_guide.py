from __future__ import annotations

import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "BUILD_WALKTHROUGH.md"
OUTPUT = ROOT / "docs" / "CTI-Pulse-Build-Walkthrough.pdf"

INK = colors.HexColor("#17232d")
MUTED = colors.HexColor("#53636d")
ACCENT = colors.HexColor("#087e8b")
PALE = colors.HexColor("#edf3f4")
LINE = colors.HexColor("#cfd9dd")


def markup(text: str) -> str:
    text = (
        text.replace("→", "->")
        .replace("–", "-")
        .replace("—", "-")
        .replace("’", "'")
        .replace("“", '"')
        .replace("”", '"')
        .replace("·", "|")
        .replace("•", "-")
        .replace("≥", ">=")
    )
    escaped = html.escape(text, quote=False)
    escaped = re.sub(r"`([^`]+)`", r'<font name="Courier" color="#075d66">\1</font>', escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", escaped)
    escaped = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<link href="\2" color="#087e8b">\1</link>', escaped)
    return escaped


class Figure(Flowable):
    def __init__(self, kind: str, width: float = 172 * mm, height: float = 53 * mm):
        super().__init__()
        self.kind = kind
        self.width = width
        self.height = height

    def _box(self, c, x, y, w, h, title, detail="", fill=colors.white):
        c.setFillColor(fill)
        c.setStrokeColor(LINE)
        c.roundRect(x, y, w, h, 5, fill=1, stroke=1)
        c.setFillColor(INK)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(x + w / 2, y + h - 13, title)
        if detail:
            c.setFillColor(MUTED)
            c.setFont("Helvetica", 6.5)
            for i, line in enumerate(detail.split("\n")):
                c.drawCentredString(x + w / 2, y + h - 24 - (i * 8), line)

    def _arrow(self, c, x1, y1, x2, y2):
        c.setStrokeColor(ACCENT)
        c.setFillColor(ACCENT)
        c.setLineWidth(1)
        c.line(x1, y1, x2, y2)
        angle = __import__("math").atan2(y2 - y1, x2 - x1)
        size = 4
        from math import cos, sin
        p1 = (x2 - size * cos(angle - 0.45), y2 - size * sin(angle - 0.45))
        p2 = (x2 - size * cos(angle + 0.45), y2 - size * sin(angle + 0.45))
        path = c.beginPath()
        path.moveTo(x2, y2)
        path.lineTo(*p1)
        path.lineTo(*p2)
        path.close()
        c.drawPath(path, fill=1, stroke=0)

    def draw(self):
        c = self.canv
        c.saveState()
        if self.kind == "architecture":
            y, h, gap, margin = 47, 48, 9, 4
            w = (self.width - 2 * margin - 3 * gap) / 4
            xs = [margin + i * (w + gap) for i in range(4)]
            labels = [
                ("Public sources", "NVD | KEV\nEPSS | GitHub"),
                ("Collection", "Fetch · normalize\ncorrelate"),
                ("Knowledge base", "SQLite\ncurrent + history"),
                ("Analyst tools", "Dashboard | API\nPDF report"),
            ]
            for x, (title, detail) in zip(xs, labels):
                self._box(c, x, y, w, h, title, detail, PALE if title == "Collection" else colors.white)
            for i in range(3):
                x = xs[i] + w
                self._arrow(c, x + 1, y + h / 2, x + gap - 1, y + h / 2)
        elif self.kind == "data model":
            center = self.width / 2
            self._box(c, center - 55, 96, 110, 39, "CVES", "one row per CVE", PALE)
            children = [
                ("EPSS_HISTORY", "time series"),
                ("POC_REFERENCES", "repository evidence"),
                ("ATTACK_MAPPINGS", "reviewed mappings"),
                ("COLLECTION_RUNS", "run status"),
            ]
            margin, gap = 4, 8
            box_w = (self.width - 2 * margin - 3 * gap) / 4
            for i, (title, detail) in enumerate(children):
                x = margin + i * (box_w + gap)
                self._box(c, x, 13, box_w, 36, title, detail)
                self._arrow(c, center, 96, x + box_w / 2, 51)
        elif self.kind == "scoring":
            segments = [
                ("CVSS / severity", .25, colors.HexColor("#087e8b")),
                ("EPSS / likelihood", .35, colors.HexColor("#236a80")),
                ("CISA KEV", .25, colors.HexColor("#8a6518")),
                ("Public PoC", .15, colors.HexColor("#536d60")),
            ]
            x, total_w, y, h = 8, self.width - 16, 44, 24
            for label, portion, color in segments:
                w = total_w * portion
                c.setFillColor(color)
                c.rect(x, y, w, h, fill=1, stroke=0)
                c.setFillColor(colors.white)
                c.setFont("Helvetica-Bold", 6.5)
                c.drawCentredString(x + w / 2, y + 8, f"{int(portion * 100)}%")
                c.setFillColor(INK)
                c.setFont("Helvetica", 6.7)
                c.drawCentredString(x + w / 2, y - 10, label)
                x += w
            c.setFillColor(MUTED)
            c.setFont("Helvetica-Bold", 8)
            c.drawCentredString(self.width / 2, 12, "Weighted signals -> 0-100 score -> Low / Medium / High / Critical")
        c.restoreState()


class GuideDocTemplate(SimpleDocTemplate):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.section_titles = []

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name == "GuideH1":
            title = flowable.getPlainText()
            key = f"section-{len(self.section_titles) + 1}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(title, key, level=0, closed=False)
            self.section_titles.append(title)


def make_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "CoverTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=26, leading=31, textColor=INK, alignment=TA_LEFT, spaceAfter=12,
        ),
        "subtitle": ParagraphStyle(
            "CoverSubtitle", parent=base["Normal"], fontSize=12, leading=17,
            textColor=MUTED, spaceAfter=18,
        ),
        "h1": ParagraphStyle(
            "GuideH1", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=17, leading=21, textColor=INK, spaceBefore=11, spaceAfter=7,
            keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "GuideH2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=11.5, leading=14, textColor=ACCENT, spaceBefore=8, spaceAfter=4,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "GuideBody", parent=base["BodyText"], fontName="Helvetica",
            fontSize=8.6, leading=12.3, textColor=INK, spaceAfter=5,
        ),
        "bullet": ParagraphStyle(
            "GuideBullet", parent=base["BodyText"], fontName="Helvetica",
            fontSize=8.4, leading=11.8, textColor=INK, leftIndent=12,
            firstLineIndent=-8, spaceAfter=3,
        ),
        "code": ParagraphStyle(
            "GuideCode", parent=base["Code"], fontName="Courier",
            fontSize=7.6, leading=10.4, textColor=INK, backColor=PALE,
            borderColor=LINE, borderWidth=.4, borderPadding=7,
            leftIndent=7, rightIndent=7, spaceBefore=3, spaceAfter=7,
        ),
        "caption": ParagraphStyle(
            "FigureCaption", parent=base["Normal"], fontSize=7.4,
            leading=9, textColor=MUTED, alignment=TA_CENTER, spaceAfter=5,
        ),
    }


def parse_table(lines: list[str], available_width: float):
    rows = []
    for line in lines:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells):
            continue
        rows.append([Paragraph(markup(cell), make_styles()["body"]) for cell in cells])
    if not rows:
        return None
    columns = max(len(row) for row in rows)
    widths = [available_width / columns] * columns
    table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("TEXTCOLOR", (0, 1), (-1, -1), INK),
        ("GRID", (0, 0), (-1, -1), .35, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
    ]))
    return table


def convert_markdown(text: str, styles, width: float):
    lines = text.splitlines()
    story = []
    index = 0
    in_code = False
    code_lines = []

    while index < len(lines):
        raw = lines[index]
        line = raw.strip()
        index += 1
        if line.startswith("```"):
            if not in_code:
                in_code = True
                code_lines = []
            else:
                code = "\n".join(code_lines)
                story.append(Paragraph(html.escape(code).replace("\n", "<br/>"), styles["code"]))
                in_code = False
            continue
        if in_code:
            code_lines.append(raw)
            continue
        if not line:
            continue
        if line.startswith("[FIGURE:") and line.endswith("]"):
            kind = line[len("[FIGURE:"):-1].strip()
            story.append(Figure(kind))
            label = {"architecture": "Figure 1. CTI-Pulse collection-to-analysis flow.",
                     "data model": "Figure 2. Core SQLite record relationships.",
                     "scoring": "Figure 3. Risk model signal weights."}.get(kind, "")
            if label:
                story.append(Paragraph(label, styles["caption"]))
            story.append(Spacer(1, 3))
            continue
        if line.startswith("|"):
            table_lines = [line]
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index].strip())
                index += 1
            table = parse_table(table_lines, width)
            if table:
                story.append(table)
                story.append(Spacer(1, 6))
            continue
        if line.startswith("# "):
            # The cover already carries the document title.
            continue
        if line.startswith("## "):
            story.append(Paragraph(markup(line[3:]), styles["h1"]))
            continue
        if line.startswith("### "):
            story.append(Paragraph(markup(line[4:]), styles["h2"]))
            continue
        if line.startswith(("- ", "* ")):
            story.append(Paragraph("• " + markup(line[2:]), styles["bullet"]))
            continue
        if re.match(r"^\d+\.\s", line):
            text_part = re.sub(r"^\d+\.\s*", "", line)
            story.append(Paragraph("• " + markup(text_part), styles["bullet"]))
            continue
        story.append(Paragraph(markup(line), styles["body"]))

    if in_code and code_lines:
        story.append(Paragraph(html.escape("\n".join(code_lines)).replace("\n", "<br/>"), styles["code"]))
    return story


def draw_page(canvas, doc):
    canvas.saveState()
    page_width, page_height = A4
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(.5)
    canvas.line(18 * mm, 15 * mm, page_width - 18 * mm, 15 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(18 * mm, 10 * mm, "CTI-Pulse | Build walkthrough")
    canvas.drawRightString(page_width - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def main():
    source = SOURCE.read_text(encoding="utf-8")
    styles = make_styles()
    doc = GuideDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=21 * mm,
        title="CTI-Pulse: How the Application Was Built",
        author="CTI-Pulse project",
        subject="Code walkthrough, architecture, development process, and tools",
    )
    story = [
        Spacer(1, 39 * mm),
        Paragraph("CTI-Pulse", styles["title"]),
        Paragraph("How the Application Was Built", styles["title"]),
        Paragraph(
            "A detailed, beginner-friendly guide to the architecture, code, data flow, "
            "development steps, tools, testing, and current limitations.",
            styles["subtitle"],
        ),
        Spacer(1, 8 * mm),
        Figure("architecture", height=63 * mm),
        Paragraph("A compact threat-intelligence pipeline built with Python, SQLite, FastAPI, and ReportLab.", styles["caption"]),
        Spacer(1, 10 * mm),
        Paragraph("<b>Purpose:</b> Understand and confidently present the implementation, not just run it.", styles["body"]),
        Paragraph("<b>Repository:</b> maramraboudi/CTIPulse", styles["body"]),
        Paragraph("<b>Format:</b> PDF generated from the maintained Markdown guide in docs/.", styles["body"]),
        PageBreak(),
    ]
    story.extend(convert_markdown(source, styles, doc.width))
    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    print(OUTPUT)


if __name__ == "__main__":
    main()
