"""Checkmarx-branded PDF export of the Tenant Recommendations page: a title
page, a severity summary, then every finding grouped by section."""
from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate, CondPageBreak, Frame, KeepTogether, NextPageTemplate, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)

_LOGO = str(Path(__file__).parent / "static" / "img" / "checkmarx-mark.png")

# Same palette as static/css/style.css.
NAVY = colors.HexColor("#140921")
NAVY_LIGHT = colors.HexColor("#241537")
ACCENT = colors.HexColor("#6b34fd")
SECONDARY = colors.HexColor("#a822bf")
TEXT = colors.HexColor("#140921")
MUTED = colors.HexColor("#605a70")
BORDER = colors.HexColor("#e3dff0")
SOFT_BG = colors.HexColor("#f5f4fa")
SEVERITY = {
    "High": (colors.HexColor("#fdecea"), colors.HexColor("#d93025"), colors.HexColor("#a3271b")),
    "Medium": (colors.HexColor("#fff6d1"), colors.HexColor("#e6b800"), colors.HexColor("#7a5c00")),
    "Low": (colors.HexColor("#f0eff2"), colors.HexColor("#9a96a3"), colors.HexColor("#55505f")),
}

PAGE_W, PAGE_H = LETTER
MARGIN = 0.75 * inch
CONTENT_W = PAGE_W - 2 * MARGIN

_STYLES = {
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=NAVY, spaceAfter=8),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=NAVY, spaceBefore=10, spaceAfter=6),
    "rule": ParagraphStyle("rule", fontName="Helvetica-Bold", fontSize=10.5, leading=13.5, textColor=TEXT),
    "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=8.5, leading=11.5, textColor=MUTED),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9, leading=12.5, textColor=TEXT, alignment=TA_LEFT),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=10.5, textColor=TEXT),
    "note": ParagraphStyle("note", fontName="Helvetica", fontSize=8.5, leading=11.5, textColor=MUTED),
    "th": ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=MUTED),
}


def _table(*args, **kwargs) -> Table:
    # Left-aligned (reportlab centers by default) so every piece of a finding
    # lines up on the same severity bar.
    table = Table(*args, **kwargs)
    table.hAlign = "LEFT"
    return table


def _p(text, style="body") -> Paragraph:
    return Paragraph(escape(str(text)), _STYLES[style])


def _fmt(iso: str | None) -> str:
    return iso[:19].replace("T", " ") + " UTC" if iso else "—"


def _chip(level: str) -> Table:
    bg, border, fg = SEVERITY.get(level, SEVERITY["Low"])
    chip = _table(
        [[Paragraph(escape(level), ParagraphStyle("chip", fontName="Helvetica-Bold", fontSize=7.5, leading=9, textColor=fg, alignment=TA_CENTER))]],
        colWidths=[0.62 * inch],
    )
    chip.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.75, border),
        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return chip


def _gradient_band(c, x, y, w, h, steps=60):
    for i in range(steps):
        t = i / (steps - 1)
        c.setFillColor(colors.Color(
            ACCENT.red + (SECONDARY.red - ACCENT.red) * t,
            ACCENT.green + (SECONDARY.green - ACCENT.green) * t,
            ACCENT.blue + (SECONDARY.blue - ACCENT.blue) * t,
        ))
        c.rect(x + w * i / steps, y, w / steps + 0.5, h, stroke=0, fill=1)


def _logo_tile(c, x, y, size):
    c.setFillColor(colors.white)
    c.roundRect(x, y, size, size, size * 0.27, stroke=0, fill=1)
    pad = size * 0.16
    c.drawImage(_LOGO, x + pad, y + pad, size - 2 * pad, size - 2 * pad, mask="auto")


def _title_page(tenant, report, severity_counts):
    def draw(c, doc):
        c.saveState()
        c.setFillColor(NAVY)
        c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
        c.setFillColor(NAVY_LIGHT)
        c.circle(PAGE_W + 0.4 * inch, PAGE_H - 1.2 * inch, 3.4 * inch, stroke=0, fill=1)
        _gradient_band(c, 0, 0, PAGE_W, 0.22 * inch)

        _logo_tile(c, MARGIN, PAGE_H - 1.75 * inch, 0.62 * inch)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 22)
        c.drawString(MARGIN + 0.8 * inch, PAGE_H - 1.5 * inch, "Checkmarx")

        top = PAGE_H * 0.58
        _gradient_band(c, MARGIN, top + 0.62 * inch, 1.1 * inch, 0.06 * inch)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 30)
        c.drawString(MARGIN, top, "Tenant Configuration")
        c.drawString(MARGIN, top - 0.48 * inch, "Recommendations")

        c.setFont("Helvetica", 11)
        c.setFillColor(colors.HexColor("#c9c2dc"))
        c.drawString(MARGIN, top - 1.05 * inch, "TENANT")
        c.setFont("Helvetica-Bold", 20)
        c.setFillColor(colors.white)
        c.drawString(MARGIN, top - 1.4 * inch, tenant)

        c.setFont("Helvetica", 10)
        c.setFillColor(colors.HexColor("#c9c2dc"))
        c.drawString(MARGIN, top - 1.9 * inch, f"Analysis updated: {_fmt(report['ran_at'])}")
        c.drawString(MARGIN, top - 2.12 * inch, f"Report generated: {_fmt(datetime.now(timezone.utc).isoformat())}")

        x = MARGIN
        for level in ("High", "Medium", "Low"):
            bg, border, fg = SEVERITY[level]
            label = f"{severity_counts.get(level, 0)} {level}"
            w = c.stringWidth(label, "Helvetica-Bold", 10) + 0.32 * inch
            c.setFillColor(bg)
            c.setStrokeColor(border)
            c.roundRect(x, top - 2.75 * inch, w, 0.3 * inch, 0.15 * inch, stroke=1, fill=1)
            c.setFillColor(fg)
            c.setFont("Helvetica-Bold", 10)
            c.drawString(x + 0.16 * inch, top - 2.75 * inch + 0.1 * inch, label)
            x += w + 0.12 * inch

        c.setFont("Helvetica", 8.5)
        c.setFillColor(colors.HexColor("#8f88a3"))
        c.drawString(MARGIN, 0.55 * inch, "Generated by the Checkmarx One Tenant Analyzer")
        c.restoreState()
    return draw


def _content_page(tenant):
    def draw(c, doc):
        c.saveState()
        band_h = 0.55 * inch
        c.setFillColor(NAVY)
        c.rect(0, PAGE_H - band_h, PAGE_W, band_h, stroke=0, fill=1)
        _gradient_band(c, 0, PAGE_H - band_h - 0.05 * inch, PAGE_W, 0.05 * inch)
        _logo_tile(c, MARGIN, PAGE_H - band_h + 0.13 * inch, 0.29 * inch)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(MARGIN + 0.4 * inch, PAGE_H - band_h + 0.22 * inch, "Tenant Recommendations")
        c.setFont("Helvetica", 9)
        c.drawRightString(PAGE_W - MARGIN, PAGE_H - band_h + 0.22 * inch, tenant)

        c.setStrokeColor(BORDER)
        c.line(MARGIN, 0.62 * inch, PAGE_W - MARGIN, 0.62 * inch)
        c.setFont("Helvetica", 8)
        c.setFillColor(MUTED)
        c.drawString(MARGIN, 0.42 * inch, "Checkmarx One Tenant Analyzer")
        c.drawRightString(PAGE_W - MARGIN, 0.42 * inch, f"Page {doc.page}")
        c.restoreState()
    return draw


def _summary(groups) -> list:
    rows = [[_p("Section", "th"), _p("High", "th"), _p("Medium", "th"), _p("Low", "th"), _p("Total", "th")]]
    for group in groups:
        counts = {"High": 0, "Medium": 0, "Low": 0}
        for f in group["findings"]:
            counts[f["warning_level"]] = counts.get(f["warning_level"], 0) + 1
        rows.append([_p(group["label"]), _p(counts["High"]), _p(counts["Medium"]), _p(counts["Low"]), _p(sum(counts.values()))])
    table = _table(rows, colWidths=[CONTENT_W - 4 * 0.85 * inch] + [0.85 * inch] * 4, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SOFT_BG),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, BORDER),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return [_p("Summary", "h1"), _p("Rules violated per section, by warning level.", "note"), Spacer(1, 6), table]


_BAR_W = 10  # width of the left column that carries a finding's severity bar


def _affected(instances, bar_color) -> tuple[Table, Table]:
    """(heading, table). The table is top-level -- not nested in another
    table's cell -- so long lists split across pages with the header repeated."""
    heading = _framed([_p(f"Affected ({len(instances)})", "label")], bar_color, top=4)
    first = instances[0] if instances else None
    columns = list(first["fields"]) if isinstance(first, dict) and first.get("fields") else ["Affected"]

    def cells(instance):
        if isinstance(instance, dict) and instance.get("fields"):
            return [str(instance["fields"].get(col, "")) for col in columns]
        return [instance["label"] if isinstance(instance, dict) else str(instance)] + [""] * (len(columns) - 1)

    values = [cells(i) for i in instances]
    # Width follows the longest value in each column (capped), so names and
    # URLs get room while short counts/dates stay narrow.
    weights = [
        min(max([len(col)] + [len(row[n]) for row in values]), 45) + 4
        for n, col in enumerate(columns)
    ]
    inner_w = CONTENT_W - _BAR_W
    widths = [inner_w * w / sum(weights) for w in weights]

    rows = [[""] + [_p(col, "th") for col in columns]]
    rows += [[""] + [_p(v, "small") for v in row] for row in values]
    table = _table(rows, colWidths=[_BAR_W] + widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (1, 0), (-1, 0), SOFT_BG),
        ("LINEBELOW", (1, 0), (-1, -1), 0.4, BORDER),
        ("BOX", (1, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LINEBEFORE", (0, 0), (0, -1), 3, bar_color),
        ("LEFTPADDING", (0, 0), (0, -1), 0), ("LEFTPADDING", (1, 0), (-1, -1), 4),
    ]))
    return heading, table


def _framed(flowables, bar_color, top=0, bottom=0) -> Table:
    """Wrap flowables in a full-width row carrying the finding's severity bar on the left."""
    table = _table([[f] for f in flowables], colWidths=[CONTENT_W])
    table.setStyle(TableStyle([
        ("LINEBEFORE", (0, 0), (0, -1), 3, bar_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("TOPPADDING", (0, 0), (-1, 0), top), ("BOTTOMPADDING", (0, -1), (-1, -1), bottom),
    ]))
    return table


def _finding(finding) -> list:
    level = finding["warning_level"]
    bar = SEVERITY.get(level, SEVERITY["Low"])[1]
    header = _table([[_chip(level), _p(finding["rule_check"], "rule")]], colWidths=[0.75 * inch, CONTENT_W - 1.0 * inch])
    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    details = _table(
        [[_p("Finding", "label"), _p(finding["reasoning"])]]
        + ([[_p("Result", "label"), _p(finding["summary"])]] if finding.get("summary") else [])
        + [[_p("Recommendation", "label"), _p(finding["recommendation"] or "—")]],
        colWidths=[1.15 * inch, CONTENT_W - 1.4 * inch],
    )
    details.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    affected_heading, affected_list = _affected(finding["instances"], bar)
    head = [_framed([header], bar, top=6), _framed([details], bar), affected_heading]
    if len(finding["instances"]) <= 12:
        # Short findings never split across pages.
        return [KeepTogether(head + [affected_list]), Spacer(1, 4)]
    # Long tables split (header row repeats); just make sure the rule and a
    # few of its rows start together rather than stranding the heading.
    return [CondPageBreak(3.5 * inch), KeepTogether(head), affected_list, Spacer(1, 4)]


def build_recommendations_pdf(tenant: str, report: dict, groups: list, severity_counts: dict) -> bytes:
    buffer = io.BytesIO()
    doc = BaseDocTemplate(
        buffer, pagesize=LETTER,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=0.95 * inch, bottomMargin=0.85 * inch,
        title=f"Tenant Recommendations - {tenant}", author="Checkmarx One Tenant Analyzer",
    )
    frame = Frame(MARGIN, 0.85 * inch, CONTENT_W, PAGE_H - 1.8 * inch, id="content")
    doc.addPageTemplates([
        PageTemplate(id="title", frames=[Frame(0, 0, PAGE_W, PAGE_H, id="title")], onPage=_title_page(tenant, report, severity_counts)),
        PageTemplate(id="content", frames=[frame], onPage=_content_page(tenant)),
    ])

    story = [NextPageTemplate("content"), PageBreak()]
    if groups:
        story += _summary(groups)
        for group in groups:
            story.append(PageBreak())
            story.append(_p(group["label"], "h1"))
            for finding in group["findings"]:
                story += _finding(finding)
    else:
        story.append(_p("No Configuration Warnings Detected.", "h2"))
    doc.build(story)
    return buffer.getvalue()
