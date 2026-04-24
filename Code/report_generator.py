"""
report_generator.py

Generates a polished penetration test reconnaissance report as a PDF.
Call generate_report(inventory, output_path) with the inventory dict from main.py.
"""

from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.platypus.flowables import Flowable


# ---------------------------
# Color Palette
# ---------------------------

DARK_BG      = colors.HexColor("#1a1a2e")
ACCENT_BLUE  = colors.HexColor("#0f3460")
ACCENT_CYAN  = colors.HexColor("#16213e")
HIGHLIGHT    = colors.HexColor("#e94560")
TEXT_LIGHT   = colors.HexColor("#f0f0f0")
TEXT_DARK    = colors.HexColor("#1a1a2e")
GRAY_LIGHT   = colors.HexColor("#f5f5f5")
GRAY_MID     = colors.HexColor("#cccccc")
GRAY_DARK    = colors.HexColor("#666666")

RISK_HIGH    = colors.HexColor("#c0392b")
RISK_MED     = colors.HexColor("#e67e22")
RISK_LOW     = colors.HexColor("#27ae60")
RISK_INFO    = colors.HexColor("#2980b9")


def risk_color(score):
    if score is None:
        return GRAY_DARK
    if score >= 7:
        return RISK_HIGH
    if score >= 4:
        return RISK_MED
    return RISK_LOW


def risk_label(score):
    if score is None:
        return "N/A"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


# ---------------------------
# Custom Flowables
# ---------------------------

class ColorBar(Flowable):
    """A solid colored horizontal bar used as a section divider."""
    def __init__(self, width, height=4, color=HIGHLIGHT):
        super().__init__()
        self.bar_width = width
        self.bar_height = height
        self.color = color

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.rect(0, 0, self.bar_width, self.bar_height, fill=1, stroke=0)

    def wrap(self, *args):
        return self.bar_width, self.bar_height


class HeaderBanner(Flowable):
    """Dark banner for the cover page."""
    def __init__(self, width, height=120):
        super().__init__()
        self.banner_width = width
        self.banner_height = height

    def draw(self):
        c = self.canv
        # Background
        c.setFillColor(DARK_BG)
        c.rect(0, 0, self.banner_width, self.banner_height, fill=1, stroke=0)
        # Accent stripe
        c.setFillColor(HIGHLIGHT)
        c.rect(0, self.banner_height - 6, self.banner_width, 6, fill=1, stroke=0)
        # Title text
        c.setFillColor(TEXT_LIGHT)
        c.setFont("Helvetica-Bold", 28)
        c.drawString(40, self.banner_height - 52, "PENETRATION TEST")
        c.setFont("Helvetica-Bold", 28)
        c.drawString(40, self.banner_height - 82, "RECONNAISSANCE REPORT")
        # Subtitle
        c.setFillColor(GRAY_MID)
        c.setFont("Helvetica", 11)
        c.drawString(40, self.banner_height - 106, "Automated Security Assessment")

    def wrap(self, *args):
        return self.banner_width, self.banner_height


# ---------------------------
# Style Setup
# ---------------------------

def build_styles():
    base = getSampleStyleSheet()

    styles = {
        "cover_meta": ParagraphStyle(
            "cover_meta", parent=base["Normal"],
            fontSize=11, textColor=GRAY_DARK, spaceAfter=4
        ),
        "section_heading": ParagraphStyle(
            "section_heading", parent=base["Heading1"],
            fontSize=14, textColor=DARK_BG, spaceBefore=18,
            spaceAfter=6, fontName="Helvetica-Bold"
        ),
        "sub_heading": ParagraphStyle(
            "sub_heading", parent=base["Heading2"],
            fontSize=11, textColor=ACCENT_BLUE, spaceBefore=10,
            spaceAfter=4, fontName="Helvetica-Bold"
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"],
            fontSize=9, textColor=TEXT_DARK, spaceAfter=4, leading=14
        ),
        "body_small": ParagraphStyle(
            "body_small", parent=base["Normal"],
            fontSize=8, textColor=GRAY_DARK, spaceAfter=2, leading=12
        ),
        "code": ParagraphStyle(
            "code", parent=base["Code"],
            fontSize=8, textColor=DARK_BG, backColor=GRAY_LIGHT,
            fontName="Courier", spaceAfter=4, leading=12,
            leftIndent=8, rightIndent=8
        ),
        "risk_high": ParagraphStyle(
            "risk_high", parent=base["Normal"],
            fontSize=9, textColor=RISK_HIGH, fontName="Helvetica-Bold"
        ),
        "risk_med": ParagraphStyle(
            "risk_med", parent=base["Normal"],
            fontSize=9, textColor=RISK_MED, fontName="Helvetica-Bold"
        ),
        "risk_low": ParagraphStyle(
            "risk_low", parent=base["Normal"],
            fontSize=9, textColor=RISK_LOW, fontName="Helvetica-Bold"
        ),
        "table_header": ParagraphStyle(
            "table_header", parent=base["Normal"],
            fontSize=9, textColor=TEXT_LIGHT, fontName="Helvetica-Bold"
        ),
        "table_cell": ParagraphStyle(
            "table_cell", parent=base["Normal"],
            fontSize=8, textColor=TEXT_DARK, leading=12
        ),
        "footer_style": ParagraphStyle(
            "footer_style", parent=base["Normal"],
            fontSize=8, textColor=GRAY_DARK, alignment=TA_CENTER
        ),
    }
    return styles


# ---------------------------
# Page Template
# ---------------------------

def make_page_template(canvas, doc):
    """Header/footer on every page except cover."""
    canvas.saveState()
    w, h = letter

    if doc.page > 1:
        # Top bar
        canvas.setFillColor(DARK_BG)
        canvas.rect(0, h - 28, w, 28, fill=1, stroke=0)
        canvas.setFillColor(HIGHLIGHT)
        canvas.rect(0, h - 31, w, 3, fill=1, stroke=0)

        canvas.setFillColor(TEXT_LIGHT)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(40, h - 19, "PENETRATION TEST RECON REPORT")
        canvas.setFont("Helvetica", 9)
        canvas.drawRightString(w - 40, h - 19,
            datetime.now().strftime("%Y-%m-%d"))

        # Bottom bar
        canvas.setFillColor(GRAY_LIGHT)
        canvas.rect(0, 0, w, 24, fill=1, stroke=0)
        canvas.setFillColor(GRAY_DARK)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(40, 8, "CONFIDENTIAL — Authorized Use Only")
        canvas.drawRightString(w - 40, 8, f"Page {doc.page}")

    canvas.restoreState()


# ---------------------------
# Section Builders
# ---------------------------

def build_cover(styles, inventory: Dict[str, Any], story: list):
    w = letter[0] - 80  # approx usable width

    story.append(HeaderBanner(w + 40))
    story.append(Spacer(1, 24))

    targets = inventory.get("targets", [])
    scan_date = datetime.now().strftime("%B %d, %Y %H:%M")
    services = inventory.get("services", [])
    host_scores = inventory.get("host_risk_score", {}) or {}

    meta = [
        ("Scan Date", scan_date),
        ("Targets", ", ".join(str(t) for t in targets) if targets else "N/A"),
        ("Total Services Found", str(len(services))),
        ("Hosts Scanned", str(len(host_scores)) if host_scores else str(len(targets))),
        ("Classification", "CONFIDENTIAL"),
    ]

    for label, value in meta:
        row = Table(
            [[Paragraph(f"<b>{label}:</b>", styles["cover_meta"]),
              Paragraph(value, styles["cover_meta"])]],
            colWidths=[2 * inch, 4 * inch]
        )
        row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(row)

    story.append(Spacer(1, 16))
    story.append(ColorBar(w + 40, color=GRAY_MID))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "This report contains the results of an automated reconnaissance scan. "
        "All findings are intended for authorized security assessment purposes only. "
        "Unauthorized use or distribution of this document is strictly prohibited.",
        styles["body_small"]
    ))
    story.append(PageBreak())


def build_executive_summary(styles, inventory: Dict[str, Any], story: list):
    services = inventory.get("services", [])
    host_scores = inventory.get("host_risk_score", {}) or {}
    targets = inventory.get("targets", [])

    high = sum(1 for s in services if isinstance(s.get("risk_score"), (int, float)) and s["risk_score"] >= 7)
    med  = sum(1 for s in services if isinstance(s.get("risk_score"), (int, float)) and 4 <= s["risk_score"] < 7)
    low  = sum(1 for s in services if isinstance(s.get("risk_score"), (int, float)) and s["risk_score"] < 4)

    avg_host_risk = (sum(host_scores.values()) / len(host_scores)) if host_scores else 0.0
    max_host = max(host_scores.items(), key=lambda kv: kv[1]) if host_scores else None

    story.append(Paragraph("Executive Summary", styles["section_heading"]))
    story.append(ColorBar(letter[0] - 80))
    story.append(Spacer(1, 8))

    summary_text = (
        f"A reconnaissance scan was performed against <b>{len(targets)}</b> target(s), "
        f"discovering <b>{len(services)}</b> active service(s) across "
        f"<b>{len(host_scores) or len(targets)}</b> host(s). "
        f"Risk scoring identified <b>{high}</b> high-risk, <b>{med}</b> medium-risk, "
        f"and <b>{low}</b> low-risk services. "
    )
    if max_host:
        summary_text += (
            f"The highest-risk host was <b>{max_host[0]}</b> with a risk score of "
            f"<b>{max_host[1]:.1f}/10</b>. "
        )
    summary_text += (
        "Immediate attention is recommended for any services rated HIGH risk. "
        "Detailed findings are provided in subsequent sections of this report."
    )

    story.append(Paragraph(summary_text, styles["body"]))
    story.append(Spacer(1, 14))

    # Risk summary table
    risk_data = [
        [Paragraph("Risk Level", styles["table_header"]),
         Paragraph("Count", styles["table_header"]),
         Paragraph("Action Required", styles["table_header"])],
        [Paragraph("HIGH", styles["risk_high"]),
         Paragraph(str(high), styles["body"]),
         Paragraph("Immediate remediation recommended", styles["body"])],
        [Paragraph("MEDIUM", styles["risk_med"]),
         Paragraph(str(med), styles["body"]),
         Paragraph("Review and remediate within 30 days", styles["body"])],
        [Paragraph("LOW", styles["risk_low"]),
         Paragraph(str(low), styles["body"]),
         Paragraph("Monitor and review periodically", styles["body"])],
    ]

    t = Table(risk_data, colWidths=[1.5 * inch, 1 * inch, 4 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#fdecea")),
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#fff4e5")),
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#eafaf1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [None]),
        ("BOX", (0, 0), (-1, -1), 0.5, GRAY_MID),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, GRAY_MID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))


def build_host_risk(styles, inventory: Dict[str, Any], story: list):
    host_scores = inventory.get("host_risk_score", {}) or {}
    host_reasons = inventory.get("host_risk_reasons", {}) or {}

    if not host_scores:
        return

    story.append(Paragraph("Host Risk Assessment", styles["section_heading"]))
    story.append(ColorBar(letter[0] - 80))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Each target host was assigned a risk score from 0–10 based on the number and "
        "severity of exposed services, known risky ports, and service fingerprinting results.",
        styles["body"]
    ))
    story.append(Spacer(1, 10))

    header = [
        Paragraph("Host", styles["table_header"]),
        Paragraph("Risk Score", styles["table_header"]),
        Paragraph("Level", styles["table_header"]),
        Paragraph("Key Risk Factors", styles["table_header"]),
    ]
    rows = [header]

    for host, score in sorted(host_scores.items(), key=lambda kv: kv[1], reverse=True):
        reasons = host_reasons.get(host, [])
        reason_text = "; ".join(reasons[:3]) if reasons else "—"
        rc = risk_color(score)
        level = risk_label(score)

        rows.append([
            Paragraph(host, styles["table_cell"]),
            Paragraph(f"{score:.1f} / 10", ParagraphStyle(
                "rs", parent=styles["table_cell"], textColor=rc, fontName="Helvetica-Bold"
            )),
            Paragraph(level, ParagraphStyle(
                "rl", parent=styles["table_cell"], textColor=rc, fontName="Helvetica-Bold"
            )),
            Paragraph(reason_text, styles["table_cell"]),
        ])

    col_widths = [1.8 * inch, 1.1 * inch, 0.9 * inch, 3.6 * inch]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GRAY_LIGHT]),
        ("BOX", (0, 0), (-1, -1), 0.5, GRAY_MID),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, GRAY_MID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))


def build_services_table(styles, inventory: Dict[str, Any], story: list):
    services = inventory.get("services", [])
    if not services:
        return

    story.append(Paragraph("Discovered Services", styles["section_heading"]))
    story.append(ColorBar(letter[0] - 80))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"The following {len(services)} service(s) were identified during the reconnaissance scan. "
        "Services are sorted by risk score (highest first).",
        styles["body"]
    ))
    story.append(Spacer(1, 10))

    def svc_sort_key(s):
        rs = s.get("risk_score")
        return (-(rs if isinstance(rs, (int, float)) else -1), s.get("host", ""), s.get("port", 0))

    header = [
        Paragraph("Host", styles["table_header"]),
        Paragraph("Port/Proto", styles["table_header"]),
        Paragraph("Service", styles["table_header"]),
        Paragraph("Version", styles["table_header"]),
        Paragraph("Risk", styles["table_header"]),
        Paragraph("TLS", styles["table_header"]),
    ]
    rows = [header]

    for svc in sorted(services, key=svc_sort_key):
        host    = svc.get("host", "")
        port    = svc.get("port", "")
        proto   = svc.get("protocol", "tcp")
        name    = svc.get("name") or "—"
        version = svc.get("version") or "—"
        risk    = svc.get("risk_score")
        tls_ver = svc.get("tls_version") or "—"

        rc = risk_color(risk)
        risk_str = f"{risk:.1f}" if isinstance(risk, (int, float)) else "N/A"

        rows.append([
            Paragraph(host, styles["table_cell"]),
            Paragraph(f"{port}/{proto}", styles["table_cell"]),
            Paragraph(name, styles["table_cell"]),
            Paragraph(str(version)[:30], styles["table_cell"]),
            Paragraph(risk_str, ParagraphStyle(
                "rsk", parent=styles["table_cell"], textColor=rc, fontName="Helvetica-Bold"
            )),
            Paragraph(tls_ver, styles["table_cell"]),
        ])

    col_widths = [1.6 * inch, 0.9 * inch, 1.0 * inch, 1.8 * inch, 0.6 * inch, 1.5 * inch]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GRAY_LIGHT]),
        ("BOX", (0, 0), (-1, -1), 0.5, GRAY_MID),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, GRAY_MID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))


def build_target_enrichment(styles, inventory: Dict[str, Any], story: list):
    target_info = inventory.get("target_info", [])
    if not target_info:
        return

    story.append(Paragraph("Target Enrichment", styles["section_heading"]))
    story.append(ColorBar(letter[0] - 80))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "DNS resolution, reverse DNS, and HTTP/HTTPS probing results for each target.",
        styles["body"]
    ))
    story.append(Spacer(1, 10))

    for t_info in target_info:
        tgt    = t_info.get("target", "")
        ips    = t_info.get("resolved_ips") or []
        ptr    = t_info.get("reverse_dns") or "—"
        http   = t_info.get("http_status") or "—"
        https  = t_info.get("https_status") or "—"
        title  = t_info.get("http_title") or t_info.get("https_title") or "—"
        server = t_info.get("http_server") or t_info.get("https_server") or "—"

        block = [
            [Paragraph(f"Target: {tgt}", ParagraphStyle(
                "th", parent=styles["sub_heading"], fontSize=10
            ))],
        ]
        detail_rows = [
            ("Resolved IPs",  ", ".join(ips) if ips else "—"),
            ("Reverse DNS",   ptr),
            ("HTTP Status",   str(http)),
            ("HTTPS Status",  str(https)),
            ("Page Title",    title),
            ("Server",        server),
        ]
        for label, value in detail_rows:
            block.append([
                Table([[
                    Paragraph(f"<b>{label}:</b>", styles["body_small"]),
                    Paragraph(str(value)[:80], styles["body_small"]),
                ]], colWidths=[1.4 * inch, 5 * inch],
                style=[("LEFTPADDING", (0,0),(-1,-1), 0),
                       ("RIGHTPADDING", (0,0),(-1,-1), 0),
                       ("TOPPADDING", (0,0),(-1,-1), 1),
                       ("BOTTOMPADDING", (0,0),(-1,-1), 1)])
            ])

        card = Table(block, colWidths=[letter[0] - 80])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT_CYAN),
            ("BACKGROUND", (0, 1), (-1, -1), GRAY_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.5, GRAY_MID),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether(card))
        story.append(Spacer(1, 8))


def build_service_detail(styles, inventory: Dict[str, Any], story: list):
    services = inventory.get("services", [])
    if not services:
        return

    def svc_sort_key(s):
        rs = s.get("risk_score")
        return (-(rs if isinstance(rs, (int, float)) else -1), s.get("host", ""), s.get("port", 0))

    high_risk = [s for s in services
                 if isinstance(s.get("risk_score"), (int, float)) and s["risk_score"] >= 4]

    if not high_risk:
        return

    story.append(Paragraph("High & Medium Risk Service Details", styles["section_heading"]))
    story.append(ColorBar(letter[0] - 80))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Detailed breakdown of services rated MEDIUM or HIGH risk, including banners, "
        "TLS details, and HTTP surface information where available.",
        styles["body"]
    ))
    story.append(Spacer(1, 10))

    for svc in sorted(high_risk, key=svc_sort_key):
        host    = svc.get("host", "")
        port    = svc.get("port", "")
        name    = svc.get("name") or "unknown"
        version = svc.get("version") or "—"
        risk    = svc.get("risk_score")
        reasons = svc.get("risk_reasons") or []
        banner  = svc.get("banner") or "—"

        rc = risk_color(risk)
        risk_str = f"{risk:.1f}/10 ({risk_label(risk)})" if isinstance(risk, (int, float)) else "N/A"

        hex_color = "#" + rc.hexval().replace("0x", "").replace("0X", "")
        title_para = Paragraph(
            f'<font color="{hex_color}"><b>{host}:{port}</b></font>'
            f'  -  {name} {version}  |  Risk: {risk_str}',
            styles["sub_heading"]
        )

        fields = [
            ("Banner",        str(banner)[:120]),
            ("TLS Version",   svc.get("tls_version") or "—"),
            ("TLS Cipher",    svc.get("tls_cipher") or "—"),
            ("Cert Subject",  svc.get("tls_cert_subject") or "—"),
            ("HTTP Status",   str(svc.get("http_status") or svc.get("https_status") or "—")),
            ("Page Title",    svc.get("http_title") or svc.get("https_title") or "—"),
            ("Server",        svc.get("http_server") or svc.get("https_server") or "—"),
            ("Risk Reasons",  "; ".join(reasons[:5]) if reasons else "—"),
        ]

        detail_rows = [[title_para]]
        for label, value in fields:
            if value and value != "—":
                detail_rows.append([
                    Table([[
                        Paragraph(f"<b>{label}:</b>", styles["body_small"]),
                        Paragraph(str(value)[:100], styles["body_small"]),
                    ]], colWidths=[1.3 * inch, 5.1 * inch],
                    style=[("LEFTPADDING", (0,0),(-1,-1), 0),
                           ("TOPPADDING", (0,0),(-1,-1), 1),
                           ("BOTTOMPADDING", (0,0),(-1,-1), 1)])
                ])

        card = Table(detail_rows, colWidths=[letter[0] - 80])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.75, rc),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether(card))
        story.append(Spacer(1, 8))


def build_recommendations(styles, story: list):
    story.append(Paragraph("General Recommendations", styles["section_heading"]))
    story.append(ColorBar(letter[0] - 80))
    story.append(Spacer(1, 8))

    recs = [
        ("Disable Unnecessary Services",
         "Any service not required for business operations should be disabled. "
         "Each open port increases the attack surface."),
        ("Apply Latest Security Patches",
         "Ensure all identified service versions are up-to-date. "
         "Outdated versions frequently contain publicly known vulnerabilities."),
        ("Enforce Strong Authentication",
         "All exposed services should require strong credentials. "
         "Disable anonymous or default credentials immediately."),
        ("Implement Network Segmentation",
         "Restrict access to sensitive services using firewalls and VLANs. "
         "Services such as databases and admin panels should not be publicly accessible."),
        ("Enable TLS on All Services",
         "Plaintext protocols (FTP, Telnet, HTTP) should be replaced or wrapped with TLS. "
         "Ensure TLS 1.2+ is enforced and legacy versions are disabled."),
        ("Monitor and Alert",
         "Deploy logging and alerting on all exposed services. "
         "Anomalous access patterns should trigger immediate investigation."),
    ]

    for i, (title, body) in enumerate(recs):
        bg = GRAY_LIGHT if i % 2 == 0 else colors.white
        block = Table([
            [Paragraph(f"{i+1}. {title}", styles["sub_heading"])],
            [Paragraph(body, styles["body"])],
        ], colWidths=[letter[0] - 80])
        block.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 0.25, GRAY_MID),
        ]))
        story.append(block)
        story.append(Spacer(1, 4))


# ---------------------------
# Main Entry Point
# ---------------------------

def generate_report(inventory: Dict[str, Any], output_path: str = "recon_report.pdf") -> str:
    """
    Generate a polished PDF recon report.

    Args:
        inventory: The inventory dict returned by run_recon() in main.py
        output_path: Where to save the PDF

    Returns:
        The output path on success.
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.45 * inch,
        title="Penetration Test Recon Report",
        author="Recon Scanner",
        subject="Automated Security Assessment",
    )

    styles = build_styles()
    story = []

    build_cover(styles, inventory, story)
    build_executive_summary(styles, inventory, story)
    story.append(Spacer(1, 10))
    build_host_risk(styles, inventory, story)
    story.append(Spacer(1, 10))
    build_services_table(styles, inventory, story)
    story.append(PageBreak())
    build_target_enrichment(styles, inventory, story)
    build_service_detail(styles, inventory, story)
    story.append(PageBreak())
    build_recommendations(styles, story)

    doc.build(story, onFirstPage=make_page_template, onLaterPages=make_page_template)
    return output_path


# ---------------------------
# Quick test with dummy data
# ---------------------------

if __name__ == "__main__":
    dummy_inventory = {
        "targets": ["45.33.32.156"],
        "target_info": [{
            "target": "45.33.32.156",
            "resolved_ips": ["45.33.32.156"],
            "reverse_dns": "scanme.nmap.org",
            "is_private_or_loopback": False,
            "http_status": 200,
            "http_server": "Apache/2.4.7",
            "http_title": "Go ahead and ScanMe!",
            "https_status": None,
            "https_server": None,
            "https_title": None,
        }],
        "services": [
            {"host": "45.33.32.156", "port": 22, "protocol": "tcp",
             "name": "ssh", "version": "OpenSSH 6.6.1p1",
             "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
             "risk_score": 5.5, "risk_reasons": ["Outdated OpenSSH version", "Public exposure"],
             "tls_version": None, "tls_cipher": None,
             "http_status": None, "http_title": None, "http_server": None,
             "https_status": None, "https_title": None, "https_server": None},
            {"host": "45.33.32.156", "port": 80, "protocol": "tcp",
             "name": "http", "version": "Apache httpd 2.4.7",
             "banner": None,
             "risk_score": 4.0, "risk_reasons": ["Plaintext HTTP", "Outdated Apache"],
             "tls_version": None, "tls_cipher": None,
             "http_status": 200, "http_title": "Go ahead and ScanMe!",
             "http_server": "Apache/2.4.7",
             "https_status": None, "https_title": None, "https_server": None},
            {"host": "45.33.32.156", "port": 21, "protocol": "tcp",
             "name": "ftp", "version": "vsftpd 2.3.4",
             "banner": "220 (vsFTPd 2.3.4)",
             "risk_score": 9.0, "risk_reasons": ["Known backdoor CVE-2011-2523", "Plaintext protocol", "World accessible"],
             "tls_version": None, "tls_cipher": None,
             "http_status": None, "http_title": None, "http_server": None,
             "https_status": None, "https_title": None, "https_server": None},
        ],
        "host_risk_score": {"45.33.32.156": 8.2},
        "host_risk_reasons": {"45.33.32.156": [
            "vsftpd 2.3.4 backdoor detected", "SSH exposed publicly", "HTTP running outdated Apache"
        ]},
    }

    path = generate_report(dummy_inventory, "recon_report.pdf")
    print(f"Report saved to {path}")
