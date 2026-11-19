
import csv
import json
import re
from pathlib import Path
from datetime import datetime

from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    LongTable,
    TableStyle
)

from config import EXPORT_DIR


# ==========================================================
# VULNEX - REPORT CONFIGURATION
# ==========================================================

NAVY = colors.HexColor("#14243A")
BLUE = colors.HexColor("#2167A5")
LIGHT_BLUE = colors.HexColor("#EAF2FA")
DARK = colors.HexColor("#263445")
MUTED = colors.HexColor("#64748B")
BORDER = colors.HexColor("#D5DEE8")
WHITE = colors.white

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#DC2626"),
    "High": colors.HexColor("#EA580C"),
    "Medium": colors.HexColor("#D97706"),
    "Low": colors.HexColor("#16A34A"),
    "Unknown": MUTED
}


# ==========================================================
# GENERAL HELPERS
# ==========================================================

def _base_name(target):
    safe = "".join(
        c if c.isalnum() or c in "-_." else "_"
        for c in str(target)
    )

    export_folder = Path(EXPORT_DIR)
    export_folder.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return export_folder / f"VULNEX_{safe}_{timestamp}"


def _timestamp():
    return datetime.now().isoformat(timespec="seconds")


def _text(value, default="N/A"):
    if value is None or value == "":
        return default

    return str(value)


def _safe(value, default="N/A"):
    """
    Safely convert values into ReportLab-compatible text.

    Supports both:
        _safe(value)
        _safe(value, "Custom fallback")
    """

    return escape(_text(value, default))


def _severity_counts(cves):
    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0
    }

    for cve in cves:
        severity = str(
            cve.get("severity", "Unknown")
        ).title()

        if severity not in counts:
            severity = "Unknown"

        counts[severity] += 1

    return counts


def _confidence(cve):
    """
    Classify evidence conservatively.

    Product-only and keyword matches are not
    treated as confirmed vulnerabilities.
    """

    match_type = str(
        cve.get("match_type", "")
    ).lower()

    verification = str(
        cve.get("verification", "")
    ).lower()

    explicitly_confirmed = (
        cve.get("confirmed") is True
        or cve.get("verified") is True
        or "confirmed" in verification
    )

    if explicitly_confirmed:
        return "Confirmed Match"

    if (
        "product-only" in match_type
        or "product only" in match_type
    ):
        return "Possible Match"

    if (
        "keyword" in match_type
        or "candidate" in match_type
    ):
        return "Informational"

    return "Unverified Candidate"


def _report_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=27,
        textColor=NAVY,
        alignment=TA_CENTER,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=MUTED,
        alignment=TA_CENTER,
        spaceAfter=16
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=BLUE,
        spaceBefore=12,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=12,
        textColor=DARK,
        spaceAfter=5
    ))

    styles.add(ParagraphStyle(
        name="SmallText",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
        textColor=MUTED
    ))

    styles.add(ParagraphStyle(
        name="TableText",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
        textColor=DARK
    ))

    styles.add(ParagraphStyle(
        name="CVEHeading",
        parent=styles["Heading3"],
        fontSize=10,
        leading=13,
        textColor=NAVY,
        spaceBefore=8,
        spaceAfter=5
    ))

    return styles


def _table_style():
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BLUE]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
    ])


# ==========================================================
# JSON EXPORT
# ==========================================================

def export_json(target, services, cves):

    path = _base_name(target).with_suffix(".json")

    report = {
        "report_title": "VULNEX Vulnerability Assessment Report",
        "generated_at": _timestamp(),
        "target": target,

        "summary": {
            "open_services": len(services),
            "cve_candidates": len(cves),
            "severity_distribution": _severity_counts(cves)
        },

        "services": services,

        "cve_candidates": [
            {
                **cve,
                "confidence": _confidence(cve)
            }
            for cve in cves
        ],

        "important_note": (
            "NVD keyword and product-only matches are candidates, "
            "not confirmed vulnerabilities. Verify the exact product, "
            "version, affected CPE configuration and vendor guidance."
        )
    }

    path.write_text(
        json.dumps(
            report,
            indent=4,
            ensure_ascii=False,
            default=str
        ),
        encoding="utf-8"
    )

    return path


# ==========================================================
# CSV EXPORT
# ==========================================================

def export_csv(target, services, cves):

    path = _base_name(target).with_suffix(".csv")

    columns = [
        "Finding Type",
        "Host",
        "Port",
        "Protocol",
        "Service",
        "Product",
        "Version",
        "CVE ID",
        "Severity",
        "CVSS Score",
        "Priority",
        "Confidence",
        "Match Type",
        "Published",
        "Description",
        "Verification",
        "Remediation",
        "NVD URL"
    ]

    with path.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=columns,
            extrasaction="ignore"
        )

        writer.writeheader()

        # Open services
        for item in services:

            writer.writerow({
                "Finding Type": "Open Service",
                "Host": item.get("host", target),
                "Port": item.get("port"),
                "Protocol": item.get("protocol"),
                "Service": item.get("service"),
                "Product": item.get("product"),
                "Version": item.get("version")
            })

        # CVE candidates
        for item in cves:

            writer.writerow({
                "Finding Type": "CVE Candidate",
                "Host": item.get("host"),
                "Port": item.get("port"),
                "Protocol": item.get("protocol"),
                "Service": item.get("service"),
                "Product": item.get("product"),
                "Version": item.get("version"),
                "CVE ID": item.get("cve_id"),
                "Severity": item.get("severity"),
                "CVSS Score": item.get("score"),
                "Priority": item.get("priority"),
                "Confidence": _confidence(item),
                "Match Type": item.get("match_type"),
                "Published": item.get("published"),
                "Description": item.get("description"),
                "Verification": item.get("verification"),
                "Remediation": item.get("remediation"),
                "NVD URL": item.get("url")
            })

    return path


# ==========================================================
# PDF HEADER AND FOOTER
# ==========================================================

def _draw_page(canvas, doc):

    canvas.saveState()

    width, height = A4

    # Header background
    canvas.setFillColor(NAVY)

    canvas.rect(
        0,
        height - 9 * mm,
        width,
        9 * mm,
        fill=1,
        stroke=0
    )

    # Header text
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 8)

    canvas.drawString(
        18 * mm,
        height - 6 * mm,
        "VULNEX | SECURITY INTELLIGENCE CENTER"
    )

    # Footer separator
    canvas.setStrokeColor(BORDER)

    canvas.line(
        18 * mm,
        15 * mm,
        width - 18 * mm,
        15 * mm
    )

    # Footer text
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7)

    canvas.drawString(
        18 * mm,
        10 * mm,
        "Confidential Security Assessment Report"
    )

    canvas.drawRightString(
        width - 18 * mm,
        10 * mm,
        f"Page {doc.page}"
    )

    canvas.restoreState()


# ==========================================================
# PDF EXPORT
# ==========================================================

def export_pdf(target, services, cves):

    path = _base_name(target).with_suffix(".pdf")

    styles = _report_styles()

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=17 * mm,
        bottomMargin=22 * mm,
        title="VULNEX Vulnerability Assessment Report",
        author="VULNEX - Security Intelligence Center"
    )

    story = []

    generated = _timestamp()
    severity_counts = _severity_counts(cves)

    # ------------------------------------------------------
    # 1. REPORT TITLE
    # ------------------------------------------------------

    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "VULNERABILITY ASSESSMENT REPORT",
        styles["ReportTitle"]
    ))

    story.append(Paragraph(
        "VULNEX | SECURITY INTELLIGENCE CENTER",
        styles["ReportSubtitle"]
    ))

    story.append(Paragraph(
        f"<b>Target:</b> {_safe(target)}",
        styles["ReportBody"]
    ))

    story.append(Paragraph(
        f"<b>Generated:</b> {_safe(generated)}",
        styles["ReportBody"]
    ))

    story.append(Paragraph(
        "<b>Assessment Type:</b> Network Service and CVE Intelligence Scan",
        styles["ReportBody"]
    ))

    # ------------------------------------------------------
    # 2. EXECUTIVE SUMMARY
    # ------------------------------------------------------

    story.append(Paragraph(
        "1. Executive Summary",
        styles["SectionHeading"]
    ))

    summary_rows = [
        ["Assessment Metric", "Result"],
        ["Target", _safe(target)],
        ["Open Services", str(len(services))],
        ["CVE Candidates", str(len(cves))],
        ["Critical Candidates", str(severity_counts["Critical"])],
        ["High Candidates", str(severity_counts["High"])],
        ["Medium Candidates", str(severity_counts["Medium"])],
        ["Low Candidates", str(severity_counts["Low"])]
    ]

    summary_table = Table(
        summary_rows,
        colWidths=[75 * mm, 90 * mm],
        repeatRows=1
    )

    summary_table.setStyle(_table_style())

    story.append(summary_table)

    # ------------------------------------------------------
    # 3. SEVERITY DISTRIBUTION
    # ------------------------------------------------------

    story.append(Paragraph(
        "2. CVE Severity Distribution",
        styles["SectionHeading"]
    ))

    severity_rows = [
        ["Severity", "Candidate Count"]
    ]

    for severity, count in severity_counts.items():
        severity_rows.append([
            severity,
            str(count)
        ])

    severity_table = Table(
        severity_rows,
        colWidths=[75 * mm, 90 * mm],
        repeatRows=1
    )

    severity_table.setStyle(_table_style())

    for index, row in enumerate(severity_rows[1:], start=1):

        severity_table.setStyle(TableStyle([
            (
                "TEXTCOLOR",
                (0, index),
                (0, index),
                SEVERITY_COLORS.get(row[0], MUTED)
            ),
            (
                "FONTNAME",
                (0, index),
                (0, index),
                "Helvetica-Bold"
            )
        ]))

    story.append(severity_table)

    # ------------------------------------------------------
    # 4. DETECTED OPEN SERVICES
    # ------------------------------------------------------

    story.append(Paragraph(
        "3. Detected Open Services",
        styles["SectionHeading"]
    ))

    service_rows = [[
        "Host",
        "Port",
        "Service",
        "Product / Version"
    ]]

    for item in services:

        product_version = " ".join(
            part for part in [
                str(item.get("product") or ""),
                str(item.get("version") or "")
            ]
            if part
        )

        service_rows.append([
            Paragraph(
                _safe(item.get("host", target)),
                styles["TableText"]
            ),
            Paragraph(
                _safe(item.get("port")),
                styles["TableText"]
            ),
            Paragraph(
                _safe(item.get("service")),
                styles["TableText"]
            ),
            Paragraph(
                _safe(product_version),
                styles["TableText"]
            )
        ])

    if len(service_rows) == 1:
        service_rows.append([
            "-",
            "-",
            "No open services found",
            "-"
        ])

    service_table = LongTable(
        service_rows,
        colWidths=[
            43 * mm,
            17 * mm,
            40 * mm,
            65 * mm
        ],
        repeatRows=1
    )

    service_table.setStyle(_table_style())

    story.append(service_table)

    # ------------------------------------------------------
    # 5. NVD CVE INTELLIGENCE
    # ------------------------------------------------------

    story.append(Paragraph(
        "4. NVD CVE Intelligence",
        styles["SectionHeading"]
    ))

    story.append(Paragraph(
        "The following findings were retrieved using NVD search. "
        "A search result does not independently establish that the "
        "detected system is vulnerable.",
        styles["ReportBody"]
    ))

    if not cves:

        story.append(Paragraph(
            "No CVE candidates were retrieved for this scan.",
            styles["ReportBody"]
        ))

    for index, cve in enumerate(cves, start=1):

        cve_id = _safe(cve.get("cve_id"))
        severity = _safe(cve.get("severity"))
        score = _safe(cve.get("score"))

        confidence = _confidence(cve)

        story.append(Paragraph(
            f"{index}. {cve_id}",
            styles["CVEHeading"]
        ))

        details = [
            ["Field", "Value"],
            ["Severity", severity],
            ["CVSS Score", score],
            ["Priority", _safe(cve.get("priority"))],
            ["Confidence", _safe(confidence)],
            ["Host", _safe(cve.get("host"))],
            ["Port", _safe(cve.get("port"))],
            ["Product", _safe(cve.get("product"))],
            ["Version", _safe(cve.get("version"))],
            ["Match Type", _safe(cve.get("match_type"))],
            ["Published", _safe(cve.get("published"))]
        ]

        details_table = Table(
            details,
            colWidths=[42 * mm, 123 * mm]
        )

        details_table.setStyle(_table_style())

        story.append(details_table)
        story.append(Spacer(1, 5))

        # Description
        story.append(Paragraph(
            "<b>Description</b>",
            styles["ReportBody"]
        ))

        description = _safe(
            cve.get("description"),
            "No description available."
        )

        story.append(Paragraph(
            description,
            styles["ReportBody"]
        ))

        # CVSS details
        cvss_details = cve.get("cvss_details") or {}

        if isinstance(cvss_details, dict) and cvss_details:

            story.append(Paragraph(
                "<b>CVSS Technical Details</b>",
                styles["ReportBody"]
            ))

            for key, value in cvss_details.items():

                story.append(Paragraph(
                    f"<b>{_safe(key)}:</b> {_safe(value)}",
                    styles["SmallText"]
                ))

        # Affected CPEs
        affected_cpes = cve.get("affected_cpes") or []

        if affected_cpes:

            story.append(Paragraph(
                "<b>Affected CPE Configurations</b>",
                styles["ReportBody"]
            ))

            for cpe in affected_cpes:

                story.append(Paragraph(
                    _safe(cpe),
                    styles["SmallText"]
                ))

        # Verification
        if cve.get("verification"):

            story.append(Paragraph(
                "<b>Verification Notes</b>",
                styles["ReportBody"]
            ))

            story.append(Paragraph(
                _safe(cve.get("verification")),
                styles["ReportBody"]
            ))

        # Remediation
        if cve.get("remediation"):

            story.append(Paragraph(
                "<b>Recommended Remediation</b>",
                styles["ReportBody"]
            ))

            story.append(Paragraph(
                _safe(cve.get("remediation")),
                styles["ReportBody"]
            ))

        # Official NVD link
        if cve.get("url"):

            url = str(cve["url"])

            if re.match(
                r"^https://nvd\.nist\.gov/vuln/detail/CVE-[A-Za-z0-9-]+$",
                url
            ):

                story.append(Paragraph(
                    f'<link href="{escape(url)}" color="blue">'
                    "Open Official NVD Record</link>",
                    styles["SmallText"]
                ))

        story.append(Spacer(1, 10))

    # ------------------------------------------------------
    # 6. ASSESSMENT NOTES AND LIMITATIONS
    # ------------------------------------------------------

    story.append(Paragraph(
        "5. Assessment Notes and Limitations",
        styles["SectionHeading"]
    ))

    notes = [
        (
            "NVD keyword matches and product-only matches are "
            "candidates, not confirmed vulnerabilities."
        ),

        (
            "A missing product version prevents reliable verification "
            "against affected version ranges."
        ),

        (
            "A detected open port indicates an accessible service "
            "from the scan location; it does not automatically "
            "establish internet exposure or exploitability."
        ),

        (
            "Confirm the affected CPE, exact software version, vendor "
            "security advisories and system configuration before "
            "classifying a finding as confirmed."
        ),

        (
            "CVSS severity and scanner priority are separate indicators. "
            "Scanner priority is not a replacement for a full risk assessment."
        )
    ]

    for note in notes:

        story.append(Paragraph(
            f"&bull; {_safe(note)}",
            styles["ReportBody"]
        ))

    story.append(Spacer(1, 12))

    story.append(Paragraph(
        "Generated by VULNEX | Security Intelligence Center",
        styles["ReportSubtitle"]
    ))

    # ------------------------------------------------------
    # 7. BUILD PDF
    # ------------------------------------------------------

    doc.build(
        story,
        onFirstPage=_draw_page,
        onLaterPages=_draw_page
    )

    return path


# ==========================================================
# END OF VULNEX REPORT GENERATOR
# ==========================================================
