from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone


def _payload(request) -> dict:
    return {
        "report_type": request.report_type,
        "title": request.title,
        "generated_for": request.generated_for,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sections": [section.model_dump() for section in request.sections],
    }


def render_json(request) -> bytes:
    return json.dumps(
        _payload(request),
        indent=2,
        sort_keys=True,
        default=str,
    ).encode("utf-8")


def render_csv(request) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["report_type", request.report_type])
    writer.writerow(["title", request.title])
    writer.writerow(["generated_for", request.generated_for])
    writer.writerow([])

    for section in request.sections:
        writer.writerow([section.heading])
        if section.narrative:
            writer.writerow(["narrative", section.narrative])
        if section.rows:
            headers = sorted(
                {
                    key
                    for row in section.rows
                    for key in row.keys()
                }
            )
            writer.writerow(headers)
            for row in section.rows:
                writer.writerow(
                    [
                        json.dumps(row.get(key), default=str)
                        if isinstance(row.get(key), (dict, list))
                        else row.get(key, "")
                        for key in headers
                    ]
                )
        writer.writerow([])

    return output.getvalue().encode("utf-8")


def render_pdf(request) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
        from reportlab.lib import colors
    except ImportError as exc:
        raise RuntimeError(
            "PDF export requires ReportLab. Install with: pip install reportlab"
        ) from exc

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph(request.title, styles["Title"]),
        Paragraph(
            f"Report type: {request.report_type}<br/>"
            f"Environment: {request.generated_for}<br/>"
            f"Generated: {datetime.now(timezone.utc).isoformat()}",
            styles["Normal"],
        ),
        Spacer(1, 8),
    ]

    for section in request.sections:
        story.append(Paragraph(section.heading, styles["Heading2"]))
        if section.narrative:
            story.append(Paragraph(section.narrative, styles["BodyText"]))
            story.append(Spacer(1, 5))

        if section.rows:
            headers = sorted(
                {
                    key
                    for row in section.rows
                    for key in row.keys()
                }
            )
            data = [headers]
            for row in section.rows:
                data.append(
                    [
                        json.dumps(row.get(key), default=str)
                        if isinstance(row.get(key), (dict, list))
                        else str(row.get(key, ""))
                        for key in headers
                    ]
                )
            table = Table(data, repeatRows=1)
            table.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 8))

    doc.build(story)
    return buffer.getvalue()


def render_report(request) -> tuple[bytes, str, str]:
    if request.report_format == "json":
        return render_json(request), "application/json", "json"
    if request.report_format == "csv":
        return render_csv(request), "text/csv; charset=utf-8", "csv"
    return render_pdf(request), "application/pdf", "pdf"
