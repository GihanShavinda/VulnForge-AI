from app.schemas.reports import FinalReportRequest, ReportSection
from app.services.report_service import render_csv, render_json


def request(fmt):
    return FinalReportRequest(
        report_type="remediation",
        report_format=fmt,
        title="VulnForge Remediation Report",
        sections=[
            ReportSection(
                heading="Cases",
                narrative="Evidence-backed remediation records.",
                rows=[
                    {
                        "finding": "F1",
                        "status": "Verified",
                        "risk_delta": 42,
                    }
                ],
            )
        ],
    )


def test_json_export():
    content = render_json(request("json")).decode("utf-8")
    assert "VulnForge Remediation Report" in content
    assert '"risk_delta": 42' in content


def test_csv_export():
    content = render_csv(request("csv")).decode("utf-8")
    assert "VulnForge Remediation Report" in content
    assert "risk_delta" in content
