from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.schemas.reports import FinalReportRequest
from app.services.report_service import render_report

router = APIRouter(
    prefix="/reports",
    tags=["final-reports"],
)


@router.post("/generate")
def generate_report(payload: FinalReportRequest):
    try:
        content, content_type, extension = render_report(payload)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    safe_title = re.sub(r"[^A-Za-z0-9._-]+", "_", payload.title).strip("_")
    safe_title = safe_title or "vulnforge_report"
    filename = f"{safe_title}.{extension}"

    return Response(
        content=content,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
