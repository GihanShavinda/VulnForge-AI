from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.config_assessment import (
    BenchmarkProfile,
    ConfigAssessmentRun,
)
from app.schemas.config_assessment import (
    BenchmarkProfileRead,
    ConfigAssessmentRequest,
    ConfigAssessmentResult,
    ConfigAssessmentRunRead,
    ConfigEvidenceRead,
    ConfigurationFindingRead,
)
from app.services.config_assessment_service import (
    ensure_benchmark_profiles,
    list_evidence,
    list_findings,
    run_assessment,
)
from app.services.config_evidence_parsers import (
    parse_lynis_report,
    parse_openscap_json,
    parse_powershell_json,
    parse_simple_control_lines,
)


router = APIRouter(
    prefix="/config-assessment",
    tags=["configuration-assessment"],
)


# ============================================================
# Benchmark profiles
# ============================================================


@router.get(
    "/profiles",
    response_model=list[BenchmarkProfileRead],
)
def profiles(
    db: Session = Depends(get_db),
):
    """
    Return the V10 benchmark profiles.

    Built-in profiles:

    - Legacy Lab
    - Standard Workstation
    - Linux Server
    - Windows Workstation
    - Web Server
    """

    ensure_benchmark_profiles(db)

    return db.scalars(
        select(BenchmarkProfile).order_by(BenchmarkProfile.name)
    ).all()


# ============================================================
# Configuration assessment
# ============================================================


@router.post(
    "/assess",
    response_model=ConfigAssessmentResult,
    status_code=status.HTTP_201_CREATED,
)
def assess(
    payload: ConfigAssessmentRequest,
    db: Session = Depends(get_db),
):
    """
    Evaluate normalized configuration evidence against one benchmark
    profile using VulnForge deterministic rules.

    This endpoint does not execute remote commands or scanners.
    Evidence must already have been collected from the authorized
    system.
    """

    try:
        run, findings = run_assessment(
            db,
            asset_id=payload.asset_id,
            profile_name=payload.profile_name,
            source_type=payload.source_type,
            source_name=payload.source_name,
            evidence_items=[
                {
                    "control_id": item.control_id,
                    "category": item.category,
                    "observed_value": item.observed_value,
                    "source_locator": item.source_locator,
                    "confidence": item.confidence,
                    "raw": item.raw,
                }
                for item in payload.evidence
            ],
        )

        return ConfigAssessmentResult(
            run=run,
            findings=findings,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


# ============================================================
# Assessment history
# ============================================================


@router.get(
    "/runs",
    response_model=list[ConfigAssessmentRunRead],
)
def runs(
    db: Session = Depends(get_db),
):
    """
    Return configuration assessment history.
    """

    return db.scalars(
        select(ConfigAssessmentRun).order_by(
            ConfigAssessmentRun.imported_at.desc()
        )
    ).all()


# ============================================================
# Assessment findings
# ============================================================


@router.get(
    "/runs/{assessment_id}/findings",
    response_model=list[ConfigurationFindingRead],
)
def findings(
    assessment_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    """
    Return configuration findings for one assessment.
    """

    return list_findings(
        db,
        assessment_id,
    )


# ============================================================
# Assessment evidence
# ============================================================


@router.get(
    "/runs/{assessment_id}/evidence",
    response_model=list[ConfigEvidenceRead],
)
def evidence(
    assessment_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    """
    Return preserved source evidence for one assessment.
    """

    return list_evidence(
        db,
        assessment_id,
    )


# ============================================================
# Lynis evidence parser
# ============================================================


@router.post("/parse/lynis")
def parse_lynis(
    payload: dict[str, Any] = Body(...),
):
    """
    Normalize Lynis report-style key/value evidence.

    Example body:

    {
        "text": "firewall-active=0\\nssh-daemon-status=running"
    }

    The parser preserves source observations and does not
    automatically convert every Lynis recommendation into a
    vulnerability finding.
    """

    text = str(
        payload.get("text") or ""
    )

    return {
        "evidence": parse_lynis_report(text)
    }


# ============================================================
# OpenSCAP evidence parser
# ============================================================


@router.post("/parse/openscap")
def parse_openscap(
    payload: dict[str, Any] = Body(...),
):
    """
    Normalize previously collected OpenSCAP evidence.

    OpenSCAP findings remain source evidence.

    VulnForge does not claim that importing OpenSCAP or
    CIS-aligned concepts represents official CIS certification.
    """

    return {
        "evidence": parse_openscap_json(payload)
    }


# ============================================================
# PowerShell evidence parser
# ============================================================


@router.post("/parse/powershell")
def parse_powershell(
    payload: Any = Body(...),
):
    """
    Normalize JSON evidence produced by the V10 Windows
    PowerShell collector.

    Supported JSON shapes:

    {
        "evidence": [
            {
                "control_id": "windows.smbv1",
                "category": "windows.smb",
                "observed_value": "SMBv1 enabled"
            }
        ]
    }

    or a direct JSON array containing those evidence objects.

    Explicit Body(...) is used so FastAPI always treats this
    endpoint as application/json rather than form/multipart data.
    """

    if not isinstance(
        payload,
        (dict, list),
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "PowerShell evidence must be a JSON object "
                "or JSON array."
            ),
        )

    return {
        "evidence": parse_powershell_json(payload)
    }


# ============================================================
# Simple deterministic evidence parser
# ============================================================


@router.post("/parse/simple-controls")
def parse_simple(
    payload: dict[str, Any] = Body(...),
):
    """
    Parse the simple deterministic V10 evidence format.

    Format:

        control_id<TAB>observed_value

    Example:

        linux.firewall_enabled    disabled
        linux.root_ssh_login      PermitRootLogin yes
    """

    text = str(
        payload.get("text") or ""
    )

    return {
        "evidence": parse_simple_control_lines(text)
    }