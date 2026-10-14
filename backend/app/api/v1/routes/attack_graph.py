from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.attack_graph import (
    AttackGraphSyncRequest,
    AttackGraphSyncRunRead,
    AttackPathEvidenceRead,
    AttackPathRecordRead,
    AttackPathRequest,
)
from app.services.attack_graph_service import (
    calculate_paths,
    list_path_evidence,
    list_paths,
    list_sync_runs,
    sync_graph,
)

router = APIRouter(
    prefix="/attack-graph",
    tags=["neo4j-attack-graph"],
)


@router.post(
    "/sync",
    response_model=AttackGraphSyncRunRead,
    status_code=status.HTTP_201_CREATED,
)
def sync(
    payload: AttackGraphSyncRequest,
    db: Session = Depends(get_db),
):
    try:
        return sync_graph(
            db,
            scenario=payload.scenario,
            nodes=payload.nodes,
            edges=payload.edges,
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


@router.post(
    "/runs/{sync_run_id}/paths",
    response_model=list[AttackPathRecordRead],
)
def paths(
    sync_run_id: uuid.UUID,
    payload: AttackPathRequest,
    db: Session = Depends(get_db),
):
    try:
        return calculate_paths(
            db,
            sync_run_id=sync_run_id,
            scenario=payload.scenario,
            start_node_key=payload.start_node_key,
            destination_node_key=payload.destination_node_key,
            max_depth=payload.max_depth,
            only_high_value_destinations=payload.only_high_value_destinations,
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


@router.get(
    "/runs",
    response_model=list[AttackGraphSyncRunRead],
)
def runs(db: Session = Depends(get_db)):
    return list_sync_runs(db)


@router.get(
    "/paths",
    response_model=list[AttackPathRecordRead],
)
def saved_paths(
    sync_run_id: uuid.UUID | None = Query(default=None),
    db: Session = Depends(get_db),
):
    return list_paths(db, sync_run_id)


@router.get(
    "/paths/{path_id}/evidence",
    response_model=list[AttackPathEvidenceRead],
)
def path_evidence(
    path_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    return list_path_evidence(db, path_id)
