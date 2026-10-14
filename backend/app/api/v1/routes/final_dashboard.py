from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.dashboard_service import final_dashboard

router = APIRouter(
    prefix="/dashboard",
    tags=["final-dashboards"],
)


@router.get("/final")
def dashboard(db: Session = Depends(get_db)):
    return final_dashboard(db)
