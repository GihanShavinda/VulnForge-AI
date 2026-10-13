from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.routes.authenticated_assessment import router as authenticated_assessment_router
from app.api.v1.routes.discovery import router as discovery_router
from app.api.v1.routes.enumeration import router as enumeration_router
from app.api.v1.routes.fingerprinting import router as fingerprinting_router
from app.api.v1.routes.security_lab import router as security_lab_router
from app.core.config import get_settings

settings=get_settings()
app=FastAPI(title=settings.app_name,version="0.5.0",debug=settings.debug)
app.add_middleware(CORSMiddleware,allow_origins=settings.cors_origin_list,allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
app.include_router(security_lab_router,prefix="/api/v1")
app.include_router(discovery_router,prefix="/api/v1")
app.include_router(enumeration_router,prefix="/api/v1")
app.include_router(fingerprinting_router,prefix="/api/v1")
app.include_router(authenticated_assessment_router,prefix="/api/v1")

@app.get("/health")
def health() -> dict[str,str]:
    return {"status":"ok","service":settings.app_name,"milestone":"V5"}
