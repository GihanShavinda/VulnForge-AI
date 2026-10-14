from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.routes.attack_graph import router as attack_graph_router
from app.api.v1.routes.authenticated_assessment import router as authenticated_assessment_router
from app.api.v1.routes.config_assessment import router as config_assessment_router
from app.api.v1.routes.discovery import router as discovery_router
from app.api.v1.routes.enumeration import router as enumeration_router
from app.api.v1.routes.environmental_risk import router as environmental_risk_router
from app.api.v1.routes.exploitability import router as exploitability_router
from app.api.v1.routes.fingerprinting import router as fingerprinting_router
from app.api.v1.routes.patch_lifecycle import router as patch_lifecycle_router
from app.api.v1.routes.sbom import router as sbom_router
from app.api.v1.routes.security_controls import router as security_controls_router
from app.api.v1.routes.security_lab import router as security_lab_router
from app.api.v1.routes.secret_exposure import router as secret_exposure_router
from app.api.v1.routes.severity_analysis import router as severity_analysis_router
from app.api.v1.routes.threat_intel import router as threat_intel_router
from app.api.v1.routes.tls_assessment import router as tls_assessment_router
from app.api.v1.routes.weakness_context import router as weakness_context_router
from app.api.v1.routes.web_assessment import router as web_assessment_router
from app.core.config import get_settings

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.18.0", debug=settings.debug)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(security_lab_router, prefix="/api/v1")
app.include_router(discovery_router, prefix="/api/v1")
app.include_router(enumeration_router, prefix="/api/v1")
app.include_router(fingerprinting_router, prefix="/api/v1")
app.include_router(authenticated_assessment_router, prefix="/api/v1")
app.include_router(sbom_router, prefix="/api/v1")
app.include_router(threat_intel_router, prefix="/api/v1")
app.include_router(weakness_context_router, prefix="/api/v1")
app.include_router(severity_analysis_router, prefix="/api/v1")
app.include_router(config_assessment_router, prefix="/api/v1")
app.include_router(web_assessment_router, prefix="/api/v1")
app.include_router(tls_assessment_router, prefix="/api/v1")
app.include_router(secret_exposure_router, prefix="/api/v1")
app.include_router(patch_lifecycle_router, prefix="/api/v1")
app.include_router(exploitability_router, prefix="/api/v1")
app.include_router(attack_graph_router, prefix="/api/v1")
app.include_router(environmental_risk_router, prefix="/api/v1")
app.include_router(security_controls_router, prefix="/api/v1")

@app.get("/health")
def health() -> dict[str, str]:
    return {"status":"ok","service":settings.app_name,"milestone":"V18"}
