from logging.config import fileConfig
from alembic import context
from sqlalchemy import engine_from_config, pool
from app.core.config import get_settings
from app.db.base import Base
from app.models.attack_graph import AttackGraphSyncRun, AttackPathEvidence, AttackPathRecord  # noqa
from app.models.authenticated_assessment import AuthenticatedEvidence, AuthenticatedScan, CredentialUseAudit  # noqa
from app.models.config_assessment import BenchmarkProfile, ConfigAssessmentRun, ConfigEvidence, ConfigurationFinding  # noqa
from app.models.discovery import DiscoveryEvidence, DiscoveryJob, DiscoveredHost  # noqa
from app.models.enumeration import EnumerationEvidence, EnumerationJob, ExposureFinding, ServiceObservation  # noqa
from app.models.environmental_risk import EnvironmentalRiskContribution, EnvironmentalRiskScore, RiskScoreVersion  # noqa
from app.models.exploitability import ExploitabilityAssessment, ExploitabilitySignal  # noqa
from app.models.fingerprinting import FingerprintEvidence, FingerprintJob, Technology, TechnologyObservation  # noqa
from app.models.patch_lifecycle import LifecycleFinding, PatchFinding, PatchLifecycleAssessmentRun  # noqa
from app.models.sbom import ComponentDriftEvent, PackageComponent, PackageVulnerabilityMatch, SbomImport, VulnerabilityAdvisory  # noqa
from app.models.security_control_awareness import SecurityControl, ControlRiskAssessment, ControlRiskContribution  # noqa
from app.models.security_lab import Asset, AssetTag, AuditLog, CredentialProfile, Network, ScanProfile, ScanScope  # noqa
from app.models.secret_exposure import SecretAttackPathSignal, SecretExposure, SecretScanImport  # noqa
from app.models.severity_analysis import VulnerabilitySeverityAnalysis  # noqa
from app.models.threat_intel import IntelConflict, IntelSyncRun, ThreatIntelObservation, ThreatIntelSource  # noqa
from app.models.tls_assessment import CryptoFinding, TLSAssessmentImport, TLSEvidence  # noqa
from app.models.weakness_context import AttackTechnique, BehaviourObservation, WeaknessCapecMapping, WeaknessTechniqueMapping  # noqa
from app.models.web_assessment import WebAssessmentImport, WebEvidence, WebFinding  # noqa

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url.replace("%","%%"))
target_metadata = Base.metadata

def run_migrations_offline():
    context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle":"named"}, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    connectable = engine_from_config(config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
