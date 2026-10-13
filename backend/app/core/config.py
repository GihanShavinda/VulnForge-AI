from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the native VulnForge backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "VulnForge AI 2.0"
    app_env: str = "development"
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    debug: bool = True

    # Database
    database_url: str = (
        "postgresql+psycopg://"
        "vulnforge_user:change-me@127.0.0.1:5432/vulnforge"
    )

    # Authorized laboratory configuration
    default_lab_cidr: str = "192.168.56.0/24"
    scanner_hostname: str = "vulnforge-scanner"
    scanner_ip: str = "192.168.56.10"

    # Nmap
    nmap_path: str = Field(
        default=r"C:\Program Files (x86)\Nmap\nmap.exe",
        validation_alias="NMAP_PATH",
    )

    # Scanner behaviour
    default_scan_timeout_seconds: int = Field(default=900, ge=5, le=86400)
    default_scan_concurrency: int = Field(default=2, ge=1, le=32)
    default_evidence_retention_days: int = Field(default=90, ge=1, le=3650)

    # Frontend / CORS
    cors_origins: str = "http://localhost:5173"

    # V5 — Credential encryption
    credential_encryption_key: str = Field(
        default="",
        validation_alias="VULNFORGE_CREDENTIAL_KEY",
    )

    # V7 — Threat Intelligence
    nvd_cve_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = Field(default="", validation_alias="NVD_API_KEY")
    osv_vulnerability_api_url: str = "https://api.osv.dev/v1/vulns"
    cisa_kev_json_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    first_epss_api_url: str = "https://api.first.org/data/v1/epss"
    threat_intel_cache_dir: str = ".cache/threat_intel"
    threat_intel_http_timeout_seconds: int = Field(default=30, ge=5, le=300)

    # V13 — Secret fingerprinting.
    # Configure this in .env. Never reuse the credential-encryption key.
    secret_fingerprint_key: str = Field(
        default="",
        validation_alias="VULNFORGE_SECRET_FINGERPRINT_KEY",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
