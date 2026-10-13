from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "VulnForge AI 2.0"
    app_env: str = "development"
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    debug: bool = True

    database_url: str = "postgresql+psycopg://vulnforge_user:change-me@127.0.0.1:5432/vulnforge"

    default_lab_cidr: str = "192.168.56.0/24"
    scanner_hostname: str = "vulnforge-scanner"
    scanner_ip: str = "192.168.56.10"

    default_scan_timeout_seconds: int = Field(default=900, ge=5, le=86400)
    default_scan_concurrency: int = Field(default=2, ge=1, le=32)
    default_evidence_retention_days: int = Field(default=90, ge=1, le=3650)

    cors_origins: str = "http://localhost:5173"
    credential_encryption_key: str = Field(default="", validation_alias="VULNFORGE_CREDENTIAL_KEY")

    # V7 threat-intelligence sources. These defaults point at the official public APIs/feeds.
    nvd_cve_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = ""
    osv_vulnerability_api_url: str = "https://api.osv.dev/v1/vulns"
    cisa_kev_json_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    first_epss_api_url: str = "https://api.first.org/data/v1/epss"

    threat_intel_cache_dir: str = ".cache/threat_intel"
    threat_intel_http_timeout_seconds: int = Field(default=30, ge=5, le=300)

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
