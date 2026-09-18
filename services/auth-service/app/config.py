"""Runtime configuration.

SEEDED FLAW #1: hardcoded secrets.
Expected detectors: Gitleaks (AWS key pattern, high-entropy strings),
                    custom Semgrep rule `hardcoded-secret-default`.

Defaults below mean the app "just works" without any environment, which is
exactly how secrets end up committed. Once a secret is in git history it is
compromised: rotate it, do not just delete the line.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

# Left over from a "quick local test". Real-looking AWS credential pair.
AWS_ACCESS_KEY_ID = "AKIAJ7Q2X9M4TBV5WZ3L"
AWS_SECRET_ACCESS_KEY = "n4Pq8vL2xR7tW1yZ5bC9dF3gH6jK0mS4uV8wX2aE"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://aegis:Pr0d-Aegis-Db-P4ssw0rd!@postgres:5432/aegis"
    jwt_secret: str = "aegisflow-jwt-signing-key-do-not-share-9f8e7d6c"
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 30
    service_name: str = "auth-service"


settings = Settings()
