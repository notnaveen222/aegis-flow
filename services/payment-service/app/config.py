"""Runtime configuration, all from environment variables.

JWT_SECRET must be the same value auth-service uses, because payment-service
verifies tokens that auth-service issued. Sharing a symmetric secret (HS256)
is the simplest model for two services under one team. Asymmetric keys
(RS256) would let payment-service verify without being able to *issue*
tokens, which matters once many services are involved.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "auth-service"
    service_name: str = "payment-service"
    log_level: str = "INFO"


settings = Settings()
