"""Runtime configuration.

Every setting comes from an environment variable. Nothing sensitive is written
in code, so a secret can never end up in git. In docker-compose these values
come from the .env file; in Kubernetes they come from a Secret object.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 30
    service_name: str = "auth-service"


settings = Settings()
