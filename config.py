from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl, field_validator
from typing import Optional


class Settings(BaseSettings):
    OIDC_ISSUER: AnyHttpUrl
    OIDC_CLIENT_ID: str
    OIDC_CLIENT_SECRET: Optional[str] = None
    OIDC_JWKS_URI: Optional[AnyHttpUrl] = None
    OIDC_AUDIENCE: Optional[str] = None
    KC_BASE: Optional[AnyHttpUrl] = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @field_validator("OIDC_ISSUER", mode="before")
    @classmethod
    def strip_trailing_slash(cls, v: AnyHttpUrl) -> AnyHttpUrl:
        return AnyHttpUrl(str(v).rstrip("/"))

    @field_validator("OIDC_AUDIENCE", mode="before")
    @classmethod
    def default_audience(cls, v: Optional[str], info) -> str:
        return v.strip() if v and v.strip() else str(info.data.get("OIDC_CLIENT_ID"))


# Singleton instance imported elsewhere
settings = Settings()
