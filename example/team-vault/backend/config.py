"""TeamVault application configuration."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── App ──────────────────────────────────────────────
    app_name: str = "TeamVault"
    debug: bool = False

    # ── Database ─────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./teamvault.db"

    # ── JWT ──────────────────────────────────────────────
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # ── OpenFGA (ch14, ch18) ─────────────────────────────
    openfga_api_url: str = "http://localhost:8080"
    openfga_store_id: str = ""
    openfga_model_id: str = ""

    # ── OPA (ch15, ch16) ─────────────────────────────────
    opa_url: str = "http://localhost:8181"
    opa_policy_path: str = "/v1/data/teamvault/authz/decision"

    model_config = {"env_file": ".env", "env_prefix": "TEAMVAULT_"}


settings = Settings()
