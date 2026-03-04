"""Application configuration — loaded from environment or .env file."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── App ──────────────────────────────────────────────
    app_name: str = "SecureNote"
    debug: bool = False

    # ── Database ─────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./securenote.db"

    # ── JWT ──────────────────────────────────────────────
    jwt_private_key_path: str = "certs/jwt_private.pem"
    jwt_public_key_path: str = "certs/jwt_public.pem"
    jwt_algorithm: str = "RS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # ── Argon2 ───────────────────────────────────────────
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536  # 64 MB
    argon2_parallelism: int = 4

    # ── AES-GCM Encryption ───────────────────────────────
    master_key_env: str = ""  # hex-encoded 256-bit key (override via env)

    # ── TOTP / MFA ───────────────────────────────────────
    totp_issuer: str = "SecureNote"
    totp_digits: int = 6
    totp_interval: int = 30
    recovery_codes_count: int = 8

    # ── OAuth2 / OIDC ───────────────────────────────────
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    oauth2_redirect_uri: str = "http://localhost:8000/auth/callback"

    # ── TLS / mTLS ──────────────────────────────────────
    tls_cert_path: str = "certs/server.crt"
    tls_key_path: str = "certs/server.key"
    tls_ca_path: str = "certs/ca.crt"
    mtls_enabled: bool = False

    model_config = {"env_file": ".env", "env_prefix": "SECURENOTE_"}


settings = Settings()
