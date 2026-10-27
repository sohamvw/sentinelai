import os
from pathlib import Path
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# Resolve the backend environment file from this module, not the caller's
# current directory. This keeps uvicorn launches from the project root and
# backend directory on the same OpenRouter configuration.
load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)

class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelAI Security Scanning Platform"

    # CORS — comma-separated origin list. Wildcard "*" disables credentials.
    CORS_ALLOWED_ORIGINS: str = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")

    # Frontend base URL used for OAuth redirects and other browser flows.
    FRONTEND_BASE_URL: str = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173")

    # Database - SentinelAI runtime state is PostgreSQL-backed. Keep this
    # explicit so local runs do not silently create a stale sentinel.db shadow DB.
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")

    # Auth & JWT
    # In production, JWT_SECRET must be set via .env — no literal default fallback.
    # The dev default below is gated by ENVIRONMENT=development; prod will refuse to start.
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # LLM provider (configured at deploy-time via Railway/Render env vars — not via UI).
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    REMEDIATION_OPENROUTER_API_KEY: str = os.getenv("REMEDIATION_OPENROUTER_API_KEY", "")
    PRIMARY_MODEL: str = os.getenv("PRIMARY_MODEL", "qwen/qwen-2.5-coder-32b-instruct")
    FALLBACK_MODEL: str = os.getenv("FALLBACK_MODEL", "deepseek/deepseek-r1")
    # Optional model used only by the remediation workflow. Leave empty to
    # use PRIMARY_MODEL, or set it to FALLBACK_MODEL for controlled testing.
    REMEDIATION_MODEL: str = os.getenv("REMEDIATION_MODEL", "")
    USE_LOCAL_FINE_TUNED: bool = os.getenv("USE_LOCAL_FINE_TUNED", "false").lower() in ("1", "true", "yes")
    LOCAL_MODEL_ENDPOINT: str = os.getenv("LOCAL_MODEL_ENDPOINT", "http://localhost:8000/v1")
    ENABLED_TOOLS: str = os.getenv("ENABLED_TOOLS", "semgrep,bandit,trivy,gitleaks,bearer,spotbugs,ast_parser")
    SEMGREP_PATH: str = os.getenv("SEMGREP_PATH", "")
    BANDIT_PATH: str = os.getenv("BANDIT_PATH", "")
    TRIVY_PATH: str = os.getenv("TRIVY_PATH", "")
    GITLEAKS_PATH: str = os.getenv("GITLEAKS_PATH", "")
    SPOTBUGS_PATH: str = os.getenv("SPOTBUGS_PATH", "")
    SPOTBUGS_HOME: str = os.getenv("SPOTBUGS_HOME", "")
    JAVA_HOME: str = os.getenv("JAVA_HOME", "")
    BEARER_PATH: str = os.getenv("BEARER_PATH", "")

    # Recipient address for operational notifications (e.g. support tickets).
    # Not used for any authentication/authorization decision.
    ADMIN_NOTIFY_EMAIL: str = os.getenv("ADMIN_NOTIFY_EMAIL", "")

    # Comma-separated list of email domains that may use GitHub OAuth to sign in.
    # Email/password signup and login are unrestricted. GitHub OAuth is the only
    # flow that requires the returned email to belong to one of these domains.
    APSIT_ALLOWED_OAUTH_DOMAINS: str = os.getenv(
        "APSIT_ALLOWED_OAUTH_DOMAINS",
        "apsit.edu.in",
    )


    # OAuth Credentials
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/auth/oauth/google/callback")
    
    GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
    GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
    GITHUB_REDIRECT_URI: str = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:8000/api/auth/oauth/github/callback")

    
    # Email Delivery (Resend / SendGrid / SMTP)
    EMAIL_PROVIDER: str = os.getenv("EMAIL_PROVIDER", "smtp") # "resend", "sendgrid", "smtp"
    RESEND_API_KEY: str = os.getenv("RESEND_API_KEY", "")
    SENDGRID_API_KEY: str = os.getenv("SENDGRID_API_KEY", "")
    
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    EMAIL_FROM: str = os.getenv("EMAIL_FROM", "auth@sentinelai.dev")

    class Config:
        env_file = str(Path(__file__).resolve().parents[2] / ".env")
        extra = "ignore"


settings = Settings()

# In any non-development environment, JWT_SECRET must be explicitly set.
# Silently defaulting to a known string is a CVE-grade mistake (SAAS-001
# in the project's own sector baseline flags exactly this class of issue).
if settings.ENVIRONMENT.lower() != "development" and not settings.JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET must be set in the environment when ENVIRONMENT != 'development'. "
        "Refusing to start with the public default secret."
    )
