from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.scans import router as scan_router
from app.api.routes.auth import router as auth_router
from app.api.routes.audit_logs import router as audit_logs_router
from app.api.routes.repository import router as repository_router
from app.api.routes.remediation import router as remediation_router
from app.core.config import settings
from app.core.database import init_db, get_database_status
from app.services.llm_provider_service import LLMProviderService
from app.scanners.multi_tool_runner import get_scanner_status


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Create the configured schema after all application modules load."""
    init_db()
    yield

app = FastAPI(
    title="SentinelAI Security Scanning Platform",
    version="0.2.0",
    lifespan=lifespan,
)

# CORS: read allowed origins from CORS_ALLOWED_ORIGINS (comma-separated env var),
# defaulting to the dev origins. Never combine a wildcard with allow_credentials=True
# — browsers reject the combination and credentialed OAuth callbacks silently fail.
_cors_origins = [
    o.strip() for o in settings.CORS_ALLOWED_ORIGINS.split(",") if o.strip()
] or ["http://localhost:5173", "http://127.0.0.1:5173"]
_cors_credentials = "*" not in _cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "SentinelAI Backend Engine Active",
        "version": "0.2.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "database": get_database_status(),
    }


@app.get("/health/dependencies")
def dependency_health():
    """Run live, credential-safe checks for the database and OpenRouter."""
    database = get_database_status()
    llm = LLMProviderService.validate_openrouter()
    return {
        "status": "healthy" if database.get("connected") and llm.get("reachable") else "degraded",
        "database": database,
        "openrouter": llm,
        "scanners": get_scanner_status(),
    }


# Router Registrations
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scan_router, prefix="/api/scans", tags=["Scans"])
app.include_router(audit_logs_router, prefix="/api/audit-logs", tags=["Audit Logs"])
app.include_router(repository_router, prefix="/api/repository", tags=["Repository"])
app.include_router(remediation_router, prefix="/api/remediation", tags=["LLM Remediation"])
