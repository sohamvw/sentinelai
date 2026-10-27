"""
SentinelAI Backend Application Package.

This package contains the core application components for SentinelAI:
- API routes and endpoints
- Services organized by phase (Phase 1-9)
- Core utilities and infrastructure
- Repository discovery and analysis modules
"""

from app.core.config import settings
from app.core.logger import get_logger

# Do not import ``app.main`` here. Importing a package must not construct the
# FastAPI application because routers import submodules while it is loading.
__all__ = ["settings", "get_logger"]
