"""
SentinelAI API Routes

This module exposes the main API routes for the SentinelAI platform.
Routes are imported directly from their respective modules in main.py.
"""

# This module exists to provide a clean namespace for route imports.
# Actual route registration happens in main.py

# Export route module names for reference
__all__ = [
    'repository',
    'auth',
    'scans',
    'audit_logs',
    'health'
]

# Note: Each route module should define its own router variable
# For example: router = APIRouter() in each route file
# Import statements should be done in main.py for the application instance