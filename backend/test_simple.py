#!/usr/bin/env python3
"""
Simple test to verify SentinelAI imports work correctly.
"""

def test_imports():
    try:
        # Test main app import
        from app import app
        print("✅ Main app imported successfully")

        # Test core components
        from app.core.config import settings
        from app.core.logger import get_logger
        print("✅ Core components imported")

        # Test route imports
        from app.api.routes.repository import router as repository_router
        from app.api.routes.auth import router as auth_router
        from app.api.routes.scans import router as scans_router
        from app.api.routes.audit_logs import router as audit_logs_router
        from app.api.routes.health import router as health_router
        print("✅ All route modules imported")

        # Test service imports
        from app.services.phase1_tree_service import Phase1TreeService
        print("✅ Phase1TreeService imported")

        print("\n🎉 All imports successful!")
        return True

    except Exception as e:
        print(f"❌ Import error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_imports()
    exit(0 if success else 1)