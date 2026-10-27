#!/usr/bin/env python3
"""
Quick test to verify SentinelAI imports work correctly
"""

import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    print("Testing SentinelAI imports...")

    try:
        # Test main app import
        from app import app
        print("✅ app imported successfully")

        # Test core components
        from app.core.config import settings
        from app.core.logger import get_logger
        print("✅ core components imported")

        # Test route imports
        from app.api.routes.repository import router as repository_router
        from app.api.routes.auth import router as auth_router
        from app.api.routes.scans import router as scans_router
        from app.api.routes.audit_logs import router as audit_logs_router
        from app.api.routes.health import router as health_router
        print("✅ all route modules imported")

        # Test service imports
        from app.services.phase1_tree_service import Phase1TreeService
        print("✅ Phase1TreeService imported")

        # Test knowledge retriever
        from app.services.knowledge_retriever import KnowledgeRetriever
        print("✅ KnowledgeRetriever imported")

        # Test policy engine
        from app.policy_engine.policy_checker import PolicyChecker
        print("✅ PolicyChecker imported")

        print("\n🎉 All imports successful! SentinelAI structure is correct.")
        return True

    except Exception as e:
        print(f"❌ Import error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_imports()
    exit(0 if success else 1)