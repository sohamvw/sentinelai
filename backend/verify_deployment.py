#!/usr/bin/env python3
"""
SentinelAI Deployment Verification Script

This script verifies the OpenRouter configuration and tests the real-time integration.
"""

import os
import sys

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    print("🚀 SentinelAI OpenRouter Deployment Verification")
    print("=" * 60)

    # Check environment variables
    from app.core.config import settings
    from app.services.llm_provider_service import LLMProviderService

    print("1. Checking OpenRouter configuration...")
    if not settings.OPENROUTER_API_KEY:
        print("❌ OpenRouter API key not set.")
        print("   Set OPENROUTER_API_KEY environment variable")
        print("   Example: export OPENROUTER_API_KEY=your-api-key-here")
        return 1

    print(f"✅ OpenRouter API key: {'*' * 20}{settings.OPENROUTER_API_KEY[-4:]}")
    print(f"✅ Primary Model: {settings.PRIMARY_MODEL}")
    print(f"✅ Fallback Model: {settings.FALLBACK_MODEL}")

    print("2. Testing OpenRouter connection...")
    try:
        # Test with a simple prompt
        response = LLMProviderService.call_llm("Hello, test connection", json_mode=False)
        print("✅ OpenRouter connection: SUCCESS")
        print(f"   Response: {response[:100]}...")
    except Exception as e:
        print(f"❌ OpenRouter connection failed: {e}")
        return 1

    print("3. Testing real-time service initialization...")
    try:
        from backend.app.services.realtime_integration import RealtimeIntegrationService
        service = RealtimeIntegrationService()
        print("✅ Real-time service initialized successfully")
    except Exception as e:
        print(f"❌ Real-time service initialization failed: {e}")
        return 1

    print("4. Verifying database connection...")
    try:
        from backend.app.core.database import get_db_connection
        conn, db_type = get_db_connection()
        cursor = conn.cursor()

        if db_type == "postgres":
            cursor.execute("SELECT 1 as test_connection")
        else:
            cursor.execute("SELECT 1 as test_connection")

        result = cursor.fetchone()
        print(f"✅ Database connection: SUCCESS ({db_type})")
        conn.close()
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return 1

    print("=" * 60)
    print("🎉 DEPLOYMENT VERIFICATION SUCCESSFUL!")
    print("✅ OpenRouter API key configured")
    print("✅ OpenRouter connection verified")
    print("✅ Real-time services initialized")
    print("✅ Database connection established")
    print()
    print("🚀 System ready for production deployment!")
    print("📊 Ready to process repositories with real-time tracking!")
    print("🏥 Open to scaling and optimization phase")

    return 0

if __name__ == "__main__":
    exit(main())