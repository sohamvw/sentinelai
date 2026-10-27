#!/usr/bin/env python3
"""
Quick verification script for SentinelAI deployment.
This script verifies that the OpenRouter configuration is properly set up.
"""

import os
import sys

def main():
    print("🚀 SentinelAI OpenRouter Deployment Verification")
    print("=" * 60)

    # Check environment variables
    from app.core.config import settings

    print("1. Checking OpenRouter configuration...")
    if not settings.OPENROUTER_API_KEY:
        print("❌ OpenRouter API key not set.")
        print("   Please set OPENROUTER_API_KEY in your .env file")
        return 1

    print(f"✅ OpenRouter API key: {'*' * 20}{settings.OPENROUTER_API_KEY[-4:]}")
    print(f"✅ Primary Model: {settings.PRIMARY_MODEL}")
    print(f"✅ Fallback Model: {settings.FALLBACK_MODEL}")

    print("2. Testing OpenRouter connection...")
    try:
        from app.services.llm_provider_service import LLMProviderService
        response = LLMProviderService.call_llm("Hello, test connection", json_mode=False)
        print("✅ OpenRouter connection: SUCCESS")
        print(f"   Response preview: {response[:100]}...")
    except Exception as e:
        print(f"❌ OpenRouter connection failed: {e}")
        return 1

    print("3. Verifying database configuration...")
    try:
        from app.core.database import get_db_connection
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
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
    print("✅ Database connection established")
    print()
    print("🚀 System ready for production!")
    print("📊 OpenRouter integration is working correctly")

    return 0

if __name__ == "__main__":
    exit(main())