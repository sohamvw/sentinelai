#!/usr/bin/env python3
"""
Test OpenRouter configuration from .env file
"""
import os

# Load environment variables from .env file
from dotenv import load_dotenv

# Load .env file
load_dotenv('.env')

# Check environment variables
openrouter_key = os.getenv('OPENROUTER_API_KEY')
primary_model = os.getenv('PRIMARY_MODEL')
fallback_model = os.getenv('FALLBACK_MODEL')

print("🔍 SentinelAI OpenRouter Configuration Check")
print("=" * 50)

if openrouter_key:
    print(f"✅ OpenRouter API Key: {'*' * 20}{openrouter_key[-4:]}")
    print(f"   Length: {len(openrouter_key)} characters")
    print(f"   Starts with 'sk-or-v1-': {openrouter_key.startswith('sk-or-v1-')}")
else:
    print("❌ OpenRouter API Key: NOT SET")

if primary_model:
    print(f"✅ Primary Model: {primary_model}")
else:
    print("❌ Primary Model: NOT SET")

if fallback_model:
    print(f"✅ Fallback Model: {fallback_model}")
else:
    print("❌ Fallback Model: NOT SET")

print("\n" + "=" * 50)
print("📋 Configuration Status:")

# Check all required variables
required_vars = [
    ('OPENROUTER_API_KEY', openrouter_key),
    ('PRIMARY_MODEL', primary_model),
    ('FALLBACK_MODEL', fallback_model)
]

all_good = True
for var_name, var_value in required_vars:
    if var_value and len(var_value.strip()) > 0:
        print(f"✅ {var_name}: CONFIGURED")
    else:
        print(f"❌ {var_name}: NOT SET")
        all_good = False

if all_good:
    print("\n🎉 SUCCESS: All OpenRouter configuration variables are set!")
    print("🚀 The system is ready for real-time OpenRouter integration.")
else:
    print("\n⚠️  WARNING: Some configuration variables are missing.")
    print("   Please check your .env file.")

print("=" * 50)