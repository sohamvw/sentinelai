"""
Sector Baseline Rulesets for SentinelAI Policy Jurisdiction Check

For Indian sectors (indian_dpdp, indian_banking, indian_general, etc.),
the canonical rules come from app/policy_engine/canonical_policy_loader.py,
which references the actual DPDP Act 2023, RBI Cyber Security Framework,
and IT Act 2000/2008 section text. This file only holds the non-Indian
sector baselines plus the sector→baseline lookup function.
"""

# Eagerly import the canonical loader so its rule-sets are merged into the
# SECTOR_BASELINES dict below. Done at module load time so the policy
# checker never has to special-case Indian sectors at call time.
from app.policy_engine.canonical_policy_loader import CANONICAL_RULESETS

SECTOR_BASELINES = {
    **CANONICAL_RULESETS,

    "banking": [
        {
            "id": "BANK-001",
            "rule": "No Plaintext Password or Cardholder Data Storage",
            "category": "PCI-DSS 3.4",
            "description": "Sensitive authentication data and card details must never be stored or logged in plaintext.",
            "patterns": ["password", "raw_password", "card_number", "cvv", "ssn"],
            "severity": "CRITICAL"
        },
        {
            "id": "BANK-002",
            "rule": "Strict Transport Layer Security (TLS 1.3 / HTTPS)",
            "category": "PCI-DSS 4.1",
            "description": "All communication containing financial data must enforce TLS 1.3 or HTTPS.",
            "patterns": ["http://", "allow_insecure", "verify=False", "ssl=False"],
            "severity": "HIGH"
        },
        {
            "id": "BANK-003",
            "rule": "Mandatory Database Encryption at Rest",
            "category": "PCI-DSS 3.4.1",
            "description": "Database connection strings and persistent storage layers must enable encryption.",
            "patterns": ["encrypt=False", "sslmode=disable", "plaintext_store"],
            "severity": "HIGH"
        }
    ],
    "healthcare": [
        {
            "id": "HEALTH-001",
            "rule": "Protected Health Information (PHI) Encryption at Rest and Transit",
            "category": "HIPAA 164.312(a)(2)(iv)",
            "description": "PHI data fields must be encrypted using AES-256 before storage or transmission.",
            "patterns": ["phi_raw", "patient_name", "medical_record", "diagnosis_plain"],
            "severity": "CRITICAL"
        },
        {
            "id": "HEALTH-002",
            "rule": "Role-Based Access Control (RBAC) Enforcement for Medical Records",
            "category": "HIPAA 164.312(a)(1)",
            "description": "Access to patient healthcare data endpoints must enforce role-based access checks.",
            "patterns": ["skip_auth", "public_access", "admin_bypass"],
            "severity": "HIGH"
        },
        {
            "id": "HEALTH-003",
            "rule": "Audit Logging for Access to Health Records",
            "category": "HIPAA 164.312(b)",
            "description": "All read/write accesses to patient records must emit immutable audit log events.",
            "patterns": ["no_log", "disable_audit", "suppress_logs"],
            "severity": "MEDIUM"
        }
    ],
    "e-commerce": [
        {
            "id": "ECOM-001",
            "rule": "Secure Payment Gateway Credentials Management",
            "category": "PCI-DSS / ISO 27001",
            "description": "Stripe/PayPal secret keys must not be hardcoded in repository files.",
            "patterns": ["sk_live_", "sk_test_", "paypal_secret", "api_secret_key"],
            "severity": "CRITICAL"
        },
        {
            "id": "ECOM-002",
            "rule": "Customer PII Masking and Retention Limits",
            "category": "GDPR Article 32",
            "description": "Customer personal identifiers must be masked or anonymized in logs.",
            "patterns": ["print(customer)", "logger.info(user_data)", "console.log(order_details)"],
            "severity": "HIGH"
        }
    ],
    "general_saas": [
        {
            "id": "SAAS-001",
            "rule": "No Hardcoded Secrets or API Keys",
            "category": "OWASP A07:2021",
            "description": "API tokens, private keys, and DB passwords must be loaded exclusively via environment variables.",
            "patterns": ["SECRET_KEY =", "API_KEY =", "PRIVATE_KEY ="],
            "severity": "HIGH"
        },
        {
            "id": "SAAS-002",
            "rule": "CSRF and CORS Origin Restrictions",
            "category": "OWASP A05:2021",
            "description": "CORS configuration must not allow wildcards ('*') in production credentials mode.",
            "patterns": ["allow_origins=['*']", "cors_origin='*'"],
            "severity": "MEDIUM"
        }
    ]
}

def get_sector_baseline(sector: str) -> list:
    """
    Sector → baseline ruleset lookup. Indian sectors (indian_dpdp,
    indian_banking, indian_general, indian_ecommerce, indian_government,
    indian_healthcare) resolve directly to the canonical rule-sets defined in
    canonical_policy_loader.py, which reference the actual DPDP Act 2023,
    RBI Cyber Security Framework, and IT Act 2000/2008 sections. Legacy
    US/EU sector keywords still fall through to the original hand-tuned
    baselines for backwards compatibility.
    """
    normalized = (sector or "general_saas").lower().replace(" ", "_")
    if normalized in SECTOR_BASELINES:
        return SECTOR_BASELINES[normalized]
    if "bank" in normalized or "fin" in normalized:
        return SECTOR_BASELINES["banking"]
    elif "health" in normalized or "hipaa" in normalized or "med" in normalized:
        return SECTOR_BASELINES["healthcare"]
    elif "e-com" in normalized or "shop" in normalized or "retail" in normalized:
        return SECTOR_BASELINES["e-commerce"]
    return SECTOR_BASELINES["general_saas"]
