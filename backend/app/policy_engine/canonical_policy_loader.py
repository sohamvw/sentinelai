"""
Canonical-policy loader for the SentinelAI policy engine.

Why this exists
---------------
Indian compliance (DPDP Act 2023, RBI Cyber Security Framework, IT Act 2000/2008)
is the user's primary jurisdiction. We embed the canonical section text inside
the repo (under `canonical_texts/`) so that:

  1. Rule generation is deterministic at scan time — no runtime network call.
  2. The audit trail in the PDF report can cite specific Indian Act sections.
  3. The same rules apply whether the user uploads their own policy or not;
     an uploaded policy supplements (does not replace) the canonical baseline.

For each canonical file we maintain a hand-tuned mapping from each
`## Section` heading to a *list of testable code patterns* that, if found in
the repository, would indicate a violation. This is the only mapping that
requires human judgement; the rule skeleton (id, severity, description) is
generated from the section text itself.
"""
import os
import re
from typing import List, Dict, Any

# ---------------------------------------------------------------------------
# Canonical-text → structured-rules mappings. Each entry encodes one Act
# section that SentinelAI enforces. Patterns are case-insensitive substrings
# that, if present in a code file, indicate a likely violation.
# ---------------------------------------------------------------------------

DPDP_RULES: List[Dict[str, Any]] = [
    {
        "id": "DPDP-009",
        "act": "Digital Personal Data Protection Act, 2023",
        "section": "Section 9 — Security Safeguards",
        "rule": "No plaintext storage of personal data fields",
        "description": (
            "Section 9 requires reasonable security safeguards to prevent a "
            "personal data breach. Plaintext columns for personal identifiers "
            "indicate missing safeguards."
        ),
        "patterns": [
            "phi_raw", "patient_name", "ssn_plain",
            "raw_password =", "password_plain =",
            ".raw_pii", "raw_email =",
        ],
        "severity": "CRITICAL",
    },
    {
        "id": "DPDP-008",
        "act": "Digital Personal Data Protection Act, 2023",
        "section": "Section 8(4) — Erasure on withdrawal of consent",
        "rule": "Right-to-erasure endpoint must exist",
        "description": (
            "Data Principals must be able to delete their personal data. "
            "Repositories serving Indian users should expose a delete-account "
            "or erase-data route."
        ),
        "patterns": [
            "delete-account", "erase_user", "right_to_erasure",
            "gdpr_erase", "delete_personal_data",
        ],
        "severity": "MEDIUM",
    },
    {
        "id": "DPDP-006",
        "act": "Digital Personal Data Protection Act, 2023",
        "section": "Section 6 — Notice",
        "rule": "Privacy notice endpoint must exist",
        "description": (
            "Data Fiduciaries must publish a privacy notice describing what "
            "personal data is processed and why."
        ),
        "patterns": [
            "privacy-notice", "privacy_policy", "/privacy",
            "privacyNotice", "privacy_policy_url",
        ],
        "severity": "MEDIUM",
    },
    {
        "id": "DPDP-044",
        "act": "Digital Personal Data Protection Act, 2023",
        "section": "Section 44 — Cross-border transfer",
        "rule": "Cross-border transfer must be auditable",
        "description": (
            "Transfer of personal data outside India is restricted by "
            "negative-list notification. Repositories handling Indian user "
            "data must not silently off-shore storage."
        ),
        "patterns": [
            "s3.amazonaws.com", "us-east-1", "us-west-2",
            "EU_WEST_", "transfer_data_abroad",
        ],
        "severity": "HIGH",
    },
    {
        "id": "DPDP-INFRA",
        "act": "Digital Personal Data Protection Act, 2023",
        "section": "Section 9 (read with Section 8(7))",
        "rule": "Encryption at rest for personal data",
        "description": (
            "Encryption is the canonical 'reasonable security safeguard'. "
            "Personal data columns must use encryption-at-rest, not plaintext."
        ),
        "patterns": [
            "encrypt=False", "sslmode=disable",
            "encryption_at_rest=false", "store_plain",
        ],
        "severity": "CRITICAL",
    },
]


# Curated from the project control pack sourced from the official MeitY DPDP
# Rules 2025 document.  Required-capability rules are positive repository
# evidence checks; their absence stays UNKNOWN rather than becoming a legal
# failure.  Source/code violations remain FAIL only when direct evidence is
# found.
DPDP_RULES_2025: List[Dict[str, Any]] = [
    {
        "id": "DPDP-R06-SEC-01",
        "act": "Digital Personal Data Protection Rules, 2025",
        "section": "Rule 6 — Reasonable security safeguards (p. 26)",
        "rule": "No disabled data-protection safeguards",
        "description": "Rule 6 safeguards include encryption/protective measures and secure access to personal data.",
        "patterns": ["verify=false", "sslmode=disable", "encrypt=false", "encryption_at_rest=false", "check_hostname=false"],
        "severity": "HIGH",
    },
    {
        "id": "DPDP-R06-AC-02",
        "act": "Digital Personal Data Protection Rules, 2025",
        "section": "Rule 6 — Access controls (p. 26)",
        "rule": "Personal-data access control must exist",
        "description": "Repository evidence should show authentication or authorization protecting personal-data access paths.",
        "patterns": ["@login_required", "@require_auth", "is_authenticated", "authorization", "get_current_user", "jwt_required", "require_role"],
        "severity": "HIGH",
    },
    {
        "id": "DPDP-R06-LOG-03",
        "act": "Digital Personal Data Protection Rules, 2025",
        "section": "Rule 6 — Logging, monitoring and review (p. 26)",
        "rule": "Security logging or monitoring capability must exist",
        "description": "Repository evidence should show audit/security logging or monitoring hooks. Operational retention remains an evidence review item.",
        "patterns": ["audit_log", "security_log", "logger.audit", "logger.warning", "security_event", "monitoring"],
        "severity": "MEDIUM",
    },
    {
        "id": "DPDP-R06-BCP-04",
        "act": "Digital Personal Data Protection Rules, 2025",
        "section": "Rule 6 — Backup and continued processing (p. 26)",
        "rule": "Backup or recovery configuration must exist",
        "description": "Repository evidence should show backup, recovery, snapshot, or restore configuration. Deployed operation requires separate evidence.",
        "patterns": ["backup", "restore", "recovery", "snapshot", "point_in_time_recovery"],
        "severity": "MEDIUM",
    },
    {
        "id": "DPDP-R07-BREACH-01",
        "act": "Digital Personal Data Protection Rules, 2025",
        "section": "Rule 7 — Personal-data breach notification (pp. 26–27)",
        "rule": "Breach-response workflow must exist",
        "description": "Repository evidence should show a breach/incident response or notification capability. The operational reporting timeline needs non-code evidence.",
        "patterns": ["breach_notify", "report_breach", "incident_response", "incident_alert", "security_incident"],
        "severity": "HIGH",
    },
]


# The only runtime sectors exposed by SentinelAI.  They are derived from the
# four user-supplied pre-parsed control packs.  Controls that need contracts,
# regulator/entity status, or production evidence deliberately return UNKNOWN
# when the repository alone cannot establish them.
RBI_FINTECH_RULES: List[Dict[str, Any]] = [
    {"id": "RBI-FIN-11", "act": "RBI Master Directions - Cyber Resilience and Digital Payment Security Controls (2024)", "section": "Default credentials/settings", "rule": "No default or hardcoded production credentials", "patterns": ["password = \"", "password = '", "api_key = \"", "api_key = '", "secret_key = \"", "secret_key = '"], "severity": "CRITICAL"},
    {"id": "RBI-FIN-12", "act": "RBI Master Directions - Cyber Resilience and Digital Payment Security Controls (2024)", "section": "Least privilege", "rule": "Payment-system access control must exist", "patterns": ["require_role", "is_admin", "authorization", "rbac", "permission_required", "get_current_user"], "severity": "HIGH"},
    {"id": "RBI-FIN-17", "act": "RBI Master Directions - Cyber Resilience and Digital Payment Security Controls (2024)", "section": "Secure SDLC", "rule": "Secure SDLC security-gate evidence must exist", "patterns": ["semgrep", "bandit", "trivy", "gitleaks", "security scan"], "severity": "HIGH"},
    {"id": "RBI-FIN-22", "act": "RBI Master Directions - Cyber Resilience and Digital Payment Security Controls (2024)", "section": "Data security", "rule": "No disabled payment-data transport or storage safeguards", "patterns": ["verify=false", "sslmode=disable", "encrypt=false", "encryption_at_rest=false", "http://"], "severity": "CRITICAL"},
    {"id": "RBI-FIN-24", "act": "RBI Master Directions - Cyber Resilience and Digital Payment Security Controls (2024)", "section": "Incident response", "rule": "Incident-response workflow must exist", "patterns": ["incident_response", "incident_alert", "report_incident", "breach_notify"], "severity": "HIGH"},
    {"id": "RBI-FIN-26", "act": "RBI Master Directions - Cyber Resilience and Digital Payment Security Controls (2024)", "section": "API security", "rule": "Payment API authentication and authorization must exist", "patterns": ["authorization", "jwt_required", "oauth", "api_key", "get_current_user"], "severity": "CRITICAL"},
    {"id": "RBI-FIN-29", "act": "RBI Master Directions - Cyber Resilience and Digital Payment Security Controls (2024)", "section": "Audit logging", "rule": "Payment audit logging must exist", "patterns": ["audit_log", "security_log", "transaction_log", "logger.audit"], "severity": "HIGH"},
]

SEBI_STOCK_MARKET_RULES: List[Dict[str, Any]] = [
    {"id": "SEBI-CSCRF-ACCESS", "act": "SEBI Cybersecurity and Cyber Resilience Framework (CSCRF), 2024", "section": "Identity, authentication and access control", "rule": "Securities-system access control must exist", "patterns": ["mfa", "two_factor", "require_role", "rbac", "authorization", "get_current_user"], "severity": "CRITICAL"},
    {"id": "SEBI-CSCRF-SDLC", "act": "SEBI Cybersecurity and Cyber Resilience Framework (CSCRF), 2024", "section": "Secure SDLC and application security testing", "rule": "Secure SDLC testing evidence must exist", "patterns": ["semgrep", "bandit", "trivy", "sast", "dast", "security scan"], "severity": "HIGH"},
    {"id": "SEBI-CSCRF-PATCH", "act": "SEBI Cybersecurity and Cyber Resilience Framework (CSCRF), 2024", "section": "Patch and vulnerability management", "rule": "No known vulnerable dependency may remain unremediated", "patterns": ["CVE-"], "severity": "HIGH"},
    {"id": "SEBI-CSCRF-LOG", "act": "SEBI Cybersecurity and Cyber Resilience Framework (CSCRF), 2024", "section": "Logging and monitoring", "rule": "Security logging and monitoring capability must exist", "patterns": ["audit_log", "security_log", "siem", "monitoring", "security_event"], "severity": "HIGH"},
    {"id": "SEBI-CSCRF-API", "act": "SEBI Cybersecurity and Cyber Resilience Framework (CSCRF), 2024", "section": "API and customer-facing application security", "rule": "Customer-facing API protection must exist", "patterns": ["authorization", "jwt_required", "rate_limit", "csrf", "input validation"], "severity": "CRITICAL"},
]

ECOMMERCE_RULES: List[Dict[str, Any]] = [
    {"id": "ECO-CP-01", "act": "Consumer Protection (E-Commerce) Rules, 2020", "section": "Grievance redressal", "rule": "E-commerce grievance mechanism must exist", "patterns": ["grievance", "complaint", "support_ticket", "customer_care"], "severity": "MEDIUM"},
    {"id": "ECO-CP-02", "act": "Consumer Protection (E-Commerce) Rules, 2020", "section": "Consumer consent", "rule": "Explicit purchase consent must exist", "patterns": ["place_order", "confirm_order", "purchase_confirm", "checkout"], "severity": "HIGH"},
    {"id": "ECO-CP-03", "act": "Consumer Protection (E-Commerce) Rules, 2020", "section": "Refund, return and cancellation information", "rule": "Refund or cancellation workflow must exist", "patterns": ["refund", "return_order", "cancel_order", "cancellation"], "severity": "MEDIUM"},
    {"id": "ECO-CP-04", "act": "Consumer Protection (E-Commerce) Rules, 2020", "section": "Consumer and transaction data protection", "rule": "No insecure consumer-data transport or credential storage", "patterns": ["verify=false", "sslmode=disable", "password = \"", "password = '", "http://"], "severity": "HIGH"},
]

SAAS_INDIA_RULES: List[Dict[str, Any]] = [
    *DPDP_RULES,
    *DPDP_RULES_2025,
    {"id": "CERTIN-01", "act": "CERT-In Directions under section 70B (2022)", "section": "Incident reporting", "rule": "Cyber-incident response workflow must exist", "patterns": ["incident_response", "report_incident", "security_incident", "incident_alert"], "severity": "HIGH"},
    {"id": "CERTIN-02", "act": "CERT-In Directions under section 70B (2022)", "section": "ICT system logs", "rule": "Security logging capability must exist", "patterns": ["audit_log", "security_log", "logger", "monitoring", "security_event"], "severity": "HIGH"},
    {"id": "CERTIN-03", "act": "CERT-In Directions under section 70B (2022)", "section": "Time synchronisation", "rule": "Time synchronisation configuration must exist", "patterns": ["ntp", "chrony", "time_server", "timesync"], "severity": "MEDIUM"},
    {"id": "CERTIN-04", "act": "CERT-In Directions under section 70B (2022)", "section": "Point of contact", "rule": "CERT-In incident contact workflow must exist", "patterns": ["cert-in", "certin", "incident_contact", "security_contact"], "severity": "MEDIUM"},
]


RBI_RULES: List[Dict[str, Any]] = [
    {
        "id": "RBI-001",
        "act": "RBI Cyber Security Framework",
        "section": "Chapter VII — Data Security",
        "rule": "No plaintext cardholder / customer data",
        "description": (
            "RBI prohibits plaintext storage of cardholder data and customer "
            "credentials. PCI-DSS aligned."
        ),
        "patterns": [
            "card_number =", "cvv =", "raw_card", "plain_card",
            "password = \"", "raw_password", "ssn_plain",
        ],
        "severity": "CRITICAL",
    },
    {
        "id": "RBI-002",
        "act": "RBI Cyber Security Framework",
        "section": "Chapter IV — Network Security",
        "rule": "No hardcoded API keys or DB credentials in source",
        "description": (
            "RBI mandates secret management; credentials must not be present "
            "in version-controlled source."
        ),
        "patterns": [
            # Match literal assignments only. Environment lookups such as
            # `QDRANT_API_KEY = os.getenv(...)` are safe configuration, not
            # embedded credentials.
            "API_KEY = \"", "API_KEY = '",
            "SECRET_KEY = \"", "SECRET_KEY = '",
            "DB_PASSWORD = \"", "DB_PASSWORD = '",
            "PRIVATE_KEY = \"", "PRIVATE_KEY = '",
            "sk_live_", "sk_test_",
        ],
        "severity": "CRITICAL",
    },
    {
        "id": "RBI-003",
        "act": "RBI Cyber Security Framework",
        "section": "Chapter VI — Vulnerability Management",
        "rule": "No disabled TLS verification or insecure HTTP",
        "description": (
            "Insecure transport configuration is a Chapter IV/VI violation."
        ),
        "patterns": [
            "verify=False", "ssl=False", "allow_insecure",
            "http://", "check_hostname=False",
        ],
        "severity": "HIGH",
    },
    {
        "id": "RBI-004",
        "act": "RBI Cyber Security Framework",
        "section": "Chapter II — Governance",
        "rule": "Audit logging on privileged operations",
        "description": (
            "All sensitive operations must be logged. Missing audit logging "
            "is a governance gap."
        ),
        "patterns": [
            "disable_audit", "suppress_logs", "no_log", "skip_audit",
        ],
        "severity": "MEDIUM",
    },
    {
        "id": "RBI-005",
        "act": "RBI Cyber Security Framework",
        "section": "Chapter IX — Incident Response",
        "rule": "Breach-notification path must be wired",
        "description": (
            "RBI requires breach reporting within 2-6 hours. A breach handler "
            "or alert sink must be present."
        ),
        "patterns": [
            "breach_notify", "incident_alert", "report_breach",
            "soc_alert", "rbi_notify",
        ],
        "severity": "MEDIUM",
    },
]


IT_ACT_RULES: List[Dict[str, Any]] = [
    {
        "id": "IT-43A",
        "act": "Information Technology Act, 2000 (as amended 2008)",
        "section": "Section 43A — Compensation for failure to protect SPDI",
        "rule": "Reasonable security practices for sensitive personal data",
        "description": (
            "Body corporates must implement reasonable security practices "
            "covering sensitive personal data or information (SPDI)."
        ),
        "patterns": [
            "phi_raw", "patient_name", "ssn_plain",
            "raw_password", "raw_card", "plain_card",
        ],
        "severity": "CRITICAL",
    },
    {
        "id": "IT-66C",
        "act": "Information Technology Act, 2000 (as amended 2008)",
        "section": "Section 66C — Identity theft",
        "rule": "No credential harvesting / no public exposure of auth tokens",
        "description": (
            "Code that exfiltrates, stores, or transmits another person's "
            "credentials without consent is a Section 66C violation."
        ),
        "patterns": [
            "harvest_creds", "collect_tokens", "steal_session",
            "raw_session_id =", "exfiltrate_token",
        ],
        "severity": "HIGH",
    },
    {
        "id": "IT-66E",
        "act": "Information Technology Act, 2000 (as amended 2008)",
        "section": "Section 66E — Violation of privacy",
        "rule": "No covert capture / transmission of private user data",
        "description": (
            "Capturing or transmitting private user data without consent is a "
            "Section 66E violation."
        ),
        "patterns": [
            "secret_capture", "hidden_capture", "spy_on_user",
            "private_log", "eavesdrop_user",
        ],
        "severity": "HIGH",
    },
    {
        "id": "IT-72",
        "act": "Information Technology Act, 2000 (as amended 2008)",
        "section": "Section 72 — Breach of confidentiality",
        "rule": "No unauthorized access logging of personal data",
        "description": (
            "Code that accesses or logs personal data without authorization "
            "violates Section 72."
        ),
        "patterns": [
            "log_user_data =", "dump_user_data(", "read_user_table",
            "select_creds",
        ],
        "severity": "HIGH",
    },
    {
        "id": "IT-SPDI",
        "act": "IT Act SPDI Rules (2011)",
        "section": "Rule 4 — Privacy policy publication",
        "rule": "Privacy policy must be published on website",
        "description": (
            "A body corporate handling SPDI must publish a privacy policy."
        ),
        "patterns": [
            "privacy-policy", "privacy_policy", "/privacy",
        ],
        "severity": "MEDIUM",
    },
    {
        "id": "IT-GOV",
        "act": "IT Act SPDI Rules (2011)",
        "section": "Rule 5 — Grievance officer",
        "rule": "Grievance officer contact must be published",
        "description": (
            "A grievance officer and contact details must be published."
        ),
        "patterns": [
            "grievance_officer", "grievance@", "/grievance",
        ],
        "severity": "LOW",
    },
]


# ---------------------------------------------------------------------------
# Sector → list of canonical rule-sets. A scan can match any sector whose
# sector id appears in this map. Multiple rule-sets are concatenated; this
# lets the user pick `indian_banking` and get both RBI and DPDP coverage.
# ---------------------------------------------------------------------------

CANONICAL_RULESETS: Dict[str, List[Dict[str, Any]]] = {
    "rbi_fintech": RBI_FINTECH_RULES,
    "sebi_stock_market": SEBI_STOCK_MARKET_RULES,
    "ecommerce_india": ECOMMERCE_RULES,
    "saas_india": SAAS_INDIA_RULES,
}


def _canonical_text_path(filename: str) -> str:
    """Absolute path to a canonical-text file in this package."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "canonical_texts", filename)


def get_canonical_text(sector: str) -> str:
    """
    Return the canonical policy text for a given sector, suitable for inclusion
    in the audit report's "Applicable Jurisdiction" section. Returns an empty
    string if the sector has no canonical text.
    """
    sector = (sector or "").lower()
    mapping = {
        "rbi_fintech": "supplied_sector_control_packs.md",
        "sebi_stock_market": "supplied_sector_control_packs.md",
        "ecommerce_india": "supplied_sector_control_packs.md",
        "saas_india": "supplied_sector_control_packs.md",
    }
    fname = mapping.get(sector)
    if not fname:
        return ""
    filenames = [fname]
    if sector == "saas_india":
        filenames.extend(["dpdp_act_2023.md", "meity_dpdp_rules_2025_controls.md"])
    try:
        texts = []
        for filename in filenames:
            path = _canonical_text_path(filename)
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    texts.append(f.read())
        return "\n\n".join(texts)
    except Exception:
        return ""


def get_canonical_rules(sector: str) -> List[Dict[str, Any]]:
    """
    Return the list of canonical rules (DPDP/RBI/IT Act) for a sector. Always
    returns a list (possibly empty).
    """
    sector = (sector or "").lower()
    return list(CANONICAL_RULESETS.get(sector, []))


def list_supported_sectors() -> List[str]:
    """
    Return all sectors the canonical loader knows about. The policy checker
    and the frontend sector dropdown should consume this list.
    """
    return sorted(CANONICAL_RULESETS.keys())


def migrate_to_db(skip_init: bool = False) -> int:
    """
    Migrate canonical rules (DPDP, RBI, IT Act) into the policy_rules table.
    Idempotent: uses ON CONFLICT on (act, section, rule_id).
    Returns the number of rules upserted.
    """
    from app.models.policy_rules import PolicyRulesRepository
    from app.core.database import init_db as db_init

    if not skip_init:
        db_init()

    # Build flat list of all canonical rules with regulator/sector tags
    # Deduplicate by (act, section, rule_id) since same rule appears in multiple sectors
    rules_to_migrate = []
    seen_keys = set()
    sector_regulator_map = {
        "rbi_fintech": "RBI",
        "sebi_stock_market": "SEBI",
        "ecommerce_india": "CONSUMER_AFFAIRS",
        "saas_india": "CERT_IN_DPDP",
    }

    for sector, rule_list in CANONICAL_RULESETS.items():
        regulator = sector_regulator_map.get(sector, "GENERIC")
        sector_tags = [sector]
        # Sector packs are intentionally isolated; do not leak controls into
        # a different regulatory context.

        for rule in rule_list:
            # Deduplicate by (act, section, rule_id) since same rule appears in multiple sectors
            key = (rule.get("act", ""), rule.get("section", ""), rule.get("id", ""))
            if key in seen_keys:
                continue
            seen_keys.add(key)

            rules_to_migrate.append({
                "regulator": regulator,
                "act": rule.get("act", ""),
                "section": rule.get("section", ""),
                "rule_id": rule.get("id", ""),
                "rule_text": rule.get("rule", ""),
                "patterns_json": rule.get("patterns", []),
                "severity": rule.get("severity", "MEDIUM"),
                "sector_tags_json": sector_tags,
                "source": "canonical",
                "is_canonical": True,
            })

    return PolicyRulesRepository.upsert_many(rules_to_migrate)


# ---------------------------------------------------------------------------
# Optional helper: when the user uploads a company policy, we still want to
# cite the *applicable* Act section for any violation we find. This mapper
# does a lightweight keyword match (case-insensitive) to attach the right
# section citation to a finding.
# ---------------------------------------------------------------------------

_ACT_CITATION_INDEX: List[Dict[str, Any]] = []


def _build_citation_index() -> List[Dict[str, Any]]:
    if _ACT_CITATION_INDEX:
        return _ACT_CITATION_INDEX
    for rule_set in (DPDP_RULES, RBI_RULES, IT_ACT_RULES):
        for r in rule_set:
            for pat in r.get("patterns", []):
                _ACT_CITATION_INDEX.append({
                    "keyword": pat.lower(),
                    "act": r["act"],
                    "section": r["section"],
                    "rule_id": r["id"],
                })
    return _ACT_CITATION_INDEX


def cite_for_pattern(evidence: str) -> Dict[str, str]:
    """
    Given a piece of evidence (a code line, an error string, etc.), return the
    Act citation that best explains why that evidence is a problem. Returns
    an empty dict if no citation matches.
    """
    if not evidence:
        return {}
    ev = evidence.lower()
    for entry in _build_citation_index():
        if entry["keyword"] in ev:
            return {
                "act": entry["act"],
                "section": entry["section"],
                "rule_id": entry["rule_id"],
            }
    return {}
