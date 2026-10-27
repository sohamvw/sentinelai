import os
import re
from typing import List, Dict, Any
from app.policy_engine.sector_baselines import get_sector_baseline
from app.policy_engine.policy_parser import PolicyParser
from app.policy_engine.canonical_policy_loader import (
    get_canonical_text,
    get_canonical_rules,
    cite_for_pattern,
    list_supported_sectors,
)
from app.models.policy_rules import PolicyRulesRepository

class PolicyChecker:

    @staticmethod
    def evaluate_repository(
        sector: str,
        uploaded_policy_text: str = "",
        policy_filename: str = "uploaded_policy.txt",
        repository_files: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Cross-references extracted custom policy rules + sector baseline ruleset
        against the repository files (parsed AST / file tree representation).
        For Indian sectors (indian_dpdp, indian_banking, indian_general, etc.),
        the baseline is loaded from the policy_rules database table (seeded from
        canonical DPDP/RBI/IT Act texts on startup) and each violation is
        annotated with the Act citation (act + section).
        """
        repository_files = repository_files or {}

        # 1. Load sector baseline from DB (with fallback to canonical loader)
        stored_rules = PolicyRulesRepository.get_by_sector(sector)
        # The versioned, in-repository baseline must always be included.  DB
        # rules are a cache/supplement, not a replacement that can silently
        # hide newer active controls after a control-pack update.
        baseline_rules = get_canonical_rules(sector) + stored_rules

        # 2. Parse uploaded policy document if provided
        extracted_rules = []
        policy_source = "sector_baseline"
        if uploaded_policy_text and uploaded_policy_text.strip():
            extracted_rules = PolicyParser.parse_policy_document(uploaded_policy_text, policy_filename)
            policy_source = "uploaded"

        # Combine rulesets (uploaded policy takes precedence, sector baseline supplements)
        # Note: extracted_rules from PolicyParser have different structure - they use "rule" key
        # while DB rules use "rule_text". Normalize here.
        normalized_baseline = []
        seen_baseline_ids = set()
        for b in baseline_rules:
            normalized = {
                "id": b.get("rule_id", "") or b.get("id", ""),
                "rule": b.get("rule_text", "") or b.get("rule", ""),
                "act": b.get("act", ""),
                "section": b.get("section", ""),
                "patterns": b.get("patterns_json", []) or b.get("patterns", []),
                "severity": b.get("severity", "MEDIUM"),
                "rule_id": b.get("rule_id", "") or b.get("id", ""),
            }
            dedupe_key = normalized["rule_id"] or normalized["rule"]
            if dedupe_key and dedupe_key in seen_baseline_ids:
                continue
            if dedupe_key:
                seen_baseline_ids.add(dedupe_key)
            normalized_baseline.append(normalized)

        all_rules = extracted_rules + [
            b for b in normalized_baseline
            if b["rule"] not in [e.get("rule") for e in extracted_rules]
        ]

        checks = []

        if not repository_files:
            raise ValueError("Compliance evaluation requires files from a cloned or uploaded repository.")

        # 3. Cross-reference rules against codebase AST / files
        for rule in all_rules:
            patterns = rule.get("patterns", [])
            rule_title = rule.get("rule", "Security & Compliance Check")
            rule_id = rule.get("id", "") or rule.get("rule_id", "")
            act = rule.get("act", "")
            section = rule.get("section", rule.get("category", ""))
            found_violation = False
            # A small group of controls describe a required, discoverable
            # capability (for example a privacy-notice route). For those,
            # finding the marker is positive evidence, not a violation.
            required_capability = "must exist" in rule_title.lower()
            capability_evidence = None

            for file_path, file_content in repository_files.items():
                if not file_content:
                    continue

                lines = file_content.splitlines()
                for line_num, line in enumerate(lines, 1):
                    for pat in patterns:
                        if pat.lower() in line.lower():
                            if required_capability:
                                capability_evidence = (file_path, line_num, line.strip())
                                break
                            found_violation = True
                            evidence = line.strip()
                            # For sectors whose rules don't ship with their own
                            # `act` / `section` (e.g. user-uploaded rules), try
                            # to cite the canonical Act that this evidence maps
                            # to. Falls back to whatever the rule itself
                            # declares.
                            citation = cite_for_pattern(evidence) if not act else {
                                "act": act, "section": section, "rule_id": rule_id,
                            }
                            checks.append({
                                "rule": rule_title,
                                "rule_id": rule_id,
                                "verdict": "violation",
                                "status": "FAIL",
                                "file_path": file_path,
                                "line_number": line_num,
                                "evidence": evidence,
                                "act": citation.get("act", act),
                                "section": citation.get("section", section),
                                "severity": rule.get("severity", "MEDIUM"),
                            })
                            break
                    if found_violation:
                        break
                if found_violation:
                    break

            if required_capability and capability_evidence:
                file_path, line_num, evidence = capability_evidence
                checks.append({
                    "rule": rule_title,
                    "rule_id": rule_id,
                    "verdict": "compliant",
                    "status": "PASS",
                    "file_path": file_path,
                    "line_number": line_num,
                    "evidence": evidence,
                    "act": act,
                    "section": section,
                    "severity": rule.get("severity", "MEDIUM"),
                })
            elif not found_violation:
                checks.append({
                    "rule": rule_title,
                    "rule_id": rule_id,
                    # A source scan cannot establish organization-wide legal
                    # compliance merely because a string was absent. Preserve
                    # the uncertainty for a human/compliance review.
                    "verdict": "unknown",
                    "status": "UNKNOWN",
                    "file_path": None,
                    "line_number": None,
                    "evidence": "No direct repository evidence was found for this control; manual evidence or a richer control check is required.",
                    "act": act,
                    "section": section,
                    "severity": rule.get("severity", "MEDIUM"),
                })

        return {
            "sector": sector,
            "policy_source": policy_source,
            "uploaded_policy_filename": policy_filename if uploaded_policy_text and uploaded_policy_text.strip() else None,
            "uploaded_policy_text": uploaded_policy_text if uploaded_policy_text and uploaded_policy_text.strip() else "",
            "checks": checks,
            "applicable_canonical_text": get_canonical_text(sector),
            "applicable_act_count": len(get_canonical_rules(sector)),
        }
