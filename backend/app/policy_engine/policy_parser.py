import re
import logging
from typing import List, Dict, Any
from app.services.llm_provider_service import LLMProviderService

logger = logging.getLogger(__name__)

class PolicyParser:

    @staticmethod
    def parse_policy_document(policy_content: str, filename: str = "policy.txt") -> List[Dict[str, Any]]:
        """
        Parses an uploaded policy document (Plain Text / Markdown / PDF content)
        into discrete structured policy rules using LLM assistance with fallback regex extraction.
        """
        if not policy_content or len(policy_content.strip()) < 10:
            return []

        prompt = f"""
Extract discrete, testable security & compliance rules from the following uploaded company policy document.
Return ONLY a valid JSON list of objects with the fields:
- "id": short string rule ID (e.g. "POL-001")
- "rule": clear rule title (e.g. "No plaintext password storage")
- "category": section or compliance standard
- "description": concise description of what code patterns violate this
- "patterns": list of 2-5 keyword strings or code idioms to search for
- "severity": "CRITICAL", "HIGH", "MEDIUM", or "LOW"

POLICY DOCUMENT CONTENT ({filename}):
---
{policy_content[:4000]}
---
        """
        
        try:
            llm_response = LLMProviderService.call_llm(prompt, json_mode=True)
            json_match = re.search(r'\[.*\]', llm_response, re.DOTALL)
            if json_match:
                import json
                rules = json.loads(json_match.group(0))
                if isinstance(rules, list):
                    return rules
        except Exception as e:
            logger.warning(f"LLM policy parsing failed, utilizing rule extraction fallback: {str(e)}")

        # Heuristic fallback parsing if LLM is unavailable or unparseable
        extracted_rules = []
        lines = policy_content.splitlines()
        rule_idx = 1
        for line in lines:
            line_str = line.strip()
            if line_str.startswith(("-", "*", "1.", "2.", "3.", "Rule:", "MUST", "SHALL")):
                extracted_rules.append({
                    "id": f"POL-{rule_idx:03d}",
                    "rule": line_str.lstrip("-*123456789. ").strip(),
                    "category": "Uploaded Company Policy",
                    "description": line_str,
                    "patterns": [word.lower() for word in line_str.split() if len(word) > 4][:3],
                    "severity": "HIGH"
                })
                rule_idx += 1

        return extracted_rules
