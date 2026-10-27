from app.knowledge.models.repository_knowledge import RepositoryKnowledge
from app.orchestration.models import AdaptiveDecision


class AdaptiveDecisionEngine:

    @staticmethod
    def run(
        knowledge: RepositoryKnowledge,
        digital_twin: dict
    ) -> AdaptiveDecision:
        decision = AdaptiveDecision(
            risk_level=knowledge.risk_level,
            checkpoints=[
                "repository_cloned",
                "repository_discovered",
                "repository_model_created",
                "repository_parsed",
                "evidence_collected",
                "knowledge_built",
                "digital_twin_created",
                "adaptive_decision_ready",
            ],
        )

        languages = set(knowledge.languages)
        package_managers = set(knowledge.package_managers)

        if "Python" in languages:
            decision.selected_modules.append("bandit_python_sast")
            decision.rationale.append("Python files detected, so Python SAST should run next.")

        if {"JavaScript", "TypeScript", "React"} & languages:
            decision.selected_modules.append("semgrep_javascript_rules")
            decision.rationale.append("JavaScript/TypeScript surface detected.")

        if "npm" in package_managers:
            decision.selected_modules.append("npm_dependency_audit")

        if "pip" in package_managers:
            decision.selected_modules.append("pip_dependency_audit")

        if knowledge.containers:
            decision.selected_modules.append("container_config_scan")

        if knowledge.api_endpoints:
            decision.selected_modules.append("api_security_review")

        if knowledge.security_findings:
            decision.selected_modules.append("secret_and_dangerous_pattern_review")
            decision.rationale.append("Security evidence exists and needs manual confirmation.")

        if knowledge.risk_level in {"HIGH", "CRITICAL"}:
            decision.selected_modules.append("human_security_checkpoint")

        if not knowledge.cloud_services:
            decision.skipped_modules.append(
                {
                    "module": "cloud_security_scan",
                    "reason": "No cloud configuration evidence was found.",
                }
            )

        if not knowledge.containers:
            decision.skipped_modules.append(
                {
                    "module": "trivy_container_scan",
                    "reason": "No Docker or compose file was found.",
                }
            )

        if not decision.selected_modules:
            decision.selected_modules.append("baseline_semgrep_scan")
            decision.rationale.append("No specific stack was detected, so baseline rules are safest.")

        decision.next_steps = AdaptiveDecisionEngine._next_steps(knowledge, digital_twin)

        return decision

    @staticmethod
    def _next_steps(
        knowledge: RepositoryKnowledge,
        digital_twin: dict
    ) -> list[str]:
        steps = [
            "Run the selected lightweight scanners and store their findings under the scan workspace.",
            "Map findings to OWASP and CWE identifiers.",
            "Generate fix suggestions only after scanner evidence is confirmed.",
        ]

        if digital_twin["risk_surface"]["api_endpoints"]:
            steps.append("Prioritize API authentication, validation, and authorization checks.")

        if knowledge.security_findings:
            steps.insert(0, "Review possible hardcoded secrets before sharing reports.")

        return steps
