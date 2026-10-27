from collections import Counter

from app.knowledge.models.evidence import Evidence
from app.knowledge.models.repository_knowledge import RepositoryKnowledge
from app.models.repository_model import RepositoryModel


class KnowledgeBuilder:

    @staticmethod
    def build(
        model: RepositoryModel,
        evidence: list[Evidence]
    ) -> RepositoryKnowledge:
        counts = Counter(item.category for item in evidence)

        dependencies = {
            str(item.value): str(item.metadata.get("version", ""))
            for item in evidence
            if item.category == "dependency"
        }

        security_findings = [
            {
                "signal": item.signal,
                "value": item.value,
                "source": item.source_path,
                "confidence": item.confidence,
            }
            for item in evidence
            if item.category == "security"
        ]

        knowledge = RepositoryKnowledge(
            repository={
                "owner": model.owner,
                "name": model.name,
                "remote_url": model.remote_url,
                "default_branch": model.default_branch,
                "current_commit": model.current_commit,
            },
            languages=KnowledgeBuilder._values(evidence, "language"),
            frameworks=KnowledgeBuilder._values(evidence, "framework"),
            databases=KnowledgeBuilder._values(evidence, "database"),
            cloud_services=KnowledgeBuilder._values(evidence, "cloud"),
            containers=KnowledgeBuilder._values(evidence, "container"),
            ci_cd=KnowledgeBuilder._values(evidence, "ci_cd"),
            package_managers=KnowledgeBuilder._values(evidence, "package_manager"),
            dependencies=dependencies,
            api_endpoints=model.api_endpoints,
            security_findings=security_findings,
            important_files=KnowledgeBuilder._sources(evidence, "important_file"),
            evidence_counts=dict(sorted(counts.items())),
            confidence=KnowledgeBuilder._confidence(evidence),
        )

        knowledge.risk_score = KnowledgeBuilder._risk_score(knowledge, model)
        knowledge.risk_level = KnowledgeBuilder._risk_level(knowledge.risk_score)
        knowledge.summary = KnowledgeBuilder._summary(knowledge, model)

        model.frameworks.update(knowledge.frameworks)
        model.databases.update(knowledge.databases)
        model.containers.update(knowledge.containers)
        model.ci_cd.update(knowledge.ci_cd)
        model.dependencies.update(knowledge.dependencies)

        return knowledge

    @staticmethod
    def _values(evidence: list[Evidence], category: str) -> list[str]:
        return sorted(
            {
                str(item.value)
                for item in evidence
                if item.category == category and item.value
            }
        )

    @staticmethod
    def _sources(evidence: list[Evidence], category: str) -> list[str]:
        return sorted(
            {
                item.source_path
                for item in evidence
                if item.category == category and item.source_path
            }
        )

    @staticmethod
    def _confidence(evidence: list[Evidence]) -> float:
        if not evidence:
            return 0.0

        return round(
            sum(item.confidence for item in evidence) / len(evidence),
            2
        )

    @staticmethod
    def _risk_score(knowledge: RepositoryKnowledge, model: RepositoryModel) -> int:
        score = 10
        score += min(len(knowledge.security_findings) * 12, 45)

        if knowledge.api_endpoints and not KnowledgeBuilder._has_auth_evidence(model):
            score += 15

        if not knowledge.ci_cd:
            score += 5

        if not any("test" in path.lower() for path in model.files):
            score += 5

        return min(score, 100)

    @staticmethod
    def _has_auth_evidence(model: RepositoryModel) -> bool:
        auth_terms = {
            "jwt",
            "passport",
            "bcrypt",
            "auth",
            "security",
        }

        dependency_names = {name.lower() for name in model.dependencies}

        return any(
            any(term in name for term in auth_terms)
            for name in dependency_names
        )

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def _summary(knowledge: RepositoryKnowledge, model: RepositoryModel) -> str:
        stack = ", ".join(knowledge.frameworks[:4]) or ", ".join(knowledge.languages[:4]) or "Unknown stack"

        return (
            f"{model.name or 'Repository'} contains {model.total_files} files, "
            f"{len(knowledge.dependencies)} dependencies, "
            f"{len(knowledge.api_endpoints)} API endpoints, and a {knowledge.risk_level} "
            f"risk profile. Primary stack: {stack}."
        )
