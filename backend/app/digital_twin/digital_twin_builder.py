from app.knowledge.models.repository_knowledge import RepositoryKnowledge


class DigitalTwinBuilder:

    @staticmethod
    def build(knowledge: RepositoryKnowledge) -> dict:
        nodes = []
        edges = []

        repository_name = knowledge.repository.get("name") or "repository"
        nodes.append({"id": repository_name, "type": "repository", "label": repository_name})

        for language in knowledge.languages:
            node_id = f"language:{language}"
            nodes.append({"id": node_id, "type": "language", "label": language})
            edges.append({"from": repository_name, "to": node_id, "relationship": "uses"})

        for framework in knowledge.frameworks:
            node_id = f"framework:{framework}"
            nodes.append({"id": node_id, "type": "framework", "label": framework})
            edges.append({"from": repository_name, "to": node_id, "relationship": "runs_on"})

        for database in knowledge.databases:
            node_id = f"database:{database}"
            nodes.append({"id": node_id, "type": "database", "label": database})
            edges.append({"from": repository_name, "to": node_id, "relationship": "persists_to"})

        for endpoint in knowledge.api_endpoints:
            label = f"{endpoint.get('method', '').upper()} {endpoint.get('path', '')}".strip()
            node_id = f"api:{label}"
            nodes.append({"id": node_id, "type": "api_endpoint", "label": label})
            edges.append({"from": repository_name, "to": node_id, "relationship": "exposes"})

        return {
            "repository": repository_name,
            "risk_surface": {
                "api_endpoints": len(knowledge.api_endpoints),
                "security_findings": len(knowledge.security_findings),
                "dependencies": len(knowledge.dependencies),
                "risk_level": knowledge.risk_level,
            },
            "nodes": nodes,
            "edges": edges,
        }
