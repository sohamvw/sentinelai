from typing import Any

from pydantic import BaseModel, Field


class RepositoryKnowledge(BaseModel):
    repository: dict[str, str] = Field(default_factory=dict)
    summary: str = ""

    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    databases: list[str] = Field(default_factory=list)
    cloud_services: list[str] = Field(default_factory=list)
    containers: list[str] = Field(default_factory=list)
    ci_cd: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    dependencies: dict[str, str] = Field(default_factory=dict)

    api_endpoints: list[dict[str, Any]] = Field(default_factory=list)
    security_findings: list[dict[str, Any]] = Field(default_factory=list)
    important_files: list[str] = Field(default_factory=list)

    evidence_counts: dict[str, int] = Field(default_factory=dict)
    risk_score: int = 0
    risk_level: str = "LOW"
    confidence: float = 0.0
