from typing import Any

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    evidence_id: str
    category: str
    signal: str
    value: Any
    source_path: str = ""
    confidence: float = 1.0
    metadata: dict[str, Any] = Field(default_factory=dict)
