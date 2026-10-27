from typing import Any

from pydantic import BaseModel, Field


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    stage: str = ""
    progress: int = 0
    workspace: str = ""
    artifacts: dict[str, str] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    knowledge: dict[str, Any] = Field(default_factory=dict)
    decision: dict[str, Any] = Field(default_factory=dict)
