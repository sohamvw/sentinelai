from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

from app.models.scan import Scan


@dataclass
class PipelineContext:
    """
    Carries the complete state of a repository analysis pipeline.
    Every module enriches this object instead of returning
    disconnected values.
    """

    scan: Scan

    repository_path: Optional[Path] = None

    repository_model: Optional[Any] = None

    evidence: list[Any] = field(default_factory=list)

    repository_knowledge: Optional[Any] = None

    digital_twin: Optional[Any] = None

    execution_plan: Optional[Any] = None

    adaptive_decision: Optional[Any] = None

    metadata: Dict[str, Any] = field(default_factory=dict)

    logs: list[str] = field(default_factory=list)

    def log(self, message: str):

        self.logs.append(message)
