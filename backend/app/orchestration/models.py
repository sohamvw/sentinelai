from pydantic import BaseModel, Field


class AdaptiveDecision(BaseModel):
    mode: str = "LIGHTWEIGHT_LOCAL_PIPELINE"
    risk_level: str = "LOW"
    selected_modules: list[str] = Field(default_factory=list)
    skipped_modules: list[dict[str, str]] = Field(default_factory=list)
    checkpoints: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
