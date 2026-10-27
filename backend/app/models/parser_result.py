from pathlib import Path

from pydantic import BaseModel, Field


class ParserResult(BaseModel):

    path: str

    language: str

    parser: str

    imports: list[str] = Field(default_factory=list)

    classes: list[str] = Field(default_factory=list)

    functions: list[str] = Field(default_factory=list)

    variables: list[str] = Field(default_factory=list)

    api_routes: list[str] = Field(default_factory=list)

    metadata: dict = Field(default_factory=dict)