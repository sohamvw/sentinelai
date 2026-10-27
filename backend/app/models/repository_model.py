from pydantic import BaseModel, Field

from app.models.file_object import FileObject
from app.models.parser_result import ParserResult


class RepositoryModel(BaseModel):

    # -------------------------------------------------
    # Repository Metadata
    # -------------------------------------------------

    name: str = ""
    owner: str = ""
    remote_url: str = ""
    default_branch: str = ""
    current_commit: str = ""
    license: str = ""

    # -------------------------------------------------
    # Repository Contents
    # -------------------------------------------------

    files: dict[str, FileObject] = Field(
        default_factory=dict
    )

    directories: list[str] = Field(
        default_factory=list
    )

    parsed_files: dict[str, ParserResult] = Field(
        default_factory=dict
    )

    # -------------------------------------------------
    # Technologies
    # -------------------------------------------------

    languages: set[str] = Field(
        default_factory=set
    )

    frameworks: set[str] = Field(
        default_factory=set
    )

    databases: set[str] = Field(
        default_factory=set
    )

    cloud_services: set[str] = Field(
        default_factory=set
    )

    containers: set[str] = Field(
        default_factory=set
    )

    ci_cd: set[str] = Field(
        default_factory=set
    )

    # -------------------------------------------------
    # Dependencies
    # -------------------------------------------------

    dependencies: dict[str, str] = Field(
        default_factory=dict
    )

    # -------------------------------------------------
    # Components
    # -------------------------------------------------

    controllers: list[str] = Field(
        default_factory=list
    )

    services: list[str] = Field(
        default_factory=list
    )

    repositories: list[str] = Field(
        default_factory=list
    )

    middlewares: list[str] = Field(
        default_factory=list
    )

    utilities: list[str] = Field(
        default_factory=list
    )

    # -------------------------------------------------
    # API
    # -------------------------------------------------

    api_endpoints: list[dict] = Field(
        default_factory=list
    )

    # -------------------------------------------------
    # Relationships
    # -------------------------------------------------

    relationship_graph: dict[str, list[str]] = Field(
        default_factory=dict
    )

    # -------------------------------------------------
    # Statistics
    # -------------------------------------------------

    total_files: int = 0
    total_directories: int = 0
    total_lines: int = 0
    total_size: int = 0

    warnings: list[dict] = Field(
        default_factory=list
    )
