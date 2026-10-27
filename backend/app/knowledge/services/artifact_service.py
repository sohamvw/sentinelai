import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class ArtifactService:

    @staticmethod
    def save_json(workspace: str, file_name: str, payload: Any) -> str:
        output = Path(workspace) / file_name

        with open(output, "w", encoding="utf-8") as file:
            json.dump(
                ArtifactService._to_json(payload),
                file,
                indent=4,
            )

        return str(output)

    @staticmethod
    def load_json(workspace: str, file_name: str) -> Any:
        file_path = Path(workspace) / file_name

        if not file_path.exists():
            return None

        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)

    @staticmethod
    def _to_json(payload: Any) -> Any:
        if isinstance(payload, BaseModel):
            return payload.model_dump(mode="json")

        if isinstance(payload, list):
            return [ArtifactService._to_json(item) for item in payload]

        if isinstance(payload, dict):
            return {
                key: ArtifactService._to_json(value)
                for key, value in payload.items()
            }

        return payload
