import json
from pathlib import Path

from app.models.repository_model import RepositoryModel


class RepositoryModelService:

    @staticmethod
    def save(
        model: RepositoryModel,
        workspace: str
    ):

        output = Path(workspace) / "repository_model.json"

        with open(
            output,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                model.model_dump(
                    mode="json"
                ),
                file,
                indent=4
            )

        return output