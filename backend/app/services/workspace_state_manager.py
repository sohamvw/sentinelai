import json
from datetime import datetime
from pathlib import Path

from app.models.scan import Scan


class WorkspaceStateManager:

    FILE_NAME = "state.json"

    @classmethod
    def initialize(cls, scan: Scan):

        workspace = Path(scan.workspace)

        state = {
            "scan_id": scan.scan_id,
            "repository_url": scan.repository_url,
            "status": scan.status,
            "current_stage": "WORKSPACE_CREATED",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "completed_modules": [],
            "failed_module": None,
            "stack": None,
            "framework": None,
            "languages": [],
            "repository_model": False,
            "digital_twin": False,
            "decision_engine": False
        }

        with open(
            workspace / cls.FILE_NAME,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                state,
                file,
                indent=4
            )

    @classmethod
    def update_stage(
        cls,
        scan: Scan,
        stage: str
    ):

        workspace = Path(scan.workspace)
        file_path = workspace / cls.FILE_NAME

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            state = json.load(file)

        state["current_stage"] = stage
        state["updated_at"] = datetime.utcnow().isoformat()

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                state,
                file,
                indent=4
            )

    @classmethod
    def complete_module(
        cls,
        scan: Scan,
        module_name: str
    ):

        workspace = Path(scan.workspace)
        file_path = workspace / cls.FILE_NAME

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            state = json.load(file)

        if module_name not in state["completed_modules"]:
            state["completed_modules"].append(module_name)

        state["updated_at"] = datetime.utcnow().isoformat()

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                state,
                file,
                indent=4
            )

    @classmethod
    def update_values(
        cls,
        scan: Scan,
        values: dict
    ):

        workspace = Path(scan.workspace)
        file_path = workspace / cls.FILE_NAME

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            state = json.load(file)

        state.update(values)
        state["updated_at"] = datetime.utcnow().isoformat()

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                state,
                file,
                indent=4
            )

    @classmethod
    def read_state(cls, scan_id: str) -> dict:
        workspace_dir = Path(__file__).resolve().parents[2] / "runtime" / "workspaces" / scan_id
        file_path = workspace_dir / cls.FILE_NAME
        if not file_path.exists():
            return None
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                return json.load(file)
        except Exception:
            return None

