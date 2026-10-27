from pathlib import Path

from app.models.scan import Scan


class WorkspaceManager:

    ROOT = Path(__file__).resolve().parents[2] / "runtime" / "workspaces"

    FOLDERS = [
        "repository",
        "blueprint",
        "findings",
        "reports",
        "logs"
    ]

    @classmethod
    def create_workspace(cls, scan: Scan):

        workspace = cls.ROOT / scan.scan_id

        for folder in cls.FOLDERS:

            (workspace / folder).mkdir(
                parents=True,
                exist_ok=True
            )

        return workspace
