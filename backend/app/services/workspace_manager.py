from pathlib import Path

from app.models.scan import Scan


class WorkspaceManager:

    ROOT = Path("runtime/workspaces")

    @classmethod
    def create_workspace(cls, scan: Scan):

        workspace = cls.ROOT / scan.scan_id

        folders = [
            "repository",
            "blueprint",
            "findings",
            "reports",
            "logs"
        ]

        for folder in folders:
            (workspace / folder).mkdir(
                parents=True,
                exist_ok=True
            )

        return workspace