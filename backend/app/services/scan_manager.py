from datetime import datetime
from pathlib import Path

from app.models.scan import Scan


class ScanManager:
    _counter = 1
    WORKSPACE_ROOT = Path(__file__).resolve().parents[2] / "runtime" / "workspaces"

    @classmethod
    def create_scan(cls, repository_url: str) -> Scan:
        now = datetime.now()
        counter = cls._counter
        scan_id = f"SCAN-{now:%Y%m%d-%H%M%S}-{counter:04d}"

        while (cls.WORKSPACE_ROOT / scan_id).exists():
            counter += 1
            scan_id = f"SCAN-{now:%Y%m%d-%H%M%S}-{counter:04d}"

        scan = Scan(
            scan_id=scan_id,
            repository_url=repository_url,
            status="RECEIVED",
            stage="SCAN_CREATED",
            progress=0,
            created_at=now
        )

        cls._counter = counter + 1

        return scan
