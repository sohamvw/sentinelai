from datetime import datetime

from app.models.scan import Scan


class ScanManager:
    _counter = 1

    @classmethod
    def create_scan(cls, repository_url: str) -> Scan:

        scan = Scan(
            scan_id=f"SCAN-{datetime.now():%Y%m%d}-{cls._counter:06d}",
            repository_url=repository_url,
            status="RECEIVED",
            stage="SCAN_CREATED",
            progress=0,
            created_at=datetime.now()
        )

        cls._counter += 1

        return scan