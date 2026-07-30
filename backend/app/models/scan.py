from dataclasses import dataclass
from datetime import datetime


@dataclass
class Scan:
    scan_id: str
    repository_url: str
    status: str
    stage: str
    progress: int
    created_at: datetime
    workspace: str = ""