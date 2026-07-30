from pydantic import BaseModel


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str