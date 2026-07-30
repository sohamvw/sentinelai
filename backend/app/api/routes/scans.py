from fastapi import APIRouter

from app.schemas.scan_request import ScanRequest
from app.schemas.scan_response import ScanResponse
from app.services.scan_service import ScanService

router = APIRouter()


@router.post(
    "",
    response_model=ScanResponse
)
def create_scan(request: ScanRequest):

    return ScanService.create_scan(request)