from fastapi import APIRouter
from typing import Optional, List
from app.services.audit_log_service import AuditLogService

router = APIRouter()


@router.get("")
def get_audit_logs(scan_id: Optional[str] = None, limit: int = 100):
    logs = AuditLogService.get_logs(scan_id=scan_id, limit=limit)
    return {
        "count": len(logs),
        "logs": logs
    }
