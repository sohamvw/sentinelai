from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import json
from pathlib import Path

AUDIT_LOGS_STORE: List[Dict[str, Any]] = []
AUDIT_LOG_PATH = Path(__file__).resolve().parents[2] / "runtime" / "audit_logs.jsonl"

try:
    if AUDIT_LOG_PATH.exists():
        for line in AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines():
            if line.strip():
                AUDIT_LOGS_STORE.append(json.loads(line))
except (OSError, ValueError):
    AUDIT_LOGS_STORE.clear()


class AuditLogService:

    @staticmethod
    def log_event(
        scan_id: str,
        stage: str,
        event_type: str,
        message: str,
        tool_name: Optional[str] = None,
        model_used: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:

        log_entry = {
            "id": f"LOG-{len(AUDIT_LOGS_STORE) + 1:05d}",
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "event_type": event_type,
            "tool_name": tool_name or "SYSTEM",
            "model_used": model_used or "NONE",
            "message": message,
            "payload": payload or {}
        }

        AUDIT_LOGS_STORE.append(log_entry)
        try:
            AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with AUDIT_LOG_PATH.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        except OSError:
            # Logging must never interrupt a scan if the persistence volume is unavailable.
            pass
        print(f"[{log_entry['timestamp']}] [{scan_id}] [{stage}] {tool_name or 'SYSTEM'} - {message}")
        return log_entry

    @staticmethod
    def get_logs(scan_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        if scan_id:
            filtered = [log for log in AUDIT_LOGS_STORE if log["scan_id"] == scan_id]
            return filtered[-limit:]
        return AUDIT_LOGS_STORE[-limit:]

    @staticmethod
    def clear_logs():
        AUDIT_LOGS_STORE.clear()
        try:
            AUDIT_LOG_PATH.unlink(missing_ok=True)
        except OSError:
            pass
