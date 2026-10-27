import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.services.remediation_service import RemediationService
from app.services.audit_log_service import AuditLogService

router = APIRouter()


@router.post("/{scan_id}/generate")
def generate_remediation(scan_id: str):
    try:
        return RemediationService.generate_bundle(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not build remediation bundle: {exc}")

@router.get("/{scan_id}")
def get_remediation_status(scan_id: str):
    if not re.fullmatch(r"SCAN-[A-Za-z0-9-]+", scan_id or ""):
        raise HTTPException(status_code=400, detail="Invalid scan identifier.")
    plan_path = RemediationService._workspace(scan_id) / "remediation_plan.json"
    if not plan_path.exists():
        # A completed scan does not have a remediation plan until the user
        # starts the generation request. This is a valid pre-generation state,
        # not an API failure, so keep polling/UI state free of noisy 404s.
        return {
            "scan_id": scan_id,
            "findings_before": None,
            "failed_controls_before": None,
            "changes_applied": 0,
            "llm_error": None,
            "generation_mode": None,
            "has_bundle": False,
            "status": "NOT_GENERATED",
        }
    import json
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    return {
        "scan_id": scan_id,
        "findings_before": len(plan.get("source_findings", [])),
        "failed_controls_before": len(plan.get("failed_policy_checks", [])),
        "changes_applied": len(plan.get("applied_changes", [])),
        "recommendations_count": len(plan.get("llm_recommendations", [])),
        "patches_proposed": len(plan.get("llm_patches", [])),
        "patches_rejected": len(plan.get("patch_rejections", [])),
        "llm_error": plan.get("llm_error"),
        "generation_mode": plan.get("generation_mode"),
        "has_bundle": (RemediationService._workspace(scan_id) / "sentinelai_remediation_bundle.zip").exists(),
        "status": "GENERATED",
    }


@router.get("/{scan_id}/download")
def download_remediation_bundle(scan_id: str):
    if not re.fullmatch(r"SCAN-[A-Za-z0-9-]+", scan_id or ""):
        raise HTTPException(status_code=400, detail="Invalid scan identifier.")
    workspace = RemediationService._workspace(scan_id)
    path = workspace / "sentinelai_remediation_bundle.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Generate a remediation bundle first.")
    AuditLogService.log_event(
        scan_id=scan_id,
        stage="LLM_REMEDIATION",
        event_type="REMEDIATION_BUNDLE_DOWNLOAD",
        message="Remediation ZIP prepared for user download; no repository changes or GitHub push performed.",
        tool_name="REMEDIATION_SERVICE",
    )
    return FileResponse(str(path), filename=f"sentinelai_remediation_{scan_id}.zip", media_type="application/zip")
