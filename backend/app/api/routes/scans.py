import os
from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File, Form
from pathlib import Path
import uuid
from fastapi.responses import HTMLResponse, FileResponse
from app.schemas.scan_request import ScanRequest
from app.services.scan_service import ScanService
from app.policy_engine.canonical_policy_loader import list_supported_sectors

router = APIRouter()

# Resolve report paths against the project root rather than the current working
# directory (CWD-dependent lookups broke when the server was launched from another path).
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


@router.get("/sectors")
def list_sectors():
    """
    List only the four curated sector packs configured for SentinelAI. The
    frontend must not present a sector whose source controls are not loaded.
    """
    return {
        "sectors": list_supported_sectors(),
        "sector_packs": [
            {"key": "rbi_fintech", "label": "RBI FinTech & Digital Payments", "authority": "RBI"},
            {"key": "sebi_stock_market", "label": "SEBI Stock Market & Securities", "authority": "SEBI"},
            {"key": "ecommerce_india", "label": "India E-Commerce & Consumer Protection", "authority": "Department of Consumer Affairs"},
            {"key": "saas_india", "label": "India SaaS (CERT-In + DPDP)", "authority": "CERT-In / MeitY"},
        ],
    }

def _report_path(scan_id: str, filename: str) -> str:
    return os.path.join(PROJECT_ROOT, "runtime", "workspaces", scan_id, filename)



@router.post("")
def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    return ScanService.start_scan_async(request, background_tasks)

@router.post("/upload")
async def create_zip_scan(background_tasks: BackgroundTasks, repository: UploadFile = File(...), sector: str = Form("rbi_fintech"), policy_document_text: str = Form(""), policy_filename: str = Form("")):
    if not repository.filename or not repository.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Repository upload must be a .zip file.")
    data = await repository.read()
    if len(data) > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="ZIP file exceeds the 100 MB limit.")
    upload_dir = Path(PROJECT_ROOT) / "runtime" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    target = upload_dir / f"{uuid.uuid4().hex}.zip"
    target.write_bytes(data)
    request = ScanRequest(source_type="zip", repository_url=str(target), branch="main", sector=sector, policy_document_text=policy_document_text or None, policy_filename=policy_filename or repository.filename)
    return ScanService.start_scan_async(request, background_tasks)


@router.get("/latest/status")
def get_latest_scan_status():
    status = ScanService.get_latest_scan_status()
    if not status:
        return {"status": "NO_SCANS"}
    return status


@router.get("/{scan_id}")
def get_scan_status(scan_id: str):
    return ScanService.get_scan_status(scan_id)


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: str):
    return ScanService.cancel_scan(scan_id)





@router.get("/report/html")
def get_report_html(scan_id: str):
    html_path = _report_path(scan_id, "report.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    raise HTTPException(status_code=404, detail="HTML report not found.")


@router.get("/report/pdf")
def get_report_pdf(scan_id: str):
    pdf_path = _report_path(scan_id, "report.pdf")
    if os.path.exists(pdf_path):
        return FileResponse(pdf_path, filename=f"sentinelai_audit_report_{scan_id}.pdf", media_type="application/pdf")
    raise HTTPException(status_code=404, detail="PDF report not found.")
