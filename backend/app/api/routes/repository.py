"""
Repository analysis endpoint for SentinelAI.

This endpoint handles Phase 1 repository intake - receiving GitHub URLs
or ZIP files, cloning them, and generating repository tree metadata.
"""
import os
import uuid
import json
import zipfile
import tempfile
import shutil
import subprocess
from pathlib import Path
from fastapi import APIRouter, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse

from app.services.phase1_tree_service import Phase1TreeService
from app.core.logger import get_logger

logger = get_logger(__name__)

router = APIRouter()

# Constants for scan workspace management
SCAN_BASE_DIR = Path(__file__).resolve().parents[3] / "runtime" / "workspaces"
MAX_ZIP_SIZE = 100 * 1024 * 1024  # 100MB max zip file
SUPPORTED_ARCHIVE_EXTENSIONS = {'.zip'}

# GitHub URL validation pattern
GITHUB_URL_PATTERN = r'^https?://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/tree/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)?$'
@router.post("/analyze")
async def analyze_repository(
    background_tasks: BackgroundTasks,
    github_url: str = None,
    archive_file: UploadFile = None,
):
    """
    Analyze a repository from GitHub URL or ZIP upload.

    This implements Phase 1 of the SentinelAI pipeline:
    1. Validate input (GitHub URL or ZIP)
    2. Create unique scan ID and workspace
    3. Clone repository safely
    4. Run Phase 1 tree analysis
    5. Generate tree.json with real data

    Args:
        github_url: GitHub repository URL (optional if using archive_file)
        archive_file: ZIP file upload (optional if using github_url)

    Returns:
        JSON with scan status, ID, and metadata
    """
    scan_id = str(uuid.uuid4())[:8]
    workspace_path = SCAN_BASE_DIR / f"SCAN-{scan_id}"

    try:
        # Validate input - exactly one of github_url or archive_file must be provided
        if not github_url and not archive_file:
            raise HTTPException(
                status_code=400,
                detail="Must provide either github_url or archive_file"
            )

        if github_url and archive_file:
            raise HTTPException(
                status_code=400,
                detail="Must provide only one of github_url or archive_file"
            )

        # Create isolated workspace
        workspace_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created workspace for scan {scan_id}: {workspace_path}")

        repository_path = None

        # Handle GitHub URL
        if github_url:
            if not _is_valid_github_url(github_url):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid GitHub URL: {github_url}"
                )

            logger.info(f"Processing GitHub URL for scan {scan_id}: {github_url}")
            repository_path = await _clone_from_github(github_url, workspace_path)

        # Handle ZIP file upload
        elif archive_file:
            logger.info(f"Processing ZIP upload for scan {scan_id}: {archive_file.filename}")
            repository_path = await _extract_zip(archive_file, workspace_path)

        # Ensure repository was successfully cloned/extracted
        if not repository_path or not Path(repository_path).exists():
            raise HTTPException(
                status_code=500,
                detail="Failed to extract repository"
            )

        # Run Phase 1 tree analysis
        logger.info(f"Running Phase 1 tree analysis for scan {scan_id}")
        tree_result = Phase1TreeService.build_tree(
            str(repository_path),
            str(workspace_path)
        )

        # Verify tree.json was created with real data
        tree_json_path = workspace_path / "tree.json"
        if not tree_json_path.exists():
            raise HTTPException(
                status_code=500,
                detail="Phase 1 tree analysis failed to generate tree.json"
            )

        # Load and validate tree.json content
        with open(tree_json_path, "r", encoding="utf-8") as f:
            tree_data = json.load(f)

        # Validate tree.json contains expected data
        if not tree_data.get("files") or len(tree_data["files"]) == 0:
            raise HTTPException(
                status_code=500,
                detail="tree.json contains no file entries"
            )

        # Get file count for verification
        total_files = tree_data.get("scan_metadata", {}).get("total_files", 0)
        if total_files == 0:
            logger.warning(f"Tree analysis completed but no files were found in scan {scan_id}")

        logger.info(
            f"Phase 1 analysis completed for scan {scan_id}: "
            f"{total_files} files analyzed, tree.json generated"
        )

        # Schedule workspace cleanup after scan is complete
        background_tasks.add_task(_cleanup_workspace, workspace_path)

        # Return success response with scan metadata
        return JSONResponse(
            status_code=200,
            content={
                "scan_id": scan_id,
                "status": "completed",
                "scan_metadata": tree_result["scan_metadata"],
                "summary": tree_result["summary"],
                "workspace_path": str(workspace_path),
                "tree_json_path": str(tree_json_path),
                "message": "Repository successfully analyzed and tree.json generated",
                "phase": "1"
            }
        )

    except HTTPException:
        # Clean up workspace on error
        if workspace_path.exists():
            shutil.rmtree(workspace_path, ignore_errors=True)
        raise

    except Exception as e:
        # Clean up workspace on unexpected error
        if workspace_path.exists():
            shutil.rmtree(workspace_path, ignore_errors=True)
        logger.error(f"Unexpected error during repository analysis for scan {scan_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Repository analysis failed: {str(e)}"
        )
def _is_valid_github_url(url: str) -> bool:
    """Validate GitHub URL format."""
    import re
    pattern = r'^https?://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/tree/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)?$'
    return bool(re.match(pattern, url))
async def _clone_from_github(github_url: str, workspace_path: Path) -> str:
    """Clone the supplied GitHub repository. No files are synthesized."""
    if shutil.which("git") is None:
        raise HTTPException(
            status_code=503,
            detail="Git is not installed or not available on PATH. Install Git for Windows before scanning repositories.",
        )
    repo_dir = workspace_path / "repository"
    result = subprocess.run(
        ["git", "clone", "--depth", "1", github_url, str(repo_dir)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0 or not repo_dir.is_dir():
        raise HTTPException(status_code=502, detail=result.stderr.strip() or "Git clone failed")
    logger.info(f"Cloned repository at: {repo_dir}")
    return str(repo_dir)
async def _extract_zip(archive_file: UploadFile, workspace_path: Path) -> str:
    """Extract ZIP file and return path to extracted repository."""
    try:
        # Validate file size
        archive_file.file.seek(0, 2)  # Seek to end
        file_size = archive_file.file.tell()
        archive_file.file.seek(0)  # Seek back to start

        if file_size > MAX_ZIP_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"ZIP file size ({file_size} bytes) exceeds maximum allowed size ({MAX_ZIP_SIZE} bytes)"
            )

        # Create repository directory
        repo_dir = workspace_path / "repository"
        repo_dir.mkdir(exist_ok=True)

        # Read ZIP content
        zip_content = await archive_file.read()

        # Extract ZIP file
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
            temp_zip.write(zip_content)
            temp_zip_path = temp_zip.name

        try:
            with zipfile.ZipFile(temp_zip_path, 'r') as zip_ref:
                # Extract all files
                zip_ref.extractall(repo_dir)

                # Validate that we got some files
                extracted_files = list(repo_dir.rglob("*"))
                if not extracted_files:
                    raise HTTPException(
                        status_code=400,
                        detail="ZIP file contains no files"
                    )

        finally:
            # Clean up temporary ZIP file
            os.unlink(temp_zip_path)

        logger.info(f"Extracted ZIP file to: {repo_dir} ({len(extracted_files)} files)")
        return str(repo_dir)

    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=400,
            detail="Invalid ZIP file format"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to extract ZIP file: {str(e)}"
        )
def _cleanup_workspace(workspace_path: Path):
    """Clean up workspace after scan is complete."""
    try:
        if workspace_path.exists():
            shutil.rmtree(workspace_path, ignore_errors=True)
            logger.info(f"Cleaned up workspace: {workspace_path}")
    except Exception as e:
        logger.error(f"Error cleaning up workspace {workspace_path}: {str(e)}")
